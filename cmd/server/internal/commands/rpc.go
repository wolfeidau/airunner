package commands

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/authn"
	connectcors "connectrpc.com/cors"
	"connectrpc.com/otelconnect"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/rs/cors"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/auth"
	"github.com/wolfeidau/airunner/internal/autossl"
	"github.com/wolfeidau/airunner/internal/logger"
	"github.com/wolfeidau/airunner/internal/server"
	"github.com/wolfeidau/airunner/internal/store"
	"github.com/wolfeidau/airunner/internal/telemetry"
)

type RPCServerCmd struct {
	Listen                   string         `help:"listen address" default:"localhost:8993"`
	Cert                     string         `help:"path to TLS cert file" default:""`
	Key                      string         `help:"path to TLS key file" default:""`
	Hostname                 string         `help:"hostname for TLS cert" default:"localhost:8993"`
	NoAuth                   bool           `help:"disable JWT authentication (development only)" default:"false"`
	JWTPublicKey             string         `help:"PEM-encoded JWT public key" env:"JWT_PUBLIC_KEY"`
	StoreType                string         `help:"job store type (memory or sqs)" default:"memory" env:"AIRUNNER_STORE_TYPE" enum:"memory,sqs"`
	SQSQueueDefault          string         `help:"SQS queue URL for default priority jobs" env:"AIRUNNER_SQS_QUEUE_DEFAULT"`
	SQSQueuePriority         string         `help:"SQS queue URL for priority jobs" env:"AIRUNNER_SQS_QUEUE_PRIORITY"`
	DynamoDBJobsTable        string         `help:"DynamoDB table name for jobs" env:"AIRUNNER_DYNAMODB_JOBS_TABLE"`
	DynamoDBEventsTable      string         `help:"DynamoDB table name for job events" env:"AIRUNNER_DYNAMODB_EVENTS_TABLE"`
	DefaultVisibilityTimeout int32          `help:"default visibility timeout in seconds for SQS messages" default:"300"`
	EventsTTLDays            int32          `help:"TTL in days for job events in DynamoDB" default:"30"`
	TokenSigningSecret       string         `help:"secret key for signing JWT tokens" env:"AIRUNNER_TOKEN_SIGNING_SECRET"`
	Execution                ExecutionFlags `embed:"" prefix:"execution-"`
}

// Execution configuration for event batching
type ExecutionFlags struct {
	BatchFlushInterval int32 `help:"flush interval in seconds for event batching" default:"2" env:"AIRUNNER_EXEC_BATCH_FLUSH_INTERVAL"`
	BatchMaxSize       int32 `help:"max batch size in events" default:"50" env:"AIRUNNER_EXEC_BATCH_MAX_SIZE"`
	BatchMaxBytes      int64 `help:"max batch size in bytes" default:"1048576" env:"AIRUNNER_EXEC_BATCH_MAX_BYTES"`
	PlaybackInterval   int32 `help:"playback interval in milliseconds for client replay" default:"50" env:"AIRUNNER_EXEC_PLAYBACK_INTERVAL"`
	HeartbeatInterval  int32 `help:"heartbeat interval in seconds" default:"30" env:"AIRUNNER_EXEC_HEARTBEAT_INTERVAL"`
}

func (s *RPCServerCmd) Run(ctx context.Context, globals *Globals) error {
	log := logger.Setup(globals.Dev)

	log.Info().Str("version", globals.Version).Msg("Starting RPC server")
	log.Info().Str("url", fmt.Sprintf("https://%s", s.Listen)).Msg("Listening for RPC connections")

	// Initialize OpenTelemetry (metrics and traces exported to Honeycomb via env vars)
	shutdown, err := telemetry.InitTelemetry(ctx, "airunner-server", globals.Version)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to initialize telemetry, continuing without metrics")
		shutdown = func(ctx context.Context) error { return nil }
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err = shutdown(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown telemetry")
		}
	}()

	// setup OTEL
	otelInterceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		return fmt.Errorf("failed to create OTEL interceptor: %w", err)
	}

	// Determine store type and create appropriate store
	var jobStore store.JobStore

	switch s.StoreType {
	case "sqs":
		jobStore, err = createSQSJobStore(ctx, s)
		if err != nil {
			return err
		}
		log.Info().Msg("Using SQS/DynamoDB job store")
	default:
		// Default to memory store for backward compatibility
		memStore := store.NewMemoryJobStore()
		if err = memStore.Start(); err != nil {
			return err
		}
		jobStore = memStore
		log.Info().Msg("Using in-memory job store")
	}

	// Start store if it has Start method
	if startable, ok := jobStore.(interface{ Start() error }); ok {
		if err = startable.Start(); err != nil {
			return err
		}
		defer func() {
			if stoppable, ok := jobStore.(interface{ Stop() error }); ok {
				if err = stoppable.Stop(); err != nil {
					log.Error().Err(err).Msg("Failed to stop job store")
				}
			}
		}()
	}

	// Create server with store
	jobServer := server.NewServer(jobStore)

	// Build handler chain: CORS -> Auth -> Connect handlers
	handler := jobServer.Handler(logger.NewConnectRequests(log), otelInterceptor)

	// Add JWT auth middleware unless disabled
	if !s.NoAuth {
		jwtAuthFunc, err := auth.NewJWTAuthFunc(s.JWTPublicKey)
		if err != nil {
			return fmt.Errorf("failed to initialize JWT auth: %w", err)
		}
		middleware := authn.NewMiddleware(jwtAuthFunc)
		handler = middleware.Wrap(handler)
		log.Info().Msg("JWT authentication enabled")
	} else {
		log.Warn().Msg("JWT authentication disabled")
	}

	// Add CORS
	handler = withCORS(s.Hostname, handler)

	httpServer := &http.Server{
		Addr:              s.Listen,
		Handler:           handler,
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    8 * 1024, // 8KiB
	}

	if s.Cert != "" && s.Key != "" {
		return httpServer.ListenAndServeTLS(s.Cert, s.Key)
	}

	cert, err := autossl.GenerateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("failed to generate ssl cert: %w", err)
	}

	// print the cert fingerprint
	fingerprint := sha256.Sum256(cert.Certificate[0])
	log.Info().
		Str("fingerprint", fmt.Sprintf("%x", fingerprint)).
		Msg("generated self-signed certificate")

	httpServer.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return httpServer.ListenAndServeTLS("", "")
}

// createSQSJobStore creates and configures an SQS/DynamoDB-backed job store
func createSQSJobStore(ctx context.Context, cmd *RPCServerCmd) (store.JobStore, error) {
	// Validate required parameters
	if cmd.SQSQueueDefault == "" {
		return nil, errors.New("SQS queue default URL is required (--sqs-queue-default or AIRUNNER_SQS_QUEUE_DEFAULT)")
	}

	if cmd.SQSQueuePriority == "" {
		return nil, errors.New("SQS queue priority URL is required (--sqs-queue-priority or AIRUNNER_SQS_QUEUE_PRIORITY)")
	}

	if cmd.DynamoDBJobsTable == "" {
		return nil, errors.New("DynamoDB jobs table name is required (--dynamodb-jobs-table or AIRUNNER_DYNAMODB_JOBS_TABLE)")
	}

	if cmd.DynamoDBEventsTable == "" {
		return nil, errors.New("DynamoDB events table name is required (--dynamodb-events-table or AIRUNNER_DYNAMODB_EVENTS_TABLE)")
	}

	if cmd.TokenSigningSecret == "" {
		return nil, errors.New("token signing secret is required (--token-signing-secret or AIRUNNER_TOKEN_SIGNING_SECRET)")
	}

	if len(cmd.TokenSigningSecret) < 32 {
		return nil, errors.New("token signing secret must be at least 32 bytes (256 bits) for HMAC-SHA256")
	}

	// Load AWS configuration (uses default credential chain: IAM role, env vars, etc.)
	awsConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create AWS SDK clients
	sqsClient := sqs.NewFromConfig(awsConfig)
	dynamoClient := dynamodb.NewFromConfig(awsConfig)

	// Build store configuration with execution config
	storeCfg := store.SQSJobStoreConfig{
		QueueURLs: map[string]string{
			"default":  cmd.SQSQueueDefault,
			"priority": cmd.SQSQueuePriority,
		},
		JobsTableName:                   cmd.DynamoDBJobsTable,
		JobEventsTableName:              cmd.DynamoDBEventsTable,
		DefaultVisibilityTimeoutSeconds: cmd.DefaultVisibilityTimeout,
		EventsTTLDays:                   cmd.EventsTTLDays,
		TokenSigningSecret:              []byte(cmd.TokenSigningSecret),
		DefaultExecutionConfig: &jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   cmd.Execution.BatchFlushInterval,
				MaxBatchSize:           cmd.Execution.BatchMaxSize,
				MaxBatchBytes:          cmd.Execution.BatchMaxBytes,
				PlaybackIntervalMillis: cmd.Execution.PlaybackInterval,
			},
			HeartbeatIntervalSeconds: cmd.Execution.HeartbeatInterval,
		},
	}

	return store.NewSQSJobStore(sqsClient, dynamoClient, storeCfg), nil
}

// withCORS adds CORS support to a Connect HTTP handler.
func withCORS(hostname string, h http.Handler) http.Handler {
	middleware := cors.New(cors.Options{
		AllowedOrigins: []string{hostname},
		AllowedMethods: connectcors.AllowedMethods(),
		AllowedHeaders: append(connectcors.AllowedHeaders(), "Authorization"),
		ExposedHeaders: connectcors.ExposedHeaders(),
	})
	return middleware.Handler(h)
}
