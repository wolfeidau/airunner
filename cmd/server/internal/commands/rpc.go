package commands

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect"
	connectcors "connectrpc.com/cors"
	"connectrpc.com/otelconnect"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/rs/cors"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/logger"
	"github.com/wolfeidau/airunner/internal/server"
	"github.com/wolfeidau/airunner/internal/store"
	awsstore "github.com/wolfeidau/airunner/internal/store/aws"
	memorystore "github.com/wolfeidau/airunner/internal/store/memory"
	"github.com/wolfeidau/airunner/internal/telemetry"
)

type RPCServerCmd struct {
	CORSOrigins []string       `help:"allowed CORS origins for frontend requests" default:"https://localhost" env:"AIRUNNER_CORS_ORIGINS"`
	Listen      string         `help:"HTTP server listen address" default:"0.0.0.0:8993" env:"AIRUNNER_LISTEN"`
	Cert        string         `help:"path to TLS cert file" default:"" env:"AIRUNNER_TLS_CERT"`
	Key         string         `help:"path to TLS key file" default:"" env:"AIRUNNER_TLS_KEY"`
	NoAuth      bool           `help:"disable authentication (development only)" default:"false" env:"AIRUNNER_NO_AUTH"`
	Tracing     bool           `help:"enable tracing" default:"false" env:"AIRUNNER_TRACING"`
	StoreType   string         `help:"job store type (memory or aws)" default:"memory" env:"AIRUNNER_STORE_TYPE" enum:"memory,aws"`
	AWSStore    AWSStoreFlags  `embed:"" prefix:"aws-"`
	Execution   ExecutionFlags `embed:"" prefix:"execution-"`
}

type AWSStoreFlags struct {
	// SQS Configuration
	QueueDefault  string `help:"SQS queue URL for default priority jobs" env:"AIRUNNER_AWS_QUEUE_DEFAULT"`
	QueuePriority string `help:"SQS queue URL for priority jobs" env:"AIRUNNER_AWS_QUEUE_PRIORITY"`

	// DynamoDB Configuration
	DynamoDBJobsTable   string `help:"DynamoDB table name for jobs" env:"AIRUNNER_AWS_JOBS_TABLE"`
	DynamoDBEventsTable string `help:"DynamoDB table name for events" env:"AIRUNNER_AWS_EVENTS_TABLE"`

	// Store Configuration
	DefaultVisibilityTimeout int32  `help:"default visibility timeout in seconds" default:"300"`
	EventsTTLDays            int32  `help:"TTL in days for job events" default:"30"`
	TokenSigningSecret       string `help:"secret key for HMAC signing of task tokens" env:"AIRUNNER_AWS_TOKEN_SECRET"`
}

func (s *AWSStoreFlags) Validate() error {
	// Validate required parameters
	if s.QueueDefault == "" {
		return errors.New("SQS queue default URL is required (--aws-queue-default or AIRUNNER_AWS_QUEUE_DEFAULT)")
	}

	if s.QueuePriority == "" {
		return errors.New("SQS queue priority URL is required (--aws-queue-priority or AIRUNNER_AWS_QUEUE_PRIORITY)")
	}

	if s.DynamoDBJobsTable == "" {
		return errors.New("DynamoDB jobs table name is required (--aws-jobs-table or AIRUNNER_AWS_JOBS_TABLE)")
	}

	if s.DynamoDBEventsTable == "" {
		return errors.New("DynamoDB events table name is required (--aws-events-table or AIRUNNER_AWS_EVENTS_TABLE)")
	}

	if s.TokenSigningSecret == "" {
		return errors.New("token signing secret is required (--aws-token-secret or AIRUNNER_AWS_TOKEN_SECRET)")
	}

	if len(s.TokenSigningSecret) < 32 {
		return errors.New("token signing secret must be at least 32 bytes (256 bits) for HMAC-SHA256")
	}
	return nil
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

	interceptors := []connect.Interceptor{logger.NewConnectRequests(log)}

	if s.Tracing {
		log.Info().Msg("Tracing is enabled")
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
		interceptors = append(interceptors, otelInterceptor)
	}

	// Determine store type and create appropriate store
	var (
		jobStore store.JobStore
		err      error
	)

	switch s.StoreType {
	case "aws":
		jobStore, err = createAWSJobStore(ctx, s)
		if err != nil {
			return err
		}
		log.Info().Msg("Using AWS job store (SQS + DynamoDB)")
	default:
		// Default to memory store for backward compatibility
		memStore := memorystore.NewJobStore()
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

	// Build handler chain: CORS -> Connect handlers
	handler := jobServer.Handler(interceptors...)

	if !s.NoAuth {
		log.Warn().Msg("Authentication is disabled (--no-auth). This should only be used in development!")
	}

	// Add CORS
	handler = withCORS(s.CORSOrigins, handler)

	// Create HTTP server
	httpServer := configureHTTPServer(s.Listen, handler)

	if s.Cert != "" && s.Key != "" {
		if _, err := os.Stat(s.Cert); err != nil {
			return fmt.Errorf("TLS certificate not found at %s. Run 'make certs' to generate certificates: %w", s.Cert, err)
		}
		if _, err := os.Stat(s.Key); err != nil {
			return fmt.Errorf("TLS key not found at %s. Run 'make certs' to generate certificates: %w", s.Key, err)
		}

		log.Info().Str("addr", s.Listen).Bool("auth", !s.NoAuth).Msg("Starting HTTPS server")
		return httpServer.ListenAndServeTLS(s.Cert, s.Key)
	}

	// Start server
	log.Info().Str("addr", s.Listen).Bool("auth", !s.NoAuth).Msg("Starting HTTP server")
	return httpServer.ListenAndServe()
}

// createAWSJobStore creates and configures an AWS-backed job store (SQS + DynamoDB)
func createAWSJobStore(ctx context.Context, cmd *RPCServerCmd) (store.JobStore, error) {
	// Validate AWS store flags
	if err := cmd.AWSStore.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate aws flags: %w", err)
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
	storeCfg := awsstore.JobStoreConfig{
		QueueURLs: map[string]string{
			"default":  cmd.AWSStore.QueueDefault,
			"priority": cmd.AWSStore.QueuePriority,
		},
		JobsTableName:                   cmd.AWSStore.DynamoDBJobsTable,
		JobEventsTableName:              cmd.AWSStore.DynamoDBEventsTable,
		DefaultVisibilityTimeoutSeconds: cmd.AWSStore.DefaultVisibilityTimeout,
		EventsTTLDays:                   cmd.AWSStore.EventsTTLDays,
		TokenSigningSecret:              []byte(cmd.AWSStore.TokenSigningSecret),
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

	return awsstore.NewJobStore(sqsClient, dynamoClient, storeCfg), nil
}

// withCORS adds CORS support to a Connect HTTP handler.
func withCORS(allowedOrigins []string, h http.Handler) http.Handler {
	middleware := cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   connectcors.AllowedMethods(),
		AllowedHeaders:   append(connectcors.AllowedHeaders(), "Authorization"),
		ExposedHeaders:   connectcors.ExposedHeaders(),
		AllowCredentials: true, // Required for cookie-based authentication
	})
	return middleware.Handler(h)
}
