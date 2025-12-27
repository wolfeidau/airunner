package commands

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
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
	"github.com/wolfeidau/airunner/internal/logger"
	"github.com/wolfeidau/airunner/internal/server"
	"github.com/wolfeidau/airunner/internal/store"
	awsstore "github.com/wolfeidau/airunner/internal/store/aws"
	memorystore "github.com/wolfeidau/airunner/internal/store/memory"
	"github.com/wolfeidau/airunner/internal/telemetry"
	"golang.org/x/sync/errgroup"
)

type RPCServerCmd struct {
	Hostname  string         `help:"hostname for TLS cert" default:"localhost"`
	StoreType string         `help:"job store type (memory or aws)" default:"memory" env:"AIRUNNER_STORE_TYPE" enum:"memory,aws"`
	AWSStore  AWSStoreFlags  `embed:"" prefix:"aws-"`
	Execution ExecutionFlags `embed:"" prefix:"execution-"`
	MTLS      MTLSFlags      `embed:"" prefix:"mtls-"`
}

type AWSStoreFlags struct {
	// SQS Configuration
	QueueDefault  string `help:"SQS queue URL for default priority jobs" env:"AIRUNNER_AWS_QUEUE_DEFAULT"`
	QueuePriority string `help:"SQS queue URL for priority jobs" env:"AIRUNNER_AWS_QUEUE_PRIORITY"`

	// DynamoDB Configuration
	DynamoDBJobsTable         string `help:"DynamoDB table name for jobs" env:"AIRUNNER_AWS_JOBS_TABLE"`
	DynamoDBEventsTable       string `help:"DynamoDB table name for events" env:"AIRUNNER_AWS_EVENTS_TABLE"`
	DynamoDBPrincipalsTable   string `help:"DynamoDB table name for principals" env:"AIRUNNER_AWS_PRINCIPALS_TABLE"`
	DynamoDBCertificatesTable string `help:"DynamoDB table name for certificates" env:"AIRUNNER_AWS_CERTS_TABLE"`

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

// MTLSFlags configuration for mTLS server
type MTLSFlags struct {
	Listen       string `help:"mTLS API listen address" default:"0.0.0.0:443" env:"AIRUNNER_MTLS_LISTEN"`
	HealthListen string `help:"health check listen address" default:"0.0.0.0:8080" env:"AIRUNNER_HEALTH_LISTEN"`
	CACert       string `help:"path to CA cert file for mTLS client verification" env:"AIRUNNER_CA_CERT"`
	ServerCert   string `help:"path to server cert file for mTLS" env:"AIRUNNER_SERVER_CERT"`
	ServerKey    string `help:"path to server key file for mTLS" env:"AIRUNNER_SERVER_KEY"`
}

// Validate MTLSFlags
func (m *MTLSFlags) Validate() error {
	// Validate required configuration
	if m.Listen == "" {
		return errors.New("mTLS listen address is required (--mtls-listen or AIRUNNER_MTLS_LISTEN)")
	}
	if m.HealthListen == "" {
		return errors.New("health listen address is required (--health-listen or AIRUNNER_HEALTH_LISTEN)")
	}
	if m.CACert == "" {
		return errors.New("CA cert path is required (--ca-cert or AIRUNNER_CA_CERT)")
	}
	if m.ServerCert == "" {
		return errors.New("server cert path is required (--server-cert or AIRUNNER_SERVER_CERT)")
	}
	if m.ServerKey == "" {
		return errors.New("server key path is required (--server-key or AIRUNNER_SERVER_KEY)")
	}
	return nil
}

func (s *RPCServerCmd) Run(ctx context.Context, globals *Globals) error {
	log := logger.Setup(globals.Dev)

	log.Info().Str("version", globals.Version).Msg("Starting RPC server")

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

	// Create principal and certificate stores for mTLS
	principalStore, certStore, err := s.createPrincipalStores(ctx)
	if err != nil {
		return err
	}
	log.Info().Msg("Principal and certificate stores initialized")

	// Create server with store
	jobServer := server.NewServer(jobStore)

	// Build handler chain: CORS -> Auth -> Connect handlers
	handler := jobServer.Handler(logger.NewConnectRequests(log), otelInterceptor)

	// Add mTLS authentication middleware
	mtlsAuth := auth.NewMTLSAuthenticator(principalStore, certStore)
	middleware := authn.NewMiddleware(mtlsAuth.AuthFunc())
	handler = middleware.Wrap(handler)
	log.Info().Msg("mTLS authentication enabled")

	// Add CORS
	handler = withCORS(s.Hostname, handler)

	// Run dual listeners: mTLS API on 443, health check on 8080
	return s.runWithMTLS(ctx, handler, principalStore)
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
func withCORS(hostname string, h http.Handler) http.Handler {
	middleware := cors.New(cors.Options{
		AllowedOrigins: []string{hostname},
		AllowedMethods: connectcors.AllowedMethods(),
		AllowedHeaders: append(connectcors.AllowedHeaders(), "Authorization"),
		ExposedHeaders: connectcors.ExposedHeaders(),
	})
	return middleware.Handler(h)
}

// createPrincipalStores creates principal and certificate stores based on store type
func (s *RPCServerCmd) createPrincipalStores(ctx context.Context) (store.PrincipalStore, store.CertificateStore, error) {
	switch s.StoreType {
	case "aws":
		// Use DynamoDB stores for production
		if s.AWSStore.DynamoDBPrincipalsTable == "" {
			return nil, nil, errors.New("DynamoDB principals table name is required (--aws-principals-table or AIRUNNER_AWS_PRINCIPALS_TABLE)")
		}
		if s.AWSStore.DynamoDBCertificatesTable == "" {
			return nil, nil, errors.New("DynamoDB certificates table name is required (--aws-certs-table or AIRUNNER_AWS_CERTS_TABLE)")
		}

		awsConfig, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load AWS config: %w", err)
		}

		dynamoClient := dynamodb.NewFromConfig(awsConfig)

		principalStore := awsstore.NewPrincipalStore(dynamoClient, s.AWSStore.DynamoDBPrincipalsTable)
		certStore := awsstore.NewCertificateStore(dynamoClient, s.AWSStore.DynamoDBCertificatesTable)

		return principalStore, certStore, nil

	default:
		// Use in-memory stores for development
		principalStore := memorystore.NewPrincipalStore()
		certStore := memorystore.NewCertificateStore()

		return principalStore, certStore, nil
	}
}

// runWithMTLS starts dual listeners: mTLS API and health check
func (s *RPCServerCmd) runWithMTLS(ctx context.Context, apiHandler http.Handler, principalStore store.PrincipalStore) error {
	log := logger.Setup(false)

	if err := s.MTLS.Validate(); err != nil {
		return fmt.Errorf("failed to validate MTLS configuration: %w", err)
	}

	// Load server certificate
	serverCert, err := tls.LoadX509KeyPair(s.MTLS.ServerCert, s.MTLS.ServerKey)
	if err != nil {
		return fmt.Errorf("failed to load server certificate: %w", err)
	}

	// Load CA certificate for client verification
	caCertPEM, err := os.ReadFile(s.MTLS.CACert)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return errors.New("failed to parse CA certificate")
	}

	// Configure TLS with client certificate verification
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Create mTLS API server
	mtlsServer := &http.Server{
		Addr:              s.MTLS.Listen,
		Handler:           apiHandler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    8 * 1024, // 8KiB
	}

	// Create health check server (HTTP only, no TLS)
	healthServer := &http.Server{
		Addr:              s.MTLS.HealthListen,
		Handler:           s.healthHandler(principalStore),
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    4 * 1024, // 4KiB
	}

	// Run both servers concurrently
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		log.Info().Str("addr", s.MTLS.Listen).Msg("Starting mTLS API server")
		if err := mtlsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("mTLS server error: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		log.Info().Str("addr", s.MTLS.HealthListen).Msg("Starting health check server")
		if err := healthServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("health server error: %w", err)
		}
		return nil
	})

	// Graceful shutdown on context cancellation
	g.Go(func() error {
		<-gctx.Done()

		log.Info().Msg("Shutting down servers...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := mtlsServer.Shutdown(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown mTLS server")
		}

		if err := healthServer.Shutdown(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown health server")
		}

		return nil
	})

	return g.Wait()
}

// healthHandler returns a simple health check handler
func (s *RPCServerCmd) healthHandler(principalStore store.PrincipalStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only allow GET requests
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Check principal store connectivity
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		_, err := principalStore.List(ctx, store.ListPrincipalsOptions{Limit: 1})
		if err != nil {
			http.Error(w, "unhealthy", http.StatusServiceUnavailable)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
}
