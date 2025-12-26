package commands

import (
	"context"
	"crypto/sha256"
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
	"github.com/wolfeidau/airunner/internal/autossl"
	"github.com/wolfeidau/airunner/internal/logger"
	"github.com/wolfeidau/airunner/internal/server"
	"github.com/wolfeidau/airunner/internal/store"
	"github.com/wolfeidau/airunner/internal/telemetry"
	"golang.org/x/sync/errgroup"
)

type RPCServerCmd struct {
	Listen                    string         `help:"listen address" default:"localhost:8993"`
	Cert                      string         `help:"path to TLS cert file" default:""`
	Key                       string         `help:"path to TLS key file" default:""`
	Hostname                  string         `help:"hostname for TLS cert" default:"localhost:8993"`
	NoAuth                    bool           `help:"disable JWT authentication (development only)" default:"false"`
	JWTPublicKey              string         `help:"PEM-encoded JWT public key" env:"JWT_PUBLIC_KEY"`
	StoreType                 string         `help:"job store type (memory or sqs)" default:"memory" env:"AIRUNNER_STORE_TYPE" enum:"memory,sqs"`
	SQSQueueDefault           string         `help:"SQS queue URL for default priority jobs" env:"AIRUNNER_SQS_QUEUE_DEFAULT"`
	SQSQueuePriority          string         `help:"SQS queue URL for priority jobs" env:"AIRUNNER_SQS_QUEUE_PRIORITY"`
	DynamoDBJobsTable         string         `help:"DynamoDB table name for jobs" env:"AIRUNNER_DYNAMODB_JOBS_TABLE"`
	DynamoDBEventsTable       string         `help:"DynamoDB table name for job events" env:"AIRUNNER_DYNAMODB_EVENTS_TABLE"`
	DynamoDBPrincipalsTable   string         `help:"DynamoDB table name for principals" env:"AIRUNNER_DYNAMODB_PRINCIPALS_TABLE"`
	DynamoDBCertificatesTable string         `help:"DynamoDB table name for certificates" env:"AIRUNNER_DYNAMODB_CERTIFICATES_TABLE"`
	DefaultVisibilityTimeout  int32          `help:"default visibility timeout in seconds for SQS messages" default:"300"`
	EventsTTLDays             int32          `help:"TTL in days for job events in DynamoDB" default:"30"`
	TokenSigningSecret        string         `help:"secret key for signing JWT tokens" env:"AIRUNNER_TOKEN_SIGNING_SECRET"`
	Execution                 ExecutionFlags `embed:"" prefix:"execution-"`
	// mTLS configuration
	MTLSListen   string `help:"mTLS API listen address" default:"" env:"AIRUNNER_MTLS_LISTEN"`
	HealthListen string `help:"health check listen address" default:"" env:"AIRUNNER_HEALTH_LISTEN"`
	CACert       string `help:"path to CA cert file for mTLS client verification" default:"" env:"AIRUNNER_CA_CERT"`
	ServerCert   string `help:"path to server cert file for mTLS" default:"" env:"AIRUNNER_SERVER_CERT"`
	ServerKey    string `help:"path to server key file for mTLS" default:"" env:"AIRUNNER_SERVER_KEY"`
	EnableMTLS   bool   `help:"enable mTLS authentication" default:"false" env:"AIRUNNER_ENABLE_MTLS"`
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

	// Create principal and certificate stores if mTLS is enabled
	var principalStore store.PrincipalStore
	var certStore store.CertificateStore

	if s.EnableMTLS {
		principalStore, certStore, err = s.createPrincipalStores(ctx)
		if err != nil {
			return err
		}
		log.Info().Msg("Principal and certificate stores initialized")
	}

	// Create server with store
	jobServer := server.NewServer(jobStore)

	// Build handler chain: CORS -> Auth -> Connect handlers
	handler := jobServer.Handler(logger.NewConnectRequests(log), otelInterceptor)

	// Add authentication middleware
	switch {
	case s.EnableMTLS:
		// mTLS authentication
		mtlsAuth := auth.NewMTLSAuthenticator(principalStore, certStore)
		middleware := authn.NewMiddleware(mtlsAuth.AuthFunc())
		handler = middleware.Wrap(handler)
		log.Info().Msg("mTLS authentication enabled")
	case !s.NoAuth:
		// JWT authentication (backward compatibility)
		jwtAuthFunc, err := auth.NewJWTAuthFunc(s.JWTPublicKey)
		if err != nil {
			return fmt.Errorf("failed to initialize JWT auth: %w", err)
		}
		middleware := authn.NewMiddleware(jwtAuthFunc)
		handler = middleware.Wrap(handler)
		log.Info().Msg("JWT authentication enabled")
	default:
		log.Warn().Msg("Authentication disabled")
	}

	// Add CORS
	handler = withCORS(s.Hostname, handler)

	// If mTLS is enabled, run dual listeners
	if s.EnableMTLS {
		return s.runWithMTLS(ctx, handler, principalStore)
	}

	// Legacy single-listener mode
	log.Info().Str("url", fmt.Sprintf("https://%s", s.Listen)).Msg("Listening for RPC connections")

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

// createPrincipalStores creates principal and certificate stores based on store type
func (s *RPCServerCmd) createPrincipalStores(ctx context.Context) (store.PrincipalStore, store.CertificateStore, error) {
	switch s.StoreType {
	case "sqs":
		// Use DynamoDB stores for production
		if s.DynamoDBPrincipalsTable == "" {
			return nil, nil, errors.New("DynamoDB principals table name is required (--dynamodb-principals-table or AIRUNNER_DYNAMODB_PRINCIPALS_TABLE)")
		}
		if s.DynamoDBCertificatesTable == "" {
			return nil, nil, errors.New("DynamoDB certificates table name is required (--dynamodb-certificates-table or AIRUNNER_DYNAMODB_CERTIFICATES_TABLE)")
		}

		awsConfig, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load AWS config: %w", err)
		}

		dynamoClient := dynamodb.NewFromConfig(awsConfig)

		principalStore := store.NewDynamoDBPrincipalStore(dynamoClient, s.DynamoDBPrincipalsTable)
		certStore := store.NewDynamoDBCertificateStore(dynamoClient, s.DynamoDBCertificatesTable)

		return principalStore, certStore, nil

	default:
		// Use in-memory stores for development
		principalStore := store.NewMemoryPrincipalStore()
		certStore := store.NewMemoryCertificateStore()

		return principalStore, certStore, nil
	}
}

// runWithMTLS starts dual listeners: mTLS API and health check
func (s *RPCServerCmd) runWithMTLS(ctx context.Context, apiHandler http.Handler, principalStore store.PrincipalStore) error {
	log := logger.Setup(false)

	// Validate required configuration
	if s.MTLSListen == "" {
		return errors.New("mTLS listen address is required (--mtls-listen or AIRUNNER_MTLS_LISTEN)")
	}
	if s.HealthListen == "" {
		return errors.New("health listen address is required (--health-listen or AIRUNNER_HEALTH_LISTEN)")
	}
	if s.CACert == "" {
		return errors.New("CA cert path is required (--ca-cert or AIRUNNER_CA_CERT)")
	}
	if s.ServerCert == "" {
		return errors.New("server cert path is required (--server-cert or AIRUNNER_SERVER_CERT)")
	}
	if s.ServerKey == "" {
		return errors.New("server key path is required (--server-key or AIRUNNER_SERVER_KEY)")
	}

	// Load server certificate
	serverCert, err := tls.LoadX509KeyPair(s.ServerCert, s.ServerKey)
	if err != nil {
		return fmt.Errorf("failed to load server certificate: %w", err)
	}

	// Load CA certificate for client verification
	caCertPEM, err := os.ReadFile(s.CACert)
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
		Addr:              s.MTLSListen,
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
		Addr:              s.HealthListen,
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
		log.Info().Str("addr", s.MTLSListen).Msg("Starting mTLS API server")
		if err := mtlsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("mTLS server error: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		log.Info().Str("addr", s.HealthListen).Msg("Starting health check server")
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
