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
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/rs/cors"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	principalv1connect "github.com/wolfeidau/airunner/api/gen/proto/go/principal/v1/principalv1connect"
	"github.com/wolfeidau/airunner/internal/auth"
	"github.com/wolfeidau/airunner/internal/bootstrap"
	"github.com/wolfeidau/airunner/internal/client"
	"github.com/wolfeidau/airunner/internal/logger"
	"github.com/wolfeidau/airunner/internal/server"
	"github.com/wolfeidau/airunner/internal/store"
	awsstore "github.com/wolfeidau/airunner/internal/store/aws"
	memorystore "github.com/wolfeidau/airunner/internal/store/memory"
	postgresstore "github.com/wolfeidau/airunner/internal/store/postgres"
	"github.com/wolfeidau/airunner/internal/telemetry"
)

type RPCServerCmd struct {
	CORSOrigins      []string           `help:"allowed CORS origins for frontend requests" default:"https://localhost" env:"AIRUNNER_CORS_ORIGINS"`
	Listen           string             `help:"HTTP server listen address" default:"0.0.0.0:8993" env:"AIRUNNER_LISTEN"`
	Cert             string             `help:"path to TLS cert file" default:"" env:"AIRUNNER_TLS_CERT"`
	Key              string             `help:"path to TLS key file" default:"" env:"AIRUNNER_TLS_KEY"`
	NoAuth           bool               `help:"disable authentication (development only)" default:"false" env:"AIRUNNER_NO_AUTH"`
	Development      bool               `help:"development mode - auto-setup LocalStack infrastructure" default:"false" env:"AIRUNNER_DEVELOPMENT"`
	DevelopmentClean bool               `help:"clean resources on startup in development mode (deletes all data)" default:"false" env:"AIRUNNER_DEVELOPMENT_CLEAN"`
	Tracing          bool               `help:"enable tracing" default:"false" env:"AIRUNNER_TRACING"`
	WebsiteURL       string             `help:"website base URL for OIDC JWKS endpoint" default:"https://localhost" env:"AIRUNNER_WEBSITE_URL"`
	StoreType        string             `help:"job store type (memory, aws, or postgres)" default:"memory" env:"AIRUNNER_STORE_TYPE" enum:"memory,aws,postgres"`
	AWSStore         AWSStoreFlags      `embed:"" prefix:"aws-"`
	PostgresStore    PostgresStoreFlags `embed:"" prefix:"postgres-"`
	Execution        ExecutionFlags     `embed:"" prefix:"execution-"`
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

	// Endpoint overrides for local development
	SQSEndpointURL      string `help:"SQS endpoint URL override (for LocalStack)" default:"" env:"AIRUNNER_AWS_SQS_ENDPOINT_URL"`
	DynamoDBEndpointURL string `help:"DynamoDB endpoint URL override (for DynamoDB Local)" default:"" env:"AIRUNNER_AWS_DYNAMODB_ENDPOINT_URL"`
}

type PostgresStoreFlags struct {
	// Connection Configuration
	ConnString string `help:"PostgreSQL connection string" env:"POSTGRES_CONNECTION_STRING"`

	// Store Configuration
	TokenSigningSecret string `help:"secret key for HMAC signing of task tokens" env:"AIRUNNER_POSTGRES_TOKEN_SECRET"`
	EventsTTLDays      int32  `help:"TTL in days for job events" default:"30"`

	// Connection Pool Configuration
	MaxConns        int32 `help:"maximum number of connections in pool" default:"20"`
	MinConns        int32 `help:"minimum number of connections in pool" default:"5"`
	MaxConnLifetime int32 `help:"maximum connection lifetime in seconds" default:"3600"`
	MaxConnIdleTime int32 `help:"maximum connection idle time in seconds" default:"1800"`

	// Migration Configuration
	AutoMigrate bool `help:"run database migrations on startup" default:"false" env:"AIRUNNER_POSTGRES_AUTO_MIGRATE"`
}

func (s *PostgresStoreFlags) Validate() error {
	if s.ConnString == "" {
		return errors.New("PostgreSQL connection string is required (--postgres-conn-string or POSTGRES_CONNECTION_STRING)")
	}

	if s.TokenSigningSecret == "" {
		return errors.New("token signing secret is required (--postgres-token-secret or AIRUNNER_POSTGRES_TOKEN_SECRET)")
	}

	if len(s.TokenSigningSecret) < 32 {
		return errors.New("token signing secret must be at least 32 bytes (256 bits) for HMAC-SHA256")
	}

	return nil
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
	log := logger.Setup(globals.Debug)

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

	// If development mode, auto-setup LocalStack infrastructure
	if s.Development {
		log.Info().Msg("Development mode enabled - setting up LocalStack infrastructure")

		// Auto-configure for LocalStack
		if s.StoreType == "" || s.StoreType == "memory" {
			s.StoreType = "aws"
		}

		// Create AWS config for local development
		localConfig, err := config.LoadDefaultConfig(ctx,
			config.WithRegion("us-east-1"),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "test")),
		)
		if err != nil {
			return fmt.Errorf("failed to create local AWS config: %w", err)
		}

		// Create SQS client pointing to LocalStack
		sqsClient := sqs.NewFromConfig(localConfig, func(o *sqs.Options) {
			o.BaseEndpoint = aws.String("http://localhost:4566")
		})

		// Create DynamoDB client pointing to DynamoDB Local
		dynamoClient := dynamodb.NewFromConfig(localConfig, func(o *dynamodb.Options) {
			o.BaseEndpoint = aws.String("http://localhost:4101")
		})

		// Bootstrap infrastructure
		resources, err := bootstrap.Bootstrap(ctx, bootstrap.Config{
			SQSClient:      sqsClient,
			DynamoClient:   dynamoClient,
			Environment:    "dev",
			CleanResources: s.DevelopmentClean,
		})
		if err != nil {
			return fmt.Errorf("failed to bootstrap development infrastructure: %w", err)
		}

		// Auto-populate configuration from bootstrapped resources
		s.AWSStore.QueueDefault = resources.QueueURLs["default"]
		s.AWSStore.QueuePriority = resources.QueueURLs["priority"]
		s.AWSStore.DynamoDBJobsTable = resources.TableNames.Jobs
		s.AWSStore.DynamoDBEventsTable = resources.TableNames.Events
		s.AWSStore.SQSEndpointURL = "http://localhost:4566"
		s.AWSStore.DynamoDBEndpointURL = "http://localhost:4101"
		s.AWSStore.TokenSigningSecret = "dev-mode-secret-key-minimum-32-characters-long"

		log.Info().
			Str("jobs_table", resources.TableNames.Jobs).
			Str("events_table", resources.TableNames.Events).
			Str("default_queue", resources.QueueURLs["default"]).
			Str("priority_queue", resources.QueueURLs["priority"]).
			Msg("Development infrastructure ready")
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
	case "postgres":
		jobStore, err = createPostgresJobStore(ctx, s)
		if err != nil {
			return err
		}
		log.Info().Msg("Using PostgreSQL job store")
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

	// Add JWT authentication middleware if enabled
	if !s.NoAuth {
		// Create caching HTTP client for Connect RPC
		cachingClient := client.NewInMemoryCachingHTTPClient()

		// Create PrincipalService client (for worker public keys and revocation list)
		principalClient := principalv1connect.NewPrincipalServiceClient(
			cachingClient,
			s.WebsiteURL,
		)

		// Create principal store adapter (bridges RPC client to store interface)
		principalStore := client.NewPrincipalStoreAdapter(principalClient)

		// Create public key cache (caches both website JWKS and worker keys)
		publicKeyCache := auth.NewPublicKeyCache(principalStore, cachingClient)

		// Create revocation checker (polls every 5 minutes)
		revocationChecker := auth.NewRevocationChecker(
			ctx,
			principalClient,
			5*time.Minute, // Refresh interval
		)
		defer revocationChecker.Stop()

		// Create JWT verifier
		jwtVerifier := auth.NewJWTVerifier(
			s.WebsiteURL, // Website URL (OIDC issuer)
			publicKeyCache,
			revocationChecker,
		)

		// Wrap handler with JWT middleware
		handler = jwtVerifier.Middleware()(handler)

		log.Info().
			Str("website_url", s.WebsiteURL).
			Msg("JWT authentication enabled")
	} else {
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

	// Load default AWS configuration
	awsConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create SQS client with optional endpoint override
	sqsClientOpts := []func(*sqs.Options){}
	if cmd.AWSStore.SQSEndpointURL != "" {
		sqsClientOpts = append(sqsClientOpts, func(o *sqs.Options) {
			o.BaseEndpoint = aws.String(cmd.AWSStore.SQSEndpointURL)
		})
	}
	sqsClient := sqs.NewFromConfig(awsConfig, sqsClientOpts...)

	// Create DynamoDB client with optional endpoint override
	dynamoClientOpts := []func(*dynamodb.Options){}
	if cmd.AWSStore.DynamoDBEndpointURL != "" {
		dynamoClientOpts = append(dynamoClientOpts, func(o *dynamodb.Options) {
			o.BaseEndpoint = aws.String(cmd.AWSStore.DynamoDBEndpointURL)
		})
	}
	dynamoClient := dynamodb.NewFromConfig(awsConfig, dynamoClientOpts...)

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

// createPostgresJobStore creates and configures a PostgreSQL-backed job store
func createPostgresJobStore(ctx context.Context, cmd *RPCServerCmd) (store.JobStore, error) {
	// Validate Postgres store flags
	if err := cmd.PostgresStore.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate postgres flags: %w", err)
	}

	// Build store configuration with execution config
	storeCfg := &postgresstore.JobStoreConfig{
		ConnString:         cmd.PostgresStore.ConnString,
		TokenSigningSecret: []byte(cmd.PostgresStore.TokenSigningSecret),
		DefaultExecutionConfig: &jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   cmd.Execution.BatchFlushInterval,
				MaxBatchSize:           cmd.Execution.BatchMaxSize,
				MaxBatchBytes:          cmd.Execution.BatchMaxBytes,
				PlaybackIntervalMillis: cmd.Execution.PlaybackInterval,
			},
			HeartbeatIntervalSeconds: cmd.Execution.HeartbeatInterval,
		},
		EventsTTLDays:   cmd.PostgresStore.EventsTTLDays,
		MaxConns:        cmd.PostgresStore.MaxConns,
		MinConns:        cmd.PostgresStore.MinConns,
		MaxConnLifetime: cmd.PostgresStore.MaxConnLifetime,
		MaxConnIdleTime: cmd.PostgresStore.MaxConnIdleTime,
		AutoMigrate:     cmd.PostgresStore.AutoMigrate,
	}

	return postgresstore.NewJobStore(ctx, storeCfg)
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
