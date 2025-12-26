package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/airunner/internal/pki"
)

// BootstrapHandler defines the interface for environment-specific bootstrap logic
type BootstrapHandler interface {
	// Setup creates the CA signer and any environment-specific infrastructure
	Setup(ctx context.Context, paths certificatePaths) (pki.CASigner, error)
	// Finalize handles post-certificate steps (upload to AWS, print summary, etc)
	Finalize(ctx context.Context, paths certificatePaths) error
}

// LocalBootstrapHandler handles local development bootstrap
type LocalBootstrapHandler struct {
	cmd *BootstrapCmd
}

// Setup for local development: verify infrastructure, create tables/queues, then setup signer
func (h *LocalBootstrapHandler) Setup(ctx context.Context, paths certificatePaths) (pki.CASigner, error) {
	log.Info().Msg("Setting up local development environment...")

	// Verify LocalStack is reachable
	if err := h.verifyLocalStackHealth(ctx); err != nil {
		return nil, fmt.Errorf("LocalStack health check failed: %w\nEnsure docker-compose is running: docker-compose up -d", err)
	}

	// Create DynamoDB tables
	if err := h.createDynamoDBTables(ctx); err != nil {
		return nil, fmt.Errorf("failed to create DynamoDB tables: %w", err)
	}

	// Create SQS queues
	if err := h.createSQSQueues(ctx); err != nil {
		return nil, fmt.Errorf("failed to create SQS queues: %w", err)
	}

	// Setup file-based CA signer
	return h.cmd.setupLocalSigner(ctx, paths)
}

// Finalize for local: print summary with local-specific instructions
func (h *LocalBootstrapHandler) Finalize(ctx context.Context, paths certificatePaths) error {
	h.cmd.printLocalBootstrapSummary(paths)
	return nil
}

// verifyLocalStackHealth checks if LocalStack is accessible
func (h *LocalBootstrapHandler) verifyLocalStackHealth(ctx context.Context) error {
	awsConfig, err := h.cmd.loadAWSConfig(ctx)
	if err != nil {
		return err
	}

	// Try to list tables - simple health check
	dynamoClient := dynamodb.NewFromConfig(awsConfig)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err = dynamoClient.ListTables(ctx, &dynamodb.ListTablesInput{})
	if err != nil {
		return fmt.Errorf("cannot reach LocalStack at %s", h.cmd.AWSEndpoint)
	}

	log.Info().Msg("LocalStack is healthy")
	return nil
}

// createDynamoDBTables creates the principals and certificates tables with proper schemas
func (h *LocalBootstrapHandler) createDynamoDBTables(ctx context.Context) error {
	log.Info().Msg("Creating DynamoDB tables...")

	awsConfig, err := h.cmd.loadAWSConfig(ctx)
	if err != nil {
		return err
	}

	dynamoClient := dynamodb.NewFromConfig(awsConfig)

	// Create principals table
	principalsTable := fmt.Sprintf("airunner_%s_principals", h.cmd.Environment)
	if err := h.createPrincipalsTable(ctx, dynamoClient, principalsTable); err != nil {
		return err
	}

	// Create certificates table
	certificatesTable := fmt.Sprintf("airunner_%s_certificates", h.cmd.Environment)
	if err := h.createCertificatesTable(ctx, dynamoClient, certificatesTable); err != nil {
		return err
	}

	log.Info().Msg("DynamoDB tables created/verified")
	return nil
}

// createPrincipalsTable creates the principals table with GSIs
func (h *LocalBootstrapHandler) createPrincipalsTable(ctx context.Context, client *dynamodb.Client, tableName string) error {
	_, err := client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("principal_id"),
				KeyType:       types.KeyTypeHash,
			},
		},
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("principal_id"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("status"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("type"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("created_at"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
			{
				IndexName: aws.String("GSI1"),
				KeySchema: []types.KeySchemaElement{
					{
						AttributeName: aws.String("status"),
						KeyType:       types.KeyTypeHash,
					},
					{
						AttributeName: aws.String("created_at"),
						KeyType:       types.KeyTypeRange,
					},
				},
				Projection: &types.Projection{
					ProjectionType: types.ProjectionTypeAll,
				},
			},
			{
				IndexName: aws.String("GSI2"),
				KeySchema: []types.KeySchemaElement{
					{
						AttributeName: aws.String("type"),
						KeyType:       types.KeyTypeHash,
					},
					{
						AttributeName: aws.String("created_at"),
						KeyType:       types.KeyTypeRange,
					},
				},
				Projection: &types.Projection{
					ProjectionType: types.ProjectionTypeAll,
				},
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})

	if err != nil {
		// Table might already exist, log and continue
		log.Info().Str("table", tableName).Msg("Principals table created or already exists")
	}
	return nil
}

// createCertificatesTable creates the certificates table with GSIs
func (h *LocalBootstrapHandler) createCertificatesTable(ctx context.Context, client *dynamodb.Client, tableName string) error {
	_, err := client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("serial_number"),
				KeyType:       types.KeyTypeHash,
			},
		},
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("serial_number"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("principal_id"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("issued_at"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("fingerprint"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
			{
				IndexName: aws.String("GSI1"),
				KeySchema: []types.KeySchemaElement{
					{
						AttributeName: aws.String("principal_id"),
						KeyType:       types.KeyTypeHash,
					},
					{
						AttributeName: aws.String("issued_at"),
						KeyType:       types.KeyTypeRange,
					},
				},
				Projection: &types.Projection{
					ProjectionType: types.ProjectionTypeAll,
				},
			},
			{
				IndexName: aws.String("GSI2"),
				KeySchema: []types.KeySchemaElement{
					{
						AttributeName: aws.String("fingerprint"),
						KeyType:       types.KeyTypeHash,
					},
				},
				Projection: &types.Projection{
					ProjectionType: types.ProjectionTypeAll,
				},
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})

	if err != nil {
		// Table might already exist, log and continue
		log.Info().Str("table", tableName).Msg("Certificates table created or already exists")
	}
	return nil
}

// createSQSQueues creates the default job queues
func (h *LocalBootstrapHandler) createSQSQueues(ctx context.Context) error {
	log.Info().Msg("Creating SQS queues...")

	awsConfig, err := h.cmd.loadAWSConfig(ctx)
	if err != nil {
		return err
	}

	sqsClient := sqs.NewFromConfig(awsConfig)

	queues := []struct {
		name    string
		timeout int32
	}{
		{"default", 300},  // 5 minutes
		{"priority", 300}, // 5 minutes
		{"dlq", 1209600},  // 14 days for DLQ
	}

	for _, q := range queues {
		queueName := fmt.Sprintf("airunner_%s_%s", h.cmd.Environment, q.name)
		_, err := sqsClient.CreateQueue(ctx, &sqs.CreateQueueInput{
			QueueName: aws.String(queueName),
			Attributes: map[string]string{
				string(sqstypes.QueueAttributeNameVisibilityTimeout): fmt.Sprintf("%d", q.timeout),
			},
		})

		if err != nil {
			// Queue might already exist, log and continue
			log.Info().Str("queue", queueName).Msg("Queue created or already exists")
		} else {
			log.Info().Str("queue", queueName).Msg("Queue created")
		}
	}

	log.Info().Msg("SQS queues created/verified")
	return nil
}

// AWSBootstrapHandler handles AWS production bootstrap
type AWSBootstrapHandler struct {
	cmd       *BootstrapCmd
	awsConfig aws.Config
}

// Setup for AWS: just setup KMS signer (infrastructure pre-exists)
func (h *AWSBootstrapHandler) Setup(ctx context.Context, paths certificatePaths) (pki.CASigner, error) {
	return h.cmd.setupKMSSigner(ctx, paths)
}

// Finalize for AWS: upload certificates to SSM
func (h *AWSBootstrapHandler) Finalize(ctx context.Context, paths certificatePaths) error {
	if err := h.cmd.uploadToAWS(ctx, h.awsConfig, paths); err != nil {
		return fmt.Errorf("failed to upload to AWS: %w", err)
	}
	h.cmd.printAWSBootstrapSummary(paths)
	return nil
}

// getBootstrapHandler returns the appropriate handler for the environment
func (cmd *BootstrapCmd) getBootstrapHandler(ctx context.Context) (BootstrapHandler, error) {
	if cmd.Environment == "local" {
		return &LocalBootstrapHandler{cmd: cmd}, nil
	}

	awsConfig, err := cmd.loadAWSConfig(ctx)
	if err != nil {
		return nil, err
	}

	return &AWSBootstrapHandler{cmd: cmd, awsConfig: awsConfig}, nil
}
