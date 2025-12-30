package bootstrap

import (
	"context"
	"fmt"
)

// Bootstrap creates all required infrastructure (SQS queues + DynamoDB tables)
// If CleanResources is true, deletes existing resources first to ensure clean state
// If CleanResources is false, creates resources only if they don't exist (preserves data)
func Bootstrap(ctx context.Context, cfg Config) (*Resources, error) {
	// Validate config
	if cfg.SQSClient == nil {
		return nil, fmt.Errorf("SQSClient is required")
	}
	if cfg.DynamoClient == nil {
		return nil, fmt.Errorf("DynamoClient is required")
	}
	if cfg.Environment == "" {
		cfg.Environment = "dev" // Default environment
	}

	resources := &Resources{
		QueueURLs: make(map[string]string),
	}

	// Create SQS queues
	queueURLs, err := CreateQueues(ctx, cfg.SQSClient, cfg.Environment, cfg.CleanResources)
	if err != nil {
		return nil, fmt.Errorf("failed to create SQS queues: %w", err)
	}
	resources.QueueURLs = queueURLs

	// Create DynamoDB tables
	jobsTable, eventsTable, err := CreateJobsTables(ctx, cfg.DynamoClient, cfg.Environment, cfg.CleanResources)
	if err != nil {
		return nil, fmt.Errorf("failed to create DynamoDB tables: %w", err)
	}
	resources.TableNames.Jobs = jobsTable
	resources.TableNames.Events = eventsTable

	return resources, nil
}

// Cleanup deletes all resources created by Bootstrap
func Cleanup(ctx context.Context, cfg Config, res *Resources) error {
	// Delete SQS queues
	if err := DeleteQueues(ctx, cfg.SQSClient, res.QueueURLs); err != nil {
		return fmt.Errorf("failed to delete queues: %w", err)
	}

	// Delete DynamoDB tables
	if err := DeleteTables(ctx, cfg.DynamoClient, res.TableNames.Jobs, res.TableNames.Events); err != nil {
		return fmt.Errorf("failed to delete tables: %w", err)
	}

	return nil
}
