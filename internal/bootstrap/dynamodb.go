package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// CreateJobsTables creates both jobs and job_events tables
// If cleanResources is true, deletes existing tables first to ensure clean state
// If cleanResources is false, reuses existing tables (preserves data)
func CreateJobsTables(ctx context.Context, client *dynamodb.Client, env string, cleanResources bool) (jobsTable, eventsTable string, err error) {
	jobsTableName := fmt.Sprintf("%s_jobs", env)
	eventsTableName := fmt.Sprintf("%s_job_events", env)

	// Create jobs table with GSI1 and GSI2
	if err := createJobsTable(ctx, client, jobsTableName, cleanResources); err != nil {
		return "", "", fmt.Errorf("failed to create jobs table: %w", err)
	}

	// Create job events table
	if err := createJobEventsTable(ctx, client, eventsTableName, cleanResources); err != nil {
		return "", "", fmt.Errorf("failed to create job events table: %w", err)
	}

	return jobsTableName, eventsTableName, nil
}

// CreateSingleJobsTable creates a single jobs table (exported for test usage)
// Always deletes existing table first to ensure clean state for tests
func CreateSingleJobsTable(ctx context.Context, client *dynamodb.Client, tableName string) error {
	return createJobsTable(ctx, client, tableName, true)
}

// CreateSingleEventsTable creates a single events table (exported for test usage)
// Always deletes existing table first to ensure clean state for tests
func CreateSingleEventsTable(ctx context.Context, client *dynamodb.Client, tableName string) error {
	return createJobEventsTable(ctx, client, tableName, true)
}

// createJobsTable creates the jobs table with GSI1 and GSI2
// Schema matches infra/backend.tf:93-144
func createJobsTable(ctx context.Context, client *dynamodb.Client, tableName string, cleanResources bool) error {
	// Delete existing table if cleanResources is true
	if cleanResources {
		if err := deleteTableIfExists(ctx, client, tableName); err != nil {
			return err
		}
	}

	input := &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("job_id"),
				KeyType:       types.KeyTypeHash,
			},
		},
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("job_id"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("queue"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("created_at"),
				AttributeType: types.ScalarAttributeTypeN,
			},
			{
				AttributeName: aws.String("request_id"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
			{
				IndexName: aws.String("GSI1"),
				KeySchema: []types.KeySchemaElement{
					{
						AttributeName: aws.String("queue"),
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
				ProvisionedThroughput: &types.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
			{
				IndexName: aws.String("GSI2"),
				KeySchema: []types.KeySchemaElement{
					{
						AttributeName: aws.String("request_id"),
						KeyType:       types.KeyTypeHash,
					},
				},
				Projection: &types.Projection{
					ProjectionType: types.ProjectionTypeKeysOnly,
				},
				ProvisionedThroughput: &types.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
		},
		BillingMode: types.BillingModeProvisioned,
		ProvisionedThroughput: &types.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(5),
			WriteCapacityUnits: aws.Int64(5),
		},
	}

	_, err := client.CreateTable(ctx, input)
	if err != nil {
		// If table already exists and we're not cleaning, that's OK
		var resourceInUse *types.ResourceInUseException
		if !cleanResources && errors.As(err, &resourceInUse) {
			return nil // Table exists, reuse it
		}
		return err
	}

	// Wait for table to be active
	waiter := dynamodb.NewTableExistsWaiter(client)
	return waiter.Wait(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	}, 30*time.Second)
}

// createJobEventsTable creates the job events table
// Schema matches infra/backend.tf:146-179
func createJobEventsTable(ctx context.Context, client *dynamodb.Client, tableName string, cleanResources bool) error {
	// Delete existing table if cleanResources is true
	if cleanResources {
		if err := deleteTableIfExists(ctx, client, tableName); err != nil {
			return err
		}
	}

	input := &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("job_id"),
				KeyType:       types.KeyTypeHash,
			},
			{
				AttributeName: aws.String("sequence"),
				KeyType:       types.KeyTypeRange,
			},
		},
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("job_id"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("sequence"),
				AttributeType: types.ScalarAttributeTypeN,
			},
		},
		BillingMode: types.BillingModeProvisioned,
		ProvisionedThroughput: &types.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(5),
			WriteCapacityUnits: aws.Int64(5),
		},
	}

	_, err := client.CreateTable(ctx, input)
	if err != nil {
		// If table already exists and we're not cleaning, that's OK
		var resourceInUse *types.ResourceInUseException
		if !cleanResources && errors.As(err, &resourceInUse) {
			return nil // Table exists, reuse it
		}
		return err
	}

	// Wait for table to be active
	waiter := dynamodb.NewTableExistsWaiter(client)
	return waiter.Wait(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	}, 30*time.Second)
}

// deleteTableIfExists attempts to delete a table if it exists
func deleteTableIfExists(ctx context.Context, client *dynamodb.Client, tableName string) error {
	// Try to delete the table
	_, err := client.DeleteTable(ctx, &dynamodb.DeleteTableInput{
		TableName: aws.String(tableName),
	})

	// If table doesn't exist, we're done
	if err != nil {
		var resourceNotFound *types.ResourceNotFoundException
		if errors.As(err, &resourceNotFound) {
			return nil
		}
		// Unknown error
		return err
	}

	// Wait for table deletion to complete
	waiter := dynamodb.NewTableNotExistsWaiter(client)
	return waiter.Wait(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	}, 30*time.Second)
}

// DeleteTables removes both jobs and events tables
func DeleteTables(ctx context.Context, client *dynamodb.Client, jobsTable, eventsTable string) error {
	if err := deleteTableIfExists(ctx, client, jobsTable); err != nil {
		return fmt.Errorf("failed to delete jobs table: %w", err)
	}

	if err := deleteTableIfExists(ctx, client, eventsTable); err != nil {
		return fmt.Errorf("failed to delete events table: %w", err)
	}

	return nil
}
