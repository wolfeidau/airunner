//go:build integration

package aws

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

const (
	testDynamoDBEndpoint = "http://localhost:4101"
	testDynamoDBRegion   = "us-east-1"
	testJobsTable        = "test_jobs_integration"
	testEventsTable      = "test_events_integration"
)

// getDynamoDBClient creates a DynamoDB client for testing
func getDynamoDBClient(t *testing.T, ctx context.Context) *dynamodb.Client {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(testDynamoDBRegion),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "test")),
	)
	require.NoError(t, err)

	return dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		o.BaseEndpoint = aws.String(testDynamoDBEndpoint)
	})
}

// createTestTable creates a simple DynamoDB table for testing
func createTestTable(t *testing.T, ctx context.Context, client *dynamodb.Client, tableName string) {
	// Try to delete the table first
	_, _ = client.DeleteTable(ctx, &dynamodb.DeleteTableInput{TableName: aws.String(tableName)})

	deleteWaiter := dynamodb.NewTableNotExistsWaiter(client)
	err := deleteWaiter.Wait(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(tableName)}, 10*time.Second)
	require.NoError(t, err)

	input := &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("job_id"), KeyType: types.KeyTypeHash},
		},
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("job_id"), AttributeType: types.ScalarAttributeTypeS},
		},
		BillingMode: types.BillingModeProvisioned,
		ProvisionedThroughput: &types.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(5),
			WriteCapacityUnits: aws.Int64(5),
		},
	}

	_, err = client.CreateTable(ctx, input)
	require.NoError(t, err)

	createWaiter := dynamodb.NewTableExistsWaiter(client)
	err = createWaiter.Wait(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(tableName)}, 10*time.Second)
	require.NoError(t, err)
}

func deleteTestTable(t *testing.T, ctx context.Context, client *dynamodb.Client, tableName string) {
	_, _ = client.DeleteTable(ctx, &dynamodb.DeleteTableInput{TableName: aws.String(tableName)})
}

// putJobRecord stores a job using the correct DynamoDB format
func putJobRecord(t *testing.T, ctx context.Context, client *dynamodb.Client, tableName string, record *jobRecord) {
	itemMap, err := attributevalue.MarshalMap(record)
	require.NoError(t, err)

	_, err = client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      itemMap,
	})
	require.NoError(t, err)
}

// TestDynamoDB_JobStoreGetPut tests basic put and get operations
func TestDynamoDB_JobStoreGetPut(t *testing.T) {
	ctx := context.Background()
	client := getDynamoDBClient(t, ctx)
	createTestTable(t, ctx, client, testJobsTable)
	defer deleteTestTable(t, ctx, client, testJobsTable)

	store := NewJobStore(nil, client, JobStoreConfig{
		JobsTableName:      testJobsTable,
		TokenSigningSecret: []byte("dynamodb-test-secret"),
	})

	// Create a job record using the proper format
	jobID := uuid.Must(uuid.NewV7()).String()
	now := time.Now()
	record := &jobRecord{
		JobID:     jobID,
		Queue:     "default",
		State:     int32(jobv1.JobState_JOB_STATE_SCHEDULED),
		RequestID: "test-request-123",
		CreatedAt: now.UnixMilli(),
		UpdatedAt: now.UnixMilli(),
		JobParams: &jobv1.JobParams{
			Repository: "https://github.com/test/repo",
			Command:    "make",
		},
	}

	putJobRecord(t, ctx, client, testJobsTable, record)

	// Retrieve and verify
	retrieved, err := store.getJobByID(ctx, jobID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Equal(t, jobID, retrieved.JobId)
	require.Equal(t, jobv1.JobState_JOB_STATE_SCHEDULED, retrieved.State)
	require.Equal(t, "https://github.com/test/repo", retrieved.JobParams.Repository)
}

// TestDynamoDB_UpdateJobState tests job state updates
func TestDynamoDB_UpdateJobState(t *testing.T) {
	ctx := context.Background()
	client := getDynamoDBClient(t, ctx)
	createTestTable(t, ctx, client, testJobsTable)
	defer deleteTestTable(t, ctx, client, testJobsTable)

	store := NewJobStore(nil, client, JobStoreConfig{
		JobsTableName:      testJobsTable,
		TokenSigningSecret: []byte("dynamodb-test-secret"),
	})

	// Create a job record
	jobID := uuid.Must(uuid.NewV7()).String()
	now := time.Now()
	record := &jobRecord{
		JobID:     jobID,
		Queue:     "default",
		State:     int32(jobv1.JobState_JOB_STATE_SCHEDULED),
		RequestID: "test-update-123",
		CreatedAt: now.UnixMilli(),
		UpdatedAt: now.UnixMilli(),
		JobParams: &jobv1.JobParams{},
	}

	putJobRecord(t, ctx, client, testJobsTable, record)

	// Get the job and update state
	job, err := store.getJobByID(ctx, jobID)
	require.NoError(t, err)

	job.State = jobv1.JobState_JOB_STATE_RUNNING
	job.UpdatedAt = timestamppb.Now()

	err = store.updateJobState(ctx, job)
	require.NoError(t, err)

	// Small delay to ensure consistency
	time.Sleep(100 * time.Millisecond)

	// Verify update
	updated, err := store.getJobByID(ctx, jobID)
	require.NoError(t, err)
	require.Equal(t, jobv1.JobState_JOB_STATE_RUNNING, updated.State)
}

// TestDynamoDB_NotFound tests error handling for missing items
func TestDynamoDB_NotFound(t *testing.T) {
	ctx := context.Background()
	client := getDynamoDBClient(t, ctx)
	createTestTable(t, ctx, client, testJobsTable)
	defer deleteTestTable(t, ctx, client, testJobsTable)

	store := NewJobStore(nil, client, JobStoreConfig{
		JobsTableName:      testJobsTable,
		TokenSigningSecret: []byte("dynamodb-test-secret"),
	})

	// Try to get non-existent job
	job, err := store.getJobByID(ctx, "non-existent-id")
	require.NoError(t, err)
	require.Nil(t, job)
}

// TestDynamoDB_JobParamsMarshaling tests that complex JobParams are preserved
func TestDynamoDB_JobParamsMarshaling(t *testing.T) {
	ctx := context.Background()
	client := getDynamoDBClient(t, ctx)
	createTestTable(t, ctx, client, testJobsTable)
	defer deleteTestTable(t, ctx, client, testJobsTable)

	store := NewJobStore(nil, client, JobStoreConfig{
		JobsTableName:      testJobsTable,
		TokenSigningSecret: []byte("dynamodb-test-secret"),
	})

	// Create a job with complex parameters
	jobID := uuid.Must(uuid.NewV7()).String()
	now := time.Now()
	record := &jobRecord{
		JobID:     jobID,
		Queue:     "default",
		State:     int32(jobv1.JobState_JOB_STATE_SCHEDULED),
		RequestID: "test-params-123",
		CreatedAt: now.UnixMilli(),
		UpdatedAt: now.UnixMilli(),
		JobParams: &jobv1.JobParams{
			Repository:       "https://github.com/test/repo",
			Commit:           "abc123",
			Branch:           "main",
			Command:          "make",
			Args:             []string{"test", "coverage"},
			Owner:            "testuser",
			TimeoutSeconds:   300,
			ProcessType:      jobv1.ProcessType_PROCESS_TYPE_PTY,
			WorkingDirectory: "/tmp/work",
			Environment: map[string]string{
				"GO_VERSION": "1.25",
				"GOOS":       "linux",
			},
			Metadata: map[string]string{
				"build_id": "123",
			},
		},
	}

	putJobRecord(t, ctx, client, testJobsTable, record)

	// Retrieve and verify all fields
	retrieved, err := store.getJobByID(ctx, jobID)
	require.NoError(t, err)

	require.Equal(t, "https://github.com/test/repo", retrieved.JobParams.Repository)
	require.Equal(t, "abc123", retrieved.JobParams.Commit)
	require.Equal(t, "main", retrieved.JobParams.Branch)
	require.Equal(t, "make", retrieved.JobParams.Command)
	require.Equal(t, []string{"test", "coverage"}, retrieved.JobParams.Args)
	require.Equal(t, "testuser", retrieved.JobParams.Owner)
	require.Equal(t, int32(300), retrieved.JobParams.TimeoutSeconds)
	require.Equal(t, jobv1.ProcessType_PROCESS_TYPE_PTY, retrieved.JobParams.ProcessType)
	require.Equal(t, "/tmp/work", retrieved.JobParams.WorkingDirectory)
	require.Equal(t, map[string]string{"GO_VERSION": "1.25", "GOOS": "linux"}, retrieved.JobParams.Environment)
	require.Equal(t, map[string]string{"build_id": "123"}, retrieved.JobParams.Metadata)
}

// TestDynamoDB_ConcurrentPuts tests concurrent operations
func TestDynamoDB_ConcurrentPuts(t *testing.T) {
	ctx := context.Background()
	client := getDynamoDBClient(t, ctx)
	createTestTable(t, ctx, client, testJobsTable)
	defer deleteTestTable(t, ctx, client, testJobsTable)

	// Concurrently put 10 jobs
	done := make(chan error, 10)
	now := time.Now()

	for i := 0; i < 10; i++ {
		go func(idx int) {
			jobID := uuid.Must(uuid.NewV7()).String()
			record := &jobRecord{
				JobID:     jobID,
				Queue:     "default",
				State:     int32(jobv1.JobState_JOB_STATE_SCHEDULED),
				RequestID: uuid.Must(uuid.NewV7()).String(),
				CreatedAt: now.UnixMilli(),
				UpdatedAt: now.UnixMilli(),
				JobParams: &jobv1.JobParams{},
			}

			itemMap, err := attributevalue.MarshalMap(record)
			if err != nil {
				done <- err
				return
			}

			_, err = client.PutItem(ctx, &dynamodb.PutItemInput{
				TableName: aws.String(testJobsTable),
				Item:      itemMap,
			})
			done <- err
		}(i)
	}

	// Collect results
	for i := 0; i < 10; i++ {
		err := <-done
		require.NoError(t, err)
	}
}
