//go:build integration

package aws

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/stretchr/testify/require"

	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

const (
	testSQSEndpoint      = "http://localhost:4566"
	testDefaultQueueName = "airunner-test-default"
)

// Test signing secret for HMAC task tokens
var testTokenSigningSecret = []byte("integration-test-secret-key-do-not-use-in-production")

// getSQSClient creates an SQS client for testing with LocalStack
func getSQSClient(t *testing.T, ctx context.Context) *sqs.Client {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(testDynamoDBRegion),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "test")),
	)
	require.NoError(t, err)

	return sqs.NewFromConfig(cfg, func(o *sqs.Options) {
		o.BaseEndpoint = aws.String(testSQSEndpoint)
	})
}

// getDynamoDBClientV2 creates a DynamoDB client using BaseEndpoint (preferred method)
func getDynamoDBClientV2(t *testing.T, ctx context.Context) *dynamodb.Client {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(testDynamoDBRegion),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "test")),
	)
	require.NoError(t, err)

	return dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		o.BaseEndpoint = aws.String(testDynamoDBEndpoint)
	})
}

// createTestTableWithGSIs creates a DynamoDB table with GSI1 and GSI2 for full testing
func createTestTableWithGSIs(t *testing.T, ctx context.Context, client *dynamodb.Client, tableName string) {
	// Try to delete the table first
	_, _ = client.DeleteTable(ctx, &dynamodb.DeleteTableInput{TableName: aws.String(tableName)})

	deleteWaiter := dynamodb.NewTableNotExistsWaiter(client)
	_ = deleteWaiter.Wait(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(tableName)}, 10*time.Second)

	input := &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("job_id"), KeyType: types.KeyTypeHash},
		},
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("job_id"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("queue"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("created_at"), AttributeType: types.ScalarAttributeTypeN},
			{AttributeName: aws.String("request_id"), AttributeType: types.ScalarAttributeTypeS},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
			{
				IndexName: aws.String("GSI1"),
				KeySchema: []types.KeySchemaElement{
					{AttributeName: aws.String("queue"), KeyType: types.KeyTypeHash},
					{AttributeName: aws.String("created_at"), KeyType: types.KeyTypeRange},
				},
				Projection: &types.Projection{ProjectionType: types.ProjectionTypeAll},
				ProvisionedThroughput: &types.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
			{
				IndexName: aws.String("GSI2"),
				KeySchema: []types.KeySchemaElement{
					{AttributeName: aws.String("request_id"), KeyType: types.KeyTypeHash},
				},
				Projection: &types.Projection{ProjectionType: types.ProjectionTypeKeysOnly},
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
	require.NoError(t, err)

	createWaiter := dynamodb.NewTableExistsWaiter(client)
	err = createWaiter.Wait(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(tableName)}, 30*time.Second)
	require.NoError(t, err)
}

// getQueueURL retrieves the SQS queue URL
func getQueueURL(t *testing.T, ctx context.Context, sqsClient *sqs.Client, queueName string) string {
	result, err := sqsClient.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{
		QueueName: aws.String(queueName),
	})
	require.NoError(t, err)
	return *result.QueueUrl
}

// purgeQueue removes all messages from the queue
func purgeQueue(t *testing.T, ctx context.Context, sqsClient *sqs.Client, queueURL string) {
	_, _ = sqsClient.PurgeQueue(ctx, &sqs.PurgeQueueInput{
		QueueUrl: aws.String(queueURL),
	})
	// Give SQS time to purge
	time.Sleep(100 * time.Millisecond)
}

// TestIntegration_EnqueueJob tests job enqueue with real SQS and DynamoDB
func TestIntegration_EnqueueJob(t *testing.T) {
	ctx := context.Background()

	sqsClient := getSQSClient(t, ctx)
	dynamoClient := getDynamoDBClientV2(t, ctx)

	tableName := "test_enqueue_" + time.Now().Format("20060102150405")
	createTestTableWithGSIs(t, ctx, dynamoClient, tableName)
	defer deleteTestTable(t, ctx, dynamoClient, tableName)

	queueURL := getQueueURL(t, ctx, sqsClient, testDefaultQueueName)
	purgeQueue(t, ctx, sqsClient, queueURL)

	store := NewJobStore(sqsClient, dynamoClient, JobStoreConfig{
		JobsTableName: tableName,
		QueueURLs: map[string]string{
			"default": queueURL,
		},
		DefaultVisibilityTimeoutSeconds: 30,
		TokenSigningSecret:              testTokenSigningSecret,
	})

	// Enqueue a job
	req := &jobv1.EnqueueJobRequest{
		Queue:     "default",
		RequestId: "test-request-123",
		JobParams: &jobv1.JobParams{
			Repository: "https://github.com/test/repo",
			Command:    "make",
			Args:       []string{"test"},
		},
	}

	resp, err := store.EnqueueJob(ctx, req)
	require.NoError(t, err)
	require.NotEmpty(t, resp.JobId)
	require.Equal(t, jobv1.JobState_JOB_STATE_SCHEDULED, resp.State)
	require.NotNil(t, resp.CreatedAt)

	// Verify job exists in DynamoDB
	job, err := store.getJobByID(ctx, resp.JobId)
	require.NoError(t, err)
	require.NotNil(t, job)
	require.Equal(t, resp.JobId, job.JobId)
	require.Equal(t, jobv1.JobState_JOB_STATE_SCHEDULED, job.State)

	// Verify message was sent to SQS (by receiving it)
	receiveResult, err := sqsClient.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(queueURL),
		MaxNumberOfMessages: 1,
		WaitTimeSeconds:     1,
	})
	require.NoError(t, err)
	require.Len(t, receiveResult.Messages, 1)
}

// TestIntegration_EnqueueIdempotency tests that duplicate request IDs return the same job
func TestIntegration_EnqueueIdempotency(t *testing.T) {
	ctx := context.Background()

	sqsClient := getSQSClient(t, ctx)
	dynamoClient := getDynamoDBClientV2(t, ctx)

	tableName := "test_idempotency_" + time.Now().Format("20060102150405")
	createTestTableWithGSIs(t, ctx, dynamoClient, tableName)
	defer deleteTestTable(t, ctx, dynamoClient, tableName)

	queueURL := getQueueURL(t, ctx, sqsClient, testDefaultQueueName)
	purgeQueue(t, ctx, sqsClient, queueURL)

	store := NewJobStore(sqsClient, dynamoClient, JobStoreConfig{
		JobsTableName: tableName,
		QueueURLs: map[string]string{
			"default": queueURL,
		},
		TokenSigningSecret: testTokenSigningSecret,
	})

	req := &jobv1.EnqueueJobRequest{
		Queue:     "default",
		RequestId: "idempotent-request-456",
		JobParams: &jobv1.JobParams{
			Repository: "https://github.com/test/repo",
			Command:    "make",
		},
	}

	// First enqueue
	resp1, err := store.EnqueueJob(ctx, req)
	require.NoError(t, err)
	require.NotEmpty(t, resp1.JobId)

	// Second enqueue with same request ID
	resp2, err := store.EnqueueJob(ctx, req)
	require.NoError(t, err)
	require.Equal(t, resp1.JobId, resp2.JobId, "Idempotent request should return same job ID")
}

// TestIntegration_FullJobLifecycle tests enqueue -> dequeue -> complete
func TestIntegration_FullJobLifecycle(t *testing.T) {
	ctx := context.Background()

	sqsClient := getSQSClient(t, ctx)
	dynamoClient := getDynamoDBClientV2(t, ctx)

	tableName := "test_lifecycle_" + time.Now().Format("20060102150405")
	createTestTableWithGSIs(t, ctx, dynamoClient, tableName)
	defer deleteTestTable(t, ctx, dynamoClient, tableName)

	queueURL := getQueueURL(t, ctx, sqsClient, testDefaultQueueName)
	purgeQueue(t, ctx, sqsClient, queueURL)

	store := NewJobStore(sqsClient, dynamoClient, JobStoreConfig{
		JobsTableName: tableName,
		QueueURLs: map[string]string{
			"default": queueURL,
		},
		DefaultVisibilityTimeoutSeconds: 30,
		TokenSigningSecret:              testTokenSigningSecret,
	})

	// 1. Enqueue a job
	enqueueReq := &jobv1.EnqueueJobRequest{
		Queue:     "default",
		RequestId: "lifecycle-test-789",
		JobParams: &jobv1.JobParams{
			Repository: "https://github.com/test/repo",
			Command:    "make",
			Args:       []string{"build"},
		},
	}

	enqueueResp, err := store.EnqueueJob(ctx, enqueueReq)
	require.NoError(t, err)
	jobID := enqueueResp.JobId

	// 2. Dequeue the job
	jobs, err := store.DequeueJobs(ctx, "default", 1, 30)
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	dequeuedJob := jobs[0]
	require.Equal(t, jobID, dequeuedJob.Job.JobId)
	require.Equal(t, jobv1.JobState_JOB_STATE_RUNNING, dequeuedJob.Job.State)
	require.NotEmpty(t, dequeuedJob.TaskToken)

	// Verify job state in DynamoDB is RUNNING
	job, err := store.getJobByID(ctx, jobID)
	require.NoError(t, err)
	require.Equal(t, jobv1.JobState_JOB_STATE_RUNNING, job.State)

	// 3. Complete the job
	result := &jobv1.JobResult{
		JobId:    jobID,
		Success:  true,
		ExitCode: 0,
	}

	err = store.CompleteJob(ctx, dequeuedJob.TaskToken, result)
	require.NoError(t, err)

	// Verify job state in DynamoDB is COMPLETED
	job, err = store.getJobByID(ctx, jobID)
	require.NoError(t, err)
	require.Equal(t, jobv1.JobState_JOB_STATE_COMPLETED, job.State)

	// 4. Verify message was deleted from SQS (queue should be empty)
	receiveResult, err := sqsClient.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(queueURL),
		MaxNumberOfMessages: 1,
		WaitTimeSeconds:     1,
	})
	require.NoError(t, err)
	require.Empty(t, receiveResult.Messages, "SQS queue should be empty after job completion")
}

// TestIntegration_DequeueNoJobs tests dequeue when queue is empty
func TestIntegration_DequeueNoJobs(t *testing.T) {
	ctx := context.Background()

	sqsClient := getSQSClient(t, ctx)
	dynamoClient := getDynamoDBClientV2(t, ctx)

	tableName := "test_empty_dequeue_" + time.Now().Format("20060102150405")
	createTestTableWithGSIs(t, ctx, dynamoClient, tableName)
	defer deleteTestTable(t, ctx, dynamoClient, tableName)

	queueURL := getQueueURL(t, ctx, sqsClient, testDefaultQueueName)
	purgeQueue(t, ctx, sqsClient, queueURL)

	store := NewJobStore(sqsClient, dynamoClient, JobStoreConfig{
		JobsTableName: tableName,
		QueueURLs: map[string]string{
			"default": queueURL,
		},
		TokenSigningSecret: testTokenSigningSecret,
	})

	// Dequeue from empty queue
	jobs, err := store.DequeueJobs(ctx, "default", 1, 30)
	require.NoError(t, err)
	require.Nil(t, jobs, "Should return nil when no jobs available")
}

// TestIntegration_CompleteJobFailed tests marking a job as failed
func TestIntegration_CompleteJobFailed(t *testing.T) {
	ctx := context.Background()

	sqsClient := getSQSClient(t, ctx)
	dynamoClient := getDynamoDBClientV2(t, ctx)

	tableName := "test_failed_" + time.Now().Format("20060102150405")
	createTestTableWithGSIs(t, ctx, dynamoClient, tableName)
	defer deleteTestTable(t, ctx, dynamoClient, tableName)

	queueURL := getQueueURL(t, ctx, sqsClient, testDefaultQueueName)
	purgeQueue(t, ctx, sqsClient, queueURL)

	store := NewJobStore(sqsClient, dynamoClient, JobStoreConfig{
		JobsTableName: tableName,
		QueueURLs: map[string]string{
			"default": queueURL,
		},
		TokenSigningSecret: testTokenSigningSecret,
	})

	// Enqueue and dequeue
	enqueueResp, err := store.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
		Queue:     "default",
		RequestId: "fail-test",
		JobParams: &jobv1.JobParams{Command: "fail"},
	})
	require.NoError(t, err)

	jobs, err := store.DequeueJobs(ctx, "default", 1, 30)
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	// Complete with failure
	result := &jobv1.JobResult{
		JobId:        enqueueResp.JobId,
		Success:      false,
		ExitCode:     1,
		ErrorMessage: "Command failed",
	}

	err = store.CompleteJob(ctx, jobs[0].TaskToken, result)
	require.NoError(t, err)

	// Verify job state is FAILED
	job, err := store.getJobByID(ctx, enqueueResp.JobId)
	require.NoError(t, err)
	require.Equal(t, jobv1.JobState_JOB_STATE_FAILED, job.State)
}

// TestIntegration_UpdateVisibility tests extending visibility timeout
func TestIntegration_UpdateVisibility(t *testing.T) {
	ctx := context.Background()

	sqsClient := getSQSClient(t, ctx)
	dynamoClient := getDynamoDBClientV2(t, ctx)

	tableName := "test_visibility_" + time.Now().Format("20060102150405")
	createTestTableWithGSIs(t, ctx, dynamoClient, tableName)
	defer deleteTestTable(t, ctx, dynamoClient, tableName)

	queueURL := getQueueURL(t, ctx, sqsClient, testDefaultQueueName)
	purgeQueue(t, ctx, sqsClient, queueURL)

	store := NewJobStore(sqsClient, dynamoClient, JobStoreConfig{
		JobsTableName: tableName,
		QueueURLs: map[string]string{
			"default": queueURL,
		},
		TokenSigningSecret: testTokenSigningSecret,
	})

	// Enqueue and dequeue with short visibility
	_, err := store.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
		Queue:     "default",
		RequestId: "visibility-test",
		JobParams: &jobv1.JobParams{Command: "long-running"},
	})
	require.NoError(t, err)

	jobs, err := store.DequeueJobs(ctx, "default", 1, 10) // 10 second visibility
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	// Extend visibility
	err = store.UpdateJobVisibility(ctx, "default", jobs[0].TaskToken, 60)
	require.NoError(t, err)

	// Complete the job
	err = store.CompleteJob(ctx, jobs[0].TaskToken, &jobv1.JobResult{
		JobId:   jobs[0].Job.JobId,
		Success: true,
	})
	require.NoError(t, err)
}

// TestIntegration_QueueNotConfigured tests error when queue is not configured
func TestIntegration_QueueNotConfigured(t *testing.T) {
	ctx := context.Background()

	dynamoClient := getDynamoDBClientV2(t, ctx)

	store := NewJobStore(nil, dynamoClient, JobStoreConfig{
		JobsTableName: "unused",
		QueueURLs:     map[string]string{}, // No queues configured
	})

	_, err := store.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
		Queue:     "nonexistent",
		RequestId: "test",
		JobParams: &jobv1.JobParams{},
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "queue not configured")
}

// createTestEventsTable creates the JobEvents table for testing
func createTestEventsTable(t *testing.T, ctx context.Context, client *dynamodb.Client, tableName string) {
	// Try to delete the table first
	_, _ = client.DeleteTable(ctx, &dynamodb.DeleteTableInput{TableName: aws.String(tableName)})

	deleteWaiter := dynamodb.NewTableNotExistsWaiter(client)
	_ = deleteWaiter.Wait(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(tableName)}, 10*time.Second)

	input := &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("job_id"), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String("sequence"), KeyType: types.KeyTypeRange},
		},
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("job_id"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("sequence"), AttributeType: types.ScalarAttributeTypeN},
		},
		BillingMode: types.BillingModeProvisioned,
		ProvisionedThroughput: &types.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(5),
			WriteCapacityUnits: aws.Int64(5),
		},
	}

	_, err := client.CreateTable(ctx, input)
	require.NoError(t, err)

	createWaiter := dynamodb.NewTableExistsWaiter(client)
	err = createWaiter.Wait(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(tableName)}, 30*time.Second)
	require.NoError(t, err)
}

// TestIntegration_EventPersistence tests publishing and querying events
func TestIntegration_EventPersistence(t *testing.T) {
	ctx := context.Background()

	sqsClient := getSQSClient(t, ctx)
	dynamoClient := getDynamoDBClientV2(t, ctx)

	jobsTableName := "test_events_jobs_" + time.Now().Format("20060102150405")
	eventsTableName := "test_events_" + time.Now().Format("20060102150405")

	createTestTableWithGSIs(t, ctx, dynamoClient, jobsTableName)
	defer deleteTestTable(t, ctx, dynamoClient, jobsTableName)

	createTestEventsTable(t, ctx, dynamoClient, eventsTableName)
	defer deleteTestTable(t, ctx, dynamoClient, eventsTableName)

	queueURL := getQueueURL(t, ctx, sqsClient, testDefaultQueueName)
	purgeQueue(t, ctx, sqsClient, queueURL)

	store := NewJobStore(sqsClient, dynamoClient, JobStoreConfig{
		JobsTableName:      jobsTableName,
		JobEventsTableName: eventsTableName,
		EventsTTLDays:      7,
		QueueURLs: map[string]string{
			"default": queueURL,
		},
		TokenSigningSecret: testTokenSigningSecret,
	})

	// Enqueue a job
	enqueueResp, err := store.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
		Queue:     "default",
		RequestId: "test-event-persistence",
		JobParams: &jobv1.JobParams{Repository: "github.com/test/repo"},
	})
	require.NoError(t, err)

	// Dequeue the job to get a task token
	jobs, err := store.DequeueJobs(ctx, "default", 1, 300)
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	taskToken := jobs[0].TaskToken

	// Publish events with client-provided sequences
	events := []*jobv1.JobEvent{
		{
			Sequence:  1,
			EventType: jobv1.EventType_EVENT_TYPE_PROCESS_START,
			EventData: &jobv1.JobEvent_ProcessStart{
				ProcessStart: &jobv1.ProcessStartEvent{Pid: 12345},
			},
		},
		{
			Sequence:  2,
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT,
			EventData: &jobv1.JobEvent_Output{
				Output: &jobv1.OutputEvent{Output: []byte("test output")},
			},
		},
		{
			Sequence:  3,
			EventType: jobv1.EventType_EVENT_TYPE_PROCESS_END,
			EventData: &jobv1.JobEvent_ProcessEnd{
				ProcessEnd: &jobv1.ProcessEndEvent{Pid: 12345, ExitCode: 0},
			},
		},
	}

	err = store.PublishEvents(ctx, taskToken, events)
	require.NoError(t, err)

	// Give DynamoDB time to persist
	time.Sleep(500 * time.Millisecond)

	// Stream events and verify
	eventChan, err := store.StreamEvents(ctx, enqueueResp.JobId, 0, 0, nil)
	require.NoError(t, err)

	receivedEvents := []*jobv1.JobEvent{}
	timeout := time.After(2 * time.Second)

	for i := 0; i < len(events); i++ {
		select {
		case event := <-eventChan:
			receivedEvents = append(receivedEvents, event)
		case <-timeout:
			t.Fatal("Timeout waiting for events")
		}
	}

	// Verify events match
	require.Len(t, receivedEvents, len(events))
	for i, event := range receivedEvents {
		require.Equal(t, events[i].Sequence, event.Sequence)
		require.Equal(t, events[i].EventType, event.EventType)
	}
}

// TestIntegration_EventFiltering tests event filtering by sequence, timestamp, and type
func TestIntegration_EventFiltering(t *testing.T) {
	ctx := context.Background()

	sqsClient := getSQSClient(t, ctx)
	dynamoClient := getDynamoDBClientV2(t, ctx)

	jobsTableName := "test_filter_jobs_" + time.Now().Format("20060102150405")
	eventsTableName := "test_filter_events_" + time.Now().Format("20060102150405")

	createTestTableWithGSIs(t, ctx, dynamoClient, jobsTableName)
	defer deleteTestTable(t, ctx, dynamoClient, jobsTableName)

	createTestEventsTable(t, ctx, dynamoClient, eventsTableName)
	defer deleteTestTable(t, ctx, dynamoClient, eventsTableName)

	queueURL := getQueueURL(t, ctx, sqsClient, testDefaultQueueName)
	purgeQueue(t, ctx, sqsClient, queueURL)

	store := NewJobStore(sqsClient, dynamoClient, JobStoreConfig{
		JobsTableName:      jobsTableName,
		JobEventsTableName: eventsTableName,
		EventsTTLDays:      0, // No TTL for this test
		QueueURLs: map[string]string{
			"default": queueURL,
		},
		TokenSigningSecret: testTokenSigningSecret,
	})

	// Enqueue and dequeue a job
	enqueueResp, err := store.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
		Queue:     "default",
		RequestId: "test-event-filtering",
		JobParams: &jobv1.JobParams{Repository: "github.com/test/repo"},
	})
	require.NoError(t, err)

	jobs, err := store.DequeueJobs(ctx, "default", 1, 300)
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	// Publish events
	events := []*jobv1.JobEvent{
		{Sequence: 1, EventType: jobv1.EventType_EVENT_TYPE_PROCESS_START},
		{Sequence: 2, EventType: jobv1.EventType_EVENT_TYPE_OUTPUT},
		{Sequence: 3, EventType: jobv1.EventType_EVENT_TYPE_OUTPUT},
		{Sequence: 4, EventType: jobv1.EventType_EVENT_TYPE_HEARTBEAT},
		{Sequence: 5, EventType: jobv1.EventType_EVENT_TYPE_PROCESS_END},
	}

	err = store.PublishEvents(ctx, jobs[0].TaskToken, events)
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	// Test 1: Filter by sequence (from sequence 3)
	eventChan, err := store.StreamEvents(ctx, enqueueResp.JobId, 3, 0, nil)
	require.NoError(t, err)

	receivedCount := 0
	timeout := time.After(1 * time.Second)
	for {
		select {
		case event := <-eventChan:
			require.GreaterOrEqual(t, event.Sequence, int64(3))
			receivedCount++
			if receivedCount == 3 { // Should get sequences 3, 4, 5
				goto test2
			}
		case <-timeout:
			goto test2
		}
	}

test2:
	require.Equal(t, 3, receivedCount, "Should receive 3 events from sequence 3")

	// Test 2: Filter by event type (only OUTPUT events)
	eventChan, err = store.StreamEvents(ctx, enqueueResp.JobId, 0, 0, []jobv1.EventType{
		jobv1.EventType_EVENT_TYPE_OUTPUT,
	})
	require.NoError(t, err)

	receivedCount = 0
	timeout = time.After(1 * time.Second)
	for {
		select {
		case event := <-eventChan:
			require.Equal(t, jobv1.EventType_EVENT_TYPE_OUTPUT, event.EventType)
			receivedCount++
			if receivedCount == 2 { // Should get 2 OUTPUT events
				goto done
			}
		case <-timeout:
			goto done
		}
	}

done:
	require.Equal(t, 2, receivedCount, "Should receive 2 OUTPUT events")
}
