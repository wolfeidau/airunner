package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/util"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Sentinel errors for common error conditions
var (
	ErrInvalidTaskToken = errors.New("invalid task token")
	ErrQueueMismatch    = errors.New("queue mismatch")
	ErrJobNotFound      = errors.New("job not found")
	ErrJobIDMismatch    = errors.New("job ID mismatch")
	ErrThrottled        = errors.New("AWS request throttled")
)

// SQS and AWS service limits
const (
	sqsMaxMessages          = 10    // SQS maximum messages per ReceiveMessage call
	sqsMaxVisibilitySeconds = 43200 // SQS maximum visibility timeout (12 hours)
	eventChannelBufferSize  = 100   // Buffer size for event streaming channels
	defaultListJobsPageSize = 50    // Default page size for ListJobs
)

// SQSJobStoreConfig holds the configuration for SQSJobStore
type SQSJobStoreConfig struct {
	QueueURLs                       map[string]string // queue name -> SQS URL
	JobsTableName                   string
	JobEventsTableName              string
	DefaultVisibilityTimeoutSeconds int32
}

// jobRecord is the DynamoDB representation of a job
// Note: Result is stored separately and not retrieved in getJobByID
type jobRecord struct {
	JobID     string           `dynamodbav:"job_id"`
	Queue     string           `dynamodbav:"queue"`
	State     int32            `dynamodbav:"state"`
	RequestID string           `dynamodbav:"request_id"`
	CreatedAt int64            `dynamodbav:"created_at"`
	UpdatedAt int64            `dynamodbav:"updated_at"`
	JobParams *jobv1.JobParams `dynamodbav:"job_params"`
}

// toProto converts a jobRecord to a protobuf Job
func (r *jobRecord) toProto() *jobv1.Job {
	return &jobv1.Job{
		JobId:     r.JobID,
		State:     jobv1.JobState(r.State),
		CreatedAt: timestamppb.New(time.UnixMilli(r.CreatedAt)),
		UpdatedAt: timestamppb.New(time.UnixMilli(r.UpdatedAt)),
		JobParams: r.JobParams,
	}
}

// recordsToProtos converts a slice of jobRecords to protobuf Jobs
func recordsToProtos(records []jobRecord) []*jobv1.Job {
	jobs := make([]*jobv1.Job, len(records))
	for i := range records {
		jobs[i] = records[i].toProto()
	}
	return jobs
}

// wrapAWSError wraps AWS SDK errors, identifying throttling errors
// Returns ErrThrottled for throttling errors, otherwise wraps the original error
func wrapAWSError(err error, msg string) error {
	if err == nil {
		return nil
	}

	// Check for DynamoDB throttling errors
	var provisionedErr *types.ProvisionedThroughputExceededException
	if errors.As(err, &provisionedErr) {
		return fmt.Errorf("%s: %w: %v", msg, ErrThrottled, err)
	}

	// Check for common throttling error messages in error strings
	// AWS SDK v2 doesn't always use typed errors for all services
	errMsg := err.Error()
	if strings.Contains(errMsg, "ThrottlingException") ||
		strings.Contains(errMsg, "RequestLimitExceeded") ||
		strings.Contains(errMsg, "TooManyRequestsException") ||
		strings.Contains(errMsg, "Throttling") {
		return fmt.Errorf("%s: %w: %v", msg, ErrThrottled, err)
	}

	// Wrap other AWS errors
	return fmt.Errorf("%s: %w", msg, err)
}

// SQSJobStore implements JobStore using AWS SQS and DynamoDB
type SQSJobStore struct {
	sqsClient    *sqs.Client
	dynamoClient *dynamodb.Client
	cfg          SQSJobStoreConfig

	// Local event streaming (same semantics as MemoryJobStore)
	mu           sync.RWMutex
	eventStreams map[string][]chan *jobv1.JobEvent

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewSQSJobStore creates a new SQS-based job store
func NewSQSJobStore(sqsClient *sqs.Client, dynamoClient *dynamodb.Client, cfg SQSJobStoreConfig) *SQSJobStore {
	return &SQSJobStore{
		sqsClient:    sqsClient,
		dynamoClient: dynamoClient,
		cfg:          cfg,
		eventStreams: make(map[string][]chan *jobv1.JobEvent),
		stopCh:       make(chan struct{}),
	}
}

// Start initializes background operations
func (s *SQSJobStore) Start() error {
	log.Info().Msg("Starting SQSJobStore")
	return nil
}

// Stop gracefully shuts down the store
func (s *SQSJobStore) Stop() error {
	log.Info().Msg("Stopping SQSJobStore")
	close(s.stopCh)
	s.wg.Wait()
	return nil
}

// taskToken is a stateless token containing job_id, queue, and receipt_handle
// Format: base64url(job_id + "|" + queue_name + "|" + sqs_receipt_handle)
// This is an internal implementation detail and should not be exported
type taskToken struct {
	JobID         string
	Queue         string
	ReceiptHandle string
}

// encodeTaskToken creates a stateless task token
func encodeTaskToken(jobID, queue, receiptHandle string) string {
	data := fmt.Sprintf("%s|%s|%s", jobID, queue, receiptHandle)
	return base64.URLEncoding.EncodeToString([]byte(data))
}

// decodeTaskToken extracts components from a task token
func decodeTaskToken(token string) (*taskToken, error) {
	if token == "" {
		return nil, fmt.Errorf("%w: token cannot be empty", ErrInvalidTaskToken)
	}

	data, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid encoding: %v", ErrInvalidTaskToken, err)
	}

	parts := strings.Split(string(data), "|")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 parts, got %d", ErrInvalidTaskToken, len(parts))
	}

	// Validate non-empty components
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("%w: empty component in token", ErrInvalidTaskToken)
	}

	return &taskToken{
		JobID:         parts[0],
		Queue:         parts[1],
		ReceiptHandle: parts[2],
	}, nil
}

// EnqueueJob adds a new job to the queue with idempotency support
func (s *SQSJobStore) EnqueueJob(ctx context.Context, req *jobv1.EnqueueJobRequest) (*jobv1.EnqueueJobResponse, error) {
	// 1. Validate queue is configured
	if _, exists := s.cfg.QueueURLs[req.Queue]; !exists {
		log.Error().Str("queue", req.Queue).Msg("Queue not configured")
		return nil, fmt.Errorf("queue not configured: %s", req.Queue)
	}

	// 2. Check idempotency via GSI2 (request_id)
	existing, err := s.getJobByRequestID(ctx, req.RequestId)
	if err != nil {
		log.Error().Err(err).Str("request_id", req.RequestId).Msg("Failed to check idempotency")
		return nil, err
	}

	if existing != nil {
		log.Info().Str("job_id", existing.JobId).Str("request_id", req.RequestId).Msg("Job already exists for request, returning existing")
		return &jobv1.EnqueueJobResponse{
			JobId:     existing.JobId,
			CreatedAt: existing.CreatedAt,
			State:     existing.State,
		}, nil
	}

	// 3. Create job record in DynamoDB
	jobID := uuid.Must(uuid.NewV7()).String()
	now := timestamppb.Now()

	jobItem := map[string]types.AttributeValue{
		"job_id":     &types.AttributeValueMemberS{Value: jobID},
		"queue":      &types.AttributeValueMemberS{Value: req.Queue},
		"state":      &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", jobv1.JobState_JOB_STATE_SCHEDULED)},
		"request_id": &types.AttributeValueMemberS{Value: req.RequestId},
		"created_at": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now.AsTime().UnixMilli())},
		"updated_at": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now.AsTime().UnixMilli())},
	}

	// Marshal JobParams to DynamoDB format
	params, err := attributevalue.MarshalMap(req.JobParams)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal job params")
		return nil, fmt.Errorf("failed to marshal job params: %w", err)
	}
	jobItem["job_params"] = &types.AttributeValueMemberM{Value: params}

	// PutItem with condition: job_id must not exist
	putInput := &dynamodb.PutItemInput{
		TableName:           aws.String(s.cfg.JobsTableName),
		Item:                jobItem,
		ConditionExpression: aws.String("attribute_not_exists(job_id)"),
	}

	_, err = s.dynamoClient.PutItem(ctx, putInput)
	if err != nil {
		log.Error().Err(err).Str("job_id", jobID).Msg("Failed to create job in DynamoDB")
		return nil, wrapAWSError(err, "failed to create job in DynamoDB")
	}

	log.Info().Str("job_id", jobID).Str("queue", req.Queue).Msg("Job created and stored in DynamoDB")

	// 4. Send message to SQS
	queueURL := s.cfg.QueueURLs[req.Queue]
	messageBody := fmt.Sprintf(`{"job_id":"%s","queue":"%s","attempt":1}`, jobID, req.Queue)
	sendInput := &sqs.SendMessageInput{
		QueueUrl:    aws.String(queueURL),
		MessageBody: aws.String(messageBody),
	}

	_, err = s.sqsClient.SendMessage(ctx, sendInput)
	if err != nil {
		log.Error().Err(err).Str("job_id", jobID).Msg("Failed to send message to SQS")
		return nil, wrapAWSError(err, "failed to send message to SQS")
	}

	log.Info().Str("job_id", jobID).Str("queue", req.Queue).Msg("Message sent to SQS queue")

	return &jobv1.EnqueueJobResponse{
		JobId:     jobID,
		CreatedAt: now,
		State:     jobv1.JobState_JOB_STATE_SCHEDULED,
	}, nil
}

// DequeueJobs retrieves jobs from the specified queue
func (s *SQSJobStore) DequeueJobs(ctx context.Context, queue string, maxJobs int, timeoutSeconds int) ([]*JobWithToken, error) {
	queueURL, exists := s.cfg.QueueURLs[queue]
	if !exists {
		log.Error().Str("queue", queue).Msg("Queue not configured")
		return nil, fmt.Errorf("queue not configured: %s", queue)
	}

	// Limit to SQS max messages per call
	numToReceive := min(maxJobs, sqsMaxMessages)

	// ReceiveMessage from SQS
	receiveInput := &sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(queueURL),
		MaxNumberOfMessages: int32(min(numToReceive, sqsMaxMessages)),            //nolint:gosec // bounded above
		WaitTimeSeconds:     0,                                                   // Non-blocking; long polling handled at service layer
		VisibilityTimeout:   int32(min(timeoutSeconds, sqsMaxVisibilitySeconds)), //nolint:gosec // SQS max is 12h
	}

	output, err := s.sqsClient.ReceiveMessage(ctx, receiveInput)
	if err != nil {
		log.Error().Err(err).Str("queue", queue).Msg("Failed to receive messages from SQS")
		return nil, wrapAWSError(err, "failed to receive messages from SQS")
	}

	if len(output.Messages) == 0 {
		log.Debug().Str("queue", queue).Msg("No messages in queue")
		// Return nil (not empty slice) when queue is empty - this is not an error condition
		// Consistent with Go conventions where nil represents "no data available"
		return nil, nil
	}

	results := make([]*JobWithToken, 0, len(output.Messages))

	// Process each message
	for _, message := range output.Messages {
		// Extract job_id from message body
		jobID := s.extractJobIDFromMessage(aws.ToString(message.Body))
		if jobID == "" {
			log.Warn().Str("message_id", aws.ToString(message.MessageId)).Msg("Failed to extract job_id from message, skipping poison message")
			// Delete poison message
			_ = s.deleteMessageFromQueue(ctx, queueURL, message)
			continue
		}

		// Get job metadata from DynamoDB
		job, err := s.getJobByID(ctx, jobID)
		if err != nil {
			log.Error().Err(err).Str("job_id", jobID).Msg("Failed to get job from DynamoDB")
			// Do NOT delete the message on transient errors; leave for redelivery
			continue
		}

		if job == nil {
			log.Warn().Str("job_id", jobID).Msg("Job not found in DynamoDB, deleting poison message")
			_ = s.deleteMessageFromQueue(ctx, queueURL, message)
			continue
		}

		// Filter out already-completed jobs
		if job.State == jobv1.JobState_JOB_STATE_COMPLETED || job.State == jobv1.JobState_JOB_STATE_FAILED {
			log.Info().Str("job_id", jobID).Int32("state", int32(job.State)).Msg("Job already completed, deleting from queue")
			_ = s.deleteMessageFromQueue(ctx, queueURL, message)
			continue
		}

		// Update job state to RUNNING
		job.State = jobv1.JobState_JOB_STATE_RUNNING
		job.UpdatedAt = timestamppb.Now()

		err = s.updateJobState(ctx, job)
		if err != nil {
			log.Error().Err(err).Str("job_id", jobID).Msg("Failed to update job state to RUNNING")
			continue
		}

		// Create task token
		taskToken := encodeTaskToken(jobID, queue, aws.ToString(message.ReceiptHandle))

		results = append(results, &JobWithToken{
			Job:       job,
			TaskToken: taskToken,
		})
	}

	log.Info().Str("queue", queue).Int("jobs_dequeued", len(results)).Msg("Successfully dequeued jobs")
	return results, nil
}

// UpdateJobVisibility extends the visibility timeout for a job
func (s *SQSJobStore) UpdateJobVisibility(ctx context.Context, queue string, taskToken string, timeoutSeconds int) error {
	// Decode task token
	tt, err := decodeTaskToken(taskToken)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid task token")
		return err // already a status error from decodeTaskToken
	}

	// Verify queue matches
	if tt.Queue != queue {
		log.Warn().Str("expected_queue", queue).Str("token_queue", tt.Queue).Msg("Queue mismatch")
		return fmt.Errorf("%w: expected %s, got %s", ErrQueueMismatch, queue, tt.Queue)
	}

	// Update visibility timeout in SQS
	queueURL := s.cfg.QueueURLs[queue]
	changeVisInput := &sqs.ChangeMessageVisibilityInput{
		QueueUrl:          aws.String(queueURL),
		ReceiptHandle:     aws.String(tt.ReceiptHandle),
		VisibilityTimeout: int32(min(timeoutSeconds, sqsMaxVisibilitySeconds)), //nolint:gosec // SQS max is 12h
	}

	_, err = s.sqsClient.ChangeMessageVisibility(ctx, changeVisInput)
	if err != nil {
		log.Error().Err(err).Str("job_id", tt.JobID).Msg("Failed to change message visibility in SQS")
		return wrapAWSError(err, "failed to change message visibility")
	}

	// Update updated_at timestamp in DynamoDB
	job, err := s.getJobByID(ctx, tt.JobID)
	if err == nil && job != nil {
		job.UpdatedAt = timestamppb.Now()
		_ = s.updateJobState(ctx, job)
	}

	log.Info().Str("job_id", tt.JobID).Int("timeout_seconds", timeoutSeconds).Msg("Updated job visibility")
	return nil
}

// CompleteJob marks a job as completed and removes it from the queue
func (s *SQSJobStore) CompleteJob(ctx context.Context, taskToken string, result *jobv1.JobResult) error {
	// Decode task token
	tt, err := decodeTaskToken(taskToken)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid task token")
		return err // already a status error from decodeTaskToken
	}

	// Verify job ID matches
	if tt.JobID != result.JobId {
		log.Warn().Str("token_job_id", tt.JobID).Str("result_job_id", result.JobId).Msg("Job ID mismatch")
		return fmt.Errorf("%w: expected %s, got %s", ErrJobIDMismatch, tt.JobID, result.JobId)
	}

	// Get job from DynamoDB
	job, err := s.getJobByID(ctx, tt.JobID)
	if err != nil {
		log.Error().Err(err).Str("job_id", tt.JobID).Msg("Failed to get job")
		return fmt.Errorf("failed to get job: %w", err)
	}
	if job == nil {
		log.Warn().Str("job_id", tt.JobID).Msg("Job not found")
		return fmt.Errorf("%w: %s", ErrJobNotFound, tt.JobID)
	}

	// Update job state
	if result.Success {
		job.State = jobv1.JobState_JOB_STATE_COMPLETED
	} else {
		job.State = jobv1.JobState_JOB_STATE_FAILED
	}
	job.UpdatedAt = timestamppb.Now()

	// Marshal JobResult for storage
	resultMap, err := attributevalue.MarshalMap(result)
	if err != nil {
		log.Error().Err(err).Str("job_id", tt.JobID).Msg("Failed to marshal job result")
		return fmt.Errorf("failed to marshal job result: %w", err)
	}

	// UpdateItem in DynamoDB
	updateBuilder := expression.Set(
		expression.Name("state"),
		expression.Value(int32(job.State)),
	).Set(
		expression.Name("updated_at"),
		expression.Value(job.UpdatedAt.AsTime().UnixMilli()),
	).Set(
		expression.Name("result"),
		expression.Value(resultMap),
	)

	expr, err := expression.NewBuilder().WithUpdate(updateBuilder).Build()
	if err != nil {
		log.Error().Err(err).Msg("Failed to build update expression")
		return fmt.Errorf("failed to build update expression: %w", err)
	}

	updateInput := &dynamodb.UpdateItemInput{
		TableName: aws.String(s.cfg.JobsTableName),
		Key: map[string]types.AttributeValue{
			"job_id": &types.AttributeValueMemberS{Value: tt.JobID},
		},
		UpdateExpression:          expr.Update(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}

	_, err = s.dynamoClient.UpdateItem(ctx, updateInput)
	if err != nil {
		log.Error().Err(err).Str("job_id", tt.JobID).Msg("Failed to update job in DynamoDB")
		return wrapAWSError(err, "failed to update job in DynamoDB")
	}

	// Delete message from SQS
	queueURL := s.cfg.QueueURLs[tt.Queue]
	deleteInput := &sqs.DeleteMessageInput{
		QueueUrl:      aws.String(queueURL),
		ReceiptHandle: aws.String(tt.ReceiptHandle),
	}

	_, err = s.sqsClient.DeleteMessage(ctx, deleteInput)
	if err != nil {
		log.Warn().Err(err).Str("job_id", tt.JobID).Msg("Failed to delete message from SQS (job already marked complete)")
		// Not a fatal error; the message will timeout and eventually be deleted
	}

	log.Info().Str("job_id", tt.JobID).Bool("success", result.Success).Msg("Job completed")
	return nil
}

// ListJobs returns a filtered list of jobs
//
// PERFORMANCE WARNING: This implementation loads all matching results into memory
// before applying pagination. For large result sets (>10,000 jobs), this can consume
// significant memory and cause high latency.
//
// Current limitations:
//   - Fetches ALL jobs from DynamoDB before filtering and paginating
//   - Memory usage grows linearly with total job count
//   - No support for cursor-based pagination
//
// Production considerations:
//   - For large deployments, implement cursor-based pagination using DynamoDB's
//     LastEvaluatedKey (see spec's Future Enhancements section)
//   - Consider implementing server-side filtering using DynamoDB FilterExpression
//   - Monitor memory usage and query latency metrics
//
// IMPORTANT: Always specify a queue filter when possible to use GSI1 Query instead
// of full table Scan. Without a queue filter, this performs a full table scan.
func (s *SQSJobStore) ListJobs(ctx context.Context, req *jobv1.ListJobsRequest) (*jobv1.ListJobsResponse, error) {
	pageSize := int(req.PageSize)
	if pageSize <= 0 {
		pageSize = defaultListJobsPageSize
	}

	page := int(req.Page)
	if page <= 0 {
		page = 1
	}

	var allJobs []*jobv1.Job

	if req.Queue != "" {
		// Query GSI1 for jobs in specific queue
		keyCond := expression.Key("queue").Equal(expression.Value(req.Queue))
		expr, err := expression.NewBuilder().WithKeyCondition(keyCond).Build()
		if err != nil {
			log.Error().Err(err).Msg("Failed to build query expression")
			return nil, fmt.Errorf("failed to build query expression: %w", err)
		}

		queryInput := &dynamodb.QueryInput{
			TableName:                 aws.String(s.cfg.JobsTableName),
			IndexName:                 aws.String("GSI1"),
			KeyConditionExpression:    expr.KeyCondition(),
			ExpressionAttributeNames:  expr.Names(),
			ExpressionAttributeValues: expr.Values(),
		}

		paginator := dynamodb.NewQueryPaginator(s.dynamoClient, queryInput)
		for paginator.HasMorePages() {
			// Check for context cancellation
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("operation canceled: %w", err)
			}

			page, err := paginator.NextPage(ctx)
			if err != nil {
				log.Error().Err(err).Str("queue", req.Queue).Msg("Failed to query jobs")
				return nil, wrapAWSError(err, "failed to query jobs")
			}

			var records []jobRecord
			err = attributevalue.UnmarshalListOfMaps(page.Items, &records)
			if err != nil {
				log.Error().Err(err).Msg("Failed to unmarshal jobs")
				return nil, fmt.Errorf("failed to unmarshal jobs: %w", err)
			}
			allJobs = append(allJobs, recordsToProtos(records)...)
		}
	} else {
		// Scan all jobs (with warning)
		log.Warn().Msg("ListJobs called without queue filter; scanning entire table")

		scanInput := &dynamodb.ScanInput{
			TableName: aws.String(s.cfg.JobsTableName),
		}

		paginator := dynamodb.NewScanPaginator(s.dynamoClient, scanInput)
		for paginator.HasMorePages() {
			// Check for context cancellation
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("operation canceled: %w", err)
			}

			page, err := paginator.NextPage(ctx)
			if err != nil {
				log.Error().Err(err).Msg("Failed to scan jobs")
				return nil, wrapAWSError(err, "failed to scan jobs")
			}

			var records []jobRecord
			err = attributevalue.UnmarshalListOfMaps(page.Items, &records)
			if err != nil {
				log.Error().Err(err).Msg("Failed to unmarshal jobs")
				return nil, fmt.Errorf("failed to unmarshal jobs: %w", err)
			}
			allJobs = append(allJobs, recordsToProtos(records)...)
		}
	}

	// Filter by state if specified
	var filteredJobs []*jobv1.Job
	for _, job := range allJobs {
		if req.State != jobv1.JobState_JOB_STATE_UNSPECIFIED && job.State != req.State {
			continue
		}
		filteredJobs = append(filteredJobs, job)
	}

	// Pagination
	startIdx := (page - 1) * pageSize
	endIdx := startIdx + pageSize

	if startIdx >= len(filteredJobs) {
		lastPage := (len(filteredJobs)-1)/pageSize + 1
		return &jobv1.ListJobsResponse{
			Jobs:     []*jobv1.Job{},
			LastPage: util.AsInt32(lastPage),
		}, nil
	}

	if endIdx > len(filteredJobs) {
		endIdx = len(filteredJobs)
	}

	lastPage := (len(filteredJobs)-1)/pageSize + 1
	return &jobv1.ListJobsResponse{
		Jobs:     filteredJobs[startIdx:endIdx],
		LastPage: util.AsInt32(lastPage),
	}, nil
}

// PublishEvents publishes events for a job (Phase 2)
func (s *SQSJobStore) PublishEvents(ctx context.Context, taskToken string, events []*jobv1.JobEvent) error {
	tt, err := decodeTaskToken(taskToken)
	if err != nil {
		return err // already a status error from decodeTaskToken
	}

	// Verify job exists
	job, err := s.getJobByID(ctx, tt.JobID)
	if err != nil {
		return fmt.Errorf("failed to get job: %w", err)
	}
	if job == nil {
		return fmt.Errorf("%w: %s", ErrJobNotFound, tt.JobID)
	}

	// Set timestamps if not already set
	for _, event := range events {
		if event.Timestamp == nil {
			event.Timestamp = timestamppb.Now()
		}
	}

	// TODO: Phase 2 - BatchWriteItem events to JobEvents table
	_ = events

	// Local fanout to active streams
	s.mu.RLock()
	for _, event := range events {
		s.fanoutEvent(tt.JobID, event)
	}
	s.mu.RUnlock()

	return nil
}

// StreamEvents creates a stream of events for a job (Phase 2)
func (s *SQSJobStore) StreamEvents(ctx context.Context, jobId string, fromSequence int64, fromTimestamp int64, eventFilter []jobv1.EventType) (<-chan *jobv1.JobEvent, error) {
	// Verify job exists
	job, err := s.getJobByID(ctx, jobId)
	if err != nil {
		return nil, fmt.Errorf("failed to get job: %w", err)
	}
	if job == nil {
		return nil, fmt.Errorf("%w: %s", ErrJobNotFound, jobId)
	}

	// TODO: Phase 2 - Query historical events from JobEvents table
	_ = fromSequence
	_ = fromTimestamp
	_ = eventFilter

	// Create channel for streaming
	eventChan := make(chan *jobv1.JobEvent, eventChannelBufferSize)

	// Register stream
	s.mu.Lock()
	s.eventStreams[jobId] = append(s.eventStreams[jobId], eventChan)
	s.mu.Unlock()

	// Spawn goroutine to manage cleanup
	go func() {
		defer func() {
			s.mu.Lock()
			streams := s.eventStreams[jobId]
			for i, ch := range streams {
				if ch == eventChan {
					s.eventStreams[jobId] = append(streams[:i], streams[i+1:]...)
					break
				}
			}
			s.mu.Unlock()
			close(eventChan)
		}()

		// Wait for context cancellation
		<-ctx.Done()
	}()

	return eventChan, nil
}

// fanoutEvent sends an event to all active streams for a job
// Must be called with at least a read lock (RLock) held on s.mu to safely access eventStreams
// Uses non-blocking sends to prevent slow consumers from blocking event publishing
func (s *SQSJobStore) fanoutEvent(jobId string, event *jobv1.JobEvent) {
	streams := s.eventStreams[jobId]
	for _, ch := range streams {
		select {
		case ch <- event:
		default:
			// Channel full, skip this stream
			log.Warn().Str("job_id", jobId).Msg("Event channel full, dropping event")
		}
	}
}

// Helper methods

// getJobByID retrieves a job from DynamoDB by job ID
func (s *SQSJobStore) getJobByID(ctx context.Context, jobID string) (*jobv1.Job, error) {
	getInput := &dynamodb.GetItemInput{
		TableName: aws.String(s.cfg.JobsTableName),
		Key: map[string]types.AttributeValue{
			"job_id": &types.AttributeValueMemberS{Value: jobID},
		},
	}

	output, err := s.dynamoClient.GetItem(ctx, getInput)
	if err != nil {
		return nil, err
	}

	if output.Item == nil {
		return nil, nil
	}

	var record jobRecord
	err = attributevalue.UnmarshalMap(output.Item, &record)
	if err != nil {
		return nil, err
	}

	return record.toProto(), nil
}

// getJobByRequestID retrieves a job by request ID for idempotency checks
// IMPORTANT: Requires GSI2 index (request_id -> job_id) to be created on the DynamoDB table
// The index must be configured with:
//   - Partition Key: request_id (String)
//   - Projection: KEYS_ONLY or ALL
//
// If the index does not exist, this method will return an error from DynamoDB
func (s *SQSJobStore) getJobByRequestID(ctx context.Context, requestID string) (*jobv1.Job, error) {
	keyCond := expression.Key("request_id").Equal(expression.Value(requestID))
	expr, err := expression.NewBuilder().WithKeyCondition(keyCond).Build()
	if err != nil {
		return nil, err
	}

	queryInput := &dynamodb.QueryInput{
		TableName:                 aws.String(s.cfg.JobsTableName),
		IndexName:                 aws.String("GSI2"),
		KeyConditionExpression:    expr.KeyCondition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}

	output, err := s.dynamoClient.Query(ctx, queryInput)
	if err != nil {
		// Will return an error if GSI2 index doesn't exist
		return nil, wrapAWSError(err, "failed to query by request_id (check GSI2 index exists)")
	}

	if len(output.Items) == 0 {
		return nil, nil
	}

	var record jobRecord
	err = attributevalue.UnmarshalMap(output.Items[0], &record)
	if err != nil {
		return nil, err
	}

	return record.toProto(), nil
}

// updateJobState updates a job's state in DynamoDB
func (s *SQSJobStore) updateJobState(ctx context.Context, job *jobv1.Job) error {
	updateBuilder := expression.Set(
		expression.Name("state"),
		expression.Value(int32(job.State)),
	).Set(
		expression.Name("updated_at"),
		expression.Value(job.UpdatedAt.AsTime().UnixMilli()),
	)

	expr, err := expression.NewBuilder().WithUpdate(updateBuilder).Build()
	if err != nil {
		return err
	}

	updateInput := &dynamodb.UpdateItemInput{
		TableName: aws.String(s.cfg.JobsTableName),
		Key: map[string]types.AttributeValue{
			"job_id": &types.AttributeValueMemberS{Value: job.JobId},
		},
		UpdateExpression:          expr.Update(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}

	_, err = s.dynamoClient.UpdateItem(ctx, updateInput)
	return err
}

// sqsJobMessage represents the message body sent to SQS
type sqsJobMessage struct {
	JobID   string `json:"job_id"`
	Queue   string `json:"queue"`
	Attempt int    `json:"attempt"`
}

// extractJobIDFromMessage parses the SQS message body to extract job_id
// Returns empty string if the message is invalid or missing job_id
func (s *SQSJobStore) extractJobIDFromMessage(body string) string {
	var msg sqsJobMessage
	if err := json.Unmarshal([]byte(body), &msg); err != nil {
		log.Debug().Err(err).Str("body", body).Msg("Failed to unmarshal SQS message")
		return ""
	}
	if msg.JobID == "" {
		log.Debug().Str("body", body).Msg("SQS message missing job_id field")
	}
	return msg.JobID
}

// deleteMessageFromQueue deletes a message from SQS
func (s *SQSJobStore) deleteMessageFromQueue(ctx context.Context, queueURL string, message sqstypes.Message) error {
	deleteInput := &sqs.DeleteMessageInput{
		QueueUrl:      aws.String(queueURL),
		ReceiptHandle: message.ReceiptHandle,
	}

	_, err := s.sqsClient.DeleteMessage(ctx, deleteInput)
	return err
}
