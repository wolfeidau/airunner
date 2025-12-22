package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	"github.com/wolfeidau/airunner/internal/telemetry"
	"github.com/wolfeidau/airunner/internal/util"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Sentinel errors for common error conditions
var (
	ErrInvalidTaskToken = errors.New("invalid task token")
	ErrQueueMismatch    = errors.New("queue mismatch")
	ErrJobNotFound      = errors.New("job not found")
	ErrJobIDMismatch    = errors.New("job ID mismatch")
	ErrThrottled        = errors.New("AWS request throttled")
	ErrEventTooLarge    = errors.New("event exceeds maximum size")
)

// SQS and AWS service limits
const (
	sqsMaxMessages          = 10    // SQS maximum messages per ReceiveMessage call
	sqsMaxVisibilitySeconds = 43200 // SQS maximum visibility timeout (12 hours)
	eventChannelBufferSize  = 100   // Buffer size for event streaming channels
	defaultListJobsPageSize = 50    // Default page size for ListJobs
	taskTokenVersion        = "v1"  // Task token format version for future compatibility

	// Storage backend item size limits
	// Maximum item size for the storage backend is 400KB, but we need to account for:
	// - Attribute names and overhead (~20KB)
	// - Base64 encoding overhead for binary data (~33% increase)
	// - Proto encoding overhead
	// Setting a conservative limit at 350KB for the serialized event payload
	maxEventPayloadBytes = 350 * 1024 // 350KB safety margin below 400KB backend limit
)

// SQSJobStoreConfig holds the configuration for SQSJobStore
type SQSJobStoreConfig struct {
	QueueURLs                       map[string]string // queue name -> SQS URL
	JobsTableName                   string
	JobEventsTableName              string
	DefaultVisibilityTimeoutSeconds int32
	EventsTTLDays                   int32  // Optional: TTL for event retention in days (0 = no TTL)
	TokenSigningSecret              []byte // Secret key for HMAC signing task tokens (required for security)
	DefaultExecutionConfig          *jobv1.ExecutionConfig
}

// jobRecord is the DynamoDB representation of a job
// Note: Result is stored separately and not retrieved in getJobByID
type jobRecord struct {
	JobID           string                 `dynamodbav:"job_id"`
	Queue           string                 `dynamodbav:"queue"`
	State           int32                  `dynamodbav:"state"`
	RequestID       string                 `dynamodbav:"request_id"`
	CreatedAt       int64                  `dynamodbav:"created_at"`
	UpdatedAt       int64                  `dynamodbav:"updated_at"`
	JobParams       *jobv1.JobParams       `dynamodbav:"job_params"`
	ExecutionConfig *jobv1.ExecutionConfig `dynamodbav:"execution_config"`
}

// toProto converts a jobRecord to a protobuf Job
func (r *jobRecord) toProto() *jobv1.Job {
	return &jobv1.Job{
		JobId:           r.JobID,
		State:           jobv1.JobState(r.State),
		CreatedAt:       timestamppb.New(time.UnixMilli(r.CreatedAt)),
		UpdatedAt:       timestamppb.New(time.UnixMilli(r.UpdatedAt)),
		JobParams:       r.JobParams,
		ExecutionConfig: r.ExecutionConfig,
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

// wrapAWSError wraps AWS SDK errors, identifying throttling and size limit errors
// Returns ErrThrottled for throttling errors, ErrEventTooLarge for size violations,
// otherwise wraps the original error
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

	// Check for storage backend item size validation errors
	// This catches cases where size validation was missed or item grew during serialization
	if strings.Contains(errMsg, "Item size has exceeded the maximum allowed size") ||
		strings.Contains(errMsg, "ValidationException") && strings.Contains(errMsg, "size") {
		return fmt.Errorf("%s: %w: item exceeds storage backend size limit. "+
			"This typically indicates an event payload is too large. "+
			"Consider reducing batch sizes or output volume: %v", msg, ErrEventTooLarge, err)
	}

	// Wrap other AWS errors
	return fmt.Errorf("%s: %w", msg, err)
}

// isRetryableAWSError checks if an AWS error should be retried with exponential backoff
// Returns true for transient errors like throttling and service unavailability
func isRetryableAWSError(err error) bool {
	if err == nil {
		return false
	}

	// Check for typed throttling error
	var provisionedErr *types.ProvisionedThroughputExceededException
	if errors.As(err, &provisionedErr) {
		return true
	}

	errMsg := err.Error()

	// Retryable error patterns
	retryable := []string{
		"ThrottlingException",
		"ProvisionedThroughputExceededException",
		"RequestLimitExceeded",
		"TooManyRequestsException",
		"ServiceUnavailable",
		"InternalServerError",
		"InternalError",
		"Throttling",
	}

	for _, pattern := range retryable {
		if strings.Contains(errMsg, pattern) {
			return true
		}
	}

	return false
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
// Format: base64url(version|job_id|queue|receipt_handle|hmac_signature)
// The HMAC signature provides integrity protection against tampering
// This is an internal implementation detail and should not be exported
type taskToken struct {
	JobID         string
	Queue         string
	ReceiptHandle string
}

// encodeTaskToken creates a signed stateless task token
// Format: base64url(v1|job_id|queue|receipt_handle|hmac_sha256_signature)
// The HMAC signature prevents token tampering and provides defense in depth
func (s *SQSJobStore) encodeTaskToken(jobID, queue, receiptHandle string) string {
	// Build the data payload with version prefix
	data := fmt.Sprintf("%s|%s|%s|%s", taskTokenVersion, jobID, queue, receiptHandle)

	// Compute HMAC-SHA256 signature
	h := hmac.New(sha256.New, s.cfg.TokenSigningSecret)
	h.Write([]byte(data))
	sig := hex.EncodeToString(h.Sum(nil))

	// Append signature to data
	signed := fmt.Sprintf("%s|%s", data, sig)

	return base64.URLEncoding.EncodeToString([]byte(signed))
}

// decodeTaskToken extracts and verifies components from a signed task token
// Validates HMAC signature to prevent tampering using constant-time comparison
func (s *SQSJobStore) decodeTaskToken(token string) (*taskToken, error) {
	if token == "" {
		return nil, fmt.Errorf("%w: token cannot be empty", ErrInvalidTaskToken)
	}

	// Base64 decode
	data, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid encoding: %v", ErrInvalidTaskToken, err)
	}

	// Split into components: version|job_id|queue|receipt_handle|signature
	parts := strings.Split(string(data), "|")
	if len(parts) != 5 {
		return nil, fmt.Errorf("%w: expected 5 parts (version|job_id|queue|receipt|sig), got %d", ErrInvalidTaskToken, len(parts))
	}

	version, jobID, queue, receiptHandle, providedSig := parts[0], parts[1], parts[2], parts[3], parts[4]

	// Validate version
	if version != taskTokenVersion {
		return nil, fmt.Errorf("%w: unsupported version %s (expected %s)", ErrInvalidTaskToken, version, taskTokenVersion)
	}

	// Validate non-empty components
	if jobID == "" || queue == "" || receiptHandle == "" {
		return nil, fmt.Errorf("%w: empty component in token", ErrInvalidTaskToken)
	}

	// Recompute HMAC signature
	payload := fmt.Sprintf("%s|%s|%s|%s", version, jobID, queue, receiptHandle)
	h := hmac.New(sha256.New, s.cfg.TokenSigningSecret)
	h.Write([]byte(payload))
	expectedSig := hex.EncodeToString(h.Sum(nil))

	// Constant-time comparison to prevent timing attacks
	if !hmac.Equal([]byte(expectedSig), []byte(providedSig)) {
		return nil, fmt.Errorf("%w: invalid signature", ErrInvalidTaskToken)
	}

	return &taskToken{
		JobID:         jobID,
		Queue:         queue,
		ReceiptHandle: receiptHandle,
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

	// Marshal ExecutionConfig to DynamoDB format
	if s.cfg.DefaultExecutionConfig != nil {
		execConfig, err := attributevalue.MarshalMap(s.cfg.DefaultExecutionConfig)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal execution config")
			return nil, fmt.Errorf("failed to marshal execution config: %w", err)
		}
		jobItem["execution_config"] = &types.AttributeValueMemberM{Value: execConfig}
	}

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

	// Record job enqueued metric
	telemetry.GetMetrics().JobsEnqueuedTotal.Add(ctx, 1,
		metric.WithAttributes(attribute.String("queue", req.Queue)))

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

		// Create task token with HMAC signature
		taskToken := s.encodeTaskToken(jobID, queue, aws.ToString(message.ReceiptHandle))

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
	// Decode and verify task token
	tt, err := s.decodeTaskToken(taskToken)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid task token")
		return err
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
	// Decode and verify task token
	tt, err := s.decodeTaskToken(taskToken)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid task token")
		return err
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

// PublishEvents publishes events for a job
func (s *SQSJobStore) PublishEvents(ctx context.Context, taskToken string, events []*jobv1.JobEvent) error {
	start := time.Now()
	metrics := telemetry.GetMetrics()

	tt, err := s.decodeTaskToken(taskToken)
	if err != nil {
		return err
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

	// Write events to DynamoDB in batches
	var publishErr error
	if s.cfg.JobEventsTableName == "" {
		log.Debug().Str("job_id", tt.JobID).Msg("JobEventsTableName not configured, skipping event persistence")
	} else if err := s.batchWriteEvents(ctx, tt.JobID, events); err != nil {
		// CRITICAL: Event persistence failed - return error to caller
		log.Error().Err(err).Str("job_id", tt.JobID).Int("event_count", len(events)).Msg("Failed to persist events to DynamoDB")
		publishErr = fmt.Errorf("failed to persist events: %w", err)

		// Record error metrics
		metrics.EventPublishErrorsTotal.Add(ctx, int64(len(events)),
			metric.WithAttributes(
				attribute.String("job_id", tt.JobID),
				attribute.String("error_type", "persistence_failed"),
			))
	} else {
		// Record successful persistence
		metrics.EventsPersistedTotal.Add(ctx, int64(len(events)),
			metric.WithAttributes(attribute.String("job_id", tt.JobID)))
	}

	// Record publish duration
	duration := time.Since(start).Milliseconds()
	metrics.EventPublishDuration.Record(ctx, float64(duration),
		metric.WithAttributes(attribute.String("job_id", tt.JobID)))

	// Record total publish attempts
	success := publishErr == nil
	metrics.EventPublishTotal.Add(ctx, int64(len(events)),
		metric.WithAttributes(
			attribute.String("job_id", tt.JobID),
			attribute.Bool("success", success),
		))

	if publishErr != nil {
		return publishErr
	}

	// Local fanout to active streams
	s.mu.RLock()
	for _, event := range events {
		s.fanoutEvent(tt.JobID, event)
	}
	s.mu.RUnlock()

	return nil
}

// StreamEvents creates a stream of events for a job
func (s *SQSJobStore) StreamEvents(ctx context.Context, jobId string, fromSequence int64, fromTimestamp int64, eventFilter []jobv1.EventType) (<-chan *jobv1.JobEvent, error) {
	// Verify job exists
	job, err := s.getJobByID(ctx, jobId)
	if err != nil {
		return nil, fmt.Errorf("failed to get job: %w", err)
	}
	if job == nil {
		return nil, fmt.Errorf("%w: %s", ErrJobNotFound, jobId)
	}

	// Create event filter map for efficient lookup
	filterMap := make(map[jobv1.EventType]bool)
	for _, eventType := range eventFilter {
		filterMap[eventType] = true
	}

	// Create channel for streaming
	eventChan := make(chan *jobv1.JobEvent, eventChannelBufferSize)

	// Register stream
	s.mu.Lock()
	s.eventStreams[jobId] = append(s.eventStreams[jobId], eventChan)
	s.mu.Unlock()

	// Spawn goroutine to handle historical replay and real-time streaming
	go func() {
		defer func() {
			s.mu.Lock()
			streams := s.eventStreams[jobId]
			newStreams := make([]chan *jobv1.JobEvent, 0, len(streams)-1)
			for _, ch := range streams {
				if ch != eventChan {
					newStreams = append(newStreams, ch)
				}
			}
			if len(newStreams) == 0 {
				delete(s.eventStreams, jobId)
			} else {
				s.eventStreams[jobId] = newStreams
			}
			s.mu.Unlock()
			close(eventChan)
		}()

		// Query and send historical events
		if s.cfg.JobEventsTableName == "" {
			log.Debug().Str("job_id", jobId).Msg("JobEventsTableName not configured, historical replay disabled")
		} else if err := s.replayHistoricalEvents(ctx, jobId, fromSequence, fromTimestamp, filterMap, eventChan); err != nil {
			log.Error().Err(err).Str("job_id", jobId).Msg("Failed to replay historical events")
			// Note: Don't fail the stream - historical replay is best-effort
			// Client will still receive real-time events
		}

		// Wait for context cancellation (real-time events arrive via fanoutEvent)
		<-ctx.Done()
	}()

	return eventChan, nil
}

// fanoutEvent sends an event to all active streams for a job
// Must be called with at least a read lock (RLock) held on s.mu to safely access eventStreams
// Uses non-blocking sends to prevent slow consumers from blocking event publishing
func (s *SQSJobStore) fanoutEvent(jobId string, event *jobv1.JobEvent) {
	metrics := telemetry.GetMetrics()
	streams := s.eventStreams[jobId]
	for _, ch := range streams {
		select {
		case ch <- event:
		default:
			// Channel full, skip this stream - DATA LOSS
			log.Error().Str("job_id", jobId).Int64("sequence", event.Sequence).Msg("Event channel full, dropping event")

			// Record channel overflow metric
			metrics.ChannelOverflowTotal.Add(context.Background(), 1,
				metric.WithAttributes(attribute.String("job_id", jobId)))
			metrics.EventsDroppedTotal.Add(context.Background(), 1,
				metric.WithAttributes(
					attribute.String("job_id", jobId),
					attribute.String("reason", "channel_full"),
				))
		}
	}
}

// Helper methods

// replayHistoricalEvents queries historical events from DynamoDB and sends them to the channel
// Events are automatically sorted by sequence (sort key) in DynamoDB
func (s *SQSJobStore) replayHistoricalEvents(ctx context.Context, jobID string, fromSequence int64, fromTimestamp int64, filterMap map[jobv1.EventType]bool, eventChan chan *jobv1.JobEvent) error {
	// Build query with job_id and optional sequence range
	keyCond := expression.Key("job_id").Equal(expression.Value(jobID))

	// Add sequence filter if specified
	if fromSequence > 0 {
		keyCond = keyCond.And(expression.Key("sequence").GreaterThanEqual(expression.Value(fromSequence)))
	}

	expr, err := expression.NewBuilder().WithKeyCondition(keyCond).Build()
	if err != nil {
		return fmt.Errorf("failed to build query expression: %w", err)
	}

	queryInput := &dynamodb.QueryInput{
		TableName:                 aws.String(s.cfg.JobEventsTableName),
		KeyConditionExpression:    expr.KeyCondition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}

	// Use paginator to handle large result sets
	paginator := dynamodb.NewQueryPaginator(s.dynamoClient, queryInput)

	for paginator.HasMorePages() {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		page, err := paginator.NextPage(ctx)
		if err != nil {
			return wrapAWSError(err, "failed to query historical events")
		}

		// Process each event in this page
		for _, item := range page.Items {
			event, err := s.unmarshalEventItem(item)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to unmarshal event, skipping")
				continue
			}

			// Apply timestamp filter
			if fromTimestamp > 0 && event.Timestamp.AsTime().UnixMilli() < fromTimestamp {
				continue
			}

			// Apply event type filter
			if len(filterMap) > 0 && !filterMap[event.EventType] {
				continue
			}

			// Send event to channel (non-blocking)
			select {
			case eventChan <- event:
			case <-ctx.Done():
				return ctx.Err()
			default:
				log.Warn().Str("job_id", jobID).Int64("sequence", event.Sequence).Msg("Event channel full, dropping historical event")
			}
		}
	}

	log.Debug().Str("job_id", jobID).Msg("Finished replaying historical events")
	return nil
}

// unmarshalEventItem unmarshals a DynamoDB item to a JobEvent
func (s *SQSJobStore) unmarshalEventItem(item map[string]types.AttributeValue) (*jobv1.JobEvent, error) {
	// Extract event_payload binary data
	payloadAttr, ok := item["event_payload"].(*types.AttributeValueMemberB)
	if !ok {
		return nil, fmt.Errorf("event_payload not found or wrong type")
	}

	// Unmarshal protobuf binary to JobEvent
	event := &jobv1.JobEvent{}
	if err := util.UnmarshalProto(payloadAttr.Value, event); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event: %w", err)
	}

	return event, nil
}

// batchWriteEvents writes events to DynamoDB JobEvents table in batches
// Handles chunking (max 25 items per BatchWriteItem) and partial failure retries
//
// IMPORTANT: Validates event size against storage backend size limits before writing.
// Events exceeding maxEventPayloadBytes will be rejected with ErrEventTooLarge.
func (s *SQSJobStore) batchWriteEvents(ctx context.Context, jobID string, events []*jobv1.JobEvent) error {
	const maxBatchSize = 25 // DynamoDB BatchWriteItem limit

	// Calculate TTL if configured
	var ttl *int64
	if s.cfg.EventsTTLDays > 0 {
		ttlSeconds := time.Now().Add(time.Duration(s.cfg.EventsTTLDays) * 24 * time.Hour).Unix()
		ttl = &ttlSeconds
	}

	// Process events in chunks of 25
	for i := 0; i < len(events); i += maxBatchSize {
		end := i + maxBatchSize
		if end > len(events) {
			end = len(events)
		}
		batch := events[i:end]

		// Build write requests for this batch
		var writeRequests []types.WriteRequest
		for _, event := range batch {
			// Marshal entire JobEvent to protobuf binary
			eventBytes, err := util.MarshalProto(event)
			if err != nil {
				log.Error().Err(err).Int64("sequence", event.Sequence).Msg("Failed to marshal event")
				return fmt.Errorf("failed to marshal event seq=%d: %w", event.Sequence, err)
			}

			// Validate event size against storage backend limits
			// Events must stay within size limits; we check against a conservative threshold
			if len(eventBytes) > maxEventPayloadBytes {
				log.Error().
					Int("event_size_bytes", len(eventBytes)).
					Int("max_allowed_bytes", maxEventPayloadBytes).
					Int64("sequence", event.Sequence).
					Int32("event_type", int32(event.EventType)).
					Str("job_id", jobID).
					Msg("Event exceeds maximum size limit for storage backend")

				return fmt.Errorf("%w: event seq=%d size=%d bytes exceeds storage limit of %d bytes. "+
					"Consider reducing output batch size or splitting large outputs",
					ErrEventTooLarge, event.Sequence, len(eventBytes), maxEventPayloadBytes)
			}

			// Build DynamoDB item
			item := map[string]types.AttributeValue{
				"job_id":        &types.AttributeValueMemberS{Value: jobID},
				"sequence":      &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", event.Sequence)},
				"timestamp":     &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", event.Timestamp.AsTime().UnixMilli())},
				"event_type":    &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", event.EventType)},
				"event_payload": &types.AttributeValueMemberB{Value: eventBytes},
			}

			// Add TTL if configured
			if ttl != nil {
				item["ttl"] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", *ttl)}
			}

			writeRequests = append(writeRequests, types.WriteRequest{
				PutRequest: &types.PutRequest{Item: item},
			})
		}

		if len(writeRequests) == 0 {
			continue
		}

		// Write batch to DynamoDB with retry for unprocessed items
		if err := s.batchWriteWithRetry(ctx, writeRequests); err != nil {
			return err
		}
	}

	return nil
}

// batchWriteWithRetry writes items to DynamoDB with exponential backoff retry for unprocessed items
func (s *SQSJobStore) batchWriteWithRetry(ctx context.Context, writeRequests []types.WriteRequest) error {
	const maxRetries = 3
	backoff := 100 * time.Millisecond

	requestItems := map[string][]types.WriteRequest{
		s.cfg.JobEventsTableName: writeRequests,
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		if len(requestItems[s.cfg.JobEventsTableName]) == 0 {
			return nil
		}

		output, err := s.dynamoClient.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
			RequestItems: requestItems,
		})
		if err != nil {
			log.Error().Err(err).Int("attempt", attempt+1).Msg("BatchWriteItem failed")

			// Check if error is retryable (throttling, service errors)
			if isRetryableAWSError(err) && attempt < maxRetries-1 {
				log.Warn().Err(err).Int("attempt", attempt+1).Msg("Retrying BatchWriteItem due to retryable error")
				time.Sleep(backoff)
				backoff *= 2
				continue
			}

			return wrapAWSError(err, "failed to batch write events")
		}

		// Check for unprocessed items
		unprocessed := output.UnprocessedItems[s.cfg.JobEventsTableName]
		if len(unprocessed) == 0 {
			log.Debug().Int("items_written", len(writeRequests)).Msg("Successfully wrote event batch")
			return nil
		}

		// Retry unprocessed items with exponential backoff
		log.Warn().Int("unprocessed_count", len(unprocessed)).Int("attempt", attempt+1).Msg("Retrying unprocessed items")
		requestItems[s.cfg.JobEventsTableName] = unprocessed

		if attempt < maxRetries-1 {
			time.Sleep(backoff)
			backoff *= 2
		}
	}

	return fmt.Errorf("failed to write all events after %d retries, %d items unprocessed",
		maxRetries, len(requestItems[s.cfg.JobEventsTableName]))
}

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
