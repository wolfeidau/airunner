# SQS/DynamoDB Backend Integration Plan

## Overview

This document outlines the phased implementation plan for deploying airunner to AWS with SQS/DynamoDB backend support. The implementation is broken into three independent phases that can be reviewed, implemented, and tested separately.

## Goals

1. **Deploy to AWS first** - Get it running in production
2. **Validate observability** - Ensure tracing/metrics work with Honeycomb
3. **Iterate on AWS** - Validate DynamoDB + SQS integration in production
4. **Build tests later** - Shape integration tests from production learnings

## Configuration Decisions

- ✅ **Terraform creates resources**: SQS queues (default + priority with DLQs) and DynamoDB tables
- ✅ **Token secret**: Generated in Terraform as SSM Parameter with random value
- ✅ **OTEL config**: Passed via Terraform variables, stored in SSM, injected via ECS secrets
- ✅ **Store selection**: Explicit `AIRUNNER_STORE_TYPE=sqs` environment variable required
- ✅ **Backward compatible**: Defaults to memory store when env var not set
- ✅ **Secrets via ECS**: All secrets use ECS secrets feature (consistent with JWT_PUBLIC_KEY pattern)

---

## Phase 1: Terraform Backend Resources

**Goal**: Create AWS infrastructure resources (SQS, DynamoDB, SSM parameters) without affecting running services.

### Files Changed
- `infra/backend.tf` (NEW)
- `infra/variables.tf` (MODIFY - add OTEL variables)
- `infra/outputs.tf` (MODIFY - add backend resource outputs)
- `infra/main.tf` (MODIFY - add random provider)

### 1.1 Add Random Provider

**File**: `infra/main.tf` (lines 1-14)

Add to `required_providers`:
```hcl
random = {
  source  = "hashicorp/random"
  version = "~> 3.6"
}
```

### 1.2 Create Backend Resources

**File**: `infra/backend.tf` (NEW)

Create the following resources:

#### SQS Queues (4 queues)
- `airunner-{env}-default-dlq` - Dead letter queue for default queue
- `airunner-{env}-default` - Main job queue
- `airunner-{env}-priority-dlq` - Dead letter queue for priority queue
- `airunner-{env}-priority` - Priority job queue

**Configuration**:
- `visibility_timeout_seconds`: 300
- `receive_wait_time_seconds`: 20 (long polling)
- `message_retention_seconds`: 1209600 (14 days)
- `sqs_managed_sse_enabled`: true
- `redrive_policy`: maxReceiveCount=3 → DLQ

#### DynamoDB Tables (2 tables)

**Table 1: `airunner_jobs`**
- Partition Key: `job_id` (S)
- GSI1: PK=`queue` (S), SK=`created_at` (N), Projection=ALL
- GSI2: PK=`request_id` (S), Projection=KEYS_ONLY
- Billing: PAY_PER_REQUEST

**Table 2: `airunner_job_events`**
- Partition Key: `job_id` (S)
- Sort Key: `sequence` (N)
- TTL: enabled on `ttl` attribute
- Billing: PAY_PER_REQUEST

#### SSM Parameters (3 secure strings)

1. **`token_signing_secret`**:
   - Random 32-byte value (generated via `random_password`)
   - Used for HMAC signing task tokens

2. **`otel_exporter_endpoint`**:
   - From Terraform variable `var.otel_exporter_endpoint`
   - Example: "https://api.honeycomb.io"

3. **`otel_exporter_headers`**:
   - From Terraform variable `var.otel_exporter_headers`
   - Example: "x-honeycomb-team=YOUR_API_KEY"

**Note**: Use conditional creation for OTEL parameters (only create if variables are non-empty).

### 1.3 Add Terraform Variables

**File**: `infra/variables.tf` (APPEND)

```hcl
variable "otel_exporter_endpoint" {
  description = "OpenTelemetry OTLP exporter endpoint (e.g., https://api.honeycomb.io)"
  type        = string
  default     = ""
}

variable "otel_exporter_headers" {
  description = "OpenTelemetry OTLP exporter headers (e.g., x-honeycomb-team=API_KEY)"
  type        = string
  default     = ""
  sensitive   = true
}
```

### 1.4 Add Terraform Outputs

**File**: `infra/outputs.tf` (APPEND)

Add outputs for:
- SQS queue URLs and ARNs (default, priority, DLQs)
- DynamoDB table names and ARNs
- SSM parameter ARNs (token secret, OTEL endpoint, OTEL headers)

### Phase 1 Validation

```bash
cd infra
terraform init -upgrade
terraform plan  # Should show ~15 new resources
```

**Review checklist**:
- ✅ All queue names use correct prefix
- ✅ DynamoDB tables have correct schema (GSI1, GSI2, TTL)
- ✅ SSM parameters are SecureString type
- ✅ Random provider configured
- ✅ Outputs include all queue URLs and table names

**Do NOT apply yet** - wait for Phase 1 approval.

---

## Phase 2: Terraform IAM and ECS Integration

**Goal**: Wire up IAM permissions and ECS task definition to use the new backend resources.

### Files Changed
- `infra/main.tf` (MODIFY - task role, execution role, task definition)

### 2.1 Update Task Role Permissions

**File**: `infra/main.tf` (ADD after line 274)

Create new resource `aws_iam_role_policy.task_sqs_dynamodb`:

```hcl
resource "aws_iam_role_policy" "task_sqs_dynamodb" {
  role = aws_iam_role.task.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSQSOperations"
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:SendMessage",
          "sqs:DeleteMessage",
          "sqs:ChangeMessageVisibility",
          "sqs:GetQueueAttributes"
        ]
        Resource = [
          aws_sqs_queue.default.arn,
          aws_sqs_queue.default_dlq.arn,
          aws_sqs_queue.priority.arn,
          aws_sqs_queue.priority_dlq.arn
        ]
      },
      {
        Sid    = "AllowDynamoDBOperations"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:BatchWriteItem"
        ]
        Resource = [
          aws_dynamodb_table.jobs.arn,
          "${aws_dynamodb_table.jobs.arn}/index/*",
          aws_dynamodb_table.job_events.arn
        ]
      }
    ]
  })
}
```

**Note**: No SSM permissions needed - secrets injected by execution role at container startup.

### 2.2 Update Execution Role for SSM Access

**File**: `infra/main.tf` (MODIFY lines 230-234)

Update existing SSM parameter read permission to include new parameters:

```hcl
Resource = [
  aws_ssm_parameter.jwt_public_key.arn,
  aws_ssm_parameter.token_signing_secret.arn,
  # Conditionally include OTEL parameters if created
  # Use: var.otel_exporter_endpoint != "" ? aws_ssm_parameter.otel_exporter_endpoint[0].arn : null
]
```

### 2.3 Update ECS Task Definition

**File**: `infra/main.tf` (MODIFY lines 538-570)

#### Add Environment Variables

Add to `container_definitions` → `environment` array:

```hcl
{
  name  = "AIRUNNER_STORE_TYPE"
  value = "sqs"
},
{
  name  = "AIRUNNER_SQS_QUEUE_DEFAULT"
  value = aws_sqs_queue.default.url
},
{
  name  = "AIRUNNER_SQS_QUEUE_PRIORITY"
  value = aws_sqs_queue.priority.url
},
{
  name  = "AIRUNNER_DYNAMODB_JOBS_TABLE"
  value = aws_dynamodb_table.jobs.name
},
{
  name  = "AIRUNNER_DYNAMODB_EVENTS_TABLE"
  value = aws_dynamodb_table.job_events.name
},
{
  name  = "AIRUNNER_DEFAULT_VISIBILITY_TIMEOUT"
  value = "300"
},
{
  name  = "AIRUNNER_EVENTS_TTL_DAYS"
  value = "30"
},
{
  name  = "AWS_REGION"
  value = var.aws_region
}
```

#### Add Secrets

Add to `container_definitions` → `secrets` array (append to existing JWT_PUBLIC_KEY):

```hcl
{
  name      = "AIRUNNER_TOKEN_SIGNING_SECRET"
  valueFrom = aws_ssm_parameter.token_signing_secret.arn
},
# Conditionally add OTEL secrets if parameters exist
{
  name      = "OTEL_EXPORTER_OTLP_ENDPOINT"
  valueFrom = aws_ssm_parameter.otel_exporter_endpoint[0].arn
},
{
  name      = "OTEL_EXPORTER_OTLP_HEADERS"
  valueFrom = aws_ssm_parameter.otel_exporter_headers[0].arn
}
```

#### Add Dependencies

Add `depends_on` to task definition:

```hcl
depends_on = [
  aws_sqs_queue.default,
  aws_dynamodb_table.jobs,
  aws_iam_role_policy.task_sqs_dynamodb
]
```

### Phase 2 Validation

```bash
cd infra
terraform plan  # Should show modifications to task role, execution role, task definition
```

**Review checklist**:
- ✅ Task role has SQS and DynamoDB permissions
- ✅ Execution role can read all SSM parameters
- ✅ Task definition includes all environment variables
- ✅ Task definition includes all secrets (token + OTEL)
- ✅ Dependencies are correct

**Impact**: Applying Phase 2 will trigger ECS service update. Server will restart but WILL FAIL because it doesn't know how to handle `AIRUNNER_STORE_TYPE=sqs` yet. This is expected - Phase 3 adds that support.

**Recommendation**: Apply Phase 1 + Phase 2 together, but deploy Phase 3 code changes before applying.

---

## Phase 3: Server Code Changes

**Goal**: Add SQS/DynamoDB store initialization logic to the server.

### Files Changed
- `cmd/server/internal/commands/rpc.go` (MODIFY)

### 3.1 Update Store Initialization

**File**: `cmd/server/internal/commands/rpc.go` (MODIFY lines 58-70)

Replace:
```go
memStore := store.NewMemoryJobStore()
if err = memStore.Start(); err != nil {
    return err
}
defer func() {
    if err = memStore.Stop(); err != nil {
        log.Error().Err(err).Msg("Failed to stop memory store")
    }
}()
```

With:
```go
storeType := os.Getenv("AIRUNNER_STORE_TYPE")
if storeType == "" {
    storeType = "memory"
}

var jobStore store.JobStore
var err error

switch storeType {
case "sqs":
    jobStore, err = s.createSQSStore(ctx)
    if err != nil {
        return fmt.Errorf("failed to create SQS store: %w", err)
    }
    log.Info().Msg("Using SQS/DynamoDB job store")
case "memory":
    jobStore = store.NewMemoryJobStore()
    log.Info().Msg("Using in-memory job store")
default:
    return fmt.Errorf("unknown store type: %s", storeType)
}

if err = jobStore.Start(); err != nil {
    return err
}
defer func() {
    if err = jobStore.Stop(); err != nil {
        log.Error().Err(err).Msg("Failed to stop job store")
    }
}()
```

### 3.2 Add Helper Method

**File**: `cmd/server/internal/commands/rpc.go` (ADD new method)

```go
func (s *RPCServerCmd) createSQSStore(ctx context.Context) (store.JobStore, error) {
    // Load AWS SDK config (uses IAM role credentials from ECS task role)
    cfg, err := config.LoadDefaultConfig(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to load AWS config: %w", err)
    }

    // Create AWS service clients
    sqsClient := sqs.NewFromConfig(cfg)
    dynamoClient := dynamodb.NewFromConfig(cfg)

    // Parse queue URLs from environment
    queueURLs := make(map[string]string)
    if url := os.Getenv("AIRUNNER_SQS_QUEUE_DEFAULT"); url != "" {
        queueURLs["default"] = url
    } else {
        return nil, errors.New("AIRUNNER_SQS_QUEUE_DEFAULT is required")
    }
    if url := os.Getenv("AIRUNNER_SQS_QUEUE_PRIORITY"); url != "" {
        queueURLs["priority"] = url
    }

    // Parse DynamoDB table names
    jobsTable := os.Getenv("AIRUNNER_DYNAMODB_JOBS_TABLE")
    if jobsTable == "" {
        return nil, errors.New("AIRUNNER_DYNAMODB_JOBS_TABLE is required")
    }
    eventsTable := os.Getenv("AIRUNNER_DYNAMODB_EVENTS_TABLE")

    // Parse configuration parameters
    visTimeout := int32(300)
    if v := os.Getenv("AIRUNNER_DEFAULT_VISIBILITY_TIMEOUT"); v != "" {
        if parsed, err := strconv.ParseInt(v, 10, 32); err == nil {
            visTimeout = int32(parsed)
        }
    }

    ttlDays := int32(0)
    if v := os.Getenv("AIRUNNER_EVENTS_TTL_DAYS"); v != "" {
        if parsed, err := strconv.ParseInt(v, 10, 32); err == nil {
            ttlDays = int32(parsed)
        }
    }

    // Get token signing secret
    tokenSecret := os.Getenv("AIRUNNER_TOKEN_SIGNING_SECRET")
    if tokenSecret == "" {
        return nil, errors.New("AIRUNNER_TOKEN_SIGNING_SECRET is required")
    }

    // Build store configuration
    storeCfg := store.SQSJobStoreConfig{
        QueueURLs:                       queueURLs,
        JobsTableName:                   jobsTable,
        JobEventsTableName:              eventsTable,
        DefaultVisibilityTimeoutSeconds: visTimeout,
        EventsTTLDays:                   ttlDays,
        TokenSigningSecret:              []byte(tokenSecret),
    }

    return store.NewSQSJobStore(sqsClient, dynamoClient, storeCfg), nil
}
```

### 3.3 Add Imports

**File**: `cmd/server/internal/commands/rpc.go` (ADD to imports)

```go
"os"
"strconv"
"errors"
"github.com/aws/aws-sdk-go-v2/config"
"github.com/aws/aws-sdk-go-v2/service/dynamodb"
"github.com/aws/aws-sdk-go-v2/service/sqs"
```

### 3.4 Update Variable References

**File**: `cmd/server/internal/commands/rpc.go` (lines 70-90)

Change all references from `memStore` to `jobStore`:
- Line 70: `jobServer := server.NewServer(jobStore)`

### Phase 3 Validation

**Local testing** (before AWS deployment):
```bash
# Test memory store still works (backward compatibility)
make build-server
./bin/airunner-server rpc-server --no-auth
# Should log: "Using in-memory job store"

# Test SQS store requires env vars
export AIRUNNER_STORE_TYPE=sqs
./bin/airunner-server rpc-server --no-auth
# Should fail with: "AIRUNNER_SQS_QUEUE_DEFAULT is required"
```

**Review checklist**:
- ✅ Backward compatible (defaults to memory store)
- ✅ Clear error messages for missing configuration
- ✅ AWS SDK uses default credential chain (IAM role)
- ✅ All required env vars validated
- ✅ Optional parameters have sensible defaults

---

## Deployment Workflow

### Pre-Deployment

1. **Review and merge Phase 1**: Terraform backend resources
2. **Review and merge Phase 2**: Terraform IAM/ECS updates
3. **Review and merge Phase 3**: Server code changes

### Deployment Steps

```bash
# 1. Build and push new Docker image
make build-server
docker build -t ghcr.io/wolfeidau/airunner/server:latest .
docker push ghcr.io/wolfeidau/airunner/server:latest

# 2. Update Terraform variable for new image
cd infra
export TF_VAR_container_image="ghcr.io/wolfeidau/airunner/server:latest"

# 3. Set OTEL configuration
export TF_VAR_otel_exporter_endpoint="https://api.honeycomb.io"
export TF_VAR_otel_exporter_headers="x-honeycomb-team=YOUR_API_KEY"

# 4. Apply Terraform
terraform init -upgrade
terraform plan -out=tfplan
# Review: should show ~15 new resources + modifications
terraform apply tfplan

# 5. Wait for ECS service update
aws ecs wait services-stable \
  --cluster $(terraform output -raw ecs_cluster_name) \
  --services $(terraform output -raw ecs_service_name)

# 6. Capture outputs
terraform output > deployment_outputs.txt
```

### Post-Deployment Validation

#### 1. Health Check
```bash
SERVICE_URL=$(terraform output -raw service_url)
curl -k $SERVICE_URL/health
# Expected: {"status":"ok"}
```

#### 2. Check Logs
```bash
aws logs tail $(terraform output -raw log_group_name) --follow
# Expected: "Using SQS/DynamoDB job store"
# Expected: No AccessDeniedException errors
```

#### 3. Submit Test Job
```bash
# Build CLI
make build-cli

# Submit job
./bin/airunner-cli submit \
  --server=$SERVICE_URL \
  --no-verify \
  github.com/example/test-repo
```

#### 4. Verify Backend Resources

**DynamoDB**:
```bash
aws dynamodb scan --table-name airunner_jobs --limit 5
# Should show job record
```

**SQS**:
```bash
DEFAULT_QUEUE_URL=$(terraform output -json sqs_queue_urls | jq -r '.default')
aws sqs get-queue-attributes \
  --queue-url $DEFAULT_QUEUE_URL \
  --attribute-names ApproximateNumberOfMessages
# Should show 1 message (if worker not running)
```

#### 5. Validate Telemetry (Honeycomb)
- Check for `airunner.jobs.enqueued.total` metric
- Verify trace spans include AWS service calls
- Monitor for `airunner.dynamodb.throttles.total` (should be 0)

---

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| "failed to load AWS config" | Task role not attached | Verify `task_role_arn` in task definition |
| "AIRUNNER_TOKEN_SIGNING_SECRET is required" | Secret not injected | Check execution role has SSM GetParameter permission |
| DynamoDB AccessDeniedException | Missing task role permissions | Verify `aws_iam_role_policy.task_sqs_dynamodb` applied |
| SQS AccessDeniedException | Missing task role permissions | Verify SQS actions in task role policy |
| Jobs stuck in SCHEDULED | No worker running | Start worker: `airunner-cli worker --server=$SERVICE_URL` |
| Task fails to start | Invalid SSM parameter ARN | Check parameter exists: `aws ssm get-parameter --name /airunner/dev/token-signing-secret` |
| OTEL metrics not appearing | Variables not set | Verify `TF_VAR_otel_exporter_*` set before `terraform apply` |

---

## Rollback Plan

### If Phase 2/3 Deployment Fails

**Option 1: Quick Rollback** (use previous task definition)
```bash
# Get previous task definition revision
PREV_TASK_DEF=$(aws ecs describe-services \
  --cluster airunner-dev-cluster \
  --services airunner-dev \
  --query 'services[0].deployments[1].taskDefinition' \
  --output text)

# Update service to use previous task definition
aws ecs update-service \
  --cluster airunner-dev-cluster \
  --service airunner-dev \
  --task-definition $PREV_TASK_DEF
```

**Option 2: Disable SQS Backend** (keep resources, revert to memory store)
```bash
# Edit task definition to remove AIRUNNER_STORE_TYPE env var
# Or set it to "memory"
terraform apply
```

**Option 3: Full Rollback** (destroy backend resources)
```bash
terraform destroy -target=aws_sqs_queue.default
terraform destroy -target=aws_dynamodb_table.jobs
# etc...
```

---

## Success Criteria

✅ **Phase 1**: Terraform plan shows ~15 new resources, no errors
✅ **Phase 2**: Terraform plan shows task role, execution role, and task def updates
✅ **Phase 3**: Local build succeeds, backward compatibility verified
✅ **Deployment**: ECS task running and healthy
✅ **Validation**: `/health` returns 200, test job in DynamoDB and SQS
✅ **Observability**: CloudWatch logs clean, Honeycomb shows metrics

---

## Post-Deployment Iteration

1. **Monitor for 24-48 hours**:
   - DynamoDB consumed capacity (should be minimal with on-demand)
   - SQS message age (should be low if workers running)
   - CloudWatch error logs
   - Honeycomb traces and metrics

2. **Validate worker flow**:
   - Start worker with `airunner-cli worker`
   - Verify job transitions: SCHEDULED → RUNNING → COMPLETED
   - Check event persistence in `airunner_job_events` table

3. **Test failure scenarios**:
   - Job that fails (exit code 1)
   - Long-running job (visibility timeout extension)
   - No worker available (job stays SCHEDULED)

4. **Build integration tests**:
   - Based on production behavior patterns
   - LocalStack setup (Phase 4 - future work)
   - Cover edge cases discovered in production

---

## References

- [SQS/DynamoDB Backend Spec](./sqs_dynamodb_backend.md) - Original design specification
- [Phase 2 Implementation Summary](../PHASE2_IMPLEMENTATION_SUMMARY.md) - SQSJobStore implementation details
- [Job API Spec](./job_api.md) - API design and contracts
