# Generate random 32-byte value for token signing
resource "random_password" "token_signing_secret" {
  length  = 32
  special = true
}

# ============================================================================
# SQS Dead Letter Queues
# ============================================================================

resource "aws_sqs_queue" "default_dlq" {
  name                      = "${local.name_prefix}-default-dlq"
  message_retention_seconds = 1209600  # 14 days

  sqs_managed_sse_enabled = true

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-default-dlq"
    }
  )
}

resource "aws_sqs_queue" "priority_dlq" {
  name                      = "${local.name_prefix}-priority-dlq"
  message_retention_seconds = 1209600  # 14 days

  sqs_managed_sse_enabled = true

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-priority-dlq"
    }
  )
}

# ============================================================================
# SQS Main Queues
# ============================================================================

resource "aws_sqs_queue" "default" {
  name                       = "${local.name_prefix}-default"
  visibility_timeout_seconds = 300
  receive_wait_time_seconds  = 20
  message_retention_seconds  = 1209600  # 14 days

  sqs_managed_sse_enabled = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.default_dlq.arn
    maxReceiveCount     = 3
  })

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-default"
    }
  )

  depends_on = [aws_sqs_queue.default_dlq]
}

resource "aws_sqs_queue" "priority" {
  name                       = "${local.name_prefix}-priority"
  visibility_timeout_seconds = 300
  receive_wait_time_seconds  = 20
  message_retention_seconds  = 1209600  # 14 days

  sqs_managed_sse_enabled = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.priority_dlq.arn
    maxReceiveCount     = 3
  })

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-priority"
    }
  )

  depends_on = [aws_sqs_queue.priority_dlq]
}

# ============================================================================
# DynamoDB Tables
# ============================================================================

resource "aws_dynamodb_table" "jobs" {
  name           = "${local.name_prefix}_jobs"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "job_id"

  attribute {
    name = "job_id"
    type = "S"
  }

  attribute {
    name = "queue"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "N"
  }

  attribute {
    name = "request_id"
    type = "S"
  }

  # GSI1: Query jobs by queue and creation time
  global_secondary_index {
    name            = "GSI1"  # Changed from "queue-created-at-index"
    hash_key        = "queue"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # GSI2: Query jobs by request ID
  global_secondary_index {
    name            = "GSI2"  # Changed from "request-id-index"
    hash_key        = "request_id"
    projection_type = "KEYS_ONLY"
  }

  # Enable point-in-time recovery for disaster recovery
  point_in_time_recovery {
    enabled = true
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-jobs-table"
    }
  )
}

resource "aws_dynamodb_table" "job_events" {
  name           = "${local.name_prefix}_job_events"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "job_id"
  range_key      = "sequence"

  attribute {
    name = "job_id"
    type = "S"
  }

  attribute {
    name = "sequence"
    type = "N"
  }

  # TTL: Auto-delete events after ttl_days
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  # Enable point-in-time recovery for disaster recovery
  point_in_time_recovery {
    enabled = true
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-job-events-table"
    }
  )
}

# ============================================================================
# SSM Secure String Parameters
# ============================================================================

resource "aws_ssm_parameter" "token_signing_secret" {
  name        = "/${var.application}/${var.environment}/token-signing-secret"
  description = "Token signing secret (32-byte random value) for ${var.application}"
  type        = "SecureString"
  value       = random_password.token_signing_secret.result

  tags = {
    Name = "${var.application}-${var.environment}-token-signing-secret"
  }
}

# Conditionally create OTEL endpoint parameter if variable is set
resource "aws_ssm_parameter" "otel_exporter_endpoint" {
  count       = var.otel_exporter_endpoint != "" ? 1 : 0
  name        = "/${var.application}/${var.environment}/otel-exporter-endpoint"
  description = "OpenTelemetry OTLP exporter endpoint for ${var.application}"
  type        = "String"
  value       = var.otel_exporter_endpoint

  tags = {
    Name = "${var.application}-${var.environment}-otel-exporter-endpoint"
  }
}

# Conditionally create OTEL headers parameter if variable is set
resource "aws_ssm_parameter" "otel_exporter_headers" {
  count       = var.otel_exporter_headers != "" ? 1 : 0
  name        = "/${var.application}/${var.environment}/otel-exporter-headers"
  description = "OpenTelemetry OTLP exporter headers (contains API keys)"
  type        = "SecureString"
  value       = var.otel_exporter_headers

  tags = {
    Name = "${var.application}-${var.environment}-otel-exporter-headers"
  }
}
