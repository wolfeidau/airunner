# Phase 3: Infrastructure

[← Back to README](README.md) | [← Phase 2: Integration](02-phase2-integration.md) | [Phase 4: Deployment →](04-phase4-deployment.md)

## Overview

**Goal:** Update Terraform configuration for AWS resources (DynamoDB, SSM, Secrets Manager, NLB, ECS).

**Duration:** 1-2 hours

**Prerequisites:**
- Phase 2 complete and verified locally
- Terraform 1.5+ installed
- AWS CLI configured with appropriate credentials

**Success Criteria:**
- [ ] Terraform plan shows expected changes
- [ ] No breaking changes to existing resources
- [ ] DynamoDB tables have correct schema and GSIs
- [ ] SSM parameters use lifecycle ignore_changes
- [ ] NLB configured for TCP passthrough on port 443

## DynamoDB Tables

**Location:** `infra/dynamodb.tf` (or similar)

**Reference:** `examples/terraform/dynamodb.tf` (structure and patterns)

**Complete Implementation:** See original spec lines 602-708

### Principals Table

```hcl
resource "aws_dynamodb_table" "principals" {
  name         = "${local.name_prefix}_principals"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principal_id"

  attribute {
    name = "principal_id"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  attribute {
    name = "type"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "N"
  }

  global_secondary_index {
    name            = "GSI1"
    hash_key        = "status"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "GSI2"
    hash_key        = "type"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = local.tags
}
```

### Certificates Table

```hcl
resource "aws_dynamodb_table" "certificates" {
  name         = "${local.name_prefix}_certificates"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "serial_number"

  attribute {
    name = "serial_number"
    type = "S"
  }

  attribute {
    name = "principal_id"
    type = "S"
  }

  attribute {
    name = "issued_at"
    type = "N"
  }

  attribute {
    name = "fingerprint"
    type = "S"
  }

  global_secondary_index {
    name            = "GSI1"
    hash_key        = "principal_id"
    range_key       = "issued_at"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "GSI2"
    hash_key        = "fingerprint"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = local.tags
}
```

## SSM Parameters and Secrets Manager

**Location:** `infra/ssm.tf` (or similar)

**Reference:** `examples/terraform/ssm.tf` (structure and patterns)

**Complete Implementation:** See original spec lines 710-783

### SSM Parameters

```hcl
resource "aws_ssm_parameter" "ca_cert" {
  name        = "/${var.application}/${var.environment}/ca-cert"
  description = "CA certificate for mTLS"
  type        = "String"
  value       = "placeholder"

  lifecycle {
    ignore_changes = [value]  # Managed by bootstrap command
  }

  tags = local.tags
}

resource "aws_ssm_parameter" "server_cert" {
  name        = "/${var.application}/${var.environment}/server-cert"
  description = "Server TLS certificate"
  type        = "String"
  value       = "placeholder"

  lifecycle {
    ignore_changes = [value]  # Managed by bootstrap command
  }

  tags = local.tags
}

resource "aws_ssm_parameter" "server_key" {
  name        = "/${var.application}/${var.environment}/server-key"
  description = "Server TLS private key"
  type        = "SecureString"
  value       = "placeholder"

  lifecycle {
    ignore_changes = [value]  # Managed by bootstrap command
  }

  tags = local.tags
}
```

### Secrets Manager (CA Key)

```hcl
resource "aws_secretsmanager_secret" "ca_key" {
  name        = "/${var.application}/${var.environment}/ca-key"
  description = "CA private key (admin access only)"

  tags = local.tags
}

# Restrict access to CA key
resource "aws_secretsmanager_secret_policy" "ca_key" {
  secret_arn = aws_secretsmanager_secret.ca_key.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAdminAccess"
        Effect = "Allow"
        Principal = {
          AWS = var.admin_role_arn
        }
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = "*"
      }
    ]
  })
}
```

## Network Load Balancer

**Location:** `infra/nlb.tf` (or similar)

**Reference:** `examples/terraform/nlb.tf` (structure and patterns)

**Complete Implementation:** See original spec lines 784-869

### Why NLB Instead of ALB?

- **TCP Passthrough:** Preserves end-to-end TLS (no termination at load balancer)
- **Client Certificate Verification:** Server controls client cert validation
- **No Certificate Management:** No need to manage certs at load balancer level

### Key Configuration

```hcl
resource "aws_lb" "main" {
  name               = "${local.name_prefix}-nlb"
  internal           = false
  load_balancer_type = "network"  # Layer 4, TCP passthrough
  subnets            = aws_subnet.public[*].id
  ip_address_type    = "dualstack"

  tags = local.tags
}

# mTLS API target group
resource "aws_lb_target_group" "mtls" {
  name_prefix = "mtls-"
  port        = 443
  protocol    = "TCP"  # No TLS termination
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    protocol            = "HTTP"
    port                = "8080"  # Health check on separate port
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
  }

  tags = local.tags
}

# mTLS listener (TCP passthrough)
resource "aws_lb_listener" "mtls" {
  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "TCP"  # Passthrough, no TLS termination

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.mtls.arn
  }
}
```

## ECS Task Definition

**Location:** `infra/ecs.tf` (or similar)

**Reference:** `examples/terraform/ecs.tf` (structure and patterns)

**Complete Implementation:** See original spec lines 870-967

### Key Updates

**Command:**
```json
"command": [
  "rpc-server",
  "--mtls-listen", "0.0.0.0:443",
  "--health-listen", "0.0.0.0:8080",
  "--hostname", "airunner-${var.environment}.${var.domain_name}"
]
```

**Port Mappings:**
```json
"portMappings": [
  {
    "containerPort": 443,
    "hostPort": 443,
    "protocol": "tcp",
    "name": "mtls-api"
  },
  {
    "containerPort": 8080,
    "hostPort": 8080,
    "protocol": "tcp",
    "name": "health"
  }
]
```

**Environment Variables:**
```json
"environment": [
  {
    "name": "AIRUNNER_PRINCIPAL_TABLE",
    "value": "${aws_dynamodb_table.principals.name}"
  },
  {
    "name": "AIRUNNER_CERT_TABLE",
    "value": "${aws_dynamodb_table.certificates.name}"
  }
]
```

**Secrets (from SSM):**
```json
"secrets": [
  {
    "name": "AIRUNNER_CA_CERT",
    "valueFrom": "${aws_ssm_parameter.ca_cert.arn}"
  },
  {
    "name": "AIRUNNER_SERVER_CERT",
    "valueFrom": "${aws_ssm_parameter.server_cert.arn}"
  },
  {
    "name": "AIRUNNER_SERVER_KEY",
    "valueFrom": "${aws_ssm_parameter.server_key.arn}"
  }
]
```

## IAM Policies

### ECS Task Role

Add DynamoDB access for new tables:

```hcl
resource "aws_iam_role_policy" "task" {
  policy = jsonencode({
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.principals.arn,
          "${aws_dynamodb_table.principals.arn}/index/*",
          aws_dynamodb_table.certificates.arn,
          "${aws_dynamodb_table.certificates.arn}/index/*"
        ]
      }
    ]
  })
}
```

### ECS Execution Role

Add SSM parameter access:

```hcl
resource "aws_iam_role_policy" "execution" {
  policy = jsonencode({
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter"
        ]
        Resource = [
          aws_ssm_parameter.ca_cert.arn,
          aws_ssm_parameter.server_cert.arn,
          aws_ssm_parameter.server_key.arn
        ]
      }
    ]
  })
}
```

## Resources to Remove

**Location:** Remove JWT-related Terraform resources

```hcl
# DELETE these resources in Phase 5:
# resource "tls_private_key" "jwt" { ... }
# resource "aws_ssm_parameter" "jwt_signing_key" { ... }
# resource "aws_ssm_parameter" "jwt_public_key" { ... }
```

**Note:** Keep JWT resources until Phase 5 (after successful deployment).

## Implementation Checklist

- [ ] Create DynamoDB tables (principals, certificates)
- [ ] Create SSM parameters with lifecycle ignore_changes
- [ ] Create Secrets Manager secret for CA key with restricted policy
- [ ] Create Network Load Balancer with TCP passthrough
- [ ] Create target groups for mTLS (443) and health (8080)
- [ ] Update ECS task definition with new command and ports
- [ ] Add environment variables for DynamoDB tables
- [ ] Add secrets for certificates
- [ ] Update IAM policies for DynamoDB and SSM access
- [ ] Run `terraform plan` and review changes

## Verification

```bash
cd infra/

# Review plan
terraform plan

# Expected changes:
# + 2 DynamoDB tables
# + 3 SSM parameters
# + 1 Secrets Manager secret
# + 1 NLB
# + 2 target groups
# + 2 listeners
# ~ 1 ECS task definition (updated)
# ~ 2 IAM policies (updated)

# Apply changes (DO NOT apply yet - wait for Phase 4)
# terraform apply
```

## Next Steps

Once Phase 3 Terraform is ready and reviewed, proceed to **[Phase 4: Deployment](04-phase4-deployment.md)**.

---

[← Back to README](README.md) | [← Phase 2: Integration](02-phase2-integration.md) | [Phase 4: Deployment →](04-phase4-deployment.md)
