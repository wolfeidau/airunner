# KMS key for CA signing (ECDSA P-256)
#
# This file provides a complete Terraform configuration for creating
# an AWS KMS key for CA certificate signing operations.
#
# The CA private key is created in KMS and never exported.
# All certificate signing operations are performed via KMS API.

resource "aws_kms_key" "ca_signing_key" {
  description              = "${var.application} ${var.environment} CA signing key"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

  deletion_window_in_days = 30
  enable_key_rotation     = false # Don't rotate CA keys

  tags = merge(local.tags, {
    Purpose = "ca-signing"
  })
}

# KMS key alias for easy reference
resource "aws_kms_alias" "ca_signing_key" {
  name          = "alias/${var.application}-${var.environment}-ca"
  target_key_id = aws_kms_key.ca_signing_key.id
}

# Store KMS key ID in SSM so bootstrap can find it
resource "aws_ssm_parameter" "ca_kms_key_id" {
  name  = "/${var.application}/${var.environment}/ca-kms-key-id"
  type  = "String"
  value = aws_kms_key.ca_signing_key.id

  tags = local.tags
}

# Grant server (ECS task role) permission to sign with KMS
resource "aws_iam_role_policy" "ecs_task_kms_signing" {
  name = "${var.application}-${var.environment}-kms-signing"
  role = aws_iam_role.ecs_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCAKeySigning"
        Effect = "Allow"
        Action = [
          "kms:Sign",
          "kms:GetPublicKey",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.ca_signing_key.arn
      }
    ]
  })
}

# Output KMS key information
output "ca_kms_key_id" {
  description = "KMS key ID for CA signing"
  value       = aws_kms_key.ca_signing_key.id
}

output "ca_kms_key_alias" {
  description = "KMS key alias for CA signing"
  value       = aws_kms_alias.ca_signing_key.name
}

output "ca_kms_key_arn" {
  description = "KMS key ARN for CA signing"
  value       = aws_kms_key.ca_signing_key.arn
}
