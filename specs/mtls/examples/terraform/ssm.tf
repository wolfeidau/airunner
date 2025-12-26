# SSM Parameters and Secrets Manager for mTLS Certificates
#
# This is an example/reference Terraform configuration.
# For the complete implementation, see the original spec:
# specs/api_auth_v2_pki_implementation_alternative_with_mtls.md lines 710-783
#
# Resources defined:
# 1. SSM Parameters (plaintext for certificates, SecureString for keys)
#    - ca-cert (String) - CA certificate, distributed to all clients
#    - server-cert (String) - Server TLS certificate
#    - server-key (SecureString) - Server TLS private key
#
# 2. Secrets Manager (restricted access)
#    - ca-key - CA private key (admin access only)
#    - IAM policy restricting access to admin role
#
# Example structure:
#
# resource "aws_ssm_parameter" "ca_cert" {
#   name        = "/${var.application}/${var.environment}/ca-cert"
#   description = "CA certificate for mTLS"
#   type        = "String"
#   value       = "placeholder"
#
#   lifecycle {
#     ignore_changes = [value]
#   }
# }
#
# resource "aws_secretsmanager_secret" "ca_key" {
#   name        = "/${var.application}/${var.environment}/ca-key"
#   description = "CA private key (admin access only)"
# }
#
# resource "aws_secretsmanager_secret_policy" "ca_key" {
#   secret_arn = aws_secretsmanager_secret.ca_key.arn
#   # ... IAM policy restricting to admin role
# }
#
# See the original spec for complete resource definitions with lifecycle rules.
