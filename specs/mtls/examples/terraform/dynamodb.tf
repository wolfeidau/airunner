# DynamoDB Tables for mTLS Principal and Certificate Management
#
# This is an example/reference Terraform configuration.
# For the complete implementation, see the original spec:
# specs/api_auth_v2_pki_implementation_alternative_with_mtls.md lines 602-708
#
# Tables defined:
# 1. principals - Stores principal metadata
#    - PK: principal_id (String)
#    - GSI1: status + created_at (for listing by status)
#    - GSI2: type + created_at (for listing all workers, users, etc.)
#    - Point-in-time recovery enabled
#
# 2. certificates - Stores certificate metadata
#    - PK: serial_number (String, hex-encoded)
#    - GSI1: principal_id + issued_at (for listing certs per principal)
#    - GSI2: fingerprint (for lookup by fingerprint)
#    - TTL enabled on ttl attribute (expires_at + 30 days)
#    - Point-in-time recovery enabled
#
# Example structure:
#
# resource "aws_dynamodb_table" "principals" {
#   name         = "${local.name_prefix}_principals"
#   billing_mode = "PAY_PER_REQUEST"
#   hash_key     = "principal_id"
#
#   attribute {
#     name = "principal_id"
#     type = "S"
#   }
#   # ... additional attributes and GSIs
# }
#
# resource "aws_dynamodb_table" "certificates" {
#   name         = "${local.name_prefix}_certificates"
#   billing_mode = "PAY_PER_REQUEST"
#   hash_key     = "serial_number"
#
#   ttl {
#     attribute_name = "ttl"
#     enabled        = true
#   }
#   # ... additional attributes and GSIs
# }
#
# See the original spec for complete table definitions with all attributes and GSIs.
