# ECS Task Definition Updates for mTLS
#
# This is an example/reference Terraform configuration.
# For the complete implementation, see the original spec:
# specs/api_auth_v2_pki_implementation_alternative_with_mtls.md lines 870-967
#
# Changes to ECS task definition:
# 1. Command updates:
#    - Add: --mtls-listen 0.0.0.0:443
#    - Add: --health-listen 0.0.0.0:8080
#    - Add: --hostname airunner-${var.environment}.${var.domain_name}
#
# 2. Port mappings:
#    - containerPort 443 (mTLS API)
#    - containerPort 8080 (health check)
#
# 3. Environment variables:
#    - AIRUNNER_PRINCIPAL_TABLE (DynamoDB table name)
#    - AIRUNNER_CERT_TABLE (DynamoDB table name)
#
# 4. Secrets (loaded from SSM):
#    - AIRUNNER_CA_CERT (SSM parameter ARN)
#    - AIRUNNER_SERVER_CERT (SSM parameter ARN)
#    - AIRUNNER_SERVER_KEY (SSM parameter ARN)
#
# Example structure:
#
# resource "aws_ecs_task_definition" "airunner" {
#   container_definitions = jsonencode([
#     {
#       name  = local.name_prefix
#       image = var.container_image
#       command = [
#         "rpc-server",
#         "--mtls-listen", "0.0.0.0:443",
#         "--health-listen", "0.0.0.0:8080",
#         "--hostname", "airunner-${var.environment}.${var.domain_name}"
#       ]
#       portMappings = [
#         { containerPort = 443, name = "mtls-api" },
#         { containerPort = 8080, name = "health" }
#       ]
#       environment = [
#         { name = "AIRUNNER_PRINCIPAL_TABLE", value = aws_dynamodb_table.principals.name },
#         { name = "AIRUNNER_CERT_TABLE", value = aws_dynamodb_table.certificates.name }
#       ]
#       secrets = [
#         { name = "AIRUNNER_CA_CERT", valueFrom = aws_ssm_parameter.ca_cert.arn },
#         { name = "AIRUNNER_SERVER_CERT", valueFrom = aws_ssm_parameter.server_cert.arn },
#         { name = "AIRUNNER_SERVER_KEY", valueFrom = aws_ssm_parameter.server_key.arn }
#       ]
#     }
#   ])
# }
#
# ECS Service updates:
# - Add load_balancer block for port 443 (mtls target group)
# - Add load_balancer block for port 8080 (health target group)
#
# See the original spec for complete task definition and service configuration.
