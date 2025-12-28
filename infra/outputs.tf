# ECS Cluster & Service Outputs
output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.main.name
}

output "ecs_cluster_arn" {
  description = "ARN of the ECS cluster"
  value       = aws_ecs_cluster.main.arn
}

output "ecs_service_name" {
  description = "Name of the ECS service"
  value       = aws_ecs_service.airunner.name
}

output "ecs_service_arn" {
  description = "ARN of the ECS service"
  value       = aws_ecs_service.airunner.arn
}

output "ecs_task_definition_arn" {
  description = "ARN of the ECS task definition"
  value       = aws_ecs_task_definition.airunner.arn
}

# Auto Scaling Outputs
output "asg_name" {
  description = "Name of the Auto Scaling Group"
  value       = aws_autoscaling_group.ecs.name
}

output "capacity_provider_name" {
  description = "Name of the capacity provider"
  value       = aws_ecs_capacity_provider.main.name
}

# CloudWatch Outputs
output "log_group_name" {
  description = "Name of the CloudWatch log group"
  value       = aws_cloudwatch_log_group.airunner.name
}

# VPC & Network Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "public_subnet_azs" {
  description = "Availability zones of the public subnets"
  value       = aws_subnet.public[*].availability_zone
}

# Security Groups Outputs
output "ecs_security_group_id" {
  description = "ID of the ECS task security group"
  value       = aws_security_group.airunner.id
}

# AMI Output
output "bottlerocket_ami_id" {
  description = "ID of the Bottlerocket AMI being used"
  value       = data.aws_ssm_parameter.bottlerocket_ami.value
  sensitive   = true
}

# IAM Outputs
output "ec2_instance_role_name" {
  description = "Name of the EC2 instance IAM role"
  value       = aws_iam_role.ec2_instance.name
}

output "ecs_task_execution_role_name" {
  description = "Name of the ECS task execution IAM role"
  value       = aws_iam_role.execution.name
}

output "ecs_task_role_name" {
  description = "Name of the ECS task IAM role"
  value       = aws_iam_role.task.name
}

# Service Access Instructions
output "service_access_instructions" {
  description = "Instructions for accessing the service"
  value = {
    view_logs            = "aws logs tail ${aws_cloudwatch_log_group.airunner.name} --follow"
    list_instances       = "aws ec2 describe-instances --filters \"Name=tag:aws:autoscaling:groupName,Values=${aws_autoscaling_group.ecs.name}\" --query 'Reservations[].Instances[].InstanceId'"
    ssm_session          = "aws ssm start-session --target <instance-id>"
    check_service_status = "aws ecs describe-services --cluster ${aws_ecs_cluster.main.name} --services ${aws_ecs_service.airunner.name}"
  }
}

# SQS Queue Outputs
output "sqs_queue_urls" {
  description = "URLs of SQS queues"
  value = {
    default      = aws_sqs_queue.default.url
    priority     = aws_sqs_queue.priority.url
    default_dlq  = aws_sqs_queue.default_dlq.url
    priority_dlq = aws_sqs_queue.priority_dlq.url
  }
}

output "sqs_queue_arns" {
  description = "ARNs of SQS queues"
  value = {
    default      = aws_sqs_queue.default.arn
    priority     = aws_sqs_queue.priority.arn
    default_dlq  = aws_sqs_queue.default_dlq.arn
    priority_dlq = aws_sqs_queue.priority_dlq.arn
  }
}

# DynamoDB Table Outputs
output "dynamodb_tables" {
  description = "DynamoDB table names"
  value = {
    jobs       = aws_dynamodb_table.jobs.name
    job_events = aws_dynamodb_table.job_events.name
  }
}

output "dynamodb_table_arns" {
  description = "DynamoDB table ARNs"
  value = {
    jobs       = aws_dynamodb_table.jobs.arn
    job_events = aws_dynamodb_table.job_events.arn
  }
}

# SSM Parameter Outputs
output "ssm_parameters" {
  description = "SSM parameter names"
  value = {
    token_signing_secret   = aws_ssm_parameter.token_signing_secret.name
    otel_exporter_endpoint = try(aws_ssm_parameter.otel_exporter_endpoint[0].name, null)
    otel_exporter_headers  = try(aws_ssm_parameter.otel_exporter_headers[0].name, null)
  }
}

output "ssm_parameter_arns" {
  description = "SSM parameter ARNs"
  value = {
    token_signing_secret   = aws_ssm_parameter.token_signing_secret.arn
    otel_exporter_endpoint = try(aws_ssm_parameter.otel_exporter_endpoint[0].arn, null)
    otel_exporter_headers  = try(aws_ssm_parameter.otel_exporter_headers[0].arn, null)
  }
}
