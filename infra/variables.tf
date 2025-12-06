variable "aws_region" {
  description = "AWS region for resources (ACM is always in us-east-1 for CloudFront)"
  type        = string
  default     = "us-east-1"
}

variable "application" {
  description = "Application name for cost allocation tagging"
  type        = string
  default     = "airunner"
}

variable "component" {
  description = "Component name for cost allocation tagging (e.g., 'cloudfront', 's3')"
  type        = string
  default     = "backend"
}

variable "environment" {
  description = "Environment name (e.g., 'prod', 'staging', 'dev')"
  type        = string
  default     = "dev"
}

variable "tags" {
  description = "Additional tags to apply to all resources (merged with cost allocation tags)"
  type        = map(string)
  default     = {}
}

variable "container_image" {
  description = "Container image URI"
  type        = string
  default     = "ghcr.io/wolfeidau/airunner/server:0.1.0"
}

variable "container_port" {
  description = "Port the container listens on"
  type        = number
  default     = 8993
}

variable "desired_count" {
  description = "Desired number of tasks"
  type        = number
  default     = 1
}

variable "min_capacity" {
  description = "Minimum number of EC2 instances"
  type        = number
  default     = 1
}

variable "max_capacity" {
  description = "Maximum number of EC2 instances"
  type        = number
  default     = 1
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t4g.small"
}

variable "task_cpu" {
  description = "Task CPU units"
  type        = string
  default     = "256"
}

variable "task_memory" {
  description = "Task memory in MB"
  type        = string
  default     = "512"
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 7
}

variable "health_check_path" {
  description = "Health check path"
  type        = string
  default     = "/health"
}

variable "auto_scaling_target_capacity" {
  description = "Target capacity percentage for auto scaling"
  type        = number
  default     = 80
}

variable "domain_name" {
  description = "Domain name for HTTPS certificate"
  type        = string
}
