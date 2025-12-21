terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Generate ECDSA key pair for JWT signing (P256/ES256)
resource "tls_private_key" "jwt" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

# Store private key in SSM (for token issuers/admin tools)
resource "aws_ssm_parameter" "jwt_signing_key" {
  name        = "/${var.application}/${var.environment}/jwt-signing-key"
  description = "JWT signing key (ECDSA P256 private key) for ${var.application}"
  type        = "SecureString"
  value       = tls_private_key.jwt.private_key_pem

  tags = {
    Name = "${var.application}-${var.environment}-jwt-signing-key"
  }
}

# Store public key in SSM (for RPC server verification)
resource "aws_ssm_parameter" "jwt_public_key" {
  name        = "/${var.application}/${var.environment}/jwt-public-key"
  description = "JWT public key (ECDSA P256) for ${var.application}"
  type        = "String"
  value       = tls_private_key.jwt.public_key_pem

  tags = {
    Name = "${var.application}-${var.environment}-jwt-public-key"
  }
}

locals {
  name_prefix = "airunner-${var.environment}"
  azs         = ["us-east-1b", "us-east-1c"]

  # Cost allocation tags
  common_tags = merge(
    var.tags,
    {
      application = var.application
      environment = var.environment
      component   = var.component
    }
  )
}

# VPC and Networking
resource "aws_vpc" "main" {
  cidr_block                       = "10.0.0.0/16"
  assign_generated_ipv6_cidr_block = true
  enable_dns_hostnames             = true
  enable_dns_support               = true

  tags = {
    Name = "${local.name_prefix}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-igw"
  }
}

resource "aws_subnet" "public" {
  count                           = length(local.azs)
  vpc_id                          = aws_vpc.main.id
  cidr_block                      = "10.0.${count.index + 1}.0/24"
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.main.ipv6_cidr_block, 8, count.index)
  availability_zone               = local.azs[count.index]
  map_public_ip_on_launch         = true
  assign_ipv6_address_on_creation = true

  tags = {
    Name = "${local.name_prefix}-public-subnet-${count.index + 1}"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  route {
    ipv6_cidr_block = "::/0"
    gateway_id      = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${local.name_prefix}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private Subnets for ECS tasks
resource "aws_subnet" "private" {
  count                           = length(local.azs)
  vpc_id                          = aws_vpc.main.id
  cidr_block                      = "10.0.${count.index + 10}.0/24"
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.main.ipv6_cidr_block, 8, count.index + 10)
  availability_zone               = local.azs[count.index]
  assign_ipv6_address_on_creation = true

  tags = {
    Name = "${local.name_prefix}-private-subnet-${count.index + 1}"
  }
}

# Private route table - routes IPv4 via NAT, IPv6 via IGW
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block           = "0.0.0.0/0"
    network_interface_id = aws_instance.nat.primary_network_interface_id
  }

  route {
    ipv6_cidr_block = "::/0"
    gateway_id      = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${local.name_prefix}-private-rt"
  }

  depends_on = [aws_instance.nat]
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Security Groups
resource "aws_security_group" "alb" {
  name        = "${local.name_prefix}-alb-sg"
  description = "ALB security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from internet (IPv4)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description      = "HTTPS from internet (IPv6)"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    description = "Allow all outbound (IPv4)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description      = "Allow all outbound (IPv6)"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${local.name_prefix}-alb-sg"
  }
}

resource "aws_security_group" "airunner" {
  name        = "${local.name_prefix}-ecs-sg"
  description = "ECS task security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Container port from ALB"
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Allow all outbound (IPv4)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description      = "Allow all outbound (IPv6)"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${local.name_prefix}-ecs-sg"
  }
}

# NAT Instance
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-arm64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "nat_instance" {
  name        = "${local.name_prefix}-nat-instance-sg"
  description = "Security group for NAT instance"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow all from VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    description = "Allow all outbound IPv4"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description      = "Allow all outbound IPv6"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${local.name_prefix}-nat-instance-sg"
  }
}

resource "aws_eip" "nat_instance" {
  domain = "vpc"

  tags = {
    Name = "${local.name_prefix}-nat-instance-eip"
  }
}

resource "aws_iam_role" "nat_instance" {
  name = "nat-instance-${local.name_prefix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${local.name_prefix}-nat-instance-role"
  }
}

resource "aws_iam_role_policy_attachment" "nat_instance_ssm" {
  role       = aws_iam_role.nat_instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "nat_instance" {
  name = "nat-instance-${local.name_prefix}"
  role = aws_iam_role.nat_instance.name
}

resource "aws_instance" "nat" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t4g.nano"
  subnet_id              = aws_subnet.public[0].id
  vpc_security_group_ids = [aws_security_group.nat_instance.id]
  iam_instance_profile   = aws_iam_instance_profile.nat_instance.name
  source_dest_check      = false

  user_data_base64 = base64encode(<<-EOF
    #!/bin/bash
    # Configure NAT
    sysctl -w net.ipv4.ip_forward=1
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

    # Get the network interface
    INTERFACE=$(ip route | grep default | awk '{print $5}')

    # Configure iptables for NAT
    iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
    iptables -A FORWARD -i $INTERFACE -o $INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i $INTERFACE -o $INTERFACE -j ACCEPT

    # Save iptables rules
    iptables-save > /etc/iptables.rules

    # Restore iptables on boot
    cat > /etc/systemd/system/iptables-restore.service <<'UNIT'
    [Unit]
    Description=Restore iptables rules
    Before=network-pre.target

    [Service]
    Type=oneshot
    ExecStart=/sbin/iptables-restore /etc/iptables.rules

    [Install]
    WantedBy=multi-user.target
    UNIT

    systemctl enable iptables-restore.service
  EOF
  )

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  monitoring = true

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-nat-instance"
    }
  )
}

resource "aws_eip_association" "nat_instance" {
  instance_id   = aws_instance.nat.id
  allocation_id = aws_eip.nat_instance.id
}

# ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "${local.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "disabled"
  }

  tags = {
    Name = "${local.name_prefix}-cluster"
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "airunner" {
  name              = "/ecs/${local.name_prefix}"
  retention_in_days = 7

  tags = {
    Name = "${local.name_prefix}-log-group"
  }
}

resource "aws_iam_role" "execution" {
  name = "ecs-express-execution--${local.name_prefix}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "execution" {
  role = aws_iam_role.execution.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLogs"
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents",
          "logs:CreateLogStream"
        ]
        Resource = "${aws_cloudwatch_log_group.airunner.arn}:*"
      },
      {
        Sid      = "ECRAuthentication"
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      {
        Sid    = "AllowSSMParameterRead"
        Effect = "Allow"
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter"
        ]
        Resource = concat(
          [
            aws_ssm_parameter.jwt_public_key.arn,
            aws_ssm_parameter.token_signing_secret.arn
          ],
          var.otel_exporter_endpoint != "" ? [aws_ssm_parameter.otel_exporter_endpoint[0].arn] : [],
          var.otel_exporter_headers != "" ? [aws_ssm_parameter.otel_exporter_headers[0].arn] : []
        )
      }
    ]
  })
}

resource "aws_iam_role" "infrastructure" {
  name = "ecs-express-infrastructure--${local.name_prefix}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "infrastructure" {
  role       = aws_iam_role.infrastructure.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSInfrastructureRolePolicyForVolumes"
}

resource "aws_iam_role" "task" {
  name = "ecs-task-${local.name_prefix}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Task role policy for SQS and DynamoDB access
resource "aws_iam_role_policy" "task_sqs_dynamodb" {
  name = "ecs-task-sqs-dynamodb-${local.name_prefix}"
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

# EC2 Instance IAM Role
resource "aws_iam_role" "ec2_instance" {
  name = "ecs-ec2-instance-${local.name_prefix}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_ecs" {
  role       = aws_iam_role.ec2_instance.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2_instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_instance" {
  name = "ecs-ec2-instance-${local.name_prefix}"
  role = aws_iam_role.ec2_instance.name
}

# Bottlerocket AMI
data "aws_ssm_parameter" "bottlerocket_ami" {
  name = "/aws/service/bottlerocket/aws-ecs-2/arm64/latest/image_id"
}

# Route53 Zone
data "aws_route53_zone" "main" {
  name = var.domain_name
}

# ACM Certificate
resource "aws_acm_certificate" "main" {
  domain_name       = "airunner-${var.environment}.${var.domain_name}"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${local.name_prefix}-cert"
  }
}

# ACM Certificate Validation
resource "aws_route53_record" "acm_validation" {
  for_each = {
    for dvo in aws_acm_certificate.main.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.main.zone_id
}

resource "aws_acm_certificate_validation" "main" {
  certificate_arn = aws_acm_certificate.main.arn
  timeouts {
    create = "5m"
  }
  depends_on = [aws_route53_record.acm_validation]
}

# EC2 Launch Template
resource "aws_launch_template" "ecs" {
  name_prefix   = "${local.name_prefix}-"
  image_id      = data.aws_ssm_parameter.bottlerocket_ami.value
  instance_type = "t4g.small"

  user_data = base64encode("[settings.ecs]\ncluster = \"${aws_ecs_cluster.main.name}\"")

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_instance.name
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge(
      local.common_tags,
      {
        Name = "${local.name_prefix}-ecs-instance"
      }
    )
  }

  tag_specifications {
    resource_type = "volume"
    tags = merge(
      local.common_tags,
      {
        Name = "${local.name_prefix}-ecs-volume"
      }
    )
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-launch-template"
    }
  )
}

# Auto Scaling Group
resource "aws_autoscaling_group" "ecs" {
  name                      = "${local.name_prefix}-asg"
  vpc_zone_identifier       = aws_subnet.public[*].id
  min_size                  = 1
  max_size                  = 1
  desired_capacity          = 1
  health_check_type         = "ELB"
  health_check_grace_period = 300

  launch_template {
    id      = aws_launch_template.ecs.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${local.name_prefix}-ecs-asg"
    propagate_at_launch = true
  }

  tag {
    key                 = "AmazonECSManaged"
    value               = "true"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Capacity Provider
resource "aws_ecs_capacity_provider" "main" {
  name = "${local.name_prefix}-cp"

  auto_scaling_group_provider {
    auto_scaling_group_arn = aws_autoscaling_group.ecs.arn
    managed_scaling {
      maximum_scaling_step_size = 1000
      minimum_scaling_step_size = 1
      status                    = "ENABLED"
      target_capacity           = 80
    }
  }

  tags = {
    Name = "${local.name_prefix}-capacity-provider"
  }
}

resource "aws_ecs_cluster_capacity_providers" "main_override" {
  cluster_name       = aws_ecs_cluster.main.name
  capacity_providers = [aws_ecs_capacity_provider.main.name]

  default_capacity_provider_strategy {
    base              = 1
    weight            = 100
    capacity_provider = aws_ecs_capacity_provider.main.name
  }
}

# ALB
resource "aws_lb" "main" {
  name               = "${local.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
  ip_address_type    = "dualstack"
  idle_timeout       = 120

  enable_deletion_protection = false

  tags = {
    Name = "${local.name_prefix}-alb"
  }
}

resource "aws_lb_target_group" "airunner" {
  name_prefix      = "tg-"
  port             = var.container_port
  protocol         = "HTTPS"
  vpc_id           = aws_vpc.main.id
  target_type      = "ip"
  protocol_version = "HTTP2"

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = "/health"
    matcher             = "200"
    protocol            = "HTTPS"

  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${local.name_prefix}-tg"
  }
}

resource "aws_lb_listener" "airunner" {
  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate_validation.main.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.airunner.arn
  }

  depends_on = [aws_acm_certificate_validation.main]
}

# ECS Task Definition
resource "aws_ecs_task_definition" "airunner" {
  family                   = local.name_prefix
  network_mode             = "awsvpc"
  requires_compatibilities = ["EC2"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name  = local.name_prefix
      image = var.container_image
      command = [
        "rpc-server",
        "--listen", "0.0.0.0:${var.container_port}",
        "--hostname", "airunner-${var.environment}.${var.domain_name}"
      ]
      essential = true
      portMappings = [
        {
          containerPort = var.container_port
          hostPort      = var.container_port
          protocol      = "tcp"
        }
      ]
      environment = concat(
        [
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
            value = data.aws_region.current.id
          },
          {
            name  = "AWS_USE_DUALSTACK_ENDPOINT"
            value = "true"
          }
        ],
        # Conditionally add OTEL_SERVICE_NAME only when OTEL is configured
        var.otel_exporter_endpoint != "" ? [
          {
            name  = "OTEL_SERVICE_NAME"
            value = "${var.environment}-airunner"
          }
        ] : []
      )
      secrets = concat(
        [
          {
            name      = "JWT_PUBLIC_KEY"
            valueFrom = aws_ssm_parameter.jwt_public_key.arn
          },
          {
            name      = "AIRUNNER_TOKEN_SIGNING_SECRET"
            valueFrom = aws_ssm_parameter.token_signing_secret.arn
          }
        ],
        var.otel_exporter_endpoint != "" ? [
          {
            name      = "OTEL_EXPORTER_OTLP_ENDPOINT"
            valueFrom = aws_ssm_parameter.otel_exporter_endpoint[0].arn
          }
        ] : [],
        var.otel_exporter_headers != "" ? [
          {
            name      = "OTEL_EXPORTER_OTLP_HEADERS"
            valueFrom = aws_ssm_parameter.otel_exporter_headers[0].arn
          }
        ] : []
      )
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.airunner.name
          "awslogs-region"        = data.aws_region.current.id
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])

  tags = {
    Name = "${local.name_prefix}-task-definition"
  }

  depends_on = [
    aws_iam_role_policy.execution,
    aws_sqs_queue.default,
    aws_sqs_queue.priority,
    aws_dynamodb_table.jobs,
    aws_dynamodb_table.job_events,
    aws_ssm_parameter.token_signing_secret
  ]
}

# ECS Service
resource "aws_ecs_service" "airunner" {
  name            = local.name_prefix
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.airunner.arn
  desired_count   = var.desired_count
  launch_type     = "EC2"

  network_configuration {
    subnets         = aws_subnet.private[*].id
    security_groups = [aws_security_group.airunner.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.airunner.arn
    container_name   = local.name_prefix
    container_port   = var.container_port
  }

  tags = {
    Name = "${local.name_prefix}-service"
  }

  depends_on = [
    aws_lb_listener.airunner,
    aws_iam_role_policy.execution,
    aws_ecs_capacity_provider.main
  ]
}

# Data source for AWS region
data "aws_region" "current" {}

# Route53 record for ALB
resource "aws_route53_record" "alb" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "airunner-${var.environment}.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}
