# Deployment Guide

This guide covers deploying the airunner infrastructure to AWS using Terraform.

## Prerequisites

- AWS account with appropriate credentials configured
- Terraform >= 1.0
- AWS CLI configured
- Region set to us-east-1 (or update `locals.azs` in main.tf)

## Quick Deploy (All at Once)

```bash
cd infra
terraform init
terraform plan
terraform apply
```

## Incremental Deploy (Recommended for Initial Setup)

Deploy in phases to catch issues early:

### Phase 1: VPC & Networking
```bash
terraform apply -target=aws_vpc.main
terraform apply -target=aws_internet_gateway.main
terraform apply -target=aws_subnet.public
terraform apply -target=aws_route_table.public
terraform apply -target=aws_route_table_association.public
```

### Phase 2: Security Groups
```bash
terraform apply -target=aws_security_group.alb
terraform apply -target=aws_security_group.airunner
```

### Phase 3: IAM Roles
```bash
terraform apply -target=aws_iam_role.execution
terraform apply -target=aws_iam_role_policy.execution
terraform apply -target=aws_iam_role.infrastructure
terraform apply -target=aws_iam_role_policy_attachment.infrastructure
terraform apply -target=aws_iam_role.task
terraform apply -target=aws_iam_role.ec2_instance
terraform apply -target=aws_iam_role_policy_attachment.ec2_ecs
terraform apply -target=aws_iam_role_policy_attachment.ec2_ssm
terraform apply -target=aws_iam_instance_profile.ec2_instance
```

### Phase 4: CloudWatch & EC2 Setup
```bash
terraform apply -target=aws_cloudwatch_log_group.airunner
terraform apply -target=aws_launch_template.ecs
```

### Phase 5: ECS Cluster
```bash
terraform apply -target=aws_ecs_cluster.main
terraform apply -target=aws_ecs_cluster_capacity_providers.main
```

### Phase 6: ASG & Capacity Provider
```bash
terraform apply -target=aws_autoscaling_group.ecs
terraform apply -target=aws_ecs_capacity_provider.main
terraform apply -target=aws_ecs_cluster_capacity_providers.main_override
```

### Phase 7: ALB & Task Definition
```bash
terraform apply -target=aws_lb.main
terraform apply -target=aws_lb_target_group.airunner
terraform apply -target=aws_lb_listener.airunner
terraform apply -target=aws_ecs_task_definition.airunner
```

### Phase 8: Service (Last)
```bash
terraform apply -target=aws_ecs_service.airunner
```

## Post-Deployment Verification

After deployment completes, verify everything is working:

### Get Key Outputs
```bash
terraform output -json > ../deployment-info.json
terraform output service_access_instructions
```

### Check ALB Status
```bash
ALB_DNS=$(terraform output -raw alb_dns_name)
echo "ALB: https://$ALB_DNS"

# Wait for targets to become healthy (usually 60-90 seconds)
aws elbv2 describe-target-health \
  --target-group-arn $(terraform output -raw alb_target_group_arn) \
  --query 'TargetHealthDescriptions[*].[Target.Id,TargetHealth.State,TargetHealth.Reason]' \
  --output table
```

### Check ECS Service Status
```bash
CLUSTER=$(terraform output -raw ecs_cluster_name)
SERVICE=$(terraform output -raw ecs_service_name)

aws ecs describe-services \
  --cluster $CLUSTER \
  --services $SERVICE \
  --query 'services[0].[runningCount,desiredCount,deployments[0].status]'
```

### List EC2 Instances
```bash
ASG=$(terraform output -raw asg_name)

aws ec2 describe-instances \
  --filters "Name=tag:aws:autoscaling:groupName,Values=$ASG" \
           "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[].[InstanceId,PrivateIpAddress,State.Name,LaunchTime]' \
  --output table
```

### View Container Logs
```bash
LOG_GROUP=$(terraform output -raw log_group_name)

# Follow live logs
aws logs tail $LOG_GROUP --follow

# View last 50 lines
aws logs tail $LOG_GROUP --max-items 50
```

### SSH into Instance (via SSM Session Manager)
```bash
# Get instance ID
INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:aws:autoscaling:groupName,Values=$(terraform output -raw asg_name)" \
           "Name=instance-state-name,Values=running" \
  --query 'Reservations[0].Instances[0].InstanceId' \
  --output text)

# Start session
aws ssm start-session --target $INSTANCE_ID

# Inside the instance, check ECS agent status
systemctl status ecs
journalctl -u ecs -f
```

## Troubleshooting

### Targets Remain Unhealthy

Check container logs:
```bash
aws logs tail $(terraform output -raw log_group_name) --follow
```

Verify security group rules allow ALB -> ECS (port 8443):
```bash
CLUSTER=$(terraform output -raw ecs_cluster_name)
SERVICE=$(terraform output -raw ecs_service_name)

aws ecs describe-services \
  --cluster $CLUSTER \
  --services $SERVICE \
  --query 'services[0].networkConfiguration.awsvpcConfiguration.securityGroups'
```

### EC2 Instance Not Joining Cluster

SSH into instance and check ECS agent:
```bash
aws ssm start-session --target <instance-id>
systemctl status ecs
journalctl -u ecs -n 50
```

### ALB Target Group Deregistering Targets

Usually indicates container exiting or health check failing. Check logs and verify:
1. Container is listening on port 8443
2. `/health` endpoint is responding with 200
3. TLS certificate is valid

## Cleanup

To destroy all resources:
```bash
terraform destroy
```

To destroy specific resources:
```bash
terraform destroy -target=aws_ecs_service.airunner
terraform destroy -target=aws_lb.main
# ... continue with other targets in reverse order
```

## Updating the Service

### Update Container Image

Use the `container_image` variable to update without modifying main.tf:

```bash
# Apply with a new image tag
terraform apply -var="container_image=ghcr.io/wolfeidau/airunner-server:v0.2.0"

# Or update terraform.tfvars and apply
echo 'container_image = "ghcr.io/wolfeidau/airunner-server:v0.2.0"' >> terraform.tfvars
terraform apply
```

The service will automatically perform a rolling update with no downtime.

### Update Other Configuration

All key settings are variables:
```bash
terraform apply \
  -var="container_image=ghcr.io/wolfeidau/airunner-server:v0.2.0" \
  -var="desired_count=2" \
  -var="instance_type=t4g.medium"
```

Available variables:

**Deployment**
- `aws_region` - AWS region (default: us-east-1)
- `container_image` - Container image URI (default: ghcr.io/wolfeidau/airunner-server:v0.1.0)
- `container_port` - Container listen port (default: 8443)
- `health_check_path` - Health check path (default: /health)

**Scaling**
- `desired_count` - Desired number of tasks (default: 1)
- `min_capacity` - Minimum EC2 instances (default: 1)
- `max_capacity` - Maximum EC2 instances (default: 2)
- `auto_scaling_target_capacity` - Target capacity % for auto scaling (default: 80)

**Compute**
- `instance_type` - EC2 instance type (default: t4g.small)
- `task_cpu` - Task CPU units (default: 256)
- `task_memory` - Task memory in MB (default: 512)

**Logging & Tagging**
- `log_retention_days` - CloudWatch log retention in days (default: 7)
- `application` - Application name for tagging (default: airunner)
- `component` - Component name for tagging (default: backend)
- `environment` - Environment name for tagging (default: dev)
- `tags` - Additional tags to apply to all resources (default: {})

## Monitoring

Key metrics to monitor:

```bash
# CPU and Memory utilization
aws cloudwatch get-metric-statistics \
  --namespace AWS/ECS \
  --metric-name CPUUtilization \
  --dimensions Name=ServiceName,Value=$(terraform output -raw ecs_service_name) \
               Name=ClusterName,Value=$(terraform output -raw ecs_cluster_name) \
  --statistics Average \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300

# Target health
CLUSTER=$(terraform output -raw ecs_cluster_name)
SERVICE=$(terraform output -raw ecs_service_name)
aws ecs describe-services \
  --cluster $CLUSTER \
  --services $SERVICE \
  --query 'services[0].[runningCount,desiredCount,pendingCount]'
```
