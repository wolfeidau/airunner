# Network Load Balancer for mTLS Passthrough
#
# This is an example/reference Terraform configuration.
# For the complete implementation, see the original spec:
# specs/api_auth_v2_pki_implementation_alternative_with_mtls.md lines 784-869
#
# Resources defined:
# 1. Network Load Balancer (TCP passthrough, no TLS termination)
# 2. Target groups:
#    - mtls (port 443) - Health check via HTTP on port 8080
#    - health (port 8080) - Direct health check endpoint
# 3. Listeners:
#    - Port 443 TCP - mTLS API traffic (passthrough)
#    - Port 8080 TCP - Health check traffic
#
# Key configuration:
# - load_balancer_type = "network" (Layer 4, TCP passthrough)
# - Protocol = "TCP" (no TLS termination at load balancer)
# - Health checks via HTTP on port 8080
# - Dual-stack (IPv4 + IPv6)
#
# Example structure:
#
# resource "aws_lb" "main" {
#   name               = "${local.name_prefix}-nlb"
#   internal           = false
#   load_balancer_type = "network"
#   ip_address_type    = "dualstack"
# }
#
# resource "aws_lb_target_group" "mtls" {
#   port     = 443
#   protocol = "TCP"
#
#   health_check {
#     protocol = "HTTP"
#     port     = "8080"
#     path     = "/health"
#   }
# }
#
# resource "aws_lb_listener" "mtls" {
#   port     = "443"
#   protocol = "TCP"
#
#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.mtls.arn
#   }
# }
#
# See the original spec for complete NLB configuration with all target groups and listeners.
