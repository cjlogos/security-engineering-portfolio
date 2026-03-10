# =============================================================================
# OUTPUTS — Cloud Detection Engineering Lab
# =============================================================================
# These values are displayed after terraform apply and can be referenced
# by other tools (attack simulation scripts, SIEM configuration, etc.)
# =============================================================================

# --- Account Info ---
output "aws_account_id" {
  description = "AWS Account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "aws_region" {
  description = "AWS Region where resources are deployed"
  value       = var.aws_region
}

# --- VPC & Networking ---
output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.lab.id
}

output "public_subnet_id" {
  description = "Public subnet ID"
  value       = aws_subnet.public.id
}

output "private_subnet_id" {
  description = "Private subnet ID"
  value       = aws_subnet.private.id
}

output "security_group_id" {
  description = "EC2 security group ID (used in attack simulations to test SG modification detection)"
  value       = aws_security_group.lab_instance.id
}

# --- EC2 ---
output "ec2_instance_id" {
  description = "EC2 instance ID (empty if deploy_ec2 = false)"
  value       = var.deploy_ec2 ? aws_instance.lab[0].id : "not-deployed"
}

output "ec2_public_ip" {
  description = "EC2 public IP address (empty if deploy_ec2 = false)"
  value       = var.deploy_ec2 ? aws_instance.lab[0].public_ip : "not-deployed"
}

# --- IAM Users ---
output "lab_admin_arn" {
  description = "ARN of the lab-admin IAM user"
  value       = aws_iam_user.lab_admin.arn
}

output "lab_analyst_arn" {
  description = "ARN of the lab-analyst IAM user"
  value       = aws_iam_user.lab_analyst.arn
}

output "lab_attacker_arn" {
  description = "ARN of the lab-attacker IAM user"
  value       = aws_iam_user.lab_attacker.arn
}

output "lab_admin_name" {
  description = "Name of the lab-admin IAM user (used in attack simulation scripts)"
  value       = aws_iam_user.lab_admin.name
}

output "lab_analyst_name" {
  description = "Name of the lab-analyst IAM user (used in attack simulation scripts)"
  value       = aws_iam_user.lab_analyst.name
}

output "lab_attacker_name" {
  description = "Name of the lab-attacker IAM user (used in attack simulation scripts)"
  value       = aws_iam_user.lab_attacker.name
}

# --- S3 Buckets ---
output "secure_bucket_name" {
  description = "Name of the properly-configured S3 bucket"
  value       = aws_s3_bucket.secure.id
}

output "misconfigured_bucket_name" {
  description = "Name of the intentionally-misconfigured S3 bucket (detection target)"
  value       = aws_s3_bucket.misconfigured.id
}

output "cloudtrail_bucket_name" {
  description = "Name of the CloudTrail log delivery bucket (used for SIEM ingestion)"
  value       = aws_s3_bucket.cloudtrail_logs.id
}

# --- CloudTrail ---
output "cloudtrail_trail_name" {
  description = "CloudTrail trail name (used in tampering detection rules)"
  value       = aws_cloudtrail.lab.name
}

output "cloudtrail_trail_arn" {
  description = "CloudTrail trail ARN"
  value       = aws_cloudtrail.lab.arn
}

# --- VPC Flow Logs ---
output "flow_log_group_name" {
  description = "CloudWatch Log Group for VPC Flow Logs"
  value       = aws_cloudwatch_log_group.flow_logs.name
}

# --- Cost Saving Reminders ---
output "cost_reminder" {
  description = "Reminder to destroy resources when done"
  value       = "Run 'terraform destroy' when done to stop all charges. EC2 costs ~$0.25/day, everything else is pennies."
}
