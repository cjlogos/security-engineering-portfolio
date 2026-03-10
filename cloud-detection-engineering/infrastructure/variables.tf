# =============================================================================
# VARIABLES — Cloud Detection Engineering Lab
# =============================================================================
# These variables control the lab environment configuration.
# Copy terraform.tfvars.example to terraform.tfvars and fill in your values.
# NEVER commit terraform.tfvars to git (it may contain your IP and preferences).
# =============================================================================

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "cloud-detection-engineering"
}

variable "environment" {
  description = "Environment tag value"
  type        = string
  default     = "lab"
}

# -----------------------------------------------------------------------------
# Networking
# -----------------------------------------------------------------------------

variable "vpc_cidr" {
  description = "CIDR block for the lab VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR block for the private subnet"
  type        = string
  default     = "10.0.2.0/24"
}

variable "my_ip" {
  description = "Your public IP address in CIDR notation (e.g., 1.2.3.4/32). Used for SSH access to EC2. Find yours at https://whatismyip.com"
  type        = string
}

# -----------------------------------------------------------------------------
# EC2
# -----------------------------------------------------------------------------

variable "instance_type" {
  description = "EC2 instance type. t3.micro is the cheapest general-purpose option (~$0.01/hr)"
  type        = string
  default     = "t3.micro"
}

variable "deploy_ec2" {
  description = "Set to false to skip EC2 deployment and save ~$7.59/month. You can still test most detections without it."
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# CloudTrail
# -----------------------------------------------------------------------------

variable "enable_s3_data_events" {
  description = "Enable S3 data event logging in CloudTrail. Costs $0.10 per 100K events. Set to false to save money if you only need management events."
  type        = bool
  default     = false
}

# -----------------------------------------------------------------------------
# VPC Flow Logs
# -----------------------------------------------------------------------------

variable "flow_log_retention_days" {
  description = "Number of days to retain VPC Flow Logs in CloudWatch. Lower = cheaper. 1 day is fine for a lab."
  type        = number
  default     = 1
}

# -----------------------------------------------------------------------------
# Common Tags
# -----------------------------------------------------------------------------

variable "common_tags" {
  description = "Tags applied to all resources for identification and cost tracking"
  type        = map(string)
  default     = {}
}

locals {
  tags = merge(
    {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
    },
    var.common_tags
  )

  # Naming prefix for all resources
  name_prefix = "${var.project_name}-${var.environment}"
}
