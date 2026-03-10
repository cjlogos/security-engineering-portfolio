# =============================================================================
# MAIN — Cloud Detection Engineering Lab
# =============================================================================
# This Terraform configuration deploys an AWS lab environment for building
# and testing cloud-native detection rules against real CloudTrail telemetry.
#
# COST OPTIMIZATION:
#   - EC2 can be disabled entirely with deploy_ec2 = false
#   - S3 data events disabled by default (enable_s3_data_events = false)
#   - VPC Flow Logs retained for only 1 day by default
#   - No NAT Gateway (saves ~$32/month) — private subnet has no internet
#   - No Elastic IP unless EC2 is deployed
#   - Run "terraform destroy" when not actively working to pay $0
#
# ESTIMATED COST (all resources running for 1 full month):
#   EC2 t3.micro:     ~$7.59/month (skip with deploy_ec2 = false)
#   CloudTrail:       ~$0 (first management event trail is free)
#   S3 storage:       ~$0.01 (minimal log volume)
#   CloudWatch Logs:  ~$0.25 (VPC flow logs, minimal traffic)
#   VPC/Subnets/SG:   $0 (no charge for VPC components)
#   IAM:              $0 (always free)
#   TOTAL:            ~$0.26/month without EC2, ~$7.85/month with EC2
#   If you deploy and destroy same day: ~$0.25-$0.50
# =============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.tags
  }
}

# Get current AWS account info (used for CloudTrail bucket policy)
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# Get the latest Amazon Linux 2023 AMI (free tier eligible, no license cost)
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}


# =============================================================================
# VPC & NETWORKING
# =============================================================================
# Detection rules supported:
#   - VPC Flow Logs feed into anomalous traffic detection
#   - Security group changes are tracked via CloudTrail
# =============================================================================

resource "aws_vpc" "lab" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${local.name_prefix}-vpc" }
}

# --- Public Subnet (EC2 instance lives here) ---
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = { Name = "${local.name_prefix}-public-subnet" }
}

# --- Private Subnet (no internet access — demonstrates network segmentation) ---
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.lab.id
  cidr_block        = var.private_subnet_cidr
  availability_zone = "${var.aws_region}a"

  tags = { Name = "${local.name_prefix}-private-subnet" }
}

# --- Internet Gateway (allows public subnet to reach the internet) ---
resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id

  tags = { Name = "${local.name_prefix}-igw" }
}

# --- Route Table for Public Subnet ---
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = { Name = "${local.name_prefix}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# No NAT Gateway for private subnet — saves ~$32/month
# Private subnet intentionally has no internet access


# =============================================================================
# VPC FLOW LOGS → CloudWatch Logs
# =============================================================================
# Detection rules supported:
#   - Unusual network traffic patterns
#   - Port scanning detection
#   - Data exfiltration via unusual outbound connections
#
# COST NOTE: VPC Flow Logs to CloudWatch cost ~$0.25/GB for vended log
# delivery + $0.03/GB/month storage. A single t3.micro in a lab generates
# very little traffic (<100MB/month). Retention set to 1 day to minimize cost.
# =============================================================================

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/${local.name_prefix}/vpc-flow-logs"
  retention_in_days = var.flow_log_retention_days

  tags = { Name = "${local.name_prefix}-flow-logs" }
}

resource "aws_iam_role" "flow_logs" {
  name = "${local.name_prefix}-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${local.name_prefix}-flow-logs-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

resource "aws_flow_log" "lab" {
  vpc_id                   = aws_vpc.lab.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 600 # 10-minute aggregation (cheaper than 1-minute)

  tags = { Name = "${local.name_prefix}-flow-log" }
}


# =============================================================================
# SECURITY GROUP — SSH from your IP only
# =============================================================================
# Detection rules supported:
#   - AuthorizeSecurityGroupIngress with 0.0.0.0/0 (attack simulation opens this)
#   - Security group modification tracking
# =============================================================================

resource "aws_security_group" "lab_instance" {
  name        = "${local.name_prefix}-instance-sg"
  description = "SSH access restricted to lab operator IP"
  vpc_id      = aws_vpc.lab.id

  # SSH from your IP only
  ingress {
    description = "SSH from operator IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  # All outbound traffic allowed
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-instance-sg" }
}


# =============================================================================
# EC2 INSTANCE (optional — disable with deploy_ec2 = false to save money)
# =============================================================================
# Detection rules supported:
#   - Unusual region API activity (EC2 generates baseline events)
#   - Security group modification detection
#
# COST: t3.micro = $0.0104/hr = ~$7.59/month if left running 24/7
#       Deploy only when needed, destroy when done = pennies
# =============================================================================

resource "aws_instance" "lab" {
  count = var.deploy_ec2 ? 1 : 0

  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.lab_instance.id]

  # No key pair — we don't actually need to SSH in for this project
  # This saves the complexity of managing key pairs
  # If you want SSH access later, add: key_name = aws_key_pair.lab.key_name

  metadata_options {
    http_tokens   = "required" # IMDSv2 only (security best practice)
    http_endpoint = "enabled"
  }

  root_block_device {
    volume_size = 30 # Amazon Linux 2023 minimum requirement
    volume_type = "gp3"
    encrypted   = true
  }

  tags = { Name = "${local.name_prefix}-instance" }
}


# =============================================================================
# IAM USERS — Three privilege levels for attack simulation
# =============================================================================
# Detection rules supported:
#   - CreateAccessKey for another user (T1098.001)
#   - AttachUserPolicy privilege escalation (T1098)
#   - Console login without MFA (T1078)
#   - Root account usage detection (T1078.004)
#
# COST: $0 — IAM is always free
# =============================================================================

# --- lab-admin: Full admin access (simulates compromised admin) ---
resource "aws_iam_user" "lab_admin" {
  name = "${local.name_prefix}-lab-admin"
  tags = { Role = "admin", Purpose = "Attack simulation - admin-level operations" }
}

resource "aws_iam_user_policy_attachment" "lab_admin" {
  user       = aws_iam_user.lab_admin.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess"
}

# --- lab-analyst: Read-only + specific S3/CloudWatch permissions ---
resource "aws_iam_user" "lab_analyst" {
  name = "${local.name_prefix}-lab-analyst"
  tags = { Role = "analyst", Purpose = "Attack simulation - analyst-level target" }
}

resource "aws_iam_user_policy_attachment" "lab_analyst_readonly" {
  user       = aws_iam_user.lab_analyst.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_user_policy" "lab_analyst_extras" {
  name = "${local.name_prefix}-analyst-s3-cw"
  user = aws_iam_user.lab_analyst.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3LabBucketAccess"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.secure.arn,
          "${aws_s3_bucket.secure.arn}/*"
        ]
      },
      {
        Sid    = "CloudWatchLogsAccess"
        Effect = "Allow"
        Action = ["logs:GetLogEvents", "logs:FilterLogEvents", "logs:DescribeLogStreams"]
        Resource = "*"
      }
    ]
  })
}

# --- lab-attacker: Minimal permissions (just enough to authenticate) ---
# This user simulates an attacker with initial low-privilege access
resource "aws_iam_user" "lab_attacker" {
  name = "${local.name_prefix}-lab-attacker"
  tags = { Role = "attacker", Purpose = "Attack simulation - low-privilege starting point" }
}

resource "aws_iam_user_policy" "lab_attacker_minimal" {
  name = "${local.name_prefix}-attacker-minimal"
  user = aws_iam_user.lab_attacker.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowSelfServiceOnly"
        Effect   = "Allow"
        Action   = [
          "sts:GetCallerIdentity",
          "iam:GetUser",
          "iam:ListUserTags"
        ]
        Resource = "*"
      }
    ]
  })
}


# =============================================================================
# S3 BUCKETS — One secure, one intentionally misconfigured
# =============================================================================
# Detection rules supported:
#   - PutBucketPolicy with Principal:* (T1530 — public bucket detection)
#   - S3 bucket encryption enforcement monitoring
#   - Data event logging for S3 object access (if enabled)
#
# COST: ~$0.023/GB/month for storage. Lab will use <100MB = essentially $0
# =============================================================================

# Random suffix for globally unique bucket names
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# --- Secure Bucket: private, encrypted, versioned (the "right way") ---
resource "aws_s3_bucket" "secure" {
  bucket = "${local.name_prefix}-secure-${random_id.bucket_suffix.hex}"

  tags = { Name = "${local.name_prefix}-secure-bucket", SecurityPosture = "hardened" }
}

resource "aws_s3_bucket_versioning" "secure" {
  bucket = aws_s3_bucket.secure.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- Misconfigured Bucket: no encryption, public access possible ---
# This bucket is INTENTIONALLY insecure for detection testing.
# Detection rule: s3-bucket-made-public will fire when we add a public policy.
resource "aws_s3_bucket" "misconfigured" {
  bucket = "${local.name_prefix}-misconfig-${random_id.bucket_suffix.hex}"

  tags = { Name = "${local.name_prefix}-misconfigured-bucket", SecurityPosture = "intentionally-vulnerable" }
}

# Public access block is DISABLED on this bucket so we can test public policy detections
resource "aws_s3_bucket_public_access_block" "misconfigured" {
  bucket                  = aws_s3_bucket.misconfigured.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}


# =============================================================================
# CLOUDTRAIL — The core data source for all detections
# =============================================================================
# Detection rules supported:
#   - ALL detection rules consume CloudTrail as their primary data source
#   - StopLogging / DeleteTrail tampering detection (T1562.008)
#
# COST: First management event trail per region = FREE
#       S3 data events = $0.10 per 100K events (disabled by default)
#       CloudTrail log S3 storage = ~$0.023/GB (minimal for a lab)
# =============================================================================

# --- Dedicated S3 bucket for CloudTrail log delivery ---
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${local.name_prefix}-cloudtrail-${random_id.bucket_suffix.hex}"

  tags = { Name = "${local.name_prefix}-cloudtrail-logs" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudTrail requires a specific bucket policy to deliver logs
resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.name_prefix}-trail"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.name_prefix}-trail"
          }
        }
      }
    ]
  })
}

# --- The CloudTrail trail itself ---
resource "aws_cloudtrail" "lab" {
  name                       = "${local.name_prefix}-trail"
  s3_bucket_name             = aws_s3_bucket.cloudtrail_logs.id
  is_multi_region_trail      = false          # Single region to reduce costs
  enable_log_file_validation = true           # Tamper detection on log files
  include_global_service_events = true        # Captures IAM events (global)

  # S3 data events (disabled by default to save money)
  # Enable with: enable_s3_data_events = true
  dynamic "event_selector" {
    for_each = var.enable_s3_data_events ? [1] : []
    content {
      read_write_type           = "All"
      include_management_events = true

      data_resource {
        type   = "AWS::S3::Object"
        values = ["arn:${data.aws_partition.current.partition}:s3:::"]
      }
    }
  }

  # Management events only (default — free)
  dynamic "event_selector" {
    for_each = var.enable_s3_data_events ? [] : [1]
    content {
      read_write_type           = "All"
      include_management_events = true
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]

  tags = { Name = "${local.name_prefix}-trail" }
}


# =============================================================================
# S3 LIFECYCLE — Auto-delete old logs to minimize storage costs
# =============================================================================

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 7 # Auto-delete CloudTrail logs after 7 days (lab doesn't need long retention)
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "misconfigured" {
  bucket = aws_s3_bucket.misconfigured.id

  rule {
    id     = "expire-test-data"
    status = "Enabled"

    filter {}

    expiration {
      days = 1 # Clean up test data daily
    }
  }
}
