<#
.SYNOPSIS
    Master Attack Simulation Runner — Cloud Detection Engineering Lab

.DESCRIPTION
    Runs all 7 attack simulations in sequence with 60-second pauses between each
    to create distinct time windows in CloudTrail logs. Each simulation generates
    specific CloudTrail events that the detection rules are designed to catch.

    PREREQUISITES:
      - AWS CLI configured with profiles: lab-admin, lab-attacker
      - Lab environment deployed via Terraform (terraform apply)
      - CloudTrail actively logging

    SETUP (run once before first use):
      aws configure --profile lab-admin
      aws configure --profile lab-attacker

.PARAMETER SkipPause
    Skip the 60-second pauses between simulations (for testing script logic only).

.EXAMPLE
    .\run-all-simulations.ps1
    .\run-all-simulations.ps1 -SkipPause

.NOTES
    All simulations use lab IAM users, NOT your security-admin account.
    Run cleanup.ps1 after simulations to revert changes.
#>

[CmdletBinding()]
param(
    [switch]$SkipPause
)

$ErrorActionPreference = "Continue"
$PauseSeconds = if ($SkipPause) { 2 } else { 60 }

function Write-SimHeader {
    param([int]$Number, [string]$Name, [string]$MitreId)
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "  SIMULATION $Number: $Name" -ForegroundColor Cyan
    Write-Host "  MITRE ATT&CK: $MitreId" -ForegroundColor DarkCyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Wait-Between {
    param([int]$Seconds)
    Write-Host "  Waiting $Seconds seconds for CloudTrail to separate events..." -ForegroundColor DarkGray
    Start-Sleep -Seconds $Seconds
}

# Get Terraform outputs for resource names
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "  ║   Cloud Detection Engineering — Attack Simulations      ║" -ForegroundColor Yellow
Write-Host "  ║   Running 7 simulations against lab environment         ║" -ForegroundColor Yellow
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
Write-Host ""

# Verify AWS profiles exist
Write-Host "  Verifying AWS CLI profiles..." -ForegroundColor Gray
try {
    $adminId = aws sts get-caller-identity --profile lab-admin --query "Arn" --output text 2>&1
    if ($LASTEXITCODE -ne 0) { throw "lab-admin profile not configured" }
    Write-Host "  [OK] lab-admin: $adminId" -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] lab-admin profile not configured. Run: aws configure --profile lab-admin" -ForegroundColor Red
    exit 1
}

try {
    $attackerId = aws sts get-caller-identity --profile lab-attacker --query "Arn" --output text 2>&1
    if ($LASTEXITCODE -ne 0) { throw "lab-attacker profile not configured" }
    Write-Host "  [OK] lab-attacker: $attackerId" -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] lab-attacker profile not configured. Run: aws configure --profile lab-attacker" -ForegroundColor Red
    exit 1
}

# Read resource names from terraform output (or use defaults)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$infraDir = Join-Path (Split-Path -Parent $scriptDir) "infrastructure"

Write-Host ""
Write-Host "  Reading resource names from Terraform..." -ForegroundColor Gray

Push-Location $infraDir
$labAdminName = (terraform output -raw lab_admin_name 2>$null)
$labAnalystName = (terraform output -raw lab_analyst_name 2>$null)
$labAttackerName = (terraform output -raw lab_attacker_name 2>$null)
$secureBucket = (terraform output -raw secure_bucket_name 2>$null)
$misconfigBucket = (terraform output -raw misconfigured_bucket_name 2>$null)
$trailName = (terraform output -raw cloudtrail_trail_name 2>$null)
$sgId = (terraform output -raw security_group_id 2>$null)
Pop-Location

if (-not $labAdminName) {
    Write-Host "  [WARN] Could not read Terraform outputs. Using defaults." -ForegroundColor Yellow
    $labAdminName = "cloud-detection-engineering-lab-lab-admin"
    $labAnalystName = "cloud-detection-engineering-lab-lab-analyst"
    $labAttackerName = "cloud-detection-engineering-lab-lab-attacker"
    $trailName = "cloud-detection-engineering-lab-trail"
}

Write-Host "  Admin user:    $labAdminName" -ForegroundColor DarkGray
Write-Host "  Analyst user:  $labAnalystName" -ForegroundColor DarkGray
Write-Host "  Attacker user: $labAttackerName" -ForegroundColor DarkGray
Write-Host "  Trail name:    $trailName" -ForegroundColor DarkGray
Write-Host "  Security Group: $sgId" -ForegroundColor DarkGray
Write-Host ""

$startTime = Get-Date
Write-Host "  Started at: $($startTime.ToString('yyyy-MM-dd HH:mm:ss UTC'))" -ForegroundColor Gray
Write-Host ""

# ═══════════════════════════════════════════════════════════════
# SIMULATION 1: IAM Key Creation for Another User (T1098.001)
# ═══════════════════════════════════════════════════════════════
Write-SimHeader -Number 1 -Name "IAM Key Creation for Another User" -MitreId "T1098.001"
Write-Host "  Attack: lab-admin creates an access key for lab-analyst" -ForegroundColor White
Write-Host "  This simulates an attacker creating persistence via a new credential." -ForegroundColor Gray
Write-Host ""

$keyOutput = aws iam create-access-key --user-name $labAnalystName --profile lab-admin --output json 2>&1
if ($LASTEXITCODE -eq 0) {
    $keyData = $keyOutput | ConvertFrom-Json
    $script:SimulatedKeyId = $keyData.AccessKey.AccessKeyId
    Write-Host "  [SUCCESS] Created access key: $($script:SimulatedKeyId)" -ForegroundColor Green
    Write-Host "  CloudTrail event: CreateAccessKey (iam.amazonaws.com)" -ForegroundColor DarkGray
} else {
    Write-Host "  [FAILED] $keyOutput" -ForegroundColor Red
}

Wait-Between -Seconds $PauseSeconds

# ═══════════════════════════════════════════════════════════════
# SIMULATION 2: S3 Bucket Policy Change to Public (T1530)
# ═══════════════════════════════════════════════════════════════
Write-SimHeader -Number 2 -Name "S3 Bucket Policy Change to Public" -MitreId "T1530"
Write-Host "  Attack: lab-admin applies a public-read policy to the misconfigured bucket" -ForegroundColor White
Write-Host "  This simulates data exfiltration preparation." -ForegroundColor Gray
Write-Host ""

if ($misconfigBucket) {
    $publicPolicy = @{
        Version = "2012-10-17"
        Statement = @(
            @{
                Sid = "PublicRead"
                Effect = "Allow"
                Principal = "*"
                Action = "s3:GetObject"
                Resource = "arn:aws:s3:::$misconfigBucket/*"
            }
        )
    } | ConvertTo-Json -Depth 5 -Compress

    aws s3api put-bucket-policy --bucket $misconfigBucket --policy $publicPolicy --profile lab-admin 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [SUCCESS] Public policy applied to: $misconfigBucket" -ForegroundColor Green
        Write-Host "  CloudTrail event: PutBucketPolicy (s3.amazonaws.com)" -ForegroundColor DarkGray
    } else {
        Write-Host "  [FAILED] Could not apply bucket policy" -ForegroundColor Red
    }
} else {
    Write-Host "  [SKIP] Misconfigured bucket name not available" -ForegroundColor Yellow
}

Wait-Between -Seconds $PauseSeconds

# ═══════════════════════════════════════════════════════════════
# SIMULATION 3: Privilege Escalation via Policy Attachment (T1098)
# ═══════════════════════════════════════════════════════════════
Write-SimHeader -Number 3 -Name "Privilege Escalation — Admin Policy Attachment" -MitreId "T1098"
Write-Host "  Attack: lab-admin attaches AdministratorAccess to lab-attacker" -ForegroundColor White
Write-Host "  This simulates privilege escalation from low-priv to admin." -ForegroundColor Gray
Write-Host ""

aws iam attach-user-policy --user-name $labAttackerName --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess" --profile lab-admin 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [SUCCESS] AdministratorAccess attached to $labAttackerName" -ForegroundColor Green
    Write-Host "  CloudTrail event: AttachUserPolicy (iam.amazonaws.com)" -ForegroundColor DarkGray
} else {
    Write-Host "  [FAILED] Could not attach policy" -ForegroundColor Red
}

Wait-Between -Seconds $PauseSeconds

# ═══════════════════════════════════════════════════════════════
# SIMULATION 4: CloudTrail Tampering Attempt (T1562.008)
# ═══════════════════════════════════════════════════════════════
Write-SimHeader -Number 4 -Name "CloudTrail Tampering — Stop Logging" -MitreId "T1562.008"
Write-Host "  Attack: lab-attacker attempts to stop CloudTrail logging" -ForegroundColor White
Write-Host "  This simulates defense evasion. The attempt may fail (expected)." -ForegroundColor Gray
Write-Host ""

$stopResult = aws cloudtrail stop-logging --name $trailName --profile lab-attacker 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [SUCCESS] CloudTrail logging stopped (will re-enable in cleanup)" -ForegroundColor Yellow
    Write-Host "  CloudTrail event: StopLogging (cloudtrail.amazonaws.com)" -ForegroundColor DarkGray
} else {
    Write-Host "  [EXPECTED] Stop attempt denied or errored: $stopResult" -ForegroundColor Cyan
    Write-Host "  The ATTEMPT still generates a CloudTrail event (that's what we detect)" -ForegroundColor DarkGray
}

Wait-Between -Seconds $PauseSeconds

# ═══════════════════════════════════════════════════════════════
# SIMULATION 5: Security Group Opened to 0.0.0.0/0 (T1562)
# ═══════════════════════════════════════════════════════════════
Write-SimHeader -Number 5 -Name "Security Group Opened to World" -MitreId "T1562"
Write-Host "  Attack: lab-admin opens SSH (port 22) to 0.0.0.0/0" -ForegroundColor White
Write-Host "  This simulates an attacker opening network access for persistence." -ForegroundColor Gray
Write-Host ""

if ($sgId) {
    aws ec2 authorize-security-group-ingress --group-id $sgId --protocol tcp --port 22 --cidr "0.0.0.0/0" --profile lab-admin 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [SUCCESS] Security group $sgId opened to 0.0.0.0/0 on port 22" -ForegroundColor Green
        Write-Host "  CloudTrail event: AuthorizeSecurityGroupIngress (ec2.amazonaws.com)" -ForegroundColor DarkGray
    } else {
        Write-Host "  [INFO] Rule may already exist or SG not found" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [SKIP] Security group ID not available" -ForegroundColor Yellow
}

Wait-Between -Seconds $PauseSeconds

# ═══════════════════════════════════════════════════════════════
# SIMULATION 6: API Activity from Unusual Region (T1078)
# ═══════════════════════════════════════════════════════════════
Write-SimHeader -Number 6 -Name "API Activity from Unusual Region" -MitreId "T1078"
Write-Host "  Attack: lab-admin makes S3 API calls targeting eu-west-1" -ForegroundColor White
Write-Host "  This simulates lateral movement or access from an unexpected geography." -ForegroundColor Gray
Write-Host ""

# List buckets from an unusual region (generates CloudTrail event with different awsRegion)
aws s3api list-buckets --region eu-west-1 --profile lab-admin 2>&1 | Out-Null
Write-Host "  [SUCCESS] S3 ListBuckets called in eu-west-1" -ForegroundColor Green

aws ec2 describe-instances --region eu-west-1 --profile lab-admin 2>&1 | Out-Null
Write-Host "  [SUCCESS] EC2 DescribeInstances called in eu-west-1" -ForegroundColor Green

aws ec2 describe-instances --region ap-southeast-1 --profile lab-admin 2>&1 | Out-Null
Write-Host "  [SUCCESS] EC2 DescribeInstances called in ap-southeast-1" -ForegroundColor Green

Write-Host "  CloudTrail events: various with awsRegion = eu-west-1, ap-southeast-1" -ForegroundColor DarkGray

Wait-Between -Seconds $PauseSeconds

# ═══════════════════════════════════════════════════════════════
# SIMULATION 7: Reconnaissance — Account Enumeration (T1087)
# ═══════════════════════════════════════════════════════════════
Write-SimHeader -Number 7 -Name "IAM Reconnaissance — Account Enumeration" -MitreId "T1087"
Write-Host "  Attack: lab-attacker enumerates IAM users, policies, and roles" -ForegroundColor White
Write-Host "  This simulates post-compromise reconnaissance." -ForegroundColor Gray
Write-Host ""

aws iam list-users --profile lab-attacker 2>&1 | Out-Null
Write-Host "  [*] Listed IAM users" -ForegroundColor DarkGray

aws iam list-roles --profile lab-attacker 2>&1 | Out-Null
Write-Host "  [*] Listed IAM roles" -ForegroundColor DarkGray

aws iam list-policies --scope Local --profile lab-attacker 2>&1 | Out-Null
Write-Host "  [*] Listed customer-managed policies" -ForegroundColor DarkGray

aws iam get-account-authorization-details --profile lab-attacker 2>&1 | Out-Null
Write-Host "  [*] Retrieved account authorization details" -ForegroundColor DarkGray

Write-Host "  CloudTrail events: ListUsers, ListRoles, ListPolicies, GetAccountAuthorizationDetails" -ForegroundColor DarkGray

# ═══════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════
$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Green
Write-Host "  ALL 7 SIMULATIONS COMPLETE" -ForegroundColor Green
Write-Host "  ============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Duration: $([math]::Round($duration.TotalMinutes, 1)) minutes" -ForegroundColor Gray
Write-Host "  CloudTrail delivery delay: 5-15 minutes" -ForegroundColor Gray
Write-Host "  Check Kibana in ~15 minutes for events." -ForegroundColor Gray
Write-Host ""
Write-Host "  IMPORTANT: Run cleanup.ps1 to revert all changes." -ForegroundColor Yellow
Write-Host ""
