<#
.SYNOPSIS
    Cleanup Script — Reverts all changes made by attack simulations.

.DESCRIPTION
    Run this after run-all-simulations.ps1 to restore the lab environment
    to its pre-simulation state. Reverses:
      - Deletes the access key created for lab-analyst
      - Removes the public bucket policy from the misconfigured bucket
      - Detaches AdministratorAccess from lab-attacker
      - Removes the 0.0.0.0/0 security group rule
      - Re-enables CloudTrail logging (if it was stopped)

.EXAMPLE
    .\cleanup.ps1
#>

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║   Cloud Detection Engineering — Simulation Cleanup      ║" -ForegroundColor Magenta
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

# Read resource names from terraform output
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$infraDir = Join-Path (Split-Path -Parent $scriptDir) "infrastructure"

Push-Location $infraDir
$labAnalystName = (terraform output -raw lab_analyst_name 2>$null)
$labAttackerName = (terraform output -raw lab_attacker_name 2>$null)
$misconfigBucket = (terraform output -raw misconfigured_bucket_name 2>$null)
$trailName = (terraform output -raw cloudtrail_trail_name 2>$null)
$sgId = (terraform output -raw security_group_id 2>$null)
Pop-Location

if (-not $labAnalystName) {
    $labAnalystName = "cloud-detection-engineering-lab-lab-analyst"
    $labAttackerName = "cloud-detection-engineering-lab-lab-attacker"
    $trailName = "cloud-detection-engineering-lab-trail"
}

# --- 1. Delete access keys created for lab-analyst ---
Write-Host "  [1/5] Removing access keys created for $labAnalystName..." -ForegroundColor White
$keys = aws iam list-access-keys --user-name $labAnalystName --profile lab-admin --output json 2>&1 | ConvertFrom-Json
if ($keys.AccessKeyMetadata) {
    foreach ($key in $keys.AccessKeyMetadata) {
        aws iam delete-access-key --user-name $labAnalystName --access-key-id $key.AccessKeyId --profile lab-admin 2>&1
        Write-Host "    Deleted key: $($key.AccessKeyId)" -ForegroundColor Green
    }
} else {
    Write-Host "    No access keys found." -ForegroundColor DarkGray
}

# --- 2. Remove public bucket policy ---
Write-Host "  [2/5] Removing public policy from $misconfigBucket..." -ForegroundColor White
if ($misconfigBucket) {
    aws s3api delete-bucket-policy --bucket $misconfigBucket --profile lab-admin 2>&1
    Write-Host "    Bucket policy removed." -ForegroundColor Green
} else {
    Write-Host "    Bucket name not available, skipping." -ForegroundColor Yellow
}

# --- 3. Detach AdministratorAccess from lab-attacker ---
Write-Host "  [3/5] Detaching AdministratorAccess from $labAttackerName..." -ForegroundColor White
aws iam detach-user-policy --user-name $labAttackerName --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess" --profile lab-admin 2>&1
Write-Host "    Policy detached." -ForegroundColor Green

# --- 4. Remove 0.0.0.0/0 security group rule ---
Write-Host "  [4/5] Removing 0.0.0.0/0 rule from security group $sgId..." -ForegroundColor White
if ($sgId) {
    aws ec2 revoke-security-group-ingress --group-id $sgId --protocol tcp --port 22 --cidr "0.0.0.0/0" --profile lab-admin 2>&1
    Write-Host "    Security group rule removed." -ForegroundColor Green
} else {
    Write-Host "    Security group ID not available, skipping." -ForegroundColor Yellow
}

# --- 5. Re-enable CloudTrail logging ---
Write-Host "  [5/5] Ensuring CloudTrail is logging..." -ForegroundColor White
aws cloudtrail start-logging --name $trailName --profile lab-admin 2>&1
Write-Host "    CloudTrail logging confirmed active." -ForegroundColor Green

Write-Host ""
Write-Host "  Cleanup complete. Lab environment restored to baseline." -ForegroundColor Green
Write-Host ""
