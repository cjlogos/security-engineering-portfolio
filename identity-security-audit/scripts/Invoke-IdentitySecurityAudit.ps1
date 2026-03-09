#Requires -Version 5.1
<#
.SYNOPSIS
    Identity Security Audit Tool
    Evaluates identity security posture across Active Directory and Microsoft Entra environments.

.DESCRIPTION
    Performs comprehensive security checks including:
    - Privileged account exposure (Global Admins, Domain Admins, service accounts)
    - Authentication security (MFA enforcement, legacy auth, Conditional Access, CA exclusions)
    - Identity hygiene (stale users, dormant service accounts, expired app credentials)

    Outputs results to the console and generates an HTML report.

.PARAMETER OutputPath
    Directory for the HTML report. Defaults to current directory.

.PARAMETER StaleThresholdDays
    Number of days of inactivity before a user is flagged as stale. Default: 90.

.PARAMETER DormantServiceAccountDays
    Number of days of inactivity before a service account is flagged as dormant. Default: 60.

.PARAMETER SkipAD
    Skip on-premises Active Directory checks.

.PARAMETER SkipEntra
    Skip Microsoft Entra ID (cloud) checks.

.EXAMPLE
    .\Invoke-IdentitySecurityAudit.ps1
    Run full audit against both AD and Entra with default settings.

.EXAMPLE
    .\Invoke-IdentitySecurityAudit.ps1 -SkipAD -StaleThresholdDays 120
    Run Entra-only audit with a 120-day stale threshold.

.EXAMPLE
    .\Invoke-IdentitySecurityAudit.ps1 -OutputPath "C:\AuditReports"
    Run full audit and save the HTML report to a custom directory.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,
    [int]$StaleThresholdDays = 90,
    [int]$DormantServiceAccountDays = 60,
    [switch]$SkipAD,
    [switch]$SkipEntra
)

# ============================================================================
# CONFIGURATION & GLOBALS
# ============================================================================

$ErrorActionPreference = "Continue"
$script:AuditTimestamp = Get-Date
$script:Findings = @()
$script:SummaryStats = @{
    TotalChecks    = 0
    Critical       = 0
    High           = 0
    Medium         = 0
    Low            = 0
    Informational  = 0
}

# Severity levels and their display properties
$script:SeverityColors = @{
    Critical      = "Red"
    High          = "DarkYellow"
    Medium        = "Yellow"
    Low           = "Cyan"
    Informational = "Gray"
}

$script:SeverityHtmlColors = @{
    Critical      = "#dc2626"
    High          = "#ea580c"
    Medium        = "#ca8a04"
    Low           = "#0891b2"
    Informational = "#6b7280"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-AuditBanner {
    $banner = @"

    ╔══════════════════════════════════════════════════════════════╗
    ║              IDENTITY SECURITY AUDIT TOOL                   ║
    ║          Active Directory & Microsoft Entra ID              ║
    ╚══════════════════════════════════════════════════════════════╝

    Timestamp : $($script:AuditTimestamp.ToString("yyyy-MM-dd HH:mm:ss"))
    Host      : $env:COMPUTERNAME
    User      : $env:USERDOMAIN\$env:USERNAME

"@
    Write-Host $banner -ForegroundColor Cyan
}

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$CheckName,
        [Parameter(Mandatory)][ValidateSet("Critical","High","Medium","Low","Informational")]
        [string]$Severity,
        [Parameter(Mandatory)][string]$Description,
        [string]$Recommendation = "",
        [object[]]$AffectedObjects = @(),
        [string]$Source = "Unknown"
    )

    $script:SummaryStats.TotalChecks++
    $script:SummaryStats[$Severity]++

    $finding = [PSCustomObject]@{
        Category         = $Category
        CheckName        = $CheckName
        Severity         = $Severity
        Description      = $Description
        Recommendation   = $Recommendation
        AffectedObjects  = $AffectedObjects
        AffectedCount    = $AffectedObjects.Count
        Source           = $Source
        Timestamp        = Get-Date
    }

    $script:Findings += $finding

    # Console output
    $color = $script:SeverityColors[$Severity]
    Write-Host "  [$Severity] " -ForegroundColor $color -NoNewline
    Write-Host "$CheckName" -ForegroundColor White
    Write-Host "    $Description" -ForegroundColor Gray

    if ($AffectedObjects.Count -gt 0) {
        Write-Host "    Affected: $($AffectedObjects.Count) object(s)" -ForegroundColor Gray
        $AffectedObjects | Select-Object -First 5 | ForEach-Object {
            Write-Host "      - $_" -ForegroundColor DarkGray
        }
        if ($AffectedObjects.Count -gt 5) {
            Write-Host "      ... and $($AffectedObjects.Count - 5) more" -ForegroundColor DarkGray
        }
    }
    Write-Host ""
}

function Write-SectionHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host ""
}

function Test-ModuleAvailable {
    param([string]$ModuleName)
    $module = Get-Module -ListAvailable -Name $ModuleName -ErrorAction SilentlyContinue
    return ($null -ne $module)
}

# ============================================================================
# ACTIVE DIRECTORY CHECKS
# ============================================================================

function Invoke-ADPrivilegedAccountChecks {
    Write-SectionHeader "Active Directory — Privileged Accounts"

    # --- Domain Admins ---
    try {
        $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive -ErrorAction Stop
        $domainAdminCount = ($domainAdmins | Measure-Object).Count

        if ($domainAdminCount -gt 5) {
            Add-Finding -Category "Privileged Accounts" -CheckName "Excessive Domain Admins" `
                -Severity "Critical" `
                -Description "Found $domainAdminCount Domain Admin accounts. Best practice recommends no more than 5." `
                -Recommendation "Review and remove unnecessary Domain Admin memberships. Use least-privilege delegation." `
                -AffectedObjects ($domainAdmins | ForEach-Object { $_.SamAccountName }) `
                -Source "Active Directory"
        }
        elseif ($domainAdminCount -gt 2) {
            Add-Finding -Category "Privileged Accounts" -CheckName "Domain Admin Membership" `
                -Severity "Medium" `
                -Description "Found $domainAdminCount Domain Admin accounts." `
                -Recommendation "Ensure all Domain Admin accounts are justified and documented." `
                -AffectedObjects ($domainAdmins | ForEach-Object { $_.SamAccountName }) `
                -Source "Active Directory"
        }
        else {
            Add-Finding -Category "Privileged Accounts" -CheckName "Domain Admin Membership" `
                -Severity "Informational" `
                -Description "Domain Admin count ($domainAdminCount) is within acceptable range." `
                -Source "Active Directory"
        }
    }
    catch {
        Write-Host "    [!] Could not query Domain Admins: $($_.Exception.Message)" -ForegroundColor Red
    }

    # --- Enterprise Admins ---
    try {
        $enterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins" -Recursive -ErrorAction Stop
        $eaCount = ($enterpriseAdmins | Measure-Object).Count

        if ($eaCount -gt 0) {
            Add-Finding -Category "Privileged Accounts" -CheckName "Enterprise Admin Exposure" `
                -Severity "High" `
                -Description "Found $eaCount Enterprise Admin account(s). This group should ideally be empty outside of forest-level changes." `
                -Recommendation "Remove permanent Enterprise Admin memberships. Use just-in-time elevation." `
                -AffectedObjects ($enterpriseAdmins | ForEach-Object { $_.SamAccountName }) `
                -Source "Active Directory"
        }
        else {
            Add-Finding -Category "Privileged Accounts" -CheckName "Enterprise Admin Exposure" `
                -Severity "Informational" `
                -Description "Enterprise Admins group is empty. This is the recommended state." `
                -Source "Active Directory"
        }
    }
    catch {
        Write-Host "    [!] Could not query Enterprise Admins: $($_.Exception.Message)" -ForegroundColor Red
    }

    # --- Schema Admins ---
    try {
        $schemaAdmins = Get-ADGroupMember -Identity "Schema Admins" -Recursive -ErrorAction Stop
        $saCount = ($schemaAdmins | Measure-Object).Count

        if ($saCount -gt 0) {
            Add-Finding -Category "Privileged Accounts" -CheckName "Schema Admin Exposure" `
                -Severity "High" `
                -Description "Found $saCount Schema Admin account(s). This group should be empty unless schema changes are in progress." `
                -Recommendation "Remove all Schema Admin memberships when not actively performing schema modifications." `
                -AffectedObjects ($schemaAdmins | ForEach-Object { $_.SamAccountName }) `
                -Source "Active Directory"
        }
    }
    catch {
        Write-Host "    [!] Could not query Schema Admins: $($_.Exception.Message)" -ForegroundColor Red
    }

    # --- Service Account Permissions ---
    try {
        $serviceAccounts = Get-ADUser -Filter {
            (ServicePrincipalName -like "*") -or
            (Name -like "svc_*") -or
            (Name -like "svc-*") -or
            (Name -like "service_*") -or
            (Name -like "sa_*")
        } -Properties ServicePrincipalName, MemberOf, PasswordLastSet, Enabled -ErrorAction Stop

        $privilegedSvcAccounts = @()
        $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")

        foreach ($svc in $serviceAccounts) {
            $memberOfNames = $svc.MemberOf | ForEach-Object {
                try { (Get-ADGroup $_).Name } catch { $_ }
            }
            $hasPriv = $memberOfNames | Where-Object { $_ -in $privilegedGroups }
            if ($hasPriv) {
                $privilegedSvcAccounts += $svc.SamAccountName
            }
        }

        if ($privilegedSvcAccounts.Count -gt 0) {
            Add-Finding -Category "Privileged Accounts" -CheckName "Over-Privileged Service Accounts" `
                -Severity "Critical" `
                -Description "Found $($privilegedSvcAccounts.Count) service account(s) with privileged group membership." `
                -Recommendation "Remove service accounts from privileged groups. Use Group Managed Service Accounts (gMSA) with least-privilege permissions." `
                -AffectedObjects $privilegedSvcAccounts `
                -Source "Active Directory"
        }
        else {
            Add-Finding -Category "Privileged Accounts" -CheckName "Service Account Permissions" `
                -Severity "Informational" `
                -Description "No service accounts found in privileged groups." `
                -Source "Active Directory"
        }
    }
    catch {
        Write-Host "    [!] Could not query service accounts: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-ADAuthenticationChecks {
    Write-SectionHeader "Active Directory — Authentication Security"

    # --- Password Policy ---
    try {
        $defaultPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop

        if ($defaultPolicy.MinPasswordLength -lt 14) {
            Add-Finding -Category "Authentication Security" -CheckName "Weak Minimum Password Length" `
                -Severity "High" `
                -Description "Minimum password length is $($defaultPolicy.MinPasswordLength). Recommended minimum is 14 characters." `
                -Recommendation "Increase minimum password length to 14+ characters. Consider passphrases." `
                -Source "Active Directory"
        }

        if (-not $defaultPolicy.ComplexityEnabled) {
            Add-Finding -Category "Authentication Security" -CheckName "Password Complexity Disabled" `
                -Severity "High" `
                -Description "Password complexity requirements are not enforced." `
                -Recommendation "Enable password complexity or implement a third-party password filter." `
                -Source "Active Directory"
        }

        if ($defaultPolicy.LockoutThreshold -eq 0) {
            Add-Finding -Category "Authentication Security" -CheckName "No Account Lockout Policy" `
                -Severity "High" `
                -Description "Account lockout threshold is not configured. Brute-force attacks are not mitigated." `
                -Recommendation "Set account lockout threshold to 10-20 attempts with a 30-minute lockout duration." `
                -Source "Active Directory"
        }

        if ($defaultPolicy.ReversibleEncryptionEnabled) {
            Add-Finding -Category "Authentication Security" -CheckName "Reversible Encryption Enabled" `
                -Severity "Critical" `
                -Description "Reversible encryption is enabled for password storage. Passwords can be recovered in plaintext." `
                -Recommendation "Disable reversible encryption immediately unless explicitly required by an application." `
                -Source "Active Directory"
        }
    }
    catch {
        Write-Host "    [!] Could not query password policy: $($_.Exception.Message)" -ForegroundColor Red
    }

    # --- Users with Password Never Expires ---
    try {
        $neverExpires = Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } `
            -Properties PasswordNeverExpires -ErrorAction Stop
        $neCount = ($neverExpires | Measure-Object).Count

        if ($neCount -gt 0) {
            Add-Finding -Category "Authentication Security" -CheckName "Password Never Expires" `
                -Severity "Medium" `
                -Description "Found $neCount enabled account(s) with 'Password Never Expires' set." `
                -Recommendation "Review and remediate. Use gMSA for service accounts. Enforce rotation for user accounts." `
                -AffectedObjects ($neverExpires | Select-Object -First 20 | ForEach-Object { $_.SamAccountName }) `
                -Source "Active Directory"
        }
    }
    catch {
        Write-Host "    [!] Could not query password-never-expires accounts: $($_.Exception.Message)" -ForegroundColor Red
    }

    # --- Legacy Protocols (NTLMv1) ---
    try {
        $lmPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
        if ($null -eq $lmPolicy -or $lmPolicy.LmCompatibilityLevel -lt 5) {
            $currentLevel = if ($null -eq $lmPolicy) { "Not Configured (default)" } else { $lmPolicy.LmCompatibilityLevel }
            Add-Finding -Category "Authentication Security" -CheckName "Legacy Authentication (NTLMv1)" `
                -Severity "High" `
                -Description "LAN Manager compatibility level is $currentLevel. NTLMv1 may be allowed, which is vulnerable to relay and cracking attacks." `
                -Recommendation "Set LmCompatibilityLevel to 5 (Send NTLMv2 response only, refuse LM & NTLM)." `
                -Source "Active Directory"
        }
    }
    catch {
        Write-Host "    [!] Could not check LM compatibility: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-ADIdentityHygieneChecks {
    Write-SectionHeader "Active Directory — Identity Hygiene"

    $staleDate = (Get-Date).AddDays(-$StaleThresholdDays)
    $dormantDate = (Get-Date).AddDays(-$DormantServiceAccountDays)

    # --- Stale User Accounts ---
    try {
        $staleUsers = Get-ADUser -Filter {
            Enabled -eq $true -and LastLogonTimestamp -lt $staleDate
        } -Properties LastLogonTimestamp, LastLogonDate, WhenCreated -ErrorAction Stop

        $staleCount = ($staleUsers | Measure-Object).Count

        if ($staleCount -gt 0) {
            $severity = if ($staleCount -gt 50) { "High" } elseif ($staleCount -gt 20) { "Medium" } else { "Low" }
            Add-Finding -Category "Identity Hygiene" -CheckName "Stale User Accounts" `
                -Severity $severity `
                -Description "Found $staleCount enabled user account(s) with no sign-in for $StaleThresholdDays+ days." `
                -Recommendation "Disable or delete stale accounts. Implement automated lifecycle management." `
                -AffectedObjects ($staleUsers | Select-Object -First 20 | ForEach-Object { $_.SamAccountName }) `
                -Source "Active Directory"
        }
        else {
            Add-Finding -Category "Identity Hygiene" -CheckName "Stale User Accounts" `
                -Severity "Informational" `
                -Description "No stale user accounts found (threshold: $StaleThresholdDays days)." `
                -Source "Active Directory"
        }
    }
    catch {
        Write-Host "    [!] Could not query stale users: $($_.Exception.Message)" -ForegroundColor Red
    }

    # --- Dormant Service Accounts ---
    try {
        $serviceAccounts = Get-ADUser -Filter {
            (ServicePrincipalName -like "*") -or
            (Name -like "svc_*") -or (Name -like "svc-*") -or
            (Name -like "service_*") -or (Name -like "sa_*")
        } -Properties LastLogonTimestamp, ServicePrincipalName, Enabled -ErrorAction Stop

        $dormantSvcAccounts = $serviceAccounts | Where-Object {
            $_.Enabled -eq $true -and
            ($null -eq $_.LastLogonTimestamp -or
             [DateTime]::FromFileTime($_.LastLogonTimestamp) -lt $dormantDate)
        }

        $dormantCount = ($dormantSvcAccounts | Measure-Object).Count

        if ($dormantCount -gt 0) {
            Add-Finding -Category "Identity Hygiene" -CheckName "Dormant Service Accounts" `
                -Severity "High" `
                -Description "Found $dormantCount enabled service account(s) with no activity for $DormantServiceAccountDays+ days." `
                -Recommendation "Disable dormant service accounts. Migrate to Group Managed Service Accounts (gMSA) where possible." `
                -AffectedObjects ($dormantSvcAccounts | ForEach-Object { $_.SamAccountName }) `
                -Source "Active Directory"
        }
    }
    catch {
        Write-Host "    [!] Could not query dormant service accounts: $($_.Exception.Message)" -ForegroundColor Red
    }

    # --- Disabled Accounts Still in Privileged Groups ---
    try {
        $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Server Operators")
        $disabledInPrivGroups = @()

        foreach ($group in $privilegedGroups) {
            try {
                $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue
                foreach ($member in $members) {
                    $user = Get-ADUser -Identity $member.SID -Properties Enabled -ErrorAction SilentlyContinue
                    if ($user -and -not $user.Enabled) {
                        $disabledInPrivGroups += "$($user.SamAccountName) (in $group)"
                    }
                }
            }
            catch { }
        }

        if ($disabledInPrivGroups.Count -gt 0) {
            Add-Finding -Category "Identity Hygiene" -CheckName "Disabled Accounts in Privileged Groups" `
                -Severity "Medium" `
                -Description "Found $($disabledInPrivGroups.Count) disabled account(s) still in privileged groups." `
                -Recommendation "Remove disabled accounts from all privileged groups immediately." `
                -AffectedObjects $disabledInPrivGroups `
                -Source "Active Directory"
        }
    }
    catch {
        Write-Host "    [!] Could not check disabled privileged accounts: $($_.Exception.Message)" -ForegroundColor Red
    }

}

# ============================================================================
# MICROSOFT ENTRA ID CHECKS
# ============================================================================

function Invoke-EntraPrivilegedAccountChecks {
    Write-SectionHeader "Microsoft Entra ID — Privileged Accounts"

    # --- Global Admins ---
    try {
        $globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" -ErrorAction Stop
        if ($globalAdminRole) {
            $globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -ErrorAction Stop
            $gaCount = ($globalAdmins | Measure-Object).Count

            if ($gaCount -gt 5) {
                Add-Finding -Category "Privileged Accounts" -CheckName "Excessive Global Admins" `
                    -Severity "Critical" `
                    -Description "Found $gaCount Global Administrator(s) in Entra ID. Microsoft recommends fewer than 5." `
                    -Recommendation "Reduce Global Admins to fewer than 5. Use least-privileged roles (e.g., User Admin, Exchange Admin)." `
                    -AffectedObjects ($globalAdmins | ForEach-Object { $_.AdditionalProperties.displayName }) `
                    -Source "Microsoft Entra ID"
            }
            elseif ($gaCount -gt 2) {
                Add-Finding -Category "Privileged Accounts" -CheckName "Global Admin Count" `
                    -Severity "Medium" `
                    -Description "Found $gaCount Global Administrator(s) in Entra ID." `
                    -Recommendation "Ensure each Global Admin assignment is justified. Use PIM for just-in-time access." `
                    -AffectedObjects ($globalAdmins | ForEach-Object { $_.AdditionalProperties.displayName }) `
                    -Source "Microsoft Entra ID"
            }
            else {
                Add-Finding -Category "Privileged Accounts" -CheckName "Global Admin Count" `
                    -Severity "Informational" `
                    -Description "Global Admin count ($gaCount) is within acceptable range." `
                    -Source "Microsoft Entra ID"
            }
        }
    }
    catch {
        Write-Host "    [!] Could not query Global Admins: $($_.Exception.Message)" -ForegroundColor Red
    }

    # --- Privileged Role Assignments (Permanent vs Eligible) ---
    try {
        $privilegedRoles = @(
            "Global Administrator", "Privileged Role Administrator",
            "Exchange Administrator", "SharePoint Administrator",
            "Security Administrator", "User Administrator",
            "Application Administrator", "Cloud Application Administrator"
        )

        $permanentAssignments = @()

        foreach ($roleName in $privilegedRoles) {
            try {
                $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
                if ($role) {
                    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction SilentlyContinue
                    foreach ($member in $members) {
                        $permanentAssignments += "$($member.AdditionalProperties.displayName) ($roleName)"
                    }
                }
            }
            catch { }
        }

        if ($permanentAssignments.Count -gt 10) {
            Add-Finding -Category "Privileged Accounts" -CheckName "Excessive Permanent Role Assignments" `
                -Severity "High" `
                -Description "Found $($permanentAssignments.Count) permanent privileged role assignments. Consider using PIM eligible assignments." `
                -Recommendation "Convert permanent assignments to PIM-eligible. Require justification and approval for activation." `
                -AffectedObjects ($permanentAssignments | Select-Object -First 20) `
                -Source "Microsoft Entra ID"
        }
    }
    catch {
        Write-Host "    [!] Could not query role assignments: $($_.Exception.Message)" -ForegroundColor Red
    }

    # --- Service Principals with High Permissions ---
    try {
        $appRegistrations = Get-MgApplication -All -ErrorAction Stop
        $highPermApps = @()

        foreach ($app in $appRegistrations) {
            $requiredAccess = $app.RequiredResourceAccess
            foreach ($resource in $requiredAccess) {
                $dangerousPermissions = $resource.ResourceAccess | Where-Object {
                    $_.Type -eq "Role"  # Application permissions (not delegated)
                }
                if ($dangerousPermissions.Count -gt 5) {
                    $highPermApps += "$($app.DisplayName) ($($dangerousPermissions.Count) app permissions)"
                }
            }
        }

        if ($highPermApps.Count -gt 0) {
            Add-Finding -Category "Privileged Accounts" -CheckName "Over-Permissioned App Registrations" `
                -Severity "High" `
                -Description "Found $($highPermApps.Count) app registration(s) with excessive application-level permissions." `
                -Recommendation "Review and reduce application permissions. Use delegated permissions where possible." `
                -AffectedObjects $highPermApps `
                -Source "Microsoft Entra ID"
        }
    }
    catch {
        Write-Host "    [!] Could not query app registrations: $($_.Exception.Message)" -ForegroundColor Red
    }

    # --- Expired or Expiring Client Secrets & Certificates ---
    try {
        $appRegistrations = Get-MgApplication -All -Property Id, DisplayName, AppId, PasswordCredentials, KeyCredentials -ErrorAction Stop
        $now = Get-Date
        $expiryWarningDays = 30
        $warningDate = $now.AddDays($expiryWarningDays)

        $expiredSecrets = @()
        $expiringSoonSecrets = @()

        foreach ($app in $appRegistrations) {
            # Check client secrets (password credentials)
            foreach ($secret in $app.PasswordCredentials) {
                if ($secret.EndDateTime -lt $now) {
                    $expiredSecrets += "$($app.DisplayName) — secret '$($secret.DisplayName)' expired $($secret.EndDateTime.ToString('yyyy-MM-dd'))"
                }
                elseif ($secret.EndDateTime -lt $warningDate) {
                    $expiringSoonSecrets += "$($app.DisplayName) — secret '$($secret.DisplayName)' expires $($secret.EndDateTime.ToString('yyyy-MM-dd'))"
                }
            }

            # Check certificates (key credentials)
            foreach ($cert in $app.KeyCredentials) {
                if ($cert.EndDateTime -lt $now) {
                    $expiredSecrets += "$($app.DisplayName) — certificate '$($cert.DisplayName)' expired $($cert.EndDateTime.ToString('yyyy-MM-dd'))"
                }
                elseif ($cert.EndDateTime -lt $warningDate) {
                    $expiringSoonSecrets += "$($app.DisplayName) — certificate '$($cert.DisplayName)' expires $($cert.EndDateTime.ToString('yyyy-MM-dd'))"
                }
            }
        }

        if ($expiredSecrets.Count -gt 0) {
            Add-Finding -Category "Identity Hygiene" -CheckName "Expired App Credentials" `
                -Severity "High" `
                -Description "Found $($expiredSecrets.Count) expired client secret(s) or certificate(s) on app registrations. Expired credentials indicate abandoned apps or poor lifecycle management." `
                -Recommendation "Remove expired credentials. Delete app registrations that are no longer in use. Establish a credential rotation policy." `
                -AffectedObjects ($expiredSecrets | Select-Object -First 20) `
                -Source "Microsoft Entra ID"
        }

        if ($expiringSoonSecrets.Count -gt 0) {
            Add-Finding -Category "Identity Hygiene" -CheckName "Expiring App Credentials (30 days)" `
                -Severity "Medium" `
                -Description "Found $($expiringSoonSecrets.Count) client secret(s) or certificate(s) expiring within $expiryWarningDays days." `
                -Recommendation "Rotate credentials before expiry to avoid service disruptions. Use managed identities where possible." `
                -AffectedObjects ($expiringSoonSecrets | Select-Object -First 20) `
                -Source "Microsoft Entra ID"
        }

        if ($expiredSecrets.Count -eq 0 -and $expiringSoonSecrets.Count -eq 0) {
            Add-Finding -Category "Identity Hygiene" -CheckName "App Credential Lifecycle" `
                -Severity "Informational" `
                -Description "No expired or soon-expiring app credentials found." `
                -Source "Microsoft Entra ID"
        }
    }
    catch {
        Write-Host "    [!] Could not check app credential expiry: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-EntraAuthenticationChecks {
    Write-SectionHeader "Microsoft Entra ID — Authentication Security"

    # --- MFA Registration Status ---
    try {
        $users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, UserType `
            -Filter "userType eq 'Member'" -ErrorAction Stop
        $noMfa = @()

        foreach ($user in $users) {
            try {
                $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
                $strongMethods = $authMethods | Where-Object {
                    $_.AdditionalProperties.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod'
                }
                if ($strongMethods.Count -eq 0) {
                    $noMfa += $user.UserPrincipalName
                }
            }
            catch { }
        }

        if ($noMfa.Count -gt 0) {
            $totalUsers = ($users | Measure-Object).Count
            $mfaPercent = [math]::Round((($totalUsers - $noMfa.Count) / $totalUsers) * 100, 1)

            $severity = if ($mfaPercent -lt 80) { "Critical" } elseif ($mfaPercent -lt 95) { "High" } else { "Medium" }

            Add-Finding -Category "Authentication Security" -CheckName "MFA Not Registered" `
                -Severity $severity `
                -Description "Found $($noMfa.Count) of $totalUsers member user(s) ($([math]::Round(100-$mfaPercent,1))%) without MFA registered. MFA coverage: $mfaPercent%." `
                -Recommendation "Enforce MFA registration via Conditional Access or Security Defaults. Target 100% coverage." `
                -AffectedObjects ($noMfa | Select-Object -First 20) `
                -Source "Microsoft Entra ID"
        }
        else {
            Add-Finding -Category "Authentication Security" -CheckName "MFA Registration" `
                -Severity "Informational" `
                -Description "All member users have MFA methods registered." `
                -Source "Microsoft Entra ID"
        }
    }
    catch {
        Write-Host "    [!] Could not check MFA status: $($_.Exception.Message)" -ForegroundColor Red
    }

    # --- Legacy Authentication ---
    try {
        $casPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        $legacyAuthBlocked = $false

        foreach ($policy in $casPolicies) {
            if ($policy.State -eq "enabled") {
                $conditions = $policy.Conditions
                $grantControls = $policy.GrantControls

                if ($conditions.ClientAppTypes -contains "exchangeActiveSync" -or
                    $conditions.ClientAppTypes -contains "other") {
                    if ($grantControls.BuiltInControls -contains "block") {
                        $legacyAuthBlocked = $true
                        break
                    }
                }
            }
        }

        if (-not $legacyAuthBlocked) {
            Add-Finding -Category "Authentication Security" -CheckName "Legacy Authentication Not Blocked" `
                -Severity "Critical" `
                -Description "No active Conditional Access policy found blocking legacy authentication protocols." `
                -Recommendation "Create a Conditional Access policy to block legacy authentication for all users. Legacy auth bypasses MFA." `
                -Source "Microsoft Entra ID"
        }
        else {
            Add-Finding -Category "Authentication Security" -CheckName "Legacy Authentication" `
                -Severity "Informational" `
                -Description "Legacy authentication is blocked via Conditional Access policy." `
                -Source "Microsoft Entra ID"
        }
    }
    catch {
        Write-Host "    [!] Could not check Conditional Access policies: $($_.Exception.Message)" -ForegroundColor Red
    }

    # --- Conditional Access Gap Analysis ---
    try {
        $casPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        $enabledPolicies = $casPolicies | Where-Object { $_.State -eq "enabled" }
        $policyCount = ($enabledPolicies | Measure-Object).Count

        $expectedControls = @{
            "MFA for Admins"          = $false
            "MFA for All Users"       = $false
            "Block Legacy Auth"       = $false
            "Require Compliant Device" = $false
            "Sign-in Risk Policy"     = $false
            "User Risk Policy"        = $false
        }

        foreach ($policy in $enabledPolicies) {
            $grant = $policy.GrantControls.BuiltInControls
            $conditions = $policy.Conditions

            if ($grant -contains "mfa") {
                if ($conditions.Users.IncludeRoles.Count -gt 0) {
                    $expectedControls["MFA for Admins"] = $true
                }
                if ($conditions.Users.IncludeUsers -contains "All") {
                    $expectedControls["MFA for All Users"] = $true
                }
            }
            if ($grant -contains "block" -and
                ($conditions.ClientAppTypes -contains "exchangeActiveSync" -or
                 $conditions.ClientAppTypes -contains "other")) {
                $expectedControls["Block Legacy Auth"] = $true
            }
            if ($grant -contains "compliantDevice") {
                $expectedControls["Require Compliant Device"] = $true
            }
            if ($conditions.SignInRiskLevels.Count -gt 0) {
                $expectedControls["Sign-in Risk Policy"] = $true
            }
            if ($conditions.UserRiskLevels.Count -gt 0) {
                $expectedControls["User Risk Policy"] = $true
            }
        }

        $gaps = $expectedControls.GetEnumerator() | Where-Object { -not $_.Value }

        if ($gaps.Count -gt 0) {
            $severity = if ($gaps.Count -ge 4) { "Critical" } elseif ($gaps.Count -ge 2) { "High" } else { "Medium" }
            Add-Finding -Category "Authentication Security" -CheckName "Conditional Access Gaps" `
                -Severity $severity `
                -Description "Found $($gaps.Count) gap(s) in Conditional Access coverage out of 6 recommended controls. $policyCount active policies found." `
                -Recommendation "Implement missing Conditional Access policies for comprehensive protection." `
                -AffectedObjects ($gaps | ForEach-Object { $_.Key }) `
                -Source "Microsoft Entra ID"
        }
        else {
            Add-Finding -Category "Authentication Security" -CheckName "Conditional Access Coverage" `
                -Severity "Informational" `
                -Description "All 6 recommended Conditional Access controls are in place across $policyCount active policies." `
                -Source "Microsoft Entra ID"
        }
    }
    catch {
        Write-Host "    [!] Could not analyze Conditional Access policies: $($_.Exception.Message)" -ForegroundColor Red
    }

    # --- Users Excluded from All Conditional Access Policies ---
    try {
        $casPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        $enabledPolicies = $casPolicies | Where-Object { $_.State -eq "enabled" }

        # Collect all user IDs that are explicitly excluded from any policy
        $exclusionCounts = @{}

        foreach ($policy in $enabledPolicies) {
            $excludedUsers = $policy.Conditions.Users.ExcludeUsers
            if ($excludedUsers) {
                foreach ($userId in $excludedUsers) {
                    if ($userId -eq "GuestsOrExternalUsers") { continue }
                    if (-not $exclusionCounts.ContainsKey($userId)) {
                        $exclusionCounts[$userId] = 0
                    }
                    $exclusionCounts[$userId]++
                }
            }
        }

        $totalEnabledPolicies = ($enabledPolicies | Measure-Object).Count
        $broadlyExcluded = @()

        # Flag users excluded from more than half of all enabled policies
        $exclusionThreshold = [math]::Ceiling($totalEnabledPolicies / 2)

        foreach ($userId in $exclusionCounts.Keys) {
            if ($exclusionCounts[$userId] -ge $exclusionThreshold) {
                try {
                    $user = Get-MgUser -UserId $userId -Property DisplayName, UserPrincipalName -ErrorAction SilentlyContinue
                    if ($user) {
                        $broadlyExcluded += "$($user.UserPrincipalName) (excluded from $($exclusionCounts[$userId]) of $totalEnabledPolicies policies)"
                    }
                    else {
                        $broadlyExcluded += "$userId (excluded from $($exclusionCounts[$userId]) of $totalEnabledPolicies policies)"
                    }
                }
                catch {
                    $broadlyExcluded += "$userId (excluded from $($exclusionCounts[$userId]) of $totalEnabledPolicies policies)"
                }
            }
        }

        if ($broadlyExcluded.Count -gt 0) {
            Add-Finding -Category "Authentication Security" -CheckName "Broadly Excluded CA Users" `
                -Severity "High" `
                -Description "Found $($broadlyExcluded.Count) user(s) excluded from more than half of all enabled Conditional Access policies ($exclusionThreshold+ of $totalEnabledPolicies). These users may bypass critical security controls." `
                -Recommendation "Review all CA exclusions. Replace permanent user exclusions with time-limited exceptions or use a dedicated break-glass account group." `
                -AffectedObjects ($broadlyExcluded | Select-Object -First 20) `
                -Source "Microsoft Entra ID"
        }
        else {
            Add-Finding -Category "Authentication Security" -CheckName "Conditional Access Exclusions" `
                -Severity "Informational" `
                -Description "No users are broadly excluded from Conditional Access policies." `
                -Source "Microsoft Entra ID"
        }
    }
    catch {
        Write-Host "    [!] Could not analyze CA exclusions: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-EntraIdentityHygieneChecks {
    Write-SectionHeader "Microsoft Entra ID — Identity Hygiene"

    $staleDate = (Get-Date).AddDays(-$StaleThresholdDays)

    # --- Stale Entra Users ---
    try {
        $entraUsers = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, SignInActivity, AccountEnabled, UserType `
            -Filter "accountEnabled eq true and userType eq 'Member'" -ErrorAction Stop

        $staleEntraUsers = @()
        foreach ($user in $entraUsers) {
            $lastSignIn = $user.SignInActivity.LastSignInDateTime
            if ($null -eq $lastSignIn -or $lastSignIn -lt $staleDate) {
                $staleEntraUsers += $user.UserPrincipalName
            }
        }

        if ($staleEntraUsers.Count -gt 0) {
            $severity = if ($staleEntraUsers.Count -gt 50) { "High" } elseif ($staleEntraUsers.Count -gt 20) { "Medium" } else { "Low" }
            Add-Finding -Category "Identity Hygiene" -CheckName "Stale Entra ID Users" `
                -Severity $severity `
                -Description "Found $($staleEntraUsers.Count) enabled Entra ID user(s) with no sign-in for $StaleThresholdDays+ days." `
                -Recommendation "Review and disable stale accounts. Enable Entra ID Access Reviews for automated lifecycle management." `
                -AffectedObjects ($staleEntraUsers | Select-Object -First 20) `
                -Source "Microsoft Entra ID"
        }
        else {
            Add-Finding -Category "Identity Hygiene" -CheckName "Stale Entra ID Users" `
                -Severity "Informational" `
                -Description "No stale Entra ID users found (threshold: $StaleThresholdDays days)." `
                -Source "Microsoft Entra ID"
        }
    }
    catch {
        Write-Host "    [!] Could not check stale Entra users: $($_.Exception.Message)" -ForegroundColor Red
    }

    # --- Guest Account Review ---
    try {
        $guests = Get-MgUser -All -Filter "userType eq 'Guest'" `
            -Property Id, DisplayName, UserPrincipalName, SignInActivity, AccountEnabled -ErrorAction Stop

        $staleGuests = @()
        foreach ($guest in $guests) {
            $lastSignIn = $guest.SignInActivity.LastSignInDateTime
            if ($null -eq $lastSignIn -or $lastSignIn -lt $staleDate) {
                $staleGuests += $guest.UserPrincipalName
            }
        }

        $totalGuests = ($guests | Measure-Object).Count

        if ($staleGuests.Count -gt 0) {
            Add-Finding -Category "Identity Hygiene" -CheckName "Stale Guest Accounts" `
                -Severity "Medium" `
                -Description "Found $($staleGuests.Count) of $totalGuests guest account(s) with no sign-in for $StaleThresholdDays+ days." `
                -Recommendation "Remove stale guest accounts. Implement Access Reviews for B2B guests." `
                -AffectedObjects ($staleGuests | Select-Object -First 20) `
                -Source "Microsoft Entra ID"
        }
    }
    catch {
        Write-Host "    [!] Could not check guest accounts: $($_.Exception.Message)" -ForegroundColor Red
    }

    # --- Dormant Service Principals ---
    try {
        $servicePrincipals = Get-MgServicePrincipal -All `
            -Property Id, DisplayName, AppId, ServicePrincipalType, SignInActivity -ErrorAction Stop

        $dormantSPs = @()
        $dormantDate = (Get-Date).AddDays(-$DormantServiceAccountDays)

        foreach ($sp in $servicePrincipals) {
            if ($sp.ServicePrincipalType -eq "Application") {
                $lastSignIn = $sp.SignInActivity.LastSignInDateTime
                if ($null -eq $lastSignIn -or $lastSignIn -lt $dormantDate) {
                    $dormantSPs += "$($sp.DisplayName) ($($sp.AppId))"
                }
            }
        }

        if ($dormantSPs.Count -gt 0) {
            $severity = if ($dormantSPs.Count -gt 20) { "High" } else { "Medium" }
            Add-Finding -Category "Identity Hygiene" -CheckName "Dormant Service Principals" `
                -Severity $severity `
                -Description "Found $($dormantSPs.Count) application service principal(s) with no sign-in for $DormantServiceAccountDays+ days." `
                -Recommendation "Review and disable or delete dormant service principals. Remove unused app registrations." `
                -AffectedObjects ($dormantSPs | Select-Object -First 20) `
                -Source "Microsoft Entra ID"
        }
    }
    catch {
        Write-Host "    [!] Could not check service principals: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================================================
# HTML REPORT GENERATION
# ============================================================================

function New-HtmlReport {
    param([string]$OutputFilePath)

    $criticalFindings = $script:Findings | Where-Object { $_.Severity -eq "Critical" }
    $highFindings     = $script:Findings | Where-Object { $_.Severity -eq "High" }
    $mediumFindings   = $script:Findings | Where-Object { $_.Severity -eq "Medium" }
    $lowFindings      = $script:Findings | Where-Object { $_.Severity -eq "Low" }
    $infoFindings     = $script:Findings | Where-Object { $_.Severity -eq "Informational" }

    $findingsHtml = ""
    foreach ($finding in ($script:Findings | Sort-Object {
        switch ($_.Severity) { "Critical" {0} "High" {1} "Medium" {2} "Low" {3} "Informational" {4} }
    })) {
        $sevColor = $script:SeverityHtmlColors[$finding.Severity]
        $affectedHtml = ""
        if ($finding.AffectedObjects.Count -gt 0) {
            $affectedItems = ($finding.AffectedObjects | Select-Object -First 10 | ForEach-Object {
                "          <li>$([System.Web.HttpUtility]::HtmlEncode($_))</li>"
            }) -join "`n"
            if ($finding.AffectedObjects.Count -gt 10) {
                $affectedItems += "`n          <li><em>... and $($finding.AffectedObjects.Count - 10) more</em></li>"
            }
            $affectedHtml = @"

        <div class="affected">
          <strong>Affected Objects ($($finding.AffectedCount)):</strong>
          <ul>
$affectedItems
          </ul>
        </div>
"@
        }

        $recommendationHtml = ""
        if ($finding.Recommendation) {
            $recommendationHtml = @"

        <div class="recommendation">
          <strong>Recommendation:</strong> $([System.Web.HttpUtility]::HtmlEncode($finding.Recommendation))
        </div>
"@
        }

        $findingsHtml += @"

      <div class="finding">
        <div class="finding-header">
          <span class="severity-badge" style="background-color: $sevColor;">$($finding.Severity)</span>
          <span class="finding-title">$([System.Web.HttpUtility]::HtmlEncode($finding.CheckName))</span>
          <span class="finding-source">$($finding.Source)</span>
        </div>
        <div class="finding-body">
          <p>$([System.Web.HttpUtility]::HtmlEncode($finding.Description))</p>$recommendationHtml$affectedHtml
        </div>
      </div>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Identity Security Audit Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f172a; color: #e2e8f0; line-height: 1.6; padding: 2rem;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    .header {
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      border: 1px solid #334155; border-radius: 12px; padding: 2rem; margin-bottom: 2rem;
      text-align: center;
    }
    .header h1 { font-size: 1.8rem; color: #60a5fa; margin-bottom: 0.5rem; }
    .header .meta { color: #94a3b8; font-size: 0.9rem; }
    .summary-grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 1rem; margin-bottom: 2rem;
    }
    .summary-card {
      background: #1e293b; border: 1px solid #334155; border-radius: 8px;
      padding: 1.2rem; text-align: center;
    }
    .summary-card .count { font-size: 2rem; font-weight: 700; }
    .summary-card .label { color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
    .finding {
      background: #1e293b; border: 1px solid #334155; border-radius: 8px;
      margin-bottom: 1rem; overflow: hidden;
    }
    .finding-header {
      display: flex; align-items: center; gap: 0.75rem;
      padding: 1rem 1.2rem; border-bottom: 1px solid #334155;
    }
    .severity-badge {
      color: #fff; padding: 0.2rem 0.6rem; border-radius: 4px;
      font-size: 0.75rem; font-weight: 600; text-transform: uppercase; white-space: nowrap;
    }
    .finding-title { font-weight: 600; color: #f1f5f9; flex: 1; }
    .finding-source {
      color: #64748b; font-size: 0.8rem; background: #0f172a;
      padding: 0.2rem 0.5rem; border-radius: 4px;
    }
    .finding-body { padding: 1rem 1.2rem; }
    .finding-body p { color: #cbd5e1; margin-bottom: 0.75rem; }
    .recommendation {
      background: #172554; border-left: 3px solid #3b82f6;
      padding: 0.75rem 1rem; border-radius: 0 4px 4px 0; margin-bottom: 0.75rem;
      color: #93c5fd; font-size: 0.9rem;
    }
    .affected { font-size: 0.85rem; color: #94a3b8; }
    .affected ul { margin-top: 0.4rem; margin-left: 1.2rem; }
    .affected li { margin-bottom: 0.2rem; }
    .footer {
      text-align: center; color: #475569; font-size: 0.8rem;
      margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #1e293b;
    }
    .section-title {
      font-size: 1.2rem; color: #60a5fa; margin: 1.5rem 0 1rem;
      padding-bottom: 0.5rem; border-bottom: 1px solid #334155;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Identity Security Audit Report</h1>
      <div class="meta">
        Generated: $($script:AuditTimestamp.ToString("yyyy-MM-dd HH:mm:ss")) |
        Host: $env:COMPUTERNAME |
        Auditor: $env:USERDOMAIN\$env:USERNAME
      </div>
    </div>

    <div class="summary-grid">
      <div class="summary-card">
        <div class="count" style="color: #60a5fa;">$($script:SummaryStats.TotalChecks)</div>
        <div class="label">Total Checks</div>
      </div>
      <div class="summary-card">
        <div class="count" style="color: #dc2626;">$($script:SummaryStats.Critical)</div>
        <div class="label">Critical</div>
      </div>
      <div class="summary-card">
        <div class="count" style="color: #ea580c;">$($script:SummaryStats.High)</div>
        <div class="label">High</div>
      </div>
      <div class="summary-card">
        <div class="count" style="color: #ca8a04;">$($script:SummaryStats.Medium)</div>
        <div class="label">Medium</div>
      </div>
      <div class="summary-card">
        <div class="count" style="color: #0891b2;">$($script:SummaryStats.Low)</div>
        <div class="label">Low</div>
      </div>
      <div class="summary-card">
        <div class="count" style="color: #6b7280;">$($script:SummaryStats.Informational)</div>
        <div class="label">Info</div>
      </div>
    </div>

    <h2 class="section-title">Findings</h2>
$findingsHtml

    <div class="footer">
      Identity Security Audit Tool | Generated by Invoke-IdentitySecurityAudit.ps1
    </div>
  </div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force
    Write-Host "  [+] HTML report saved to: $OutputFilePath" -ForegroundColor Green
}

# ============================================================================
# CONSOLE SUMMARY
# ============================================================================

function Write-AuditSummary {
    Write-Host ""
    Write-Host "  ═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  AUDIT SUMMARY" -ForegroundColor Cyan
    Write-Host "  ═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Total Checks    : $($script:SummaryStats.TotalChecks)" -ForegroundColor White
    Write-Host "  Critical        : $($script:SummaryStats.Critical)" -ForegroundColor Red
    Write-Host "  High            : $($script:SummaryStats.High)" -ForegroundColor DarkYellow
    Write-Host "  Medium          : $($script:SummaryStats.Medium)" -ForegroundColor Yellow
    Write-Host "  Low             : $($script:SummaryStats.Low)" -ForegroundColor Cyan
    Write-Host "  Informational   : $($script:SummaryStats.Informational)" -ForegroundColor Gray
    Write-Host ""

    if ($script:SummaryStats.Critical -gt 0) {
        Write-Host "  ⚠  CRITICAL FINDINGS REQUIRE IMMEDIATE ATTENTION" -ForegroundColor Red
        $script:Findings | Where-Object { $_.Severity -eq "Critical" } | ForEach-Object {
            Write-Host "     → $($_.CheckName): $($_.Description)" -ForegroundColor Red
        }
        Write-Host ""
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Invoke-IdentitySecurityAudit {
    Write-AuditBanner

    # --- Prerequisite Checks ---
    if (-not $SkipAD) {
        if (-not (Test-ModuleAvailable "ActiveDirectory")) {
            Write-Host "  [!] ActiveDirectory module not found. Install RSAT or use -SkipAD." -ForegroundColor Red
            Write-Host "      Install: Install-WindowsFeature RSAT-AD-PowerShell (Server)" -ForegroundColor Gray
            Write-Host "      Install: Add-WindowsCapability -Name Rsat.ActiveDirectory* -Online (Win10/11)" -ForegroundColor Gray
            $script:SkipADLocal = $true
        }
        else {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $script:SkipADLocal = $false
        }
    }
    else { $script:SkipADLocal = $true }

    if (-not $SkipEntra) {
        if (-not (Test-ModuleAvailable "Microsoft.Graph.Users")) {
            Write-Host "  [!] Microsoft Graph PowerShell SDK not found. Install or use -SkipEntra." -ForegroundColor Red
            Write-Host "      Install: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Gray
            $script:SkipEntraLocal = $true
        }
        else {
            try {
                $context = Get-MgContext -ErrorAction Stop
                if (-not $context) {
                    Write-Host "  [!] Not connected to Microsoft Graph. Connecting..." -ForegroundColor Yellow
                    Connect-MgGraph -Scopes @(
                        "User.Read.All",
                        "Directory.Read.All",
                        "Policy.Read.All",
                        "Application.Read.All",
                        "AuditLog.Read.All",
                        "UserAuthenticationMethod.Read.All"
                    ) -ErrorAction Stop
                }
                Write-Host "  [✓] Connected to Microsoft Graph as: $((Get-MgContext).Account)" -ForegroundColor Green
                $script:SkipEntraLocal = $false
            }
            catch {
                Write-Host "  [!] Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
                $script:SkipEntraLocal = $true
            }
        }
    }
    else { $script:SkipEntraLocal = $true }

    if ($script:SkipADLocal -and $script:SkipEntraLocal) {
        Write-Host ""
        Write-Host "  [!] No audit sources available. Exiting." -ForegroundColor Red
        return
    }

    # Add System.Web for HTML encoding
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "  Starting audit..." -ForegroundColor White
    Write-Host ""

    # --- Run AD Checks ---
    if (-not $script:SkipADLocal) {
        Invoke-ADPrivilegedAccountChecks
        Invoke-ADAuthenticationChecks
        Invoke-ADIdentityHygieneChecks
    }
    else {
        Write-Host "  [SKIP] Active Directory checks skipped." -ForegroundColor DarkGray
    }

    # --- Run Entra Checks ---
    if (-not $script:SkipEntraLocal) {
        Invoke-EntraPrivilegedAccountChecks
        Invoke-EntraAuthenticationChecks
        Invoke-EntraIdentityHygieneChecks
    }
    else {
        Write-Host "  [SKIP] Microsoft Entra ID checks skipped." -ForegroundColor DarkGray
    }

    # --- Summary & Report ---
    Write-AuditSummary

    $reportFileName = "IdentitySecurityAudit_$($script:AuditTimestamp.ToString('yyyyMMdd_HHmmss')).html"
    $reportPath = Join-Path $OutputPath $reportFileName
    New-HtmlReport -OutputFilePath $reportPath

    Write-Host ""
    Write-Host "  Audit complete." -ForegroundColor Green
    Write-Host ""
}

# Run the audit
Invoke-IdentitySecurityAudit
