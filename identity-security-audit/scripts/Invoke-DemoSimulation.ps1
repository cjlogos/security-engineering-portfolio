<#
.SYNOPSIS
    Demo simulation for Invoke-IdentitySecurityAudit.ps1

.DESCRIPTION
    Mocks all Active Directory and Microsoft Entra ID cmdlets with realistic
    fictitious data for Contoso Corporation, then dot-sources and runs the
    actual audit script. Produces full console output and an HTML report
    identical to what a real run would generate — no AD or Entra connectivity
    required.

    Use this to validate the audit logic, demonstrate the tool in interviews,
    or generate sample reports for your portfolio.

.EXAMPLE
    .\Invoke-DemoSimulation.ps1

.NOTES
    All data is fictitious. No real organization's data is used.
    Run from the same directory as Invoke-IdentitySecurityAudit.ps1.
#>

$ErrorActionPreference = "Continue"
Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────────┐" -ForegroundColor Magenta
Write-Host "  │       DEMO SIMULATION MODE — Contoso Corporation        │" -ForegroundColor Magenta
Write-Host "  │   All data is fictitious. No real AD/Entra connection.  │" -ForegroundColor Magenta
Write-Host "  └──────────────────────────────────────────────────────────┘" -ForegroundColor Magenta
Write-Host ""

# ============================================================================
# MOCK DATA — Contoso Corporation
# ============================================================================

$now = Get-Date
$staleDate = $now.AddDays(-120)
$dormantDate = $now.AddDays(-90)

# --- Mock AD Users ---
$script:MockDomainAdmins = @(
    @{ SamAccountName = "admin.jthompson"; SID = "S-1-5-21-1234-1001" }
    @{ SamAccountName = "admin.mgarcia";   SID = "S-1-5-21-1234-1002" }
    @{ SamAccountName = "admin.rwilson";   SID = "S-1-5-21-1234-1003" }
    @{ SamAccountName = "admin.kpatel";    SID = "S-1-5-21-1234-1004" }
    @{ SamAccountName = "admin.lcheng";    SID = "S-1-5-21-1234-1005" }
    @{ SamAccountName = "admin.dokafor";   SID = "S-1-5-21-1234-1006" }
    @{ SamAccountName = "admin.skim";      SID = "S-1-5-21-1234-1007" }
    @{ SamAccountName = "admin.nkovacs";   SID = "S-1-5-21-1234-1008" }
) | ForEach-Object { [PSCustomObject]$_ }

$script:MockEnterpriseAdmins = @(
    @{ SamAccountName = "admin.jthompson"; SID = "S-1-5-21-1234-1001" }
    @{ SamAccountName = "admin.rwilson";   SID = "S-1-5-21-1234-1003" }
) | ForEach-Object { [PSCustomObject]$_ }

$script:MockSchemaAdmins = @(
    @{ SamAccountName = "admin.jthompson"; SID = "S-1-5-21-1234-1001" }
) | ForEach-Object { [PSCustomObject]$_ }

# Service accounts with SPNs or svc_ naming
$script:MockServiceAccounts = @(
    @{ SamAccountName = "svc_backup";     Name = "svc_backup";     ServicePrincipalName = @("backup/dc01"); MemberOf = @("CN=Domain Admins,DC=contoso,DC=com"); Enabled = $true; PasswordLastSet = $now.AddDays(-400) }
    @{ SamAccountName = "svc_sqlprod";    Name = "svc_sqlprod";    ServicePrincipalName = @("MSSQLSvc/sql01:1433"); MemberOf = @("CN=Administrators,DC=contoso,DC=com"); Enabled = $true; PasswordLastSet = $now.AddDays(-300) }
    @{ SamAccountName = "svc-exchange";   Name = "svc-exchange";   ServicePrincipalName = @("exchangeRFR/ex01"); MemberOf = @("CN=Domain Admins,DC=contoso,DC=com"); Enabled = $true; PasswordLastSet = $now.AddDays(-500) }
    @{ SamAccountName = "svc_crm";        Name = "svc_crm";       ServicePrincipalName = @("HTTP/crm01"); MemberOf = @("CN=Users,DC=contoso,DC=com"); Enabled = $true; PasswordLastSet = $now.AddDays(-200) }
    @{ SamAccountName = "svc_legacycrm";  Name = "svc_legacycrm"; ServicePrincipalName = @("HTTP/crmold"); MemberOf = @("CN=Users,DC=contoso,DC=com"); Enabled = $true; LastLogonTimestamp = ($dormantDate.AddDays(-30)).ToFileTime() }
    @{ SamAccountName = "sa_abandonedapp"; Name = "sa_abandonedapp"; ServicePrincipalName = $null; MemberOf = @("CN=Users,DC=contoso,DC=com"); Enabled = $true; LastLogonTimestamp = ($dormantDate.AddDays(-60)).ToFileTime() }
    @{ SamAccountName = "svc-printold";   Name = "svc-printold";   ServicePrincipalName = $null; MemberOf = @("CN=Users,DC=contoso,DC=com"); Enabled = $true; LastLogonTimestamp = ($dormantDate.AddDays(-45)).ToFileTime() }
    @{ SamAccountName = "svc_abandonedweb"; Name = "svc_abandonedweb"; ServicePrincipalName = $null; MemberOf = @("CN=Users,DC=contoso,DC=com"); Enabled = $true; LastLogonTimestamp = $null }
    @{ SamAccountName = "svc_abandonedapi"; Name = "svc_abandonedapi"; ServicePrincipalName = @("HTTP/apiold"); MemberOf = @("CN=Users,DC=contoso,DC=com"); Enabled = $true; LastLogonTimestamp = ($dormantDate.AddDays(-20)).ToFileTime() }
) | ForEach-Object { [PSCustomObject]$_ }

# Stale users (63)
$staleNames = @(
    "d.richardson","p.oconnell","m.nakamura","r.fernandez","t.kowalski",
    "a.bergstrom","s.oduya","c.delacroix","w.tanaka","j.moreno",
    "l.ivanova","b.mueller","h.sato","g.andersson","f.dubois",
    "e.chen","k.johansson","n.rossi","q.popov","u.klein",
    "v.yamamoto","x.larsen","z.petrov","aa.silva","ab.schmidt",
    "ac.watanabe","ad.martin","ae.jensen","af.suzuki","ag.novak",
    "ah.park","ai.gruber","aj.kimura","ak.olsen","al.lehmann",
    "am.hayashi","an.berg","ao.fischer","ap.santos","aq.muller",
    "ar.ito","as.hansen","at.wolf","au.takahashi","av.nilsson",
    "aw.bauer","ax.morita","ay.lindqvist","az.huber","ba.saito",
    "bb.eriksson","bc.kraus","bd.taniguchi","be.svensson","bf.braun",
    "bg.ogawa","bh.dahl","bi.richter","bj.kato","bk.lund",
    "bl.frank","bm.yamaguchi","bn.strand"
)
$script:MockStaleUsers = $staleNames | ForEach-Object {
    [PSCustomObject]@{
        SamAccountName     = $_
        LastLogonTimestamp  = ($staleDate.AddDays(-([Math]::Abs($_.GetHashCode()) % 200))).ToFileTime()
        LastLogonDate      = $staleDate.AddDays(-([Math]::Abs($_.GetHashCode()) % 200))
        WhenCreated        = $now.AddDays(-800)
        Enabled            = $true
    }
}

# Password never expires (47 accounts)
$neverExpiresNames = @("svc_backup","svc_sqlprod","svc-exchange","svc_crm","j.martinez","l.nguyen","svc_legacycrm","sa_abandonedapp","svc-printold","svc_sharepoint") +
    (1..37 | ForEach-Object { "user.neverexp$_" })
$script:MockNeverExpires = $neverExpiresNames | ForEach-Object {
    [PSCustomObject]@{
        SamAccountName      = $_
        PasswordNeverExpires = $true
        Enabled             = $true
    }
}

# Disabled accounts still in privileged groups
$script:MockDisabledPrivMembers = @{
    "Domain Admins"    = @(
        [PSCustomObject]@{ SamAccountName = "admin.jthompson"; SID = "S-1-5-21-1234-1001" }
        [PSCustomObject]@{ SamAccountName = "ex.admin.jlee";   SID = "S-1-5-21-1234-2001" }
        [PSCustomObject]@{ SamAccountName = "ex.admin.bkumar"; SID = "S-1-5-21-1234-2002" }
    )
    "Administrators"   = @(
        [PSCustomObject]@{ SamAccountName = "old.svc_deploy";  SID = "S-1-5-21-1234-2003" }
    )
    "Server Operators" = @(
        [PSCustomObject]@{ SamAccountName = "ex.admin.smartin"; SID = "S-1-5-21-1234-2004" }
    )
}
$script:MockDisabledUsers = @{
    "S-1-5-21-1234-2001" = [PSCustomObject]@{ SamAccountName = "ex.admin.jlee";    Enabled = $false }
    "S-1-5-21-1234-2002" = [PSCustomObject]@{ SamAccountName = "ex.admin.bkumar";  Enabled = $false }
    "S-1-5-21-1234-2003" = [PSCustomObject]@{ SamAccountName = "old.svc_deploy";   Enabled = $false }
    "S-1-5-21-1234-2004" = [PSCustomObject]@{ SamAccountName = "ex.admin.smartin"; Enabled = $false }
    "S-1-5-21-1234-1001" = [PSCustomObject]@{ SamAccountName = "admin.jthompson";  Enabled = $true }
}

# Password policy
$script:MockPasswordPolicy = [PSCustomObject]@{
    MinPasswordLength            = 8
    ComplexityEnabled            = $true
    LockoutThreshold             = 0
    ReversibleEncryptionEnabled  = $false
}

# --- Mock Entra Data ---
$script:MockGlobalAdminRole = [PSCustomObject]@{
    Id          = "ga-role-id-001"
    DisplayName = "Global Administrator"
}

$gaNames = @("James Thompson","Maria Garcia","Robert Wilson","Kevin Patel","Lisa Cheng","David Okafor","Sarah Kim")
$script:MockGlobalAdminMembers = $gaNames | ForEach-Object {
    [PSCustomObject]@{
        Id                   = [guid]::NewGuid().ToString()
        AdditionalProperties = @{ displayName = $_ }
    }
}

# Privileged role members
$script:MockRoleMembers = @{
    "Global Administrator"            = @("James Thompson","Maria Garcia","Robert Wilson","Kevin Patel","Lisa Cheng","David Okafor","Sarah Kim")
    "User Administrator"              = @("Robert Wilson","Tom Bradley")
    "Exchange Administrator"          = @("Sarah Kim","Aisha Hassan")
    "SharePoint Administrator"        = @("David Okafor")
    "Security Administrator"          = @("Kevin Patel","Mark Rivera")
    "Application Administrator"       = @("Lisa Cheng")
    "Cloud Application Administrator" = @("Nina Kovacs","James Park")
    "Privileged Role Administrator"   = @("James Thompson")
}

# App registrations
$script:MockAppRegistrations = @(
    [PSCustomObject]@{
        Id = "app-001"; DisplayName = "Contoso-Legacy-Sync"; AppId = "a1a1a1a1"
        RequiredResourceAccess = @(
            [PSCustomObject]@{ ResourceAccess = (1..12 | ForEach-Object { [PSCustomObject]@{ Type = "Role" } }) }
        )
        PasswordCredentials = @(
            [PSCustomObject]@{ DisplayName = "prod-key"; EndDateTime = [DateTime]"2025-08-14" }
        )
        KeyCredentials = @()
    }
    [PSCustomObject]@{
        Id = "app-002"; DisplayName = "Contoso-HR-Integration"; AppId = "b2b2b2b2"
        RequiredResourceAccess = @(
            [PSCustomObject]@{ ResourceAccess = (1..9 | ForEach-Object { [PSCustomObject]@{ Type = "Role" } }) }
        )
        PasswordCredentials = @()
        KeyCredentials = @(
            [PSCustomObject]@{ DisplayName = "auth-cert"; EndDateTime = $now.AddDays(24) }
        )
    }
    [PSCustomObject]@{
        Id = "app-003"; DisplayName = "DevOps-Pipeline-Prod"; AppId = "c3c3c3c3"
        RequiredResourceAccess = @(
            [PSCustomObject]@{ ResourceAccess = (1..8 | ForEach-Object { [PSCustomObject]@{ Type = "Role" } }) }
        )
        PasswordCredentials = @(
            [PSCustomObject]@{ DisplayName = "deploy-key"; EndDateTime = $now.AddDays(19) }
        )
        KeyCredentials = @()
    }
    [PSCustomObject]@{
        Id = "app-004"; DisplayName = "Marketing-Analytics-Tool"; AppId = "d4d4d4d4"
        RequiredResourceAccess = @(
            [PSCustomObject]@{ ResourceAccess = (1..7 | ForEach-Object { [PSCustomObject]@{ Type = "Role" } }) }
        )
        PasswordCredentials = @()
        KeyCredentials = @()
    }
    [PSCustomObject]@{
        Id = "app-005"; DisplayName = "Old-CRM-Connector"; AppId = "e5e5e5e5"
        RequiredResourceAccess = @(
            [PSCustomObject]@{ ResourceAccess = @([PSCustomObject]@{ Type = "Delegated" }) }
        )
        PasswordCredentials = @(
            [PSCustomObject]@{ DisplayName = "api-key-v1"; EndDateTime = [DateTime]"2025-03-01" }
        )
        KeyCredentials = @(
            [PSCustomObject]@{ DisplayName = "signing-cert"; EndDateTime = [DateTime]"2025-06-22" }
        )
    }
    [PSCustomObject]@{
        Id = "app-006"; DisplayName = "Abandoned-Test-App"; AppId = "f6f6f6f6"
        RequiredResourceAccess = @()
        PasswordCredentials = @(
            [PSCustomObject]@{ DisplayName = "dev-key"; EndDateTime = [DateTime]"2024-11-30" }
        )
        KeyCredentials = @()
    }
    [PSCustomObject]@{
        Id = "app-007"; DisplayName = "HR-Onboarding-v1"; AppId = "g7g7g7g7"
        RequiredResourceAccess = @()
        PasswordCredentials = @(
            [PSCustomObject]@{ DisplayName = "service-key"; EndDateTime = [DateTime]"2025-12-15" }
        )
        KeyCredentials = @()
    }
    [PSCustomObject]@{
        Id = "app-008"; DisplayName = "Finance-Reporting-App"; AppId = "h8h8h8h8"
        RequiredResourceAccess = @()
        PasswordCredentials = @(
            [PSCustomObject]@{ DisplayName = "old-bi-key"; EndDateTime = [DateTime]"2026-01-10" }
            [PSCustomObject]@{ DisplayName = "bi-key"; EndDateTime = $now.AddDays(27) }
        )
        KeyCredentials = @()
    }
)

# Entra users (412 members, 34 without MFA)
$noMfaUsers = @("d.richardson","p.oconnell","m.nakamura","temp.contractor01","temp.contractor02") +
    (1..29 | ForEach-Object { "nomfa.user$_" })

$script:MockEntraUsers = @()
$allEntraNames = $noMfaUsers + (1..378 | ForEach-Object { "user$_" })
foreach ($name in $allEntraNames) {
    $isStale = $name -in @("d.richardson","p.oconnell","m.nakamura","r.fernandez","t.kowalski","a.bergstrom","s.oduya","c.delacroix","w.tanaka","j.moreno") +
        (1..18 | ForEach-Object { "user$_" })
    $lastSign = if ($isStale) { $staleDate.AddDays(-30) } else { $now.AddDays(-5) }

    $script:MockEntraUsers += [PSCustomObject]@{
        Id                = [guid]::NewGuid().ToString()
        DisplayName       = $name
        UserPrincipalName = "$name@contoso.com"
        UserType          = "Member"
        AccountEnabled    = $true
        SignInActivity     = [PSCustomObject]@{ LastSignInDateTime = $lastSign }
    }
}

# Guest accounts (42 total, 15 stale)
$guestDomains = @("fabrikam.com","northwind.com","litware.com","adatum.com","fourthcoffee.com","relecloud.com","tailspin.com","proseware.com","wingtip.com","datum.com")
$script:MockGuestUsers = @()
for ($i = 0; $i -lt 42; $i++) {
    $domain = $guestDomains[$i % $guestDomains.Count]
    $prefix = @("vendor","partner","consultant","ext")[$i % 4]
    $lastSign = if ($i -lt 15) { $staleDate.AddDays(-50) } else { $now.AddDays(-10) }
    $script:MockGuestUsers += [PSCustomObject]@{
        Id                = [guid]::NewGuid().ToString()
        DisplayName       = "$prefix.guest$i"
        UserPrincipalName = "$prefix.guest${i}_$domain#EXT#@contoso.onmicrosoft.com"
        AccountEnabled    = $true
        SignInActivity     = [PSCustomObject]@{ LastSignInDateTime = $lastSign }
    }
}

# Conditional Access policies (4 enabled, missing 3 controls)
$script:MockCAPolicies = @(
    [PSCustomObject]@{
        Id    = "cap-001"; DisplayName = "Require MFA for Admins"; State = "enabled"
        Conditions = [PSCustomObject]@{
            Users = [PSCustomObject]@{
                IncludeUsers  = @()
                IncludeRoles  = @("ga-role-id-001","ua-role-id-002")
                ExcludeUsers  = @("user-breakglass-id","user-jthompson-id")
            }
            ClientAppTypes     = @("browser","mobileAppsAndDesktopClients")
            SignInRiskLevels   = @()
            UserRiskLevels     = @()
        }
        GrantControls = [PSCustomObject]@{ BuiltInControls = @("mfa") }
    }
    [PSCustomObject]@{
        Id    = "cap-002"; DisplayName = "Require MFA for All Users"; State = "enabled"
        Conditions = [PSCustomObject]@{
            Users = [PSCustomObject]@{
                IncludeUsers  = @("All")
                IncludeRoles  = @()
                ExcludeUsers  = @("user-breakglass-id","user-jthompson-id")
            }
            ClientAppTypes     = @("browser","mobileAppsAndDesktopClients")
            SignInRiskLevels   = @()
            UserRiskLevels     = @()
        }
        GrantControls = [PSCustomObject]@{ BuiltInControls = @("mfa") }
    }
    [PSCustomObject]@{
        Id    = "cap-003"; DisplayName = "Require Compliant Device"; State = "enabled"
        Conditions = [PSCustomObject]@{
            Users = [PSCustomObject]@{
                IncludeUsers  = @("All")
                IncludeRoles  = @()
                ExcludeUsers  = @("user-breakglass-id","user-jthompson-id")
            }
            ClientAppTypes     = @("browser","mobileAppsAndDesktopClients")
            SignInRiskLevels   = @()
            UserRiskLevels     = @()
        }
        GrantControls = [PSCustomObject]@{ BuiltInControls = @("compliantDevice") }
    }
    [PSCustomObject]@{
        Id    = "cap-004"; DisplayName = "Block High Risk Sign-ins"; State = "enabled"
        Conditions = [PSCustomObject]@{
            Users = [PSCustomObject]@{
                IncludeUsers  = @("All")
                IncludeRoles  = @()
                ExcludeUsers  = @("user-breakglass-id")
            }
            ClientAppTypes     = @("browser","mobileAppsAndDesktopClients")
            SignInRiskLevels   = @()
            UserRiskLevels     = @()
        }
        GrantControls = [PSCustomObject]@{ BuiltInControls = @("block") }
    }
)

# Service principals (22 dormant)
$spNames = @("Old-CRM-Connector","Abandoned-Test-App","Legacy-Sync-Tool","Dev-Scratch-App","QA-TestHarness-v2",
    "Marketing-Old-API","Staging-Auth-Proxy","Deprecated-Webhook","Temp-DataMigration","Old-Monitoring-Agent") +
    (1..12 | ForEach-Object { "Dormant-App-$_" })
$script:MockServicePrincipals = $spNames | ForEach-Object {
    [PSCustomObject]@{
        Id                    = [guid]::NewGuid().ToString()
        DisplayName           = $_
        AppId                 = [guid]::NewGuid().ToString()
        ServicePrincipalType  = "Application"
        SignInActivity         = [PSCustomObject]@{ LastSignInDateTime = $dormantDate.AddDays(-30) }
    }
}
# Add some active ones
$script:MockServicePrincipals += @(
    [PSCustomObject]@{ Id = [guid]::NewGuid().ToString(); DisplayName = "Active-App-1"; AppId = [guid]::NewGuid().ToString(); ServicePrincipalType = "Application"; SignInActivity = [PSCustomObject]@{ LastSignInDateTime = $now.AddDays(-2) } }
    [PSCustomObject]@{ Id = [guid]::NewGuid().ToString(); DisplayName = "Active-App-2"; AppId = [guid]::NewGuid().ToString(); ServicePrincipalType = "Application"; SignInActivity = [PSCustomObject]@{ LastSignInDateTime = $now.AddDays(-5) } }
)

# ============================================================================
# MOCK FUNCTIONS — Override real cmdlets
# ============================================================================

function Get-Module { param([switch]$ListAvailable, [string]$Name) return [PSCustomObject]@{ Name = $Name } }
function Import-Module { param([string]$Name) }
function Add-Type { param([string]$AssemblyName) }

function Get-MgContext { return [PSCustomObject]@{ Account = "admin@contoso.com" } }
function Connect-MgGraph { param([string[]]$Scopes) }

function Get-ADGroupMember {
    param([string]$Identity, [switch]$Recursive)
    switch ($Identity) {
        "Domain Admins"    { return $script:MockDomainAdmins }
        "Enterprise Admins" { return $script:MockEnterpriseAdmins }
        "Schema Admins"    { return $script:MockSchemaAdmins }
        default {
            if ($script:MockDisabledPrivMembers.ContainsKey($Identity)) {
                return $script:MockDisabledPrivMembers[$Identity]
            }
            return @()
        }
    }
}

function Get-ADUser {
    param($Filter, $Identity, [string[]]$Properties, [switch]$ErrorAction)

    if ($Identity) {
        if ($script:MockDisabledUsers.ContainsKey($Identity)) {
            return $script:MockDisabledUsers[$Identity]
        }
        return $null
    }

    $filterStr = "$Filter"

    if ($filterStr -match "ServicePrincipalName|svc_|svc-|service_|sa_") {
        return $script:MockServiceAccounts
    }
    if ($filterStr -match "PasswordNeverExpires") {
        return $script:MockNeverExpires
    }
    if ($filterStr -match "LastLogonTimestamp") {
        return $script:MockStaleUsers
    }
    return @()
}

function Get-ADGroup {
    param([string]$Identity)
    return [PSCustomObject]@{
        Name              = $Identity
        DistinguishedName = "CN=$Identity,DC=contoso,DC=com"
    }
}

function Get-ADDefaultDomainPasswordPolicy {
    return $script:MockPasswordPolicy
}

function Get-ItemProperty {
    param([string]$Path, [string]$Name)
    if ($Path -match "Lsa" -and $Name -eq "LmCompatibilityLevel") {
        return [PSCustomObject]@{ LmCompatibilityLevel = 3 }
    }
    return $null
}

function Get-MgDirectoryRole {
    param([string]$Filter)
    if ($Filter -match "Global Administrator") {
        return $script:MockGlobalAdminRole
    }
    foreach ($roleName in $script:MockRoleMembers.Keys) {
        if ($Filter -match [regex]::Escape($roleName)) {
            return [PSCustomObject]@{ Id = "role-$($roleName.GetHashCode())"; DisplayName = $roleName }
        }
    }
    return $null
}

function Get-MgDirectoryRoleMember {
    param([string]$DirectoryRoleId)
    if ($DirectoryRoleId -eq "ga-role-id-001") {
        return $script:MockGlobalAdminMembers
    }
    foreach ($roleName in $script:MockRoleMembers.Keys) {
        if ($DirectoryRoleId -eq "role-$($roleName.GetHashCode())") {
            return $script:MockRoleMembers[$roleName] | ForEach-Object {
                [PSCustomObject]@{
                    Id                   = [guid]::NewGuid().ToString()
                    AdditionalProperties = @{ displayName = $_ }
                }
            }
        }
    }
    return @()
}

function Get-MgApplication {
    param([switch]$All, [string[]]$Property)
    return $script:MockAppRegistrations
}

function Get-MgUser {
    param([switch]$All, [string]$UserId, [string[]]$Property, [string]$Filter)

    if ($UserId) {
        if ($UserId -eq "user-breakglass-id") {
            return [PSCustomObject]@{ DisplayName = "Break Glass Account"; UserPrincipalName = "breakglass@contoso.com" }
        }
        if ($UserId -eq "user-jthompson-id") {
            return [PSCustomObject]@{ DisplayName = "James Thompson"; UserPrincipalName = "admin.jthompson@contoso.com" }
        }
        return $null
    }

    if ($Filter -match "Guest") {
        return $script:MockGuestUsers
    }
    return $script:MockEntraUsers
}

function Get-MgUserAuthenticationMethod {
    param([string]$UserId)
    $user = $script:MockEntraUsers | Where-Object { $_.Id -eq $UserId }
    if ($user -and ($user.DisplayName -match "^nomfa\.|^temp\.contractor|^d\.richardson|^p\.oconnell|^m\.nakamura")) {
        return @([PSCustomObject]@{ AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod' } })
    }
    return @(
        [PSCustomObject]@{ AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod' } }
        [PSCustomObject]@{ AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' } }
    )
}

function Get-MgIdentityConditionalAccessPolicy {
    param([switch]$All)
    return $script:MockCAPolicies
}

function Get-MgServicePrincipal {
    param([switch]$All, [string[]]$Property)
    return $script:MockServicePrincipals
}

# ============================================================================
# RUN THE ACTUAL AUDIT SCRIPT
# ============================================================================

Write-Host "  Loading Invoke-IdentitySecurityAudit.ps1..." -ForegroundColor Gray
Write-Host ""

# Dot-source the main script to get all functions
$scriptPath = Join-Path $PSScriptRoot "Invoke-IdentitySecurityAudit.ps1"
if (-not (Test-Path $scriptPath)) {
    Write-Host "  [ERROR] Invoke-IdentitySecurityAudit.ps1 not found in $PSScriptRoot" -ForegroundColor Red
    Write-Host "  Place this demo script in the same directory as the audit script." -ForegroundColor Yellow
    exit 1
}

# We need to extract the functions from the script without running the main execution.
# The simplest approach: read the script, remove the last line that calls Invoke-IdentitySecurityAudit,
# dot-source the modified version, then call it ourselves.

$scriptContent = Get-Content $scriptPath -Raw

# Remove the #Requires line (we don't need version check in demo)
$scriptContent = $scriptContent -replace '#Requires -Version 5\.1', ''

# Remove the param block at the top (we'll set our own)
$scriptContent = $scriptContent -replace '(?s)\[CmdletBinding\(\)\]\s*param\(.*?\)', ''

# Remove the final execution call
$scriptContent = $scriptContent -replace '# Run the audit\s*\r?\nInvoke-IdentitySecurityAudit', ''

# Set the parameters
$OutputPath = Join-Path $PSScriptRoot "demo-output"
$StaleThresholdDays = 90
$DormantServiceAccountDays = 60
$SkipAD = $false
$SkipEntra = $false

if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Execute the modified script content to define all functions
try {
    $tempScript = [System.IO.Path]::GetTempFileName() + ".ps1"
    $scriptContent | Set-Content -Path $tempScript -Encoding UTF8
    . $tempScript
    Remove-Item $tempScript -ErrorAction SilentlyContinue
}
catch {
    Write-Host "  [ERROR] Failed to load audit functions: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Now run the audit
Invoke-IdentitySecurityAudit

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────────┐" -ForegroundColor Magenta
Write-Host "  │             DEMO SIMULATION COMPLETE                     │" -ForegroundColor Magenta
Write-Host "  │   Check the demo-output folder for the HTML report.     │" -ForegroundColor Magenta
Write-Host "  └──────────────────────────────────────────────────────────┘" -ForegroundColor Magenta
Write-Host ""
