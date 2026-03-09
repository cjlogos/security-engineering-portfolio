<#
.SYNOPSIS
    AD Privilege Escalation Analyzer - TEST HARNESS with Mock Data.

.DESCRIPTION
    This is a standalone test version that uses mock Active Directory data instead of
    live LDAP queries. It validates every analysis function (recursion, risk tagging,
    stale detection, DCSync detection, unified output) without requiring a domain
    controller or the ActiveDirectory PowerShell module.

    The mock environment simulates "mocklab.local" with:
    - 19 privileged groups (all well-known groups the scanner looks for)
    - 25 users including admin accounts, service accounts, stale accounts, delegation abuse
    - 10 computers including unconstrained/constrained delegation hosts
    - Nested group chains (3 levels deep) to test recursion
    - Kerberoastable accounts (with SPNs), both privileged and unprivileged
    - AS-REP roastable account
    - Unconstrained and constrained delegation on users and computers
    - Stale privileged accounts (old passwords, no recent logons)
    - Orphaned adminCount=1 accounts no longer in privileged groups
    - Mock DCSync-capable principal (non-default)
    - Mock ACL risk entries on AdminSDHolder, domain root, OUs, and privileged groups
    - Mock GPO links, trust relationships, and LAPS coverage data

    Expected findings (use to validate output):
      CRITICAL: 1 (DCSync - svc_replication)
      HIGH:     ~18-22 (Tier 0 members, unconstrained delegation, high-risk ACLs)
      MEDIUM:   ~8-12 (Kerberoast, constrained delegation, stale, orphaned adminCount)

.PARAMETER OutputPath
    Root folder for output. Default: .\TestOutput

.PARAMETER ShowConsoleSummary
    Display summary table in console.

.EXAMPLE
    .\Invoke-ADPrivilegeAnalyzer-TestHarness.ps1 -ShowConsoleSummary

.NOTES
    No dependencies required. Runs on any Windows machine with PowerShell 5.1+.
    Does NOT require the ActiveDirectory module or domain membership.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = '.\TestOutput',
    [int]$StalePasswordDays = 365,
    [int]$StaleLogonDays = 180,
    [switch]$ShowConsoleSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# Force all optional scans on for testing
$IncludeAclScan        = $true
$IncludeDelegationScan = $true
$IncludeTrustScan      = $true
$IncludeLapsCheck      = $true
$IncludeGpoLinkScan    = $true

# ═══════════════════════════════════════════════════════════════
#  SECTION 1: SHARED FUNCTIONS (identical to production script)
# ═══════════════════════════════════════════════════════════════

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')]
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $colors = @{ INFO = 'Cyan'; WARN = 'Yellow'; ERROR = 'Red'; SUCCESS = 'Green' }
    Write-Host "[$timestamp] [$($Level.PadRight(7))] $Message" -ForegroundColor $colors[$Level]
}

function Ensure-Folder {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force -ErrorAction Continue | Out-Null
    }
}

function Export-Report {
    param(
        [Parameter(Mandatory)] [object]$Data,
        [Parameter(Mandatory)] [string]$Path
    )
    try {
        $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Continue
        Write-Log "Wrote report: $Path" 'SUCCESS'
    }
    catch {
        Write-Log "Failed to write report: $Path -- $($_.Exception.Message)" 'ERROR'
    }
}

function New-SummaryRow {
    param([string]$Category, [int]$Count, [string]$Notes)
    [pscustomobject]@{ Category = $Category; Count = $Count; Notes = $Notes }
}

# ── Object Cache (same structure, populated by mock data instead of LDAP) ──
$script:ObjectCache = @{}
$script:GroupMemberCache = @{}

function Get-CachedObject {
    param([string]$DistinguishedName)
    if ($script:ObjectCache.ContainsKey($DistinguishedName)) {
        return $script:ObjectCache[$DistinguishedName]
    }
    return $null
}

# ═══════════════════════════════════════════════════════════════
#  SECTION 2: MOCK DATA FACTORY
# ═══════════════════════════════════════════════════════════════

function New-FakeUser {
    param(
        [string]$Name,
        [string]$Sam,
        [string]$OU = 'OU=Users,DC=mocklab,DC=local',
        [int]$AdminCount = 0,
        [string[]]$SPNs = @(),
        [bool]$DoesNotRequirePreAuth = $false,
        [bool]$TrustedForDelegation = $false,
        [bool]$TrustedToAuthForDelegation = $false,
        [string[]]$AllowedToDelegateTo = @(),
        [DateTime]$PwdLastSet = (Get-Date).AddDays(-30),
        [DateTime]$LastLogon = (Get-Date).AddDays(-1),
        [bool]$Enabled = $true
    )

    $dn = "CN=$Name,$OU"
    [pscustomobject]@{
        Name                            = $Name
        samAccountName                  = $Sam
        objectClass                     = @('top','person','organizationalPerson','user')
        objectSid                       = "S-1-5-21-1234567890-1234567890-1234567890-$([Math]::Abs($Sam.GetHashCode()) % 99999)"
        adminCount                      = $AdminCount
        DistinguishedName               = $dn
        servicePrincipalName            = $SPNs
        DoesNotRequirePreAuth           = $DoesNotRequirePreAuth
        TrustedForDelegation            = $TrustedForDelegation
        TrustedToAuthForDelegation      = $TrustedToAuthForDelegation
        'msDS-AllowedToDelegateTo'      = $AllowedToDelegateTo
        pwdLastSet                      = $PwdLastSet
        lastLogonTimestamp              = $LastLogon
        Enabled                         = $Enabled
        memberof                        = @()
        whenCreated                     = (Get-Date).AddDays(-400)
        whenChanged                     = (Get-Date).AddDays(-5)
    }
}

function New-FakeComputer {
    param(
        [string]$Name,
        [string]$Sam,
        [string]$OS = 'Windows Server 2022 Standard',
        [bool]$TrustedForDelegation = $false,
        [bool]$TrustedToAuthForDelegation = $false,
        [string[]]$AllowedToDelegateTo = @(),
        [bool]$LegacyLaps = $false,
        [bool]$WindowsLaps = $false
    )

    $dn = "CN=$Name,OU=Servers,DC=mocklab,DC=local"
    [pscustomobject]@{
        Name                               = $Name
        samAccountName                     = $Sam
        objectClass                        = @('top','person','organizationalPerson','user','computer')
        objectSid                          = "S-1-5-21-1234567890-1234567890-1234567890-$([Math]::Abs($Sam.GetHashCode()) % 99999)"
        adminCount                         = 0
        DistinguishedName                  = $dn
        TrustedForDelegation               = $TrustedForDelegation
        TrustedToAuthForDelegation         = $TrustedToAuthForDelegation
        'msDS-AllowedToDelegateTo'         = $AllowedToDelegateTo
        operatingSystem                    = $OS
        lastLogonTimestamp                 = (Get-Date).AddDays(-2)
        servicePrincipalName               = @("HOST/$Name", "HOST/$Name.mocklab.local")
        PrimaryGroupID                     = 515
        'ms-Mcs-AdmPwdExpirationTime'      = if ($LegacyLaps) { (Get-Date).AddDays(30).ToFileTimeUtc() } else { $null }
        'msLAPS-PasswordExpirationTime'     = if ($WindowsLaps) { (Get-Date).AddDays(30) } else { $null }
        'msLAPS-EncryptedPassword'          = $null
        whenCreated                        = (Get-Date).AddDays(-200)
        whenChanged                        = (Get-Date).AddDays(-3)
    }
}

function New-FakeGroup {
    param(
        [string]$Name,
        [string]$Sam = $Name,
        [string]$Container = 'OU=Groups,DC=mocklab,DC=local',
        [string]$GroupScope = 'DomainLocal',
        [string]$GroupCategory = 'Security',
        [int]$AdminCount = 0,
        [string[]]$MemberDNs = @(),
        [string]$Description = ''
    )

    $dn = "CN=$Name,$Container"
    [pscustomobject]@{
        Name                 = $Name
        samAccountName       = $Sam
        objectClass          = @('top','group')
        objectSid            = "S-1-5-21-1234567890-1234567890-1234567890-$([Math]::Abs($Sam.GetHashCode()) % 99999)"
        adminCount           = $AdminCount
        DistinguishedName    = $dn
        member               = $MemberDNs
        managedBy            = $null
        GroupScope            = $GroupScope
        GroupCategory         = $GroupCategory
        Description          = $Description
        SID                  = "S-1-5-21-1234567890-1234567890-1234567890-$([Math]::Abs($Sam.GetHashCode()) % 99999)"
        whenCreated          = (Get-Date).AddDays(-400)
        whenChanged          = (Get-Date).AddDays(-10)
    }
}

function Initialize-FakeData {
    Write-Log '=== FAKE MODE: Building simulated AD environment for mocklab.local ===' 'INFO'

    # ──────────────────────────────
    # USERS (25 total)
    # ──────────────────────────────

    $users = @(
        # -- Normal domain admin --
        (New-FakeUser -Name 'John Smith'     -Sam 'jsmith'      -AdminCount 1 -PwdLastSet (Get-Date).AddDays(-20)  -LastLogon (Get-Date).AddDays(-1))
        (New-FakeUser -Name 'Sarah Connor'   -Sam 'sconnor'     -AdminCount 1 -PwdLastSet (Get-Date).AddDays(-15)  -LastLogon (Get-Date).AddHours(-3))

        # -- Kerberoastable service account (privileged - High) --
        (New-FakeUser -Name 'svc_sql'        -Sam 'svc_sql'     -AdminCount 1 -SPNs @('MSSQLSvc/SQL01.mocklab.local:1433','MSSQLSvc/SQL01.mocklab.local') -PwdLastSet (Get-Date).AddDays(-90) -LastLogon (Get-Date).AddDays(-1))

        # -- Kerberoastable service account (not privileged - Medium) --
        (New-FakeUser -Name 'svc_web'        -Sam 'svc_web'     -SPNs @('HTTP/web01.mocklab.local') -PwdLastSet (Get-Date).AddDays(-60) -LastLogon (Get-Date).AddDays(-2))

        # -- AS-REP Roastable user --
        (New-FakeUser -Name 'temp.contractor' -Sam 'temp.contractor' -DoesNotRequirePreAuth $true -PwdLastSet (Get-Date).AddDays(-45) -LastLogon (Get-Date).AddDays(-10))

        # -- Unconstrained delegation user (dangerous) --
        (New-FakeUser -Name 'svc_exchange'   -Sam 'svc_exchange' -AdminCount 1 -TrustedForDelegation $true -PwdLastSet (Get-Date).AddDays(-200) -LastLogon (Get-Date).AddDays(-1))

        # -- Constrained delegation user --
        (New-FakeUser -Name 'svc_proxy'      -Sam 'svc_proxy'   -TrustedToAuthForDelegation $true -AllowedToDelegateTo @('cifs/FILE01.mocklab.local','cifs/FILE02.mocklab.local') -PwdLastSet (Get-Date).AddDays(-100) -LastLogon (Get-Date).AddDays(-5))

        # -- Stale DA: password 500 days old, last logon 400 days ago --
        (New-FakeUser -Name 'old.admin'      -Sam 'old.admin'   -AdminCount 1 -PwdLastSet (Get-Date).AddDays(-500) -LastLogon (Get-Date).AddDays(-400))

        # -- Stale DA: never logged on --
        (New-FakeUser -Name 'setup.admin'    -Sam 'setup.admin' -AdminCount 1 -PwdLastSet (Get-Date).AddDays(-600) -LastLogon ([DateTime]::MinValue) -Enabled $false)

        # -- Orphaned adminCount (was in DA, removed, but flag stuck) --
        (New-FakeUser -Name 'former.admin'   -Sam 'former.admin' -AdminCount 1 -PwdLastSet (Get-Date).AddDays(-200) -LastLogon (Get-Date).AddDays(-180))

        # -- DCSync abuse account --
        (New-FakeUser -Name 'svc_replication' -Sam 'svc_replication' -PwdLastSet (Get-Date).AddDays(-30) -LastLogon (Get-Date).AddDays(-1))

        # -- Normal users (no findings expected) --
        (New-FakeUser -Name 'Alice Johnson'  -Sam 'ajohnson'    -PwdLastSet (Get-Date).AddDays(-10)  -LastLogon (Get-Date).AddHours(-2))
        (New-FakeUser -Name 'Bob Williams'   -Sam 'bwilliams'   -PwdLastSet (Get-Date).AddDays(-20)  -LastLogon (Get-Date).AddDays(-1))
        (New-FakeUser -Name 'Carol Davis'    -Sam 'cdavis'      -PwdLastSet (Get-Date).AddDays(-5)   -LastLogon (Get-Date).AddHours(-6))
        (New-FakeUser -Name 'Dave Miller'    -Sam 'dmiller'     -PwdLastSet (Get-Date).AddDays(-40)  -LastLogon (Get-Date).AddDays(-3))
        (New-FakeUser -Name 'Eve Wilson'     -Sam 'ewilson'     -PwdLastSet (Get-Date).AddDays(-25)  -LastLogon (Get-Date).AddDays(-1))

        # -- Account Operators member --
        (New-FakeUser -Name 'helpdesk.lead'  -Sam 'helpdesk.lead' -AdminCount 1 -PwdLastSet (Get-Date).AddDays(-50) -LastLogon (Get-Date).AddDays(-1))

        # -- Backup Operators member --
        (New-FakeUser -Name 'svc_backup'     -Sam 'svc_backup'  -AdminCount 1 -PwdLastSet (Get-Date).AddDays(-300) -LastLogon (Get-Date).AddDays(-250))

        # -- DnsAdmins member --
        (New-FakeUser -Name 'dns.admin'      -Sam 'dns.admin'   -AdminCount 1 -PwdLastSet (Get-Date).AddDays(-70) -LastLogon (Get-Date).AddDays(-2))

        # -- GPO Creator --
        (New-FakeUser -Name 'gpo.manager'    -Sam 'gpo.manager' -AdminCount 1 -PwdLastSet (Get-Date).AddDays(-45) -LastLogon (Get-Date).AddDays(-3))

        # -- Schema Admin --
        (New-FakeUser -Name 'schema.admin'   -Sam 'schema.admin' -AdminCount 1 -PwdLastSet (Get-Date).AddDays(-800) -LastLogon (Get-Date).AddDays(-700))

        # -- Nested group member (will be put in IT-Admins -> Server-Ops -> Domain Admins chain) --
        (New-FakeUser -Name 'nested.admin'   -Sam 'nested.admin' -AdminCount 1 -PwdLastSet (Get-Date).AddDays(-30) -LastLogon (Get-Date).AddDays(-1))

        # -- Member of a nested chain but also Kerberoastable --
        (New-FakeUser -Name 'svc_monitor'    -Sam 'svc_monitor' -AdminCount 1 -SPNs @('HTTP/monitor.mocklab.local:8443') -PwdLastSet (Get-Date).AddDays(-150) -LastLogon (Get-Date).AddDays(-10))

        # -- Protected Users member (good practice) --
        (New-FakeUser -Name 'secure.admin'   -Sam 'secure.admin' -AdminCount 1 -PwdLastSet (Get-Date).AddDays(-10) -LastLogon (Get-Date).AddHours(-1))

        # -- Read-only DC service account --
        (New-FakeUser -Name 'rodc.svc'       -Sam 'rodc.svc'    -PwdLastSet (Get-Date).AddDays(-60) -LastLogon (Get-Date).AddDays(-5))
    )

    # ──────────────────────────────
    # COMPUTERS (10 total)
    # ──────────────────────────────

    $computers = @(
        # Domain controllers (unconstrained delegation is expected on DCs)
        (New-FakeComputer -Name 'DC01'       -Sam 'DC01$'        -OS 'Windows Server 2022 Datacenter' -TrustedForDelegation $true -WindowsLaps $true)
        (New-FakeComputer -Name 'DC02'       -Sam 'DC02$'        -OS 'Windows Server 2022 Datacenter' -TrustedForDelegation $true -WindowsLaps $true)

        # Unconstrained delegation on a NON-DC (bad - should flag)
        (New-FakeComputer -Name 'APP-SERVER01' -Sam 'APP-SERVER01$' -OS 'Windows Server 2019 Standard' -TrustedForDelegation $true -LegacyLaps $true)

        # Constrained delegation
        (New-FakeComputer -Name 'WEB01'      -Sam 'WEB01$'       -OS 'Windows Server 2019 Standard' -TrustedToAuthForDelegation $true -AllowedToDelegateTo @('http/intranet.mocklab.local') -WindowsLaps $true)

        # Normal servers
        (New-FakeComputer -Name 'SQL01'      -Sam 'SQL01$'       -OS 'Windows Server 2022 Standard' -WindowsLaps $true)
        (New-FakeComputer -Name 'FILE01'     -Sam 'FILE01$'      -OS 'Windows Server 2019 Standard' -LegacyLaps $true)
        (New-FakeComputer -Name 'FILE02'     -Sam 'FILE02$'      -OS 'Windows Server 2016 Standard')  # No LAPS

        # Workstations
        (New-FakeComputer -Name 'WKS001'     -Sam 'WKS001$'      -OS 'Windows 11 Enterprise' -WindowsLaps $true)
        (New-FakeComputer -Name 'WKS002'     -Sam 'WKS002$'      -OS 'Windows 10 Enterprise' -LegacyLaps $true)
        (New-FakeComputer -Name 'WKS003'     -Sam 'WKS003$'      -OS 'Windows 10 Enterprise')  # No LAPS
    )

    # ──────────────────────────────
    # Build user/computer DN lookups
    # ──────────────────────────────

    $userDnMap = @{}
    foreach ($u in $users) { $userDnMap[$u.samAccountName] = $u.DistinguishedName }

    $compDnMap = @{}
    foreach ($c in $computers) { $compDnMap[$c.samAccountName] = $c.DistinguishedName }

    # ──────────────────────────────
    # GROUPS with membership wiring
    # ──────────────────────────────

    # Custom nested groups (to test recursion depth)
    $itAdminsMembers = @(
        $userDnMap['nested.admin'],
        $userDnMap['svc_monitor']
    )

    $serverOpsCustomMembers = @(
        "CN=IT-Admins,OU=Groups,DC=mocklab,DC=local"    # nested group
    )

    $groups = @(
        # ── Well-known privileged groups ──
        (New-FakeGroup -Name 'Administrators'        -Container 'CN=Builtin,DC=mocklab,DC=local' -GroupScope 'DomainLocal' -AdminCount 1 `
            -MemberDNs @(
                'CN=Domain Admins,OU=Groups,DC=mocklab,DC=local',
                'CN=Enterprise Admins,OU=Groups,DC=mocklab,DC=local'
            ) `
            -Description 'Built-in Administrators')

        (New-FakeGroup -Name 'Domain Admins'         -Container 'OU=Groups,DC=mocklab,DC=local' -GroupScope 'Global' -AdminCount 1 `
            -MemberDNs @(
                $userDnMap['jsmith'],
                $userDnMap['sconnor'],
                $userDnMap['svc_sql'],
                $userDnMap['svc_exchange'],
                $userDnMap['old.admin'],
                $userDnMap['setup.admin'],
                "CN=Server-Ops-Custom,OU=Groups,DC=mocklab,DC=local"    # nested group chain
            ) `
            -Description 'Domain Administrators')

        (New-FakeGroup -Name 'Enterprise Admins'     -Container 'OU=Groups,DC=mocklab,DC=local' -GroupScope 'Universal' -AdminCount 1 `
            -MemberDNs @($userDnMap['jsmith']) `
            -Description 'Enterprise Administrators')

        (New-FakeGroup -Name 'Schema Admins'         -Container 'OU=Groups,DC=mocklab,DC=local' -GroupScope 'Universal' -AdminCount 1 `
            -MemberDNs @($userDnMap['schema.admin']) `
            -Description 'Schema Administrators')

        (New-FakeGroup -Name 'Account Operators'     -Container 'CN=Builtin,DC=mocklab,DC=local' -GroupScope 'DomainLocal' -AdminCount 1 `
            -MemberDNs @($userDnMap['helpdesk.lead']) `
            -Description 'Account Operators')

        (New-FakeGroup -Name 'Backup Operators'      -Container 'CN=Builtin,DC=mocklab,DC=local' -GroupScope 'DomainLocal' -AdminCount 1 `
            -MemberDNs @($userDnMap['svc_backup']) `
            -Description 'Backup Operators')

        (New-FakeGroup -Name 'Print Operators'       -Container 'CN=Builtin,DC=mocklab,DC=local' -GroupScope 'DomainLocal' -AdminCount 1 `
            -MemberDNs @() `
            -Description 'Print Operators')

        (New-FakeGroup -Name 'Server Operators'      -Container 'CN=Builtin,DC=mocklab,DC=local' -GroupScope 'DomainLocal' -AdminCount 1 `
            -MemberDNs @() `
            -Description 'Server Operators')

        (New-FakeGroup -Name 'Group Policy Creator Owners' -Container 'OU=Groups,DC=mocklab,DC=local' -GroupScope 'Global' -AdminCount 1 `
            -MemberDNs @($userDnMap['gpo.manager']) `
            -Description 'GPO Creator Owners')

        (New-FakeGroup -Name 'Cert Publishers'       -Container 'OU=Groups,DC=mocklab,DC=local' -GroupScope 'DomainLocal' `
            -MemberDNs @() `
            -Description 'Certificate Publishers')

        (New-FakeGroup -Name 'DnsAdmins'             -Container 'OU=Groups,DC=mocklab,DC=local' -GroupScope 'DomainLocal' -AdminCount 1 `
            -MemberDNs @($userDnMap['dns.admin']) `
            -Description 'DNS Administrators')

        (New-FakeGroup -Name 'Enterprise Key Admins' -Container 'OU=Groups,DC=mocklab,DC=local' -GroupScope 'Universal' `
            -MemberDNs @() `
            -Description 'Enterprise Key Admins')

        (New-FakeGroup -Name 'Key Admins'            -Container 'OU=Groups,DC=mocklab,DC=local' -GroupScope 'DomainLocal' `
            -MemberDNs @() `
            -Description 'Key Admins')

        (New-FakeGroup -Name 'Remote Desktop Users'  -Container 'CN=Builtin,DC=mocklab,DC=local' -GroupScope 'DomainLocal' `
            -MemberDNs @($userDnMap['ajohnson'], $userDnMap['bwilliams']) `
            -Description 'Remote Desktop Users')

        (New-FakeGroup -Name 'Protected Users'       -Container 'OU=Groups,DC=mocklab,DC=local' -GroupScope 'Global' `
            -MemberDNs @($userDnMap['secure.admin']) `
            -Description 'Protected Users')

        (New-FakeGroup -Name 'Allowed RODC Password Replication Group' -Container 'OU=Groups,DC=mocklab,DC=local' -GroupScope 'DomainLocal' `
            -MemberDNs @() `
            -Description 'RODC Allowed Replication')

        (New-FakeGroup -Name 'Denied RODC Password Replication Group'  -Container 'OU=Groups,DC=mocklab,DC=local' -GroupScope 'DomainLocal' `
            -MemberDNs @() `
            -Description 'RODC Denied Replication')

        (New-FakeGroup -Name 'Read-only Domain Controllers'            -Container 'OU=Groups,DC=mocklab,DC=local' -GroupScope 'Global' `
            -MemberDNs @() `
            -Description 'RODCs')

        (New-FakeGroup -Name 'Cryptographic Operators' -Container 'CN=Builtin,DC=mocklab,DC=local' -GroupScope 'DomainLocal' `
            -MemberDNs @() `
            -Description 'Cryptographic Operators')

        # ── Custom groups for nesting tests ──
        (New-FakeGroup -Name 'Server-Ops-Custom'     -Container 'OU=Groups,DC=mocklab,DC=local' -GroupScope 'Global' `
            -MemberDNs $serverOpsCustomMembers `
            -Description 'Custom Server Operators group')

        (New-FakeGroup -Name 'IT-Admins'             -Container 'OU=Groups,DC=mocklab,DC=local' -GroupScope 'Global' `
            -MemberDNs $itAdminsMembers `
            -Description 'IT Administrators (nested into Server-Ops-Custom -> Domain Admins)')
    )

    # ──────────────────────────────
    # Populate caches
    # ──────────────────────────────

    foreach ($u in $users) {
        $script:ObjectCache[$u.DistinguishedName] = $u
    }
    foreach ($c in $computers) {
        $script:ObjectCache[$c.DistinguishedName] = $c
    }
    foreach ($g in $groups) {
        $script:ObjectCache[$g.DistinguishedName] = $g
        $script:GroupMemberCache[$g.DistinguishedName] = @($g.member)
    }

    Write-Log "Mock cache loaded: $(@($users).Count) users, $(@($computers).Count) computers, $(@($groups).Count) groups" 'SUCCESS'
    Write-Log "Total cached objects: $($script:ObjectCache.Count)" 'INFO'
}

# ═══════════════════════════════════════════════════════════════
#  SECTION 3: ANALYSIS FUNCTIONS (from production script)
# ═══════════════════════════════════════════════════════════════

function Get-WellKnownPrivilegedGroups {
    param([string]$DomainDn)

    $targets = @(
        'Administrators', 'Domain Admins', 'Enterprise Admins', 'Schema Admins',
        'Account Operators', 'Backup Operators', 'Print Operators', 'Server Operators',
        'Group Policy Creator Owners', 'Cert Publishers', 'DnsAdmins',
        'Enterprise Key Admins', 'Key Admins', 'Remote Desktop Users',
        'Protected Users', 'Allowed RODC Password Replication Group',
        'Denied RODC Password Replication Group', 'Read-only Domain Controllers',
        'Cryptographic Operators'
    )

    $results = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($dn in $script:ObjectCache.Keys) {
        $obj = $script:ObjectCache[$dn]
        $oc = $obj.objectClass
        $isGroup = if ($oc -is [array]) { $oc -contains 'group' } else { $oc -eq 'group' }
        if (-not $isGroup) { continue }
        if ($targets -contains $obj.Name) {
            if ($seen.Add($obj.DistinguishedName)) {
                $results.Add($obj)
            }
        }
    }

    return $results | Sort-Object Name -Unique
}

function Get-RecursiveGroupMembers {
    param(
        [Parameter(Mandatory)] [string]$GroupDn,
        [Parameter(Mandatory)] [string]$RootGroupName
    )

    $visitedGroups = New-Object 'System.Collections.Generic.HashSet[string]'
    $results = New-Object System.Collections.Generic.List[object]

    function Expand-Group {
        param([string]$CurrentGroupDn, [int]$Depth, [string[]]$PathSoFar)

        if ([string]::IsNullOrWhiteSpace($CurrentGroupDn)) { return }
        if (-not $visitedGroups.Add($CurrentGroupDn)) { return }

        $group = Get-CachedObject -DistinguishedName $CurrentGroupDn
        if (-not $group) { return }
        $groupSam = if ($group.samAccountName) { $group.samAccountName } else { $group.Name }

        $memberDns = @()
        if ($script:GroupMemberCache.ContainsKey($CurrentGroupDn)) {
            $memberDns = $script:GroupMemberCache[$CurrentGroupDn]
        }

        foreach ($memberDn in $memberDns) {
            if ([string]::IsNullOrWhiteSpace($memberDn)) { continue }
            $memberObj = Get-CachedObject -DistinguishedName $memberDn
            if (-not $memberObj) { continue }

            $memberName = if ($memberObj.Name) { $memberObj.Name } else { $memberObj.samAccountName }
            $currentPath = @($PathSoFar + $groupSam + $memberName)

            $objClass = $memberObj.objectClass
            if ($objClass -is [array]) {
                if ($objClass -contains 'computer')  { $objClass = 'computer' }
                elseif ($objClass -contains 'user')  { $objClass = 'user' }
                elseif ($objClass -contains 'group') { $objClass = 'group' }
                else { $objClass = ($objClass | Select-Object -Last 1) }
            }

            $results.Add([pscustomobject]@{
                RootPrivilegedGroup     = $RootGroupName
                ParentGroup             = $groupSam
                MemberName              = $memberName
                MemberSamAccountName    = $memberObj.samAccountName
                MemberClass             = $objClass
                MemberDistinguishedName = $memberObj.DistinguishedName
                MemberSid               = $memberObj.objectSid
                MemberAdminCount        = $memberObj.adminCount
                NestingDepth            = $Depth + 1
                Path                    = ($currentPath -join ' -> ')
            })

            if ($objClass -eq 'group') {
                Expand-Group -CurrentGroupDn $memberObj.DistinguishedName -Depth ($Depth + 1) -PathSoFar ($PathSoFar + $groupSam)
            }
        }
    }

    Expand-Group -CurrentGroupDn $GroupDn -Depth 0 -PathSoFar @()
    return $results
}

function Get-DomainTierZeroIndicators {
    param([object[]]$GroupMembershipRows)

    $tierZeroGroupNames = @(
        'Administrators', 'Domain Admins', 'Enterprise Admins', 'Schema Admins',
        'Account Operators', 'Backup Operators', 'Print Operators', 'Server Operators',
        'DnsAdmins', 'Group Policy Creator Owners', 'Enterprise Key Admins', 'Key Admins'
    )

    return $GroupMembershipRows | Where-Object {
        $_.RootPrivilegedGroup -in $tierZeroGroupNames -and
        $_.MemberClass -in @('user','group','computer','msDS-GroupManagedServiceAccount')
    } | Select-Object RootPrivilegedGroup, MemberName, MemberSamAccountName, MemberClass,
        MemberDistinguishedName, MemberSid, MemberAdminCount, NestingDepth, Path
}

function Get-AdminCountObjects {
    param([string]$DomainDn)
    $script:ObjectCache.Values | Where-Object { $_.adminCount -eq 1 } |
        Select-Object @{n='Name';e={$_.Name}}, samAccountName, objectClass, distinguishedName, adminCount, whenCreated, whenChanged
}

function Get-InterestingUserRisks {
    param([string]$DomainDn)

    $findings = New-Object System.Collections.Generic.List[object]

    $users = $script:ObjectCache.Values | Where-Object {
        $oc = $_.objectClass
        if ($oc -is [array]) { $oc -contains 'user' -and $oc -notcontains 'computer' } else { $oc -eq 'user' }
    }

    foreach ($user in $users) {
        if ($user.servicePrincipalName -and @($user.servicePrincipalName).Count -gt 0) {
            $findings.Add([pscustomobject]@{
                RiskType          = 'KerberoastableUser'
                SamAccountName    = $user.samAccountName
                DistinguishedName = $user.DistinguishedName
                Detail            = ($user.servicePrincipalName -join '; ')
                Severity          = if ($user.adminCount -eq 1) { 'High' } else { 'Medium' }
            })
        }

        if ($user.DoesNotRequirePreAuth -eq $true) {
            $findings.Add([pscustomobject]@{
                RiskType          = 'ASREPRoastableUser'
                SamAccountName    = $user.samAccountName
                DistinguishedName = $user.DistinguishedName
                Detail            = 'DoesNotRequirePreAuth = True'
                Severity          = if ($user.adminCount -eq 1) { 'High' } else { 'Medium' }
            })
        }

        if ($user.TrustedForDelegation -eq $true) {
            $findings.Add([pscustomobject]@{
                RiskType          = 'UnconstrainedDelegationUser'
                SamAccountName    = $user.samAccountName
                DistinguishedName = $user.DistinguishedName
                Detail            = 'TrustedForDelegation = True'
                Severity          = 'High'
            })
        }

        if ($user.TrustedToAuthForDelegation -eq $true -or ($user.'msDS-AllowedToDelegateTo' -and @($user.'msDS-AllowedToDelegateTo').Count -gt 0)) {
            $findings.Add([pscustomobject]@{
                RiskType          = 'ConstrainedDelegationUser'
                SamAccountName    = $user.samAccountName
                DistinguishedName = $user.DistinguishedName
                Detail            = ($user.'msDS-AllowedToDelegateTo' -join '; ')
                Severity          = 'Medium'
            })
        }
    }

    return $findings
}

function Get-InterestingComputerRisks {
    param([string]$DomainDn)

    $findings = New-Object System.Collections.Generic.List[object]

    $computers = $script:ObjectCache.Values | Where-Object {
        $oc = $_.objectClass
        if ($oc -is [array]) { $oc -contains 'computer' } else { $oc -eq 'computer' }
    }

    foreach ($computer in $computers) {
        if ($computer.TrustedForDelegation -eq $true) {
            $findings.Add([pscustomobject]@{
                RiskType          = 'UnconstrainedDelegationComputer'
                SamAccountName    = $computer.samAccountName
                DistinguishedName = $computer.DistinguishedName
                Detail            = $computer.operatingSystem
                Severity          = 'High'
            })
        }

        if ($computer.TrustedToAuthForDelegation -eq $true -or ($computer.'msDS-AllowedToDelegateTo' -and @($computer.'msDS-AllowedToDelegateTo').Count -gt 0)) {
            $findings.Add([pscustomobject]@{
                RiskType          = 'ConstrainedDelegationComputer'
                SamAccountName    = $computer.samAccountName
                DistinguishedName = $computer.DistinguishedName
                Detail            = ($computer.'msDS-AllowedToDelegateTo' -join '; ')
                Severity          = 'Medium'
            })
        }
    }

    return $findings
}

function Get-StalePrivilegedAccounts {
    param(
        [object[]]$PrivilegedMembershipRows,
        [int]$PasswordAgeDays,
        [int]$LogonAgeDays
    )

    Write-Log "Checking for stale privileged accounts (pwd > $PasswordAgeDays days, logon > $LogonAgeDays days)..."

    $results = New-Object System.Collections.Generic.List[object]
    $now = Get-Date
    $passwordThreshold = $now.AddDays(-$PasswordAgeDays)
    $logonThreshold = $now.AddDays(-$LogonAgeDays)

    $privilegedUserDns = $PrivilegedMembershipRows |
        Where-Object { $_.MemberClass -eq 'user' } |
        Select-Object -ExpandProperty MemberDistinguishedName -Unique

    foreach ($dn in $privilegedUserDns) {
        $user = Get-CachedObject -DistinguishedName $dn
        if (-not $user) { continue }

        $pwdLastSet = $null
        $lastLogon = $null
        $staleReasons = New-Object System.Collections.Generic.List[string]

        if ($user.pwdLastSet) {
            try {
                if ($user.pwdLastSet -is [long] -or $user.pwdLastSet -is [int64]) {
                    $pwdLastSet = [DateTime]::FromFileTimeUtc($user.pwdLastSet)
                } else {
                    $pwdLastSet = [DateTime]$user.pwdLastSet
                }
            }
            catch { $pwdLastSet = $null }
        }

        if ($user.lastLogonTimestamp) {
            try {
                if ($user.lastLogonTimestamp -is [long] -or $user.lastLogonTimestamp -is [int64]) {
                    $lastLogon = [DateTime]::FromFileTimeUtc($user.lastLogonTimestamp)
                } else {
                    $lastLogon = [DateTime]$user.lastLogonTimestamp
                }
            }
            catch { $lastLogon = $null }
        }

        if ($pwdLastSet -and $pwdLastSet -lt $passwordThreshold) {
            $age = [math]::Round(($now - $pwdLastSet).TotalDays)
            $staleReasons.Add("Password $age days old")
        }

        if ($lastLogon -and $lastLogon -lt $logonThreshold) {
            $age = [math]::Round(($now - $lastLogon).TotalDays)
            $staleReasons.Add("Last logon $age days ago")
        }
        elseif ($lastLogon -eq [DateTime]::MinValue -or -not $lastLogon) {
            $staleReasons.Add('No logon timestamp recorded')
        }

        if ($staleReasons.Count -eq 0) { continue }

        $groups = @($PrivilegedMembershipRows |
            Where-Object { $_.MemberDistinguishedName -eq $dn } |
            Select-Object -ExpandProperty RootPrivilegedGroup -Unique) -join '; '

        $isEnabled = $true
        if ($null -ne $user.Enabled) { $isEnabled = $user.Enabled }

        $results.Add([pscustomobject]@{
            SamAccountName     = $user.samAccountName
            Name               = $user.Name
            DistinguishedName  = $dn
            Enabled            = $isEnabled
            PrivilegedGroups   = $groups
            PasswordLastSet    = $pwdLastSet
            LastLogonTimestamp = $lastLogon
            StaleReasons       = ($staleReasons -join '; ')
            Severity           = if ($staleReasons.Count -ge 2) { 'High' } else { 'Medium' }
        })
    }

    Write-Log "Found $($results.Count) stale privileged account(s)." $(if ($results.Count -gt 0) { 'WARN' } else { 'SUCCESS' })
    return $results
}

# ═══════════════════════════════════════════════════════════════
#  SECTION 4: MOCK REPLACEMENTS FOR LIVE-ONLY FUNCTIONS
#  (DCSync, ACL scans, GPO links, trusts, LAPS)
# ═══════════════════════════════════════════════════════════════

function Get-DCSyncCapablePrincipals {
    param([string]$DomainDn)

    Write-Log 'Checking for DCSync-capable principals (MOCK DATA)...'

    # Simulate ACL scan results: expected principals + one attacker-controlled account
    $result = @(
        [pscustomobject]@{
            Principal        = 'MOCKLAB\Domain Controllers'
            HasGetChanges    = $true
            HasGetChangesAll = $true
            CanDCSync        = $true
            Severity         = 'INFO'
            Notes            = 'Expected built-in principal'
        },
        [pscustomobject]@{
            Principal        = 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'
            HasGetChanges    = $true
            HasGetChangesAll = $true
            CanDCSync        = $true
            Severity         = 'INFO'
            Notes            = 'Expected built-in principal'
        },
        [pscustomobject]@{
            Principal        = 'BUILTIN\Administrators'
            HasGetChanges    = $true
            HasGetChangesAll = $true
            CanDCSync        = $true
            Severity         = 'INFO'
            Notes            = 'Expected built-in principal'
        },
        # THIS IS THE DANGEROUS ONE - a non-default principal with DCSync rights
        [pscustomobject]@{
            Principal        = 'MOCKLAB\svc_replication'
            HasGetChanges    = $true
            HasGetChangesAll = $true
            CanDCSync        = $true
            Severity         = 'Critical'
            Notes            = 'NON-DEFAULT DCSync rights - investigate immediately'
        }
    )

    $nonDefault = @($result | Where-Object { $_.Severity -ne 'INFO' })
    if ($nonDefault.Count -gt 0) {
        Write-Log "ALERT: Found $($nonDefault.Count) non-default DCSync-capable principal(s)!" 'WARN'
    }
    return $result
}

function Get-AdminSDHolderAclRisks {
    param([string]$DomainDn)

    Write-Log 'Scanning AdminSDHolder ACL (MOCK DATA)...'

    # Simulate a dangerous ACL entry on AdminSDHolder
    @(
        [pscustomobject]@{
            ObjectName        = 'AdminSDHolder'
            ObjectCategory    = 'AdminSDHolder'
            DistinguishedName = "CN=AdminSDHolder,CN=System,$DomainDn"
            IdentityReference = 'MOCKLAB\svc_exchange'
            Rights            = 'GenericAll'
            AccessControlType = 'Allow'
            IsInherited       = $false
            InheritanceType   = 'None'
            ObjectTypeGuid    = $null
            InheritedObjectType = $null
            RiskTags          = 'GenericAll'
        },
        [pscustomobject]@{
            ObjectName        = 'AdminSDHolder'
            ObjectCategory    = 'AdminSDHolder'
            DistinguishedName = "CN=AdminSDHolder,CN=System,$DomainDn"
            IdentityReference = 'MOCKLAB\helpdesk.lead'
            Rights            = 'WriteDacl'
            AccessControlType = 'Allow'
            IsInherited       = $false
            InheritanceType   = 'None'
            ObjectTypeGuid    = $null
            InheritedObjectType = $null
            RiskTags          = 'WriteDacl'
        }
    )
}

function Get-DomainObjectAclRisks {
    param([string]$DomainDn)

    Write-Log 'Scanning domain root / OU / privileged group ACLs (MOCK DATA)...'

    @(
        # Someone has WriteOwner on Domain Admins
        [pscustomobject]@{
            ObjectName        = 'Domain Admins'
            ObjectCategory    = 'PrivilegedGroup'
            DistinguishedName = "CN=Domain Admins,OU=Groups,$DomainDn"
            IdentityReference = 'MOCKLAB\svc_monitor'
            Rights            = 'WriteOwner'
            AccessControlType = 'Allow'
            IsInherited       = $false
            InheritanceType   = 'None'
            ObjectTypeGuid    = $null
            InheritedObjectType = $null
            RiskTags          = 'WriteOwner'
        },
        # GenericWrite on an OU
        [pscustomobject]@{
            ObjectName        = 'Servers'
            ObjectCategory    = 'OU'
            DistinguishedName = "OU=Servers,$DomainDn"
            IdentityReference = 'MOCKLAB\helpdesk.lead'
            Rights            = 'GenericWrite'
            AccessControlType = 'Allow'
            IsInherited       = $false
            InheritanceType   = 'All'
            ObjectTypeGuid    = $null
            InheritedObjectType = $null
            RiskTags          = 'GenericWrite'
        },
        # WriteMember on Domain Admins (can add themselves)
        [pscustomobject]@{
            ObjectName        = 'Domain Admins'
            ObjectCategory    = 'PrivilegedGroup'
            DistinguishedName = "CN=Domain Admins,OU=Groups,$DomainDn"
            IdentityReference = 'MOCKLAB\dns.admin'
            Rights            = 'WriteProperty'
            AccessControlType = 'Allow'
            IsInherited       = $false
            InheritanceType   = 'None'
            ObjectTypeGuid    = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
            InheritedObjectType = $null
            RiskTags          = 'WriteMember'
        },
        # ResetPassword on domain root (applies to all child users)
        [pscustomobject]@{
            ObjectName        = 'Domain Root'
            ObjectCategory    = 'Domain'
            DistinguishedName = $DomainDn
            IdentityReference = 'MOCKLAB\svc_proxy'
            Rights            = 'ExtendedRight'
            AccessControlType = 'Allow'
            IsInherited       = $false
            InheritanceType   = 'Descendents'
            ObjectTypeGuid    = '00299570-246d-11d0-a768-00aa006e0529'
            InheritedObjectType = $null
            RiskTags          = 'ExtendedRight,ResetPassword'
        }
    )
}

function Get-GpoLinkOverview {
    param([string]$DomainDn)

    Write-Log 'Collecting GPO link overview (MOCK DATA)...'

    @(
        [pscustomobject]@{
            LinkedTargetName = 'mocklab.local'
            LinkedTargetDN   = $DomainDn
            GpoDisplayName   = 'Default Domain Policy'
            GpoDN            = "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,$DomainDn"
            LinkEnabled      = $true
            LinkEnforced     = $false
        },
        [pscustomobject]@{
            LinkedTargetName = 'Servers'
            LinkedTargetDN   = "OU=Servers,$DomainDn"
            GpoDisplayName   = 'Server Hardening Policy'
            GpoDN            = "CN={A1B2C3D4-1234-5678-9ABC-DEF012345678},CN=Policies,CN=System,$DomainDn"
            LinkEnabled      = $true
            LinkEnforced     = $true
        },
        [pscustomobject]@{
            LinkedTargetName = 'Users'
            LinkedTargetDN   = "OU=Users,$DomainDn"
            GpoDisplayName   = 'User Lockout Policy'
            GpoDN            = "CN={E5F6A7B8-ABCD-1234-5678-90ABCDEF1234},CN=Policies,CN=System,$DomainDn"
            LinkEnabled      = $true
            LinkEnforced     = $false
        },
        [pscustomobject]@{
            LinkedTargetName = 'Users'
            LinkedTargetDN   = "OU=Users,$DomainDn"
            GpoDisplayName   = 'Legacy Mapping Policy'
            GpoDN            = "CN={DEADBEEF-CAFE-BABE-DEAD-BEEF00000001},CN=Policies,CN=System,$DomainDn"
            LinkEnabled      = $false
            LinkEnforced     = $false
        }
    )
}

function Get-TrustOverview {
    Write-Log 'Collecting trust overview (MOCK DATA)...'

    @(
        [pscustomobject]@{
            Name                       = 'partner.corp'
            Source                     = 'mocklab.local'
            Target                     = 'partner.corp'
            Direction                  = 'Bidirectional'
            TrustType                  = 'External'
            ForestTransitive           = $false
            SelectiveAuthentication    = $false
            SIDFilteringQuarantined    = $true
            IntraForest                = $false
        },
        [pscustomobject]@{
            Name                       = 'dev.mocklab.local'
            Source                     = 'mocklab.local'
            Target                     = 'dev.mocklab.local'
            Direction                  = 'Bidirectional'
            TrustType                  = 'ParentChild'
            ForestTransitive           = $true
            SelectiveAuthentication    = $false
            SIDFilteringQuarantined    = $false
            IntraForest                = $true
        }
    )
}

function Get-LapsOverview {
    param([string]$DomainDn)

    Write-Log 'Collecting LAPS coverage (MOCK DATA)...'

    $rows = New-Object System.Collections.Generic.List[object]

    $computers = $script:ObjectCache.Values | Where-Object {
        $oc = $_.objectClass
        if ($oc -is [array]) { $oc -contains 'computer' } else { $oc -eq 'computer' }
    }

    foreach ($computer in $computers) {
        $legacyLaps = [bool]$computer.'ms-Mcs-AdmPwdExpirationTime'
        $windowsLaps = [bool]($computer.'msLAPS-PasswordExpirationTime' -or $computer.'msLAPS-EncryptedPassword')

        $rows.Add([pscustomobject]@{
            ComputerName    = $computer.Name
            SamAccountName  = $computer.SamAccountName
            OperatingSystem = $computer.operatingSystem
            LegacyLAPS      = $legacyLaps
            WindowsLAPS     = $windowsLaps
            AnyLAPSDetected = ($legacyLaps -or $windowsLaps)
        })
    }

    return $rows
}

# ── Upward Group Trace (mock version - simulates parent lookup from cache) ──
function Get-UpwardGroupTrace {
    param([string]$ObjectDn)

    $results = New-Object System.Collections.Generic.List[object]

    # Find all groups this object is a member of by scanning the group member cache
    foreach ($groupDn in $script:GroupMemberCache.Keys) {
        if ($script:GroupMemberCache[$groupDn] -contains $ObjectDn) {
            $group = Get-CachedObject -DistinguishedName $groupDn
            if (-not $group) { continue }

            $results.Add([pscustomobject]@{
                SourceObjectDN      = $ObjectDn
                ParentGroup         = $group.samAccountName
                ParentGroupDN       = $group.DistinguishedName
                ParentGroupSID      = $group.objectSid
                ParentGroupScope    = $group.GroupScope
                ParentGroupCategory = $group.GroupCategory
                Depth               = 1
                Path                = $group.samAccountName
            })

            # One level up: find groups that contain THIS group
            foreach ($parentGroupDn in $script:GroupMemberCache.Keys) {
                if ($script:GroupMemberCache[$parentGroupDn] -contains $groupDn) {
                    $parentGroup = Get-CachedObject -DistinguishedName $parentGroupDn
                    if (-not $parentGroup) { continue }

                    $results.Add([pscustomobject]@{
                        SourceObjectDN      = $ObjectDn
                        ParentGroup         = $parentGroup.samAccountName
                        ParentGroupDN       = $parentGroup.DistinguishedName
                        ParentGroupSID      = $parentGroup.objectSid
                        ParentGroupScope    = $parentGroup.GroupScope
                        ParentGroupCategory = $parentGroup.GroupCategory
                        Depth               = 2
                        Path                = "$($group.samAccountName) -> $($parentGroup.samAccountName)"
                    })
                }
            }
        }
    }

    return $results
}

# ═══════════════════════════════════════════════════════════════
#  SECTION 5: UNIFIED FINDINGS BUILDER (from production script)
# ═══════════════════════════════════════════════════════════════

function Build-UnifiedFindings {
    param(
        [object[]]$TierZeroPaths,
        [object[]]$UserRisks,
        [object[]]$ComputerRisks,
        [object[]]$DCSyncFindings,
        [object[]]$StaleAccounts,
        [object[]]$AdminCountObjects,
        [object[]]$AdminSdHolderRisks,
        [object[]]$DomainAclRisks
    )

    $unified = New-Object System.Collections.Generic.List[object]

    foreach ($row in $TierZeroPaths) {
        $unified.Add([pscustomobject]@{
            FindingType    = "$($row.RootPrivilegedGroup) Member"
            Name           = $row.MemberName
            SamAccountName = $row.MemberSamAccountName
            Risk           = 'HIGH'
            Detail         = "Nested depth: $($row.NestingDepth) | Path: $($row.Path)"
            ObjectClass    = $row.MemberClass
        })
    }

    foreach ($row in $UserRisks) {
        $unified.Add([pscustomobject]@{
            FindingType    = $row.RiskType
            Name           = $row.SamAccountName
            SamAccountName = $row.SamAccountName
            Risk           = $row.Severity.ToUpper()
            Detail         = $row.Detail
            ObjectClass    = 'user'
        })
    }

    foreach ($row in $ComputerRisks) {
        $unified.Add([pscustomobject]@{
            FindingType    = $row.RiskType
            Name           = $row.SamAccountName
            SamAccountName = $row.SamAccountName
            Risk           = $row.Severity.ToUpper()
            Detail         = $row.Detail
            ObjectClass    = 'computer'
        })
    }

    foreach ($row in $DCSyncFindings) {
        if ($row.Severity -eq 'INFO') { continue }
        $unified.Add([pscustomobject]@{
            FindingType    = 'DCSync-Capable Principal'
            Name           = $row.Principal
            SamAccountName = $row.Principal
            Risk           = 'CRITICAL'
            Detail         = $row.Notes
            ObjectClass    = 'unknown'
        })
    }

    foreach ($row in $StaleAccounts) {
        $unified.Add([pscustomobject]@{
            FindingType    = 'Stale Privileged Account'
            Name           = $row.Name
            SamAccountName = $row.SamAccountName
            Risk           = $row.Severity.ToUpper()
            Detail         = "$($row.StaleReasons) | Groups: $($row.PrivilegedGroups)"
            ObjectClass    = 'user'
        })
    }

    $privilegedSams = @($TierZeroPaths | Select-Object -ExpandProperty MemberSamAccountName -Unique)
    foreach ($obj in $AdminCountObjects) {
        if ($obj.samAccountName -notin $privilegedSams) {
            $unified.Add([pscustomobject]@{
                FindingType    = 'Orphaned AdminCount Account'
                Name           = $obj.Name
                SamAccountName = $obj.samAccountName
                Risk           = 'MEDIUM'
                Detail         = 'adminCount=1 but not currently in a privileged group (possible stale SDProp stamp)'
                ObjectClass    = $obj.objectClass
            })
        }
    }

    foreach ($row in @($AdminSdHolderRisks) + @($DomainAclRisks)) {
        if ($null -eq $row) { continue }
        $unified.Add([pscustomobject]@{
            FindingType    = "ACL Risk on $($row.ObjectCategory): $($row.ObjectName)"
            Name           = $row.IdentityReference
            SamAccountName = $row.IdentityReference
            Risk           = if ($row.RiskTags -match 'GenericAll|WriteDacl|WriteOwner|ResetPassword|DS-Replication') { 'HIGH' } else { 'MEDIUM' }
            Detail         = "Rights: $($row.Rights) | Tags: $($row.RiskTags)"
            ObjectClass    = 'acl-entry'
        })
    }

    return $unified | Sort-Object @{e={
        switch ($_.Risk) { 'CRITICAL' {0} 'HIGH' {1} 'MEDIUM' {2} 'LOW' {3} default {4} }
    }}, FindingType, SamAccountName
}

# ═══════════════════════════════════════════════════════════════
#  SECTION 6: MAIN EXECUTION (mock-adapted)
# ═══════════════════════════════════════════════════════════════

try {
    $totalSw = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Host ''
    Write-Host '+==================================================================+' -ForegroundColor Yellow
    Write-Host '|   AD Privilege Escalation Analyzer - TEST HARNESS (Mock Data)   |' -ForegroundColor Yellow
    Write-Host '|   Domain: mocklab.local    NO AD module required                |' -ForegroundColor Yellow
    Write-Host '+==================================================================+' -ForegroundColor Yellow
    Write-Host ''

    # ── Skip: Ensure-ActiveDirectoryModule (not needed) ──
    # ── Skip: Get-DomainContext (replaced with mock values) ──

    Ensure-Folder -Path $OutputPath
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $runPath = Join-Path $OutputPath "Run_$timestamp"
    Ensure-Folder -Path $runPath

    # Mock domain context
    $domainDn      = 'DC=mocklab,DC=local'
    $domainName    = 'mocklab.local'
    $domainNetBIOS = 'MOCKLAB'

    # ── Build mock object cache (replaces Initialize-ObjectCache + LDAP) ──
    Initialize-FakeData

    # ── Metadata ──
    $metadata = [pscustomobject]@{
        RunTimestamp          = Get-Date
        TestHarness           = $true
        DomainDNSRoot         = $domainName
        DomainNetBIOSName     = $domainNetBIOS
        DomainDN              = $domainDn
        ForestName            = $domainName
        ForestMode            = 'Windows2016Forest'
        DomainMode            = 'Windows2016Domain'
        PDCEmulator           = 'DC01.mocklab.local'
        RIDMaster             = 'DC01.mocklab.local'
        InfrastructureMaster  = 'DC01.mocklab.local'
        SchemaMaster          = 'DC01.mocklab.local'
        DomainNamingMaster    = 'DC01.mocklab.local'
        ExecutedBy            = "$env:USERNAME (test harness)"
        ComputerName          = $env:COMPUTERNAME
        IncludeAclScan        = $true
        IncludeDelegationScan = $true
        IncludeTrustScan      = $true
        IncludeLapsCheck      = $true
        IncludeGpoLinkScan    = $true
        StalePasswordDays     = $StalePasswordDays
        StaleLogonDays        = $StaleLogonDays
    }
    Export-Report -Data @($metadata) -Path (Join-Path $runPath '00-Run-Metadata.csv')

    # ── Privileged Groups ──
    Write-Log 'Enumerating privileged groups...'
    $privilegedGroups = Get-WellKnownPrivilegedGroups -DomainDn $domainDn |
        Select-Object Name, SamAccountName, SID, DistinguishedName, GroupScope, GroupCategory,
            adminCount, managedBy, whenCreated, whenChanged, Description
    Export-Report -Data $privilegedGroups -Path (Join-Path $runPath '01-Privileged-Groups.csv')

    # ── Recursive Membership ──
    Write-Log 'Tracing downward membership from privileged groups...'
    $privilegedMembership = New-Object System.Collections.Generic.List[object]

    foreach ($group in $privilegedGroups) {
        try {
            $members = Get-RecursiveGroupMembers -GroupDn $group.DistinguishedName -RootGroupName $group.SamAccountName
            foreach ($row in $members) { $privilegedMembership.Add($row) }
        }
        catch { Write-Log "Failed to recursively enumerate group '$($group.SamAccountName)': $($_.Exception.Message)" 'WARN' }
    }

    $privilegedMembershipRows = $privilegedMembership | Sort-Object RootPrivilegedGroup, NestingDepth, MemberClass, MemberSamAccountName
    Export-Report -Data $privilegedMembershipRows -Path (Join-Path $runPath '02-Privileged-Group-Recursive-Membership.csv')

    # ── Tier 0 Indicators ──
    Write-Log 'Flagging Tier 0 / DA-equivalent paths...'
    $tierZeroPaths = @(Get-DomainTierZeroIndicators -GroupMembershipRows $privilegedMembershipRows)
    Export-Report -Data $tierZeroPaths -Path (Join-Path $runPath '03-Tier0-Indicators.csv')

    # ── AdminCount Objects ──
    Write-Log 'Enumerating adminCount=1 objects...'
    $adminCountObjects = @(Get-AdminCountObjects -DomainDn $domainDn)
    Export-Report -Data $adminCountObjects -Path (Join-Path $runPath '04-AdminCount-Objects.csv')

    # ── Upward Group Traces ──
    Write-Log 'Tracing upward group memberships for adminCount=1 objects...'
    $upwardTraceRows = New-Object System.Collections.Generic.List[object]
    foreach ($obj in $adminCountObjects) {
        try {
            $up = Get-UpwardGroupTrace -ObjectDn $obj.distinguishedName
            foreach ($row in $up) { $upwardTraceRows.Add($row) }
        }
        catch { Write-Log "Failed upward tracing for '$($obj.samAccountName)'" 'WARN' }
    }
    Export-Report -Data $upwardTraceRows -Path (Join-Path $runPath '05-Upward-Group-Trace-for-AdminCount.csv')

    # ── User Risks ──
    Write-Log 'Checking user-based escalation indicators...'
    $userRisks = @(Get-InterestingUserRisks -DomainDn $domainDn)
    Export-Report -Data $userRisks -Path (Join-Path $runPath '06-User-Risks.csv')

    # ── Computer Risks ──
    Write-Log 'Checking computer-based escalation indicators...'
    $computerRisks = @(Get-InterestingComputerRisks -DomainDn $domainDn)
    Export-Report -Data $computerRisks -Path (Join-Path $runPath '07-Computer-Risks.csv')

    # ── DCSync Detection ──
    $dcsyncFindings = @(Get-DCSyncCapablePrincipals -DomainDn $domainDn)
    Export-Report -Data $dcsyncFindings -Path (Join-Path $runPath '08-DCSync-Capable-Principals.csv')

    # ── Stale Privileged Accounts ──
    $staleAccounts = @(Get-StalePrivilegedAccounts -PrivilegedMembershipRows $privilegedMembershipRows `
        -PasswordAgeDays $StalePasswordDays -LogonAgeDays $StaleLogonDays)
    Export-Report -Data $staleAccounts -Path (Join-Path $runPath '09-Stale-Privileged-Accounts.csv')

    # ── ACL Scans ──
    $adminSdHolderRisks = @(Get-AdminSDHolderAclRisks -DomainDn $domainDn)
    Export-Report -Data $adminSdHolderRisks -Path (Join-Path $runPath '10-AdminSDHolder-ACL-Risks.csv')

    $domainAclRisks = @(Get-DomainObjectAclRisks -DomainDn $domainDn)
    Export-Report -Data $domainAclRisks -Path (Join-Path $runPath '11-Domain-OU-PrivGroup-ACL-Risks.csv')

    # ── GPO Links ──
    $gpoLinks = @(Get-GpoLinkOverview -DomainDn $domainDn)
    Export-Report -Data $gpoLinks -Path (Join-Path $runPath '12-GPO-Link-Overview.csv')

    # ── Trusts ──
    $trusts = @(Get-TrustOverview)
    Export-Report -Data $trusts -Path (Join-Path $runPath '13-Trust-Overview.csv')

    # ── LAPS ──
    $laps = @(Get-LapsOverview -DomainDn $domainDn)
    Export-Report -Data $laps -Path (Join-Path $runPath '14-LAPS-Overview.csv')

    # ── Delegation Summary ──
    $delegationSummary = @(@($userRisks) + @($computerRisks)) | Where-Object { $_.RiskType -match 'Delegation' }
    Export-Report -Data @($delegationSummary) -Path (Join-Path $runPath '15-Delegation-Summary.csv')

    # ── Unified Findings ──
    Write-Log 'Building unified findings report...'
    $unifiedFindings = @(Build-UnifiedFindings `
        -TierZeroPaths $tierZeroPaths `
        -UserRisks $userRisks `
        -ComputerRisks $computerRisks `
        -DCSyncFindings $dcsyncFindings `
        -StaleAccounts $staleAccounts `
        -AdminCountObjects $adminCountObjects `
        -AdminSdHolderRisks $adminSdHolderRisks `
        -DomainAclRisks $domainAclRisks)

    Export-Report -Data $unifiedFindings -Path (Join-Path $runPath '98-Unified-Findings.csv')

    # ── Executive Summary ──
    Write-Log 'Building executive summary...'

    $criticalCount = @($unifiedFindings | Where-Object { $_.Risk -eq 'CRITICAL' }).Count
    $highCount     = @($unifiedFindings | Where-Object { $_.Risk -eq 'HIGH' }).Count
    $mediumCount   = @($unifiedFindings | Where-Object { $_.Risk -eq 'MEDIUM' }).Count

    $summaryRows = @(
        (New-SummaryRow -Category 'CRITICAL Findings'                 -Count $criticalCount                          -Notes 'DCSync, critical ACL abuse'),
        (New-SummaryRow -Category 'HIGH Findings'                     -Count $highCount                              -Notes 'Tier 0 membership, unconstrained delegation, high-risk ACLs'),
        (New-SummaryRow -Category 'MEDIUM Findings'                   -Count $mediumCount                            -Notes 'Kerberoast, constrained delegation, stale accounts, orphaned adminCount'),
        (New-SummaryRow -Category 'Total Unified Findings'            -Count $unifiedFindings.Count                  -Notes 'All findings consolidated into 98-Unified-Findings.csv'),
        (New-SummaryRow -Category '---'                               -Count 0                                       -Notes '---'),
        (New-SummaryRow -Category 'Privileged Groups Enumerated'      -Count @($privilegedGroups).Count              -Notes 'Well-known privileged groups discovered'),
        (New-SummaryRow -Category 'Recursive Membership Rows'         -Count @($privilegedMembershipRows).Count      -Notes 'All direct and nested members under privileged groups'),
        (New-SummaryRow -Category 'Tier 0 / DA-Equivalent Indicators' -Count $tierZeroPaths.Count                    -Notes 'Objects in or nested into highly privileged groups'),
        (New-SummaryRow -Category 'adminCount=1 Objects'              -Count $adminCountObjects.Count                -Notes 'Protected/AdminSDHolder-linked objects'),
        (New-SummaryRow -Category 'User Risk Findings'                -Count $userRisks.Count                        -Notes 'Kerberoast, AS-REP roast, delegation'),
        (New-SummaryRow -Category 'Computer Risk Findings'            -Count $computerRisks.Count                    -Notes 'Delegation-related computer findings'),
        (New-SummaryRow -Category 'DCSync-Capable Principals'         -Count $dcsyncFindings.Count                   -Notes "Non-default: $(@($dcsyncFindings | Where-Object { $_.Severity -ne 'INFO' }).Count)"),
        (New-SummaryRow -Category 'Stale Privileged Accounts'         -Count $staleAccounts.Count                    -Notes "Pwd > $StalePasswordDays days or logon > $StaleLogonDays days"),
        (New-SummaryRow -Category 'AdminSDHolder ACL Findings'        -Count $adminSdHolderRisks.Count               -Notes 'Mock ACL data'),
        (New-SummaryRow -Category 'Domain/OU/PrivGroup ACL Findings'  -Count $domainAclRisks.Count                   -Notes 'Mock ACL data'),
        (New-SummaryRow -Category 'GPO Link Rows'                     -Count $gpoLinks.Count                         -Notes 'Mock GPO data'),
        (New-SummaryRow -Category 'Trust Rows'                        -Count $trusts.Count                           -Notes 'Mock trust data'),
        (New-SummaryRow -Category 'LAPS Overview Rows'                -Count $laps.Count                             -Notes 'From cached computer objects')
    )
    Export-Report -Data $summaryRows -Path (Join-Path $runPath '99-Summary.csv')

    # ── README ──
    @"
AD Privilege Escalation Analyzer - TEST HARNESS Output
======================================================
THIS OUTPUT WAS GENERATED FROM MOCK DATA - NOT A REAL AD ENVIRONMENT.

Run path : $runPath
Executed : $(Get-Date)
Domain   : $domainName ($domainNetBIOS) [SIMULATED]

Mock Environment Summary
────────────────────────
Users      : 25  (including admins, service accounts, stale accounts, delegation abuse)
Computers  : 10  (including DCs, unconstrained/constrained delegation, LAPS mixed)
Groups     : 21  (19 well-known + 2 custom nested groups for recursion testing)

Deliberate Misconfigurations Seeded
────────────────────────────────────
1.  DCSync rights on svc_replication          -> should appear as CRITICAL in unified
2.  Kerberoastable admin (svc_sql in DA)      -> HIGH Kerberoast finding
3.  Kerberoastable non-admin (svc_web)        -> MEDIUM Kerberoast finding
4.  Kerberoastable nested admin (svc_monitor) -> HIGH Kerberoast + Tier0 path
5.  AS-REP Roastable (temp.contractor)        -> MEDIUM AS-REP finding
6.  Unconstrained delegation user (svc_exchange)         -> HIGH
7.  Constrained delegation user (svc_proxy)              -> MEDIUM
8.  Unconstrained delegation computer (APP-SERVER01)     -> HIGH
9.  Constrained delegation computer (WEB01)              -> MEDIUM
10. Stale DA: old.admin (pwd 500d, logon 400d)           -> HIGH stale
11. Stale DA: setup.admin (pwd 600d, never logged in)    -> HIGH stale
12. Stale Schema Admin: schema.admin (pwd 800d, logon 700d) -> HIGH stale
13. Stale Backup Op: svc_backup (pwd 300d, logon 250d)  -> HIGH stale
14. Orphaned adminCount: former.admin (not in any group) -> MEDIUM orphan
15. 3-level nesting: IT-Admins -> Server-Ops-Custom -> Domain Admins
16. AdminSDHolder ACL: svc_exchange has GenericAll       -> HIGH ACL
17. AdminSDHolder ACL: helpdesk.lead has WriteDacl       -> HIGH ACL
18. DA group: svc_monitor has WriteOwner                 -> HIGH ACL
19. DA group: dns.admin can WriteMember                  -> MEDIUM ACL
20. Domain root: svc_proxy has ResetPassword             -> HIGH ACL
21. OU Servers: helpdesk.lead has GenericWrite            -> MEDIUM ACL
22. 2 computers with no LAPS (FILE02, WKS003)
23. 2 AD trusts (1 external, 1 parent-child)
24. 4 GPO links (1 disabled)

Validation Checklist
────────────────────
[ ] 98-Unified-Findings.csv has CRITICAL/HIGH/MEDIUM findings
[ ] Nested group chain appears in 02-Recursive-Membership and 03-Tier0
[ ] Stale accounts appear in 09-Stale with correct reasons
[ ] DCSync appears in 08-DCSync with svc_replication flagged Critical
[ ] former.admin appears as orphaned adminCount in unified
[ ] LAPS shows FILE02 and WKS003 as AnyLAPSDetected=False
[ ] Delegation summary includes both user and computer findings
[ ] All 19 well-known groups appear in 01-Privileged-Groups.csv
"@ | Set-Content -Path (Join-Path $runPath 'README.txt') -Encoding UTF8

    $totalSw.Stop()
    Write-Log "Test harness complete in $([math]::Round($totalSw.Elapsed.TotalSeconds, 1))s. Output: $runPath" 'SUCCESS'

    # ── Console Summary ──
    # Always show for test harness
    Write-Host ''
    Write-Host '+============================================================+' -ForegroundColor Magenta
    Write-Host '|   AD Privilege Escalation Analyzer - Test Results           |' -ForegroundColor Magenta
    Write-Host '+============================================================+' -ForegroundColor Magenta
    Write-Host ''

    if ($criticalCount -gt 0) { Write-Host "  CRITICAL : $criticalCount findings" -ForegroundColor Red }
    if ($highCount -gt 0)     { Write-Host "  HIGH     : $highCount findings" -ForegroundColor Yellow }
    if ($mediumCount -gt 0)   { Write-Host "  MEDIUM   : $mediumCount findings" -ForegroundColor Cyan }
    Write-Host ''
    $summaryRows | Where-Object { $_.Category -ne '---' } | Format-Table -AutoSize
    Write-Host "  Output Path: $runPath" -ForegroundColor Green
    Write-Host ''

    # ── Quick validation checks ──
    Write-Host '-- Automated Validation --' -ForegroundColor Yellow
    $pass = 0; $fail = 0

    function Assert-Test {
        param([string]$Label, [bool]$Condition)
        if ($Condition) {
            Write-Host "  [PASS] $Label" -ForegroundColor Green
            $script:passCount++
        } else {
            Write-Host "  [FAIL] $Label" -ForegroundColor Red
            $script:failCount++
        }
    }
    $script:passCount = 0
    $script:failCount = 0

    Assert-Test 'Privileged groups found (expect 19)'          (@($privilegedGroups).Count -eq 19)
    Assert-Test 'Tier 0 indicators found (expect > 0)'        ($tierZeroPaths.Count -gt 0)
    Assert-Test 'Nested members found (expect > 0)'           (@($privilegedMembershipRows).Count -gt 0)
    Assert-Test 'DCSync finding includes svc_replication'      ($dcsyncFindings | Where-Object { $_.Principal -match 'svc_replication' -and $_.Severity -eq 'Critical' })
    Assert-Test 'DCSync expected principals marked INFO'       (($dcsyncFindings | Where-Object { $_.Severity -eq 'INFO' }).Count -ge 2)
    Assert-Test 'Kerberoastable users found (expect >= 3)'    (($userRisks | Where-Object { $_.RiskType -eq 'KerberoastableUser' }).Count -ge 3)
    Assert-Test 'AS-REP roastable user found'                 (($userRisks | Where-Object { $_.RiskType -eq 'ASREPRoastableUser' }).Count -ge 1)
    Assert-Test 'Unconstrained delegation user found'         (($userRisks | Where-Object { $_.RiskType -eq 'UnconstrainedDelegationUser' }).Count -ge 1)
    Assert-Test 'Constrained delegation user found'           (($userRisks | Where-Object { $_.RiskType -eq 'ConstrainedDelegationUser' }).Count -ge 1)
    Assert-Test 'Unconstrained delegation computer found'     (($computerRisks | Where-Object { $_.RiskType -eq 'UnconstrainedDelegationComputer' }).Count -ge 1)
    Assert-Test 'Constrained delegation computer found'       (($computerRisks | Where-Object { $_.RiskType -eq 'ConstrainedDelegationComputer' }).Count -ge 1)
    Assert-Test 'Stale privileged accounts found (expect >= 2)' ($staleAccounts.Count -ge 2)
    Assert-Test 'Orphaned adminCount found (former.admin)'    (($unifiedFindings | Where-Object { $_.FindingType -eq 'Orphaned AdminCount Account' -and $_.SamAccountName -eq 'former.admin' }).Count -eq 1)
    Assert-Test 'AdminSDHolder ACL risks found'               ($adminSdHolderRisks.Count -ge 1)
    Assert-Test 'Domain/OU/Group ACL risks found'             ($domainAclRisks.Count -ge 1)
    Assert-Test 'LAPS coverage shows non-LAPS machines'       (($laps | Where-Object { $_.AnyLAPSDetected -eq $false }).Count -ge 2)
    Assert-Test 'Trust overview has 2 trusts'                 ($trusts.Count -eq 2)
    Assert-Test 'GPO links found (expect 4)'                  ($gpoLinks.Count -eq 4)
    Assert-Test 'Unified findings has CRITICAL entries'       ($criticalCount -ge 1)
    Assert-Test 'Unified findings has HIGH entries'           ($highCount -ge 1)
    Assert-Test 'Unified findings has MEDIUM entries'         ($mediumCount -ge 1)
    Assert-Test 'Nesting depth > 1 in recursive membership'  (($privilegedMembershipRows | Where-Object { $_.NestingDepth -gt 1 }).Count -gt 0)
    Assert-Test 'Delegation summary includes user+computer'   (($delegationSummary | Where-Object { $_.RiskType -match 'User' }).Count -ge 1 -and ($delegationSummary | Where-Object { $_.RiskType -match 'Computer' }).Count -ge 1)

    Write-Host ''
    Write-Host "  Results: $($script:passCount) passed, $($script:failCount) failed" -ForegroundColor $(if ($script:failCount -eq 0) { 'Green' } else { 'Red' })
    Write-Host ''
}
catch {
    Write-Log $_.Exception.Message 'ERROR'
    throw
}
