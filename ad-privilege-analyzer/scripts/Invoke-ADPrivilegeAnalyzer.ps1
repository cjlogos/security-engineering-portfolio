<#
.SYNOPSIS
    AD Privilege Escalation Analyzer - Identifies privilege escalation risks in Active Directory.

.DESCRIPTION
    Performs automated enumeration of AD objects and highlights privilege escalation risks
    commonly abused during post-compromise attack paths. Checks include:

    - Domain Admin inheritance chains (recursive nested group membership)
    - Unconstrained and constrained delegation
    - AdminCount=1 objects and AdminSDHolder ACL abuse
    - Kerberoastable and AS-REP roastable accounts
    - DCSync-capable principals (DS-Replication extended rights)
    - Stale privileged accounts (password age, last logon)
    - GPO link mapping, trust overview, LAPS coverage
    - ACL-based escalation on domain root, OUs, and privileged groups

    Produces both detailed per-check CSVs and a unified findings summary matching
    the format: FindingType, Name, SamAccountName, Risk

.PARAMETER OutputPath
    Root folder for output. A timestamped subfolder is created per run.

.PARAMETER StalePasswordDays
    Accounts with passwords older than this many days are flagged as stale. Default: 365.

.PARAMETER StaleLogonDays
    Accounts that have not logged on in this many days are flagged as stale. Default: 180.

.PARAMETER IncludeAclScan
    Enable ACL scanning on AdminSDHolder, domain root, OUs, and privileged groups.

.PARAMETER IncludeDelegationScan
    Produce a consolidated delegation summary CSV.

.PARAMETER IncludeTrustScan
    Enumerate AD trust relationships.

.PARAMETER IncludeLapsCheck
    Check LAPS coverage across computer objects.

.PARAMETER IncludeGpoLinkScan
    Map GPO links to OUs and domain root.

.PARAMETER ShowConsoleSummary
    Display a summary table in the console after completion.

.EXAMPLE
    .\Invoke-ADPrivilegeAnalyzer.ps1 -IncludeAclScan -ShowConsoleSummary

.EXAMPLE
    .\Invoke-ADPrivilegeAnalyzer.ps1 -IncludeAclScan -IncludeDelegationScan -IncludeTrustScan -IncludeLapsCheck -IncludeGpoLinkScan -StalePasswordDays 180 -ShowConsoleSummary

.NOTES
    Requires: ActiveDirectory PowerShell module (RSAT).
    Run from a domain-joined machine with read access to AD.
    Author: Improved by Claude from ChatGPT-generated base.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = 'C:\caltech\AD-Privilege-Escalation-Analyzer',
    [int]$StalePasswordDays = 365,
    [int]$StaleLogonDays = 180,
    [switch]$IncludeAclScan,
    [switch]$IncludeDelegationScan,
    [switch]$IncludeTrustScan,
    [switch]$IncludeLapsCheck,
    [switch]$IncludeGpoLinkScan,
    [switch]$ShowConsoleSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ─────────────────────────────────────────────
# Region: Logging and Utility Functions
# ─────────────────────────────────────────────

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

function Convert-IdentityReferenceToSam {
    param([object]$IdentityReference)
    try {
        if ($null -eq $IdentityReference) { return $null }
        $value = $IdentityReference.Value
        if ([string]::IsNullOrWhiteSpace($value)) { return $null }
        if ($value -match '^S-1-') {
            try {
                $sid = New-Object System.Security.Principal.SecurityIdentifier($value)
                return ($sid.Translate([System.Security.Principal.NTAccount])).Value
            }
            catch { return $value }
        }
        return $value
    }
    catch { return $null }
}

# ─────────────────────────────────────────────
# Region: AD Context and Module Check
# ─────────────────────────────────────────────

function Ensure-ActiveDirectoryModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw 'The ActiveDirectory PowerShell module is not installed. Install RSAT / AD PowerShell tools and try again.'
    }
    Import-Module ActiveDirectory -ErrorAction Continue
}

function Get-RootDSEInfo {
    try { return [ADSI]'LDAP://RootDSE' }
    catch { throw 'Unable to bind to LDAP://RootDSE. Run this from a domain-joined system with access to Active Directory.' }
}

function Get-DomainContext {
    $root = Get-RootDSEInfo
    $domainDn = [string]$root.defaultNamingContext
    $configDn = [string]$root.configurationNamingContext
    $schemaDn = [string]$root.schemaNamingContext

    try {
        $domain = Get-ADDomain -Identity $domainDn -ErrorAction Continue
        $forest = Get-ADForest -ErrorAction Continue
    }
    catch {
        Write-Log 'Failed to query Get-ADDomain / Get-ADForest. Some fields may be blank.' 'WARN'
        $domain = $null
        $forest = $null
    }

    [pscustomobject]@{
        RootDSE   = $root
        DomainDN  = $domainDn
        ConfigDN  = $configDn
        SchemaDN  = $schemaDn
        Domain    = $domain
        Forest    = $forest
    }
}

# ─────────────────────────────────────────────
# Region: Object Cache (Performance Optimization)
# ─────────────────────────────────────────────
# Fetches all users, computers, and groups in bulk up front,
# then lookups are done from the hashtable instead of per-object
# LDAP queries during recursion.

$script:ObjectCache = @{}
$script:GroupMemberCache = @{}

function Initialize-ObjectCache {
    param([string]$DomainDn)

    Write-Log 'Building object cache (bulk LDAP queries)...'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    # Cache all users
    try {
        $users = Get-ADUser -Filter * -SearchBase $DomainDn -Properties `
            samAccountName, objectClass, objectSid, adminCount, distinguishedName, name,
            servicePrincipalName, userAccountControl, DoesNotRequirePreAuth,
            TrustedForDelegation, TrustedToAuthForDelegation, 'msDS-AllowedToDelegateTo',
            pwdLastSet, lastLogonTimestamp, memberof, Enabled, whenCreated, whenChanged `
            -ErrorAction Continue

        foreach ($u in $users) {
            $script:ObjectCache[$u.DistinguishedName] = $u
        }
        Write-Log "  Cached $(@($users).Count) user objects." 'INFO'
    }
    catch { Write-Log "Failed to cache users: $($_.Exception.Message)" 'WARN' }

    # Cache all computers
    try {
        $computers = Get-ADComputer -Filter * -SearchBase $DomainDn -Properties `
            samAccountName, objectClass, objectSid, adminCount, distinguishedName, name,
            TrustedForDelegation, TrustedToAuthForDelegation, 'msDS-AllowedToDelegateTo',
            operatingSystem, lastLogonTimestamp, servicePrincipalName, PrimaryGroupID,
            'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime', 'msLAPS-EncryptedPassword',
            whenCreated, whenChanged `
            -ErrorAction Continue

        foreach ($c in $computers) {
            $script:ObjectCache[$c.DistinguishedName] = $c
        }
        Write-Log "  Cached $(@($computers).Count) computer objects." 'INFO'
    }
    catch { Write-Log "Failed to cache computers: $($_.Exception.Message)" 'WARN' }

    # Cache all groups with their member lists
    try {
        $groups = Get-ADGroup -Filter * -SearchBase $DomainDn -Properties `
            samAccountName, objectClass, objectSid, adminCount, distinguishedName, name,
            member, managedBy, groupScope, groupCategory, description,
            whenCreated, whenChanged `
            -ErrorAction Continue

        foreach ($g in $groups) {
            $script:ObjectCache[$g.DistinguishedName] = $g
            $script:GroupMemberCache[$g.DistinguishedName] = @($g.member)
        }
        Write-Log "  Cached $(@($groups).Count) group objects." 'INFO'
    }
    catch { Write-Log "Failed to cache groups: $($_.Exception.Message)" 'WARN' }

    $sw.Stop()
    Write-Log "Object cache built in $([math]::Round($sw.Elapsed.TotalSeconds, 1))s. Total objects: $($script:ObjectCache.Count)" 'SUCCESS'
}

function Get-CachedObject {
    param([string]$DistinguishedName)
    if ($script:ObjectCache.ContainsKey($DistinguishedName)) {
        return $script:ObjectCache[$DistinguishedName]
    }
    # Fallback to live query if not cached (e.g. foreign security principals)
    try {
        $obj = Get-ADObject -Identity $DistinguishedName -Properties objectClass, name, samAccountName, objectSid, adminCount, distinguishedName -ErrorAction Continue
        $script:ObjectCache[$DistinguishedName] = $obj
        return $obj
    }
    catch { return $null }
}

# ─────────────────────────────────────────────
# Region: Privileged Group Enumeration
# ─────────────────────────────────────────────

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
        if ($obj.objectClass -notmatch 'group') { continue }
        if ($targets -contains $obj.Name) {
            if ($seen.Add($obj.DistinguishedName)) {
                $results.Add($obj)
            }
        }
    }

    return $results | Sort-Object Name -Unique
}

# ─────────────────────────────────────────────
# Region: Recursive Group Membership (Cache-Based)
# ─────────────────────────────────────────────

function Get-RecursiveGroupMembers {
    param(
        [Parameter(Mandatory)] [string]$GroupDn,
        [Parameter(Mandatory)] [string]$RootGroupName
    )

    $visitedGroups = New-Object 'System.Collections.Generic.HashSet[string]'
    $results = New-Object System.Collections.Generic.List[object]

    function Expand-Group {
        param(
            [string]$CurrentGroupDn,
            [int]$Depth,
            [string[]]$PathSoFar
        )
        if ([string]::IsNullOrWhiteSpace($CurrentGroupDn)) { return }
        if (-not $visitedGroups.Add($CurrentGroupDn)) { return }

        $group = Get-CachedObject -DistinguishedName $CurrentGroupDn
        if (-not $group) { return }
        $groupSam = $group.samAccountName
        if (-not $groupSam) { $groupSam = $group.Name }

        $memberDns = @()
        if ($script:GroupMemberCache.ContainsKey($CurrentGroupDn)) {
            $memberDns = $script:GroupMemberCache[$CurrentGroupDn]
        }

        foreach ($memberDn in $memberDns) {
            $memberObj = Get-CachedObject -DistinguishedName $memberDn
            if (-not $memberObj) { continue }

            $memberName = if ($memberObj.Name) { $memberObj.Name } else { $memberObj.samAccountName }
            $currentPath = @($PathSoFar + $groupSam + $memberName)
            $pathText = $currentPath -join ' -> '

            # Determine objectClass - handle multi-valued
            $objClass = $memberObj.objectClass
            if ($objClass -is [array]) {
                if ($objClass -contains 'user')     { $objClass = 'user' }
                elseif ($objClass -contains 'computer') { $objClass = 'computer' }
                elseif ($objClass -contains 'group') { $objClass = 'group' }
                elseif ($objClass -contains 'msDS-GroupManagedServiceAccount') { $objClass = 'msDS-GroupManagedServiceAccount' }
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
                Path                    = $pathText
            })

            if ($objClass -eq 'group') {
                Expand-Group -CurrentGroupDn $memberObj.DistinguishedName -Depth ($Depth + 1) -PathSoFar ($PathSoFar + $groupSam)
            }
        }
    }

    Expand-Group -CurrentGroupDn $GroupDn -Depth 0 -PathSoFar @()
    return $results
}

# ─────────────────────────────────────────────
# Region: Upward Group Trace
# ─────────────────────────────────────────────

function Get-UpwardGroupTrace {
    param([string]$ObjectDn)

    $visited = New-Object 'System.Collections.Generic.HashSet[string]'
    $results = New-Object System.Collections.Generic.List[object]

    function Expand-Up {
        param(
            [string]$CurrentDn,
            [int]$Depth,
            [string[]]$Path
        )
        if ([string]::IsNullOrWhiteSpace($CurrentDn)) { return }

        try {
            $parents = Get-ADPrincipalGroupMembership -Identity $CurrentDn -ErrorAction Continue
        }
        catch {
            Write-Log "Upward trace failed for '$CurrentDn': $($_.Exception.Message)" 'WARN'
            return
        }

        foreach ($parent in $parents) {
            if (-not $visited.Add($parent.DistinguishedName)) { continue }
            $newPath = @($Path + $parent.SamAccountName)
            $results.Add([pscustomobject]@{
                SourceObjectDN       = $ObjectDn
                ParentGroup          = $parent.SamAccountName
                ParentGroupDN        = $parent.DistinguishedName
                ParentGroupSID       = $parent.SID.Value
                ParentGroupScope     = $parent.GroupScope
                ParentGroupCategory  = $parent.GroupCategory
                Depth                = $Depth + 1
                Path                 = $newPath -join ' -> '
            })
            Expand-Up -CurrentDn $parent.DistinguishedName -Depth ($Depth + 1) -Path $newPath
        }
    }

    Expand-Up -CurrentDn $ObjectDn -Depth 0 -Path @()
    return $results
}

# ─────────────────────────────────────────────
# Region: ACL Risk Analysis
# ─────────────────────────────────────────────

# Well-known extended rights GUIDs for risk tagging
$script:ExtendedRightsMap = @{
    '00299570-246d-11d0-a768-00aa006e0529' = 'ResetPassword'
    'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'WriteMember'
    '4c164200-20c0-11d0-a768-00aa006e0529' = 'User-Force-Change-Password'
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
    'ab721a53-1e2f-11d0-9819-00aa0040529b' = 'User-Change-Password'
    '00000000-0000-0000-0000-000000000000' = 'AllExtendedRights'
}

function Convert-ADRightsToRisk {
    param(
        [string]$Rights,
        [string]$ObjectTypeGuid,
        [string]$InheritedObjectTypeGuid
    )

    $riskTags = New-Object System.Collections.Generic.List[string]

    if ($Rights -match 'GenericAll')      { $riskTags.Add('GenericAll') }
    if ($Rights -match 'GenericWrite')    { $riskTags.Add('GenericWrite') }
    if ($Rights -match 'WriteDacl')       { $riskTags.Add('WriteDacl') }
    if ($Rights -match 'WriteOwner')      { $riskTags.Add('WriteOwner') }
    if ($Rights -match 'CreateChild')     { $riskTags.Add('CreateChild') }
    if ($Rights -match 'DeleteChild')     { $riskTags.Add('DeleteChild') }
    if ($Rights -match 'ExtendedRight')   { $riskTags.Add('ExtendedRight') }
    if ($Rights -match 'Self')            { $riskTags.Add('Self') }

    # Map known extended rights GUIDs
    if ($ObjectTypeGuid -and $script:ExtendedRightsMap.ContainsKey($ObjectTypeGuid)) {
        $riskTags.Add($script:ExtendedRightsMap[$ObjectTypeGuid])
    }

    return ($riskTags | Sort-Object -Unique) -join ','
}

function Test-IsInterestingPrincipal {
    param([string]$IdentityReference)
    if ([string]::IsNullOrWhiteSpace($IdentityReference)) { return $false }

    $safeBuiltIns = @(
        'NT AUTHORITY\SYSTEM',
        'BUILTIN\Administrators',
        'BUILTIN\Pre-Windows 2000 Compatible Access',
        'NT AUTHORITY\Authenticated Users',
        'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS',
        'Everyone',
        'SELF',
        'CREATOR OWNER'
    )

    return ($safeBuiltIns -notcontains $IdentityReference)
}

function Get-ObjectAclRisks {
    param(
        [Parameter(Mandatory)] [string]$DistinguishedName,
        [Parameter(Mandatory)] [string]$ObjectLabel,
        [Parameter(Mandatory)] [string]$ObjectCategory
    )

    $result = New-Object System.Collections.Generic.List[object]

    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DistinguishedName")
        $acl = $entry.ObjectSecurity
        $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    }
    catch {
        Write-Log "Failed to read ACL on $DistinguishedName" 'WARN'
        return $result
    }

    foreach ($rule in $rules) {
        try {
            $identity = Convert-IdentityReferenceToSam -IdentityReference $rule.IdentityReference
            if (-not (Test-IsInterestingPrincipal -IdentityReference $identity)) { continue }
            if ($rule.AccessControlType -ne 'Allow') { continue }

            $rights = [string]$rule.ActiveDirectoryRights
            $objectType = if ($rule.ObjectType -and $rule.ObjectType -ne [guid]::Empty) { $rule.ObjectType.Guid } else { $null }
            $inheritedObjectType = if ($rule.InheritedObjectType -and $rule.InheritedObjectType -ne [guid]::Empty) { $rule.InheritedObjectType.Guid } else { $null }
            $riskTags = Convert-ADRightsToRisk -Rights $rights -ObjectTypeGuid $objectType -InheritedObjectTypeGuid $inheritedObjectType

            if ([string]::IsNullOrWhiteSpace($riskTags)) { continue }

            $result.Add([pscustomobject]@{
                ObjectName            = $ObjectLabel
                ObjectCategory        = $ObjectCategory
                DistinguishedName     = $DistinguishedName
                IdentityReference     = $identity
                Rights                = $rights
                AccessControlType     = [string]$rule.AccessControlType
                IsInherited           = $rule.IsInherited
                InheritanceType       = [string]$rule.InheritanceType
                ObjectTypeGuid        = $objectType
                InheritedObjectType   = $inheritedObjectType
                RiskTags              = $riskTags
            })
        }
        catch {
            Write-Log "Failed to parse an ACL rule on $DistinguishedName" 'WARN'
        }
    }

    return $result
}

# ─────────────────────────────────────────────
# Region: DCSync Detection
# ─────────────────────────────────────────────

function Get-DCSyncCapablePrincipals {
    param([string]$DomainDn)

    Write-Log 'Checking for DCSync-capable principals on domain root...'

    $result = New-Object System.Collections.Generic.List[object]

    # The GUIDs that together allow DCSync
    $getChangesGuid    = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    $getChangesAllGuid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainDn")
        $acl = $entry.ObjectSecurity
        $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    }
    catch {
        Write-Log "Failed to read domain root ACL for DCSync check: $($_.Exception.Message)" 'WARN'
        return $result
    }

    # Build a map of principal -> which replication rights they hold
    $principalRights = @{}

    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        $rights = [string]$rule.ActiveDirectoryRights
        $objectType = if ($rule.ObjectType -and $rule.ObjectType -ne [guid]::Empty) { $rule.ObjectType.Guid } else { $null }

        # Check for GenericAll (implies all extended rights) or specific replication GUIDs
        $hasGetChanges = $false
        $hasGetChangesAll = $false

        if ($rights -match 'GenericAll') {
            $hasGetChanges = $true
            $hasGetChangesAll = $true
        }
        if ($objectType -eq $getChangesGuid)    { $hasGetChanges = $true }
        if ($objectType -eq $getChangesAllGuid)  { $hasGetChangesAll = $true }
        # AllExtendedRights also grants both
        if (($rights -match 'ExtendedRight') -and ($objectType -eq '00000000-0000-0000-0000-000000000000' -or $null -eq $objectType)) {
            $hasGetChanges = $true
            $hasGetChangesAll = $true
        }

        if (-not ($hasGetChanges -or $hasGetChangesAll)) { continue }

        $identity = Convert-IdentityReferenceToSam -IdentityReference $rule.IdentityReference
        if ([string]::IsNullOrWhiteSpace($identity)) { continue }

        if (-not $principalRights.ContainsKey($identity)) {
            $principalRights[$identity] = @{ GetChanges = $false; GetChangesAll = $false }
        }
        if ($hasGetChanges)    { $principalRights[$identity].GetChanges = $true }
        if ($hasGetChangesAll) { $principalRights[$identity].GetChangesAll = $true }
    }

    # A principal can DCSync if they have BOTH rights
    foreach ($principal in $principalRights.Keys) {
        $r = $principalRights[$principal]
        if ($r.GetChanges -and $r.GetChangesAll) {
            # Determine if this is an expected/safe principal
            $expected = $principal -match '(?i)(Domain Controllers|Enterprise Domain Controllers|SYSTEM|Administrators)'
            $severity = if ($expected) { 'INFO' } else { 'Critical' }

            $result.Add([pscustomobject]@{
                Principal          = $principal
                HasGetChanges      = $true
                HasGetChangesAll   = $true
                CanDCSync          = $true
                Severity           = $severity
                Notes              = if ($expected) { 'Expected built-in principal' } else { 'NON-DEFAULT DCSync rights - investigate immediately' }
            })
        }
    }

    $nonDefault = @($result | Where-Object { $_.Severity -ne 'INFO' })
    if ($nonDefault.Count -gt 0) {
        Write-Log "ALERT: Found $($nonDefault.Count) non-default DCSync-capable principal(s)!" 'WARN'
    }
    else {
        Write-Log 'No non-default DCSync-capable principals found.' 'SUCCESS'
    }

    return $result
}

# ─────────────────────────────────────────────
# Region: Stale Privileged Account Detection
# ─────────────────────────────────────────────

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

    # Get unique user DNs from privileged membership
    $privilegedUserDns = $PrivilegedMembershipRows |
        Where-Object { $_.MemberClass -eq 'user' } |
        Select-Object -ExpandProperty MemberDistinguishedName -Unique

    foreach ($dn in $privilegedUserDns) {
        $user = Get-CachedObject -DistinguishedName $dn
        if (-not $user) { continue }

        $pwdLastSet = $null
        $lastLogon = $null
        $staleReasons = New-Object System.Collections.Generic.List[string]

        # Parse pwdLastSet
        if ($user.pwdLastSet) {
            try {
                if ($user.pwdLastSet -is [long] -or $user.pwdLastSet -is [int64]) {
                    $pwdLastSet = [DateTime]::FromFileTimeUtc($user.pwdLastSet)
                }
                else {
                    $pwdLastSet = [DateTime]$user.pwdLastSet
                }
            }
            catch { $pwdLastSet = $null }
        }

        # Parse lastLogonTimestamp
        if ($user.lastLogonTimestamp) {
            try {
                if ($user.lastLogonTimestamp -is [long] -or $user.lastLogonTimestamp -is [int64]) {
                    $lastLogon = [DateTime]::FromFileTimeUtc($user.lastLogonTimestamp)
                }
                else {
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
        elseif (-not $lastLogon) {
            $staleReasons.Add('No logon timestamp recorded')
        }

        if ($staleReasons.Count -eq 0) { continue }

        # Determine which privileged groups this user is in
        $groups = @($PrivilegedMembershipRows |
            Where-Object { $_.MemberDistinguishedName -eq $dn } |
            Select-Object -ExpandProperty RootPrivilegedGroup -Unique) -join '; '

        $isEnabled = $true
        if ($null -ne $user.Enabled) { $isEnabled = $user.Enabled }

        $results.Add([pscustomobject]@{
            SamAccountName       = $user.samAccountName
            Name                 = $user.Name
            DistinguishedName    = $dn
            Enabled              = $isEnabled
            PrivilegedGroups     = $groups
            PasswordLastSet      = $pwdLastSet
            LastLogonTimestamp   = $lastLogon
            StaleReasons         = ($staleReasons -join '; ')
            Severity             = if ($staleReasons.Count -ge 2) { 'High' } else { 'Medium' }
        })
    }

    Write-Log "Found $($results.Count) stale privileged account(s)." $(if ($results.Count -gt 0) { 'WARN' } else { 'SUCCESS' })
    return $results
}

# ─────────────────────────────────────────────
# Region: User and Computer Risk Checks
# ─────────────────────────────────────────────

function Get-AdminCountObjects {
    param([string]$DomainDn)
    try {
        $script:ObjectCache.Values | Where-Object { $_.adminCount -eq 1 } |
            Select-Object @{n='Name';e={$_.Name}}, samAccountName, objectClass, distinguishedName, adminCount, whenCreated, whenChanged
    }
    catch {
        Write-Log 'Failed to enumerate adminCount=1 objects.' 'WARN'
        @()
    }
}

function Get-InterestingUserRisks {
    param([string]$DomainDn)

    $findings = New-Object System.Collections.Generic.List[object]

    $users = $script:ObjectCache.Values | Where-Object {
        $oc = $_.objectClass
        if ($oc -is [array]) { $oc -contains 'user' -and $oc -notcontains 'computer' }
        else { $oc -eq 'user' }
    }

    foreach ($user in $users) {
        try {
            if ($user.servicePrincipalName) {
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

            if ($user.TrustedToAuthForDelegation -eq $true -or $user.'msDS-AllowedToDelegateTo') {
                $findings.Add([pscustomobject]@{
                    RiskType          = 'ConstrainedDelegationUser'
                    SamAccountName    = $user.samAccountName
                    DistinguishedName = $user.DistinguishedName
                    Detail            = ($user.'msDS-AllowedToDelegateTo' -join '; ')
                    Severity          = 'Medium'
                })
            }
        }
        catch {
            Write-Log "Failed to evaluate user '$($user.samAccountName)' for risk checks." 'WARN'
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
        try {
            if ($computer.TrustedForDelegation -eq $true) {
                $findings.Add([pscustomobject]@{
                    RiskType          = 'UnconstrainedDelegationComputer'
                    SamAccountName    = $computer.samAccountName
                    DistinguishedName = $computer.DistinguishedName
                    Detail            = $computer.operatingSystem
                    Severity          = 'High'
                })
            }

            if ($computer.TrustedToAuthForDelegation -eq $true -or $computer.'msDS-AllowedToDelegateTo') {
                $findings.Add([pscustomobject]@{
                    RiskType          = 'ConstrainedDelegationComputer'
                    SamAccountName    = $computer.samAccountName
                    DistinguishedName = $computer.DistinguishedName
                    Detail            = ($computer.'msDS-AllowedToDelegateTo' -join '; ')
                    Severity          = 'Medium'
                })
            }
        }
        catch {
            Write-Log "Failed to evaluate computer '$($computer.samAccountName)' for risk checks." 'WARN'
        }
    }

    return $findings
}

# ─────────────────────────────────────────────
# Region: Tier 0 Indicators
# ─────────────────────────────────────────────

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

# ─────────────────────────────────────────────
# Region: ACL Scans (AdminSDHolder, Domain, OUs, Groups)
# ─────────────────────────────────────────────

function Get-AdminSDHolderAclRisks {
    param([string]$DomainDn)
    $dn = "CN=AdminSDHolder,CN=System,$DomainDn"
    return Get-ObjectAclRisks -DistinguishedName $dn -ObjectLabel 'AdminSDHolder' -ObjectCategory 'AdminSDHolder'
}

function Get-DomainObjectAclRisks {
    param([string]$DomainDn)

    $risks = New-Object System.Collections.Generic.List[object]
    $risks.AddRange((Get-ObjectAclRisks -DistinguishedName $DomainDn -ObjectLabel 'Domain Root' -ObjectCategory 'Domain'))

    try {
        $ous = Get-ADOrganizationalUnit -Filter * -SearchBase $DomainDn -Properties distinguishedName, name -ErrorAction Continue
        foreach ($ou in $ous) {
            $ouRisks = Get-ObjectAclRisks -DistinguishedName $ou.DistinguishedName -ObjectLabel $ou.Name -ObjectCategory 'OU'
            foreach ($row in $ouRisks) { $risks.Add($row) }
        }
    }
    catch { Write-Log 'Failed to enumerate OU ACLs.' 'WARN' }

    $criticalGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','DnsAdmins','Group Policy Creator Owners')

    try {
        foreach ($dn in $script:ObjectCache.Keys) {
            $obj = $script:ObjectCache[$dn]
            if ($obj.objectClass -notmatch 'group') { continue }
            if ($obj.Name -in $criticalGroups) {
                $groupRisks = Get-ObjectAclRisks -DistinguishedName $obj.DistinguishedName -ObjectLabel $obj.Name -ObjectCategory 'PrivilegedGroup'
                foreach ($row in $groupRisks) { $risks.Add($row) }
            }
        }
    }
    catch { Write-Log 'Failed to enumerate privileged group ACLs.' 'WARN' }

    return $risks
}

# ─────────────────────────────────────────────
# Region: GPO Links, Trusts, LAPS
# ─────────────────────────────────────────────

function Get-GpoLinkOverview {
    param([string]$DomainDn)

    $rows = New-Object System.Collections.Generic.List[object]

    try {
        $containers = Get-ADObject -LDAPFilter '(|(objectClass=organizationalUnit)(objectClass=domainDNS))' -SearchBase $DomainDn -Properties gPLink, name, distinguishedName -ErrorAction Continue
    }
    catch {
        Write-Log 'Failed to enumerate GPO link data.' 'WARN'
        return $rows
    }

    foreach ($container in $containers) {
        $gpLink = [string]$container.gPLink
        if ([string]::IsNullOrWhiteSpace($gpLink)) { continue }

        $matches = [regex]::Matches($gpLink, '\[LDAP://(?<dn>[^;\]]+);(?<status>\d+)\]')
        foreach ($match in $matches) {
            $gpoDn = $match.Groups['dn'].Value
            $status = $match.Groups['status'].Value
            $enabled = $status -in @('0','2')
            $enforced = $status -in @('2','3')

            $gpoName = $null
            try {
                $gpo = Get-ADObject -Identity $gpoDn -Properties displayName -ErrorAction Continue
                $gpoName = $gpo.displayName
            }
            catch {}

            $rows.Add([pscustomobject]@{
                LinkedTargetName = $container.Name
                LinkedTargetDN   = $container.DistinguishedName
                GpoDisplayName   = $gpoName
                GpoDN            = $gpoDn
                LinkEnabled      = $enabled
                LinkEnforced     = $enforced
            })
        }
    }

    return $rows
}

function Get-TrustOverview {
    try {
        Get-ADTrust -Filter * -ErrorAction Continue |
            Select-Object Name, Source, Target, Direction, TrustType, ForestTransitive,
                SelectiveAuthentication, SIDFilteringQuarantined, IntraForest
    }
    catch {
        Write-Log 'Failed to enumerate AD trusts.' 'WARN'
        @()
    }
}

function Get-LapsOverview {
    param([string]$DomainDn)

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
            OperatingSystem = $computer.OperatingSystem
            LegacyLAPS      = $legacyLaps
            WindowsLAPS     = $windowsLaps
            AnyLAPSDetected = ($legacyLaps -or $windowsLaps)
        })
    }

    return $rows
}

# ─────────────────────────────────────────────
# Region: Unified Findings Summary
# ─────────────────────────────────────────────

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

    # Tier 0 membership
    foreach ($row in $TierZeroPaths) {
        $unified.Add([pscustomobject]@{
            FindingType     = "$($row.RootPrivilegedGroup) Member"
            Name            = $row.MemberName
            SamAccountName  = $row.MemberSamAccountName
            Risk            = 'HIGH'
            Detail          = "Nested depth: $($row.NestingDepth) | Path: $($row.Path)"
            ObjectClass     = $row.MemberClass
        })
    }

    # User risks (Kerberoast, ASREP, delegation)
    foreach ($row in $UserRisks) {
        $unified.Add([pscustomobject]@{
            FindingType     = $row.RiskType
            Name            = $row.SamAccountName
            SamAccountName  = $row.SamAccountName
            Risk            = $row.Severity.ToUpper()
            Detail          = $row.Detail
            ObjectClass     = 'user'
        })
    }

    # Computer risks
    foreach ($row in $ComputerRisks) {
        $unified.Add([pscustomobject]@{
            FindingType     = $row.RiskType
            Name            = $row.SamAccountName
            SamAccountName  = $row.SamAccountName
            Risk            = $row.Severity.ToUpper()
            Detail          = $row.Detail
            ObjectClass     = 'computer'
        })
    }

    # DCSync
    foreach ($row in $DCSyncFindings) {
        if ($row.Severity -eq 'INFO') { continue }  # Skip expected principals in unified view
        $unified.Add([pscustomobject]@{
            FindingType     = 'DCSync-Capable Principal'
            Name            = $row.Principal
            SamAccountName  = $row.Principal
            Risk            = 'CRITICAL'
            Detail          = $row.Notes
            ObjectClass     = 'unknown'
        })
    }

    # Stale accounts
    foreach ($row in $StaleAccounts) {
        $unified.Add([pscustomobject]@{
            FindingType     = 'Stale Privileged Account'
            Name            = $row.Name
            SamAccountName  = $row.SamAccountName
            Risk            = $row.Severity.ToUpper()
            Detail          = "$($row.StaleReasons) | Groups: $($row.PrivilegedGroups)"
            ObjectClass     = 'user'
        })
    }

    # AdminCount orphans (objects with adminCount=1 that aren't in any privileged group)
    $privilegedSams = @($TierZeroPaths | Select-Object -ExpandProperty MemberSamAccountName -Unique)
    foreach ($obj in $AdminCountObjects) {
        if ($obj.samAccountName -notin $privilegedSams) {
            $unified.Add([pscustomobject]@{
                FindingType     = 'Orphaned AdminCount Account'
                Name            = $obj.Name
                SamAccountName  = $obj.samAccountName
                Risk            = 'MEDIUM'
                Detail          = 'adminCount=1 but not currently in a privileged group (possible stale SDProp stamp)'
                ObjectClass     = $obj.objectClass
            })
        }
    }

    # ACL-based risks (AdminSDHolder and domain/OU/group)
    foreach ($row in @($AdminSdHolderRisks) + @($DomainAclRisks)) {
        if ($null -eq $row) { continue }
        $unified.Add([pscustomobject]@{
            FindingType     = "ACL Risk on $($row.ObjectCategory): $($row.ObjectName)"
            Name            = $row.IdentityReference
            SamAccountName  = $row.IdentityReference
            Risk            = if ($row.RiskTags -match 'GenericAll|WriteDacl|WriteOwner|ResetPassword|DS-Replication') { 'HIGH' } else { 'MEDIUM' }
            Detail          = "Rights: $($row.Rights) | Tags: $($row.RiskTags)"
            ObjectClass     = 'acl-entry'
        })
    }

    return $unified | Sort-Object @{e={
        switch ($_.Risk) { 'CRITICAL' {0} 'HIGH' {1} 'MEDIUM' {2} 'LOW' {3} default {4} }
    }}, FindingType, SamAccountName
}

# ─────────────────────────────────────────────
# Region: Summary Row Helper
# ─────────────────────────────────────────────

function New-SummaryRow {
    param([string]$Category, [int]$Count, [string]$Notes)
    [pscustomobject]@{ Category = $Category; Count = $Count; Notes = $Notes }
}

# ═════════════════════════════════════════════
# MAIN EXECUTION
# ═════════════════════════════════════════════

try {
    $totalSw = [System.Diagnostics.Stopwatch]::StartNew()

    Ensure-ActiveDirectoryModule
    Ensure-Folder -Path $OutputPath

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $runPath = Join-Path $OutputPath "Run_$timestamp"
    Ensure-Folder -Path $runPath

    Write-Log 'Collecting Active Directory context...'
    $ctx = Get-DomainContext

    $domainName    = if ($ctx.Domain) { $ctx.Domain.DNSRoot } else { $env:USERDNSDOMAIN }
    $domainNetBIOS = if ($ctx.Domain) { $ctx.Domain.NetBIOSName } else { $env:USERDOMAIN }

    # ── Bulk cache all objects ──
    Initialize-ObjectCache -DomainDn $ctx.DomainDN

    # ── Metadata ──
    $metadata = [pscustomobject]@{
        RunTimestamp          = Get-Date
        DomainDNSRoot         = $domainName
        DomainNetBIOSName     = $domainNetBIOS
        DomainDN              = $ctx.DomainDN
        ForestName            = if ($ctx.Forest) { $ctx.Forest.Name } else { $null }
        ForestMode            = if ($ctx.Forest) { $ctx.Forest.ForestMode } else { $null }
        DomainMode            = if ($ctx.Domain) { $ctx.Domain.DomainMode } else { $null }
        PDCEmulator           = if ($ctx.Domain) { $ctx.Domain.PDCEmulator } else { $null }
        RIDMaster             = if ($ctx.Domain) { $ctx.Domain.RIDMaster } else { $null }
        InfrastructureMaster  = if ($ctx.Domain) { $ctx.Domain.InfrastructureMaster } else { $null }
        SchemaMaster          = if ($ctx.Forest) { $ctx.Forest.SchemaMaster } else { $null }
        DomainNamingMaster    = if ($ctx.Forest) { $ctx.Forest.DomainNamingMaster } else { $null }
        ExecutedBy            = "$env:USERDOMAIN\$env:USERNAME"
        ComputerName          = $env:COMPUTERNAME
        IncludeAclScan        = [bool]$IncludeAclScan
        IncludeDelegationScan = [bool]$IncludeDelegationScan
        IncludeTrustScan      = [bool]$IncludeTrustScan
        IncludeLapsCheck      = [bool]$IncludeLapsCheck
        IncludeGpoLinkScan    = [bool]$IncludeGpoLinkScan
        StalePasswordDays     = $StalePasswordDays
        StaleLogonDays        = $StaleLogonDays
    }
    Export-Report -Data @($metadata) -Path (Join-Path $runPath '00-Run-Metadata.csv')

    # ── Privileged Groups ──
    Write-Log 'Enumerating privileged groups...'
    $privilegedGroups = Get-WellKnownPrivilegedGroups -DomainDn $ctx.DomainDN |
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
        catch { Write-Log "Failed to recursively enumerate group '$($group.SamAccountName)'" 'WARN' }
    }

    $privilegedMembershipRows = $privilegedMembership | Sort-Object RootPrivilegedGroup, NestingDepth, MemberClass, MemberSamAccountName
    Export-Report -Data $privilegedMembershipRows -Path (Join-Path $runPath '02-Privileged-Group-Recursive-Membership.csv')

    # ── Tier 0 Indicators ──
    Write-Log 'Flagging Tier 0 / DA-equivalent paths...'
    $tierZeroPaths = Get-DomainTierZeroIndicators -GroupMembershipRows $privilegedMembershipRows
    Export-Report -Data $tierZeroPaths -Path (Join-Path $runPath '03-Tier0-Indicators.csv')

    # ── AdminCount Objects ──
    Write-Log 'Enumerating adminCount=1 objects...'
    $adminCountObjects = Get-AdminCountObjects -DomainDn $ctx.DomainDN
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
    $userRisks = Get-InterestingUserRisks -DomainDn $ctx.DomainDN
    Export-Report -Data $userRisks -Path (Join-Path $runPath '06-User-Risks.csv')

    # ── Computer Risks ──
    Write-Log 'Checking computer-based escalation indicators...'
    $computerRisks = Get-InterestingComputerRisks -DomainDn $ctx.DomainDN
    Export-Report -Data $computerRisks -Path (Join-Path $runPath '07-Computer-Risks.csv')

    # ── DCSync Detection (always runs) ──
    $dcsyncFindings = Get-DCSyncCapablePrincipals -DomainDn $ctx.DomainDN
    Export-Report -Data $dcsyncFindings -Path (Join-Path $runPath '08-DCSync-Capable-Principals.csv')

    # ── Stale Privileged Accounts (always runs) ──
    $staleAccounts = Get-StalePrivilegedAccounts -PrivilegedMembershipRows $privilegedMembershipRows `
        -PasswordAgeDays $StalePasswordDays -LogonAgeDays $StaleLogonDays
    Export-Report -Data $staleAccounts -Path (Join-Path $runPath '09-Stale-Privileged-Accounts.csv')

    # ── Optional: ACL Scans ──
    $adminSdHolderRisks = @()
    $domainAclRisks = @()
    if ($IncludeAclScan) {
        Write-Log 'Running ACL-based privilege escalation scan...'
        $adminSdHolderRisks = Get-AdminSDHolderAclRisks -DomainDn $ctx.DomainDN
        Export-Report -Data $adminSdHolderRisks -Path (Join-Path $runPath '10-AdminSDHolder-ACL-Risks.csv')

        $domainAclRisks = Get-DomainObjectAclRisks -DomainDn $ctx.DomainDN
        Export-Report -Data $domainAclRisks -Path (Join-Path $runPath '11-Domain-OU-PrivGroup-ACL-Risks.csv')
    }

    # ── Optional: GPO Links ──
    $gpoLinks = @()
    if ($IncludeGpoLinkScan) {
        Write-Log 'Collecting GPO link overview...'
        $gpoLinks = Get-GpoLinkOverview -DomainDn $ctx.DomainDN
        Export-Report -Data $gpoLinks -Path (Join-Path $runPath '12-GPO-Link-Overview.csv')
    }

    # ── Optional: Trusts ──
    $trusts = @()
    if ($IncludeTrustScan) {
        Write-Log 'Collecting trust overview...'
        $trusts = Get-TrustOverview
        Export-Report -Data $trusts -Path (Join-Path $runPath '13-Trust-Overview.csv')
    }

    # ── Optional: LAPS ──
    $laps = @()
    if ($IncludeLapsCheck) {
        Write-Log 'Collecting LAPS coverage overview...'
        $laps = Get-LapsOverview -DomainDn $ctx.DomainDN
        Export-Report -Data $laps -Path (Join-Path $runPath '14-LAPS-Overview.csv')
    }

    # ── Optional: Delegation Summary ──
    if ($IncludeDelegationScan) {
        $delegationSummary = @($userRisks + $computerRisks) | Where-Object { $_.RiskType -match 'Delegation' }
        Export-Report -Data $delegationSummary -Path (Join-Path $runPath '15-Delegation-Summary.csv')
    }

    # ── Unified Findings (matches documented output format) ──
    Write-Log 'Building unified findings report...'
    $unifiedFindings = Build-UnifiedFindings `
        -TierZeroPaths $tierZeroPaths `
        -UserRisks $userRisks `
        -ComputerRisks $computerRisks `
        -DCSyncFindings $dcsyncFindings `
        -StaleAccounts $staleAccounts `
        -AdminCountObjects $adminCountObjects `
        -AdminSdHolderRisks $adminSdHolderRisks `
        -DomainAclRisks $domainAclRisks

    Export-Report -Data $unifiedFindings -Path (Join-Path $runPath '98-Unified-Findings.csv')

    # ── Executive Summary ──
    Write-Log 'Building executive summary...'

    $criticalCount = @($unifiedFindings | Where-Object { $_.Risk -eq 'CRITICAL' }).Count
    $highCount     = @($unifiedFindings | Where-Object { $_.Risk -eq 'HIGH' }).Count
    $mediumCount   = @($unifiedFindings | Where-Object { $_.Risk -eq 'MEDIUM' }).Count

    $summaryRows = @(
        (New-SummaryRow -Category 'CRITICAL Findings'                     -Count $criticalCount                          -Notes 'DCSync, critical ACL abuse'),
        (New-SummaryRow -Category 'HIGH Findings'                         -Count $highCount                              -Notes 'Tier 0 membership, unconstrained delegation, high-risk ACLs'),
        (New-SummaryRow -Category 'MEDIUM Findings'                       -Count $mediumCount                            -Notes 'Kerberoast, constrained delegation, stale accounts, orphaned adminCount'),
        (New-SummaryRow -Category 'Total Unified Findings'                -Count @($unifiedFindings).Count               -Notes 'All findings consolidated into 98-Unified-Findings.csv'),
        (New-SummaryRow -Category '---'                                   -Count 0                                       -Notes '---'),
        (New-SummaryRow -Category 'Privileged Groups Enumerated'          -Count @($privilegedGroups).Count              -Notes 'Well-known privileged groups discovered'),
        (New-SummaryRow -Category 'Recursive Membership Rows'             -Count @($privilegedMembershipRows).Count      -Notes 'All direct and nested members under privileged groups'),
        (New-SummaryRow -Category 'Tier 0 / DA-Equivalent Indicators'     -Count @($tierZeroPaths).Count                 -Notes 'Objects in or nested into highly privileged groups'),
        (New-SummaryRow -Category 'adminCount=1 Objects'                  -Count @($adminCountObjects).Count             -Notes 'Protected/AdminSDHolder-linked objects'),
        (New-SummaryRow -Category 'User Risk Findings'                    -Count @($userRisks).Count                     -Notes 'Kerberoast, AS-REP roast, delegation'),
        (New-SummaryRow -Category 'Computer Risk Findings'                -Count @($computerRisks).Count                 -Notes 'Delegation-related computer findings'),
        (New-SummaryRow -Category 'DCSync-Capable Principals'             -Count @($dcsyncFindings).Count                -Notes "Non-default: $(@($dcsyncFindings | Where-Object { $_.Severity -ne 'INFO' }).Count)"),
        (New-SummaryRow -Category 'Stale Privileged Accounts'             -Count @($staleAccounts).Count                 -Notes "Pwd > $StalePasswordDays days or logon > $StaleLogonDays days"),
        (New-SummaryRow -Category 'AdminSDHolder ACL Findings'            -Count @($adminSdHolderRisks).Count            -Notes 'Only with -IncludeAclScan'),
        (New-SummaryRow -Category 'Domain/OU/PrivGroup ACL Findings'      -Count @($domainAclRisks).Count                -Notes 'Only with -IncludeAclScan'),
        (New-SummaryRow -Category 'GPO Link Rows'                         -Count @($gpoLinks).Count                      -Notes 'Only with -IncludeGpoLinkScan'),
        (New-SummaryRow -Category 'Trust Rows'                            -Count @($trusts).Count                        -Notes 'Only with -IncludeTrustScan'),
        (New-SummaryRow -Category 'LAPS Overview Rows'                    -Count @($laps).Count                          -Notes 'Only with -IncludeLapsCheck')
    )
    Export-Report -Data $summaryRows -Path (Join-Path $runPath '99-Summary.csv')

    # ── README ──
    $readmePath = Join-Path $runPath 'README.txt'
    @"
AD Privilege Escalation Analyzer Output
========================================

Run path : $runPath
Executed : $(Get-Date)
Domain   : $domainName ($domainNetBIOS)

Report Index
────────────
00-Run-Metadata.csv                          Run parameters and domain info
01-Privileged-Groups.csv                     High-risk groups in the domain
02-Privileged-Group-Recursive-Membership.csv All nested members under privileged groups
03-Tier0-Indicators.csv                      Objects with Domain Admin / equivalent paths
04-AdminCount-Objects.csv                    Protected objects (adminCount=1)
05-Upward-Group-Trace-for-AdminCount.csv     Parent-group chains for protected objects
06-User-Risks.csv                            Kerberoast / AS-REP / delegation findings
07-Computer-Risks.csv                        Delegation findings on computer accounts
08-DCSync-Capable-Principals.csv             Principals with replication rights on domain root
09-Stale-Privileged-Accounts.csv             Privileged users with old passwords / no recent logon
10-AdminSDHolder-ACL-Risks.csv               AdminSDHolder ACL findings (with -IncludeAclScan)
11-Domain-OU-PrivGroup-ACL-Risks.csv         Domain / OU / privileged group ACL findings (with -IncludeAclScan)
12-GPO-Link-Overview.csv                     GPO link mapping (with -IncludeGpoLinkScan)
13-Trust-Overview.csv                        AD trust data (with -IncludeTrustScan)
14-LAPS-Overview.csv                         LAPS coverage (with -IncludeLapsCheck)
15-Delegation-Summary.csv                    Combined delegation findings (with -IncludeDelegationScan)

98-Unified-Findings.csv                      ** ALL findings in one file: FindingType, Name, SamAccountName, Risk, Detail **
99-Summary.csv                               High-level counts and risk breakdown

Important Notes
───────────────
- This script surfaces likely escalation paths; it does not prove exploitability.
- Some findings may be inherited, legacy, or intentionally delegated.
- AdminCount, ACL, and delegation findings should always be validated in context.
- DCSync-capable principals marked 'INFO' are expected built-in accounts.
- Stale thresholds: password age > $StalePasswordDays days, last logon > $StaleLogonDays days.
- Error messages may reflect permissions, replication, stale objects, or incomplete RSAT
  visibility. Investigate root cause rather than assuming the first error is the true failure.
"@ | Set-Content -Path $readmePath -Encoding UTF8

    $totalSw.Stop()
    Write-Log "Analysis complete in $([math]::Round($totalSw.Elapsed.TotalSeconds, 1))s. Output: $runPath" 'SUCCESS'

    if ($ShowConsoleSummary) {
        Write-Host ''
        Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Magenta
        Write-Host '║        AD Privilege Escalation Analyzer - Summary           ║' -ForegroundColor Magenta
        Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Magenta
        Write-Host ''

        if ($criticalCount -gt 0) {
            Write-Host "  CRITICAL : $criticalCount findings" -ForegroundColor Red
        }
        if ($highCount -gt 0) {
            Write-Host "  HIGH     : $highCount findings" -ForegroundColor Yellow
        }
        if ($mediumCount -gt 0) {
            Write-Host "  MEDIUM   : $mediumCount findings" -ForegroundColor Cyan
        }
        Write-Host ''
        $summaryRows | Where-Object { $_.Category -ne '---' } | Format-Table -AutoSize
        Write-Host "  Output Path: $runPath" -ForegroundColor Green
        Write-Host ''
    }
}
catch {
    Write-Log $_.Exception.Message 'ERROR'
    throw
}
