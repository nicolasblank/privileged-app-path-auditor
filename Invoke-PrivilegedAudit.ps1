<#
.SYNOPSIS
    Identifies privilege escalation paths through Entra ID app registrations, maps shadow admin
    relationships, and audits privileged role membership.

.DESCRIPTION
    Connects to Microsoft Entra ID via Microsoft Graph, identifies app registrations and service
    principals with high-impact permissions, and reports which users hold
    privileged directory roles versus those who don't.

    Modes:
      PermissionAudit    - Dangerous application and delegated permission grants
      RoleAudit          - Users in/not in privileged directory roles
      AttackPath         - End-to-end privilege escalation paths
      ShadowAdmins       - Users who own SPs with privileged roles
      StalePrivilege     - Dormant high-privilege apps with valid creds
      ConsentRisk        - Tenant consent policy weaknesses
      CredentialHygiene  - Credential type risk for high-privilege apps
      Full               - All of the above

.PARAMETER Mode
    Which audit mode to run. Default: Full.

.PARAMETER ExportPath
    Optional folder path to export CSV results.

.PARAMETER InactiveDays
    Days of inactivity before an app is flagged as stale. Default from config or 90.

.PARAMETER ConfigPath
    Path to config directory. Default: ./config

.EXAMPLE
    .\Invoke-PrivilegedAudit.ps1 -Mode Full
    .\Invoke-PrivilegedAudit.ps1 -Mode AttackPath -ExportPath ./audit-results
    .\Invoke-PrivilegedAudit.ps1 -Mode StalePrivilege -InactiveDays 60

.NOTES
    Version: 0.5.2

    This project uses the Microsoft first-party app name database from
    merill/microsoft-info (https://github.com/merill/microsoft-info) — MIT licensed.
    The database is refreshed daily and cached locally for 24 hours.

.LINK
    https://github.com/nicolasblank/privileged-app-path-auditor
#>

[CmdletBinding()]
param(
    [ValidateSet('PermissionAudit', 'RoleAudit', 'AttackPath', 'ShadowAdmins', 'StalePrivilege', 'ConsentRisk', 'CredentialHygiene', 'Full')]
    [string]$Mode = 'Full',

    [string]$ExportPath,

    [int]$InactiveDays,

    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config')
)

$script:Version = '0.5.2'
$script:CachedDangerousApps = $null
$script:CachedRoleAssignments = $null
$script:CachedRoleDefinitions = $null
$script:CachedServicePrincipals = $null
$script:CachedResourceServicePrincipals = @{}
$script:StalePrivilegeDataAvailable = $null
$script:Coverage = [ordered]@{}
$script:MicrosoftGraphAppId = '00000003-0000-0000-c000-000000000000'

# Note: StrictMode is intentionally not set. The Microsoft Graph SDK returns
# hashtables/OrderedDictionaries whose properties are not compatible with
# StrictMode Version 2+ (.Count and property-existence checks can fail).
$ErrorActionPreference = 'Stop'

#region ── Configuration Loading ──────────────────────────────────────────────

# Hardcoded defaults — these are used if no config files exist
$script:DefaultDangerousPermissions = @(
    @{ name = 'RoleManagement.ReadWrite.Directory'; type = 'Application'; resourceAppId = $script:MicrosoftGraphAppId; resourceName = 'Microsoft Graph'; risk = 'Critical'; reason = 'Can assign any Entra ID role to any principal, including Global Administrator'; attackAction = 'assign a privileged directory role to a controlled principal' }
    @{ name = 'AppRoleAssignment.ReadWrite.All';    type = 'Application'; resourceAppId = $script:MicrosoftGraphAppId; resourceName = 'Microsoft Graph'; risk = 'Critical'; reason = 'Can grant itself or any app any application permission'; attackAction = 'grant a controlled app additional high-impact application permissions' }
    @{ name = 'Application.ReadWrite.All';          type = 'Application'; resourceAppId = $script:MicrosoftGraphAppId; resourceName = 'Microsoft Graph'; risk = 'Critical'; reason = 'Can modify any app registration credentials and impersonate it'; attackAction = 'add credentials to another app registration and inherit that app permissions' }
    @{ name = 'Directory.ReadWrite.All';            type = 'Application'; resourceAppId = $script:MicrosoftGraphAppId; resourceName = 'Microsoft Graph'; risk = 'High';     reason = 'Near-full write access to directory objects, subject to protected-operation restrictions'; attackAction = 'modify directory objects allowed by Directory.ReadWrite.All' }
    @{ name = 'Directory.AccessAsUser.All';         type = 'Delegated';   resourceAppId = $script:MicrosoftGraphAppId; resourceName = 'Microsoft Graph'; risk = 'Critical'; reason = 'Full directory access as the signed-in user'; attackAction = 'act with the signed-in user permissions through Microsoft Graph' }
)

$script:DefaultPrivilegedRoles = @(
    @{ name = 'Global Administrator';                  templateId = '62e90394-69f5-4237-9190-012177145e10'; tier = 'Critical' }
    @{ name = 'Privileged Role Administrator';         templateId = 'e8611ab8-c189-46e8-94e1-60213ab1f814'; tier = 'Critical' }
    @{ name = 'Privileged Authentication Administrator'; templateId = '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'; tier = 'Critical' }
    @{ name = 'Global Reader';                         templateId = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451'; tier = 'High' }
    @{ name = 'Security Administrator';                templateId = '194ae4cb-b126-40b2-bd5b-6091b380977d'; tier = 'High' }
    @{ name = 'Conditional Access Administrator';      templateId = 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'; tier = 'High' }
    @{ name = 'Exchange Administrator';                templateId = '29232cdf-9323-42fd-ade2-1d097af3e4de'; tier = 'High' }
    @{ name = 'SharePoint Administrator';              templateId = 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'; tier = 'High' }
    @{ name = 'User Administrator';                    templateId = 'fe930be7-5e62-47db-91af-98c3a49a38b1'; tier = 'High' }
    @{ name = 'Application Administrator';             templateId = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'; tier = 'High' }
    @{ name = 'Cloud Application Administrator';       templateId = '158c047a-c907-4556-b7ef-446551a6b5f7'; tier = 'High' }
    @{ name = 'Authentication Administrator';          templateId = 'c4e39bd9-1100-46d3-8c65-fb160da0071f'; tier = 'Medium' }
    @{ name = 'Helpdesk Administrator';                templateId = '729827e3-9c14-49f7-bb1b-9608f156bbb8'; tier = 'Medium' }
    @{ name = 'Intune Administrator';                  templateId = '3a2c62db-5318-420d-8d74-23affee5d9d5'; tier = 'High' }
    # 2026 additions and classification changes. Runtime role definitions remain authoritative.
    @{ name = 'AI Administrator';                      templateId = 'd2562ede-74db-457e-a7b6-544e236ebb61'; tier = 'High' }
    @{ name = 'AI Reader';                             templateId = '1fe13547-53f6-408d-ac04-7f8eed167b38'; tier = 'High' }
    @{ name = 'Agent ID Administrator';                templateId = 'db506228-d27e-4b7d-95e5-295956d6615f'; tier = 'High' }
    @{ name = 'Agent Registry Administrator';          templateId = '6b942400-691f-4bf0-9d12-d8a254a2baf5'; tier = 'High' }
    @{ name = 'Authentication Extensibility Password Administrator'; templateId = '0b00bede-4072-4d22-b441-e7df02a1ef63'; tier = 'High' }
    @{ name = 'Customer Delegated Administration Relationship Administrator'; templateId = 'fc8ad4e2-40e4-4724-8317-bcda7503ecbf'; tier = 'High' }
    @{ name = 'Entra Backup Administrator';            templateId = 'b6a27b2b-f905-4b2e-81b5-0d90e0ef1fdb'; tier = 'High' }
    @{ name = 'Identity Governance Administrator';     templateId = '45d8d3c5-c802-45c6-b32a-1d70b5e1e86e'; tier = 'High' }
    @{ name = 'Security Operator';                      templateId = '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f'; tier = 'High' }
    @{ name = 'Tenant Governance Administrator';       templateId = '1981f584-96e9-4a6f-95b0-f522373f8fae'; tier = 'High' }
)

$script:DefaultAuditConfig = @{
    stalePrivilege = @{ inactiveDays = 90 }
    filters = @{
        excludeDisabledApps              = $false
        excludeFirstPartyMicrosoftApps   = $true
        excludeAppIds                    = @()
    }
    consentRisk = @{ flagUserConsentedApps = $true }
    credentialHygiene = @{
        preferredCredentialTypes = @('Certificate', 'Federated')
        riskyCredentialTypes    = @('Secret', 'SP-Secret', 'SP-Certificate')
        flagMultipleCredentials = $true
        flagExpiredCredentials  = $true
    }
    output = @{
        truncateAfter             = 50
        maxUsersInRoleAuditList   = 500
    }
}

# Built-in fallback only. Runtime role permissions are used for built-in and custom roles.
$script:KnownApplicationControlRoleTemplateIds = @(
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' # Application Administrator
    '158c047a-c907-4556-b7ef-446551a6b5f7' # Cloud Application Administrator
)

$script:DefaultAttackPaths = @(
    @{
        id          = 'APP_OWNER_ESCALATION'
        name        = 'App Owner Escalation'
        severity    = 'Critical'
        description = 'A non-admin user owns an app registration that has dangerous application permissions.'
        remediation = @(
            'Remove the non-admin user as owner of the app'
            'Replace the dangerous permission with a least-privilege alternative'
            'Apply Conditional Access for workload identities on the service principal'
            'Use Managed Identity instead of app registration where possible'
        )
    }
    @{
        id          = 'SHADOW_ADMIN_SP'
        name        = 'Shadow Admin via Service Principal Role'
        severity    = 'Critical'
        description = 'A non-admin user owns a service principal that holds a privileged directory role.'
        remediation = @(
            'Remove the non-admin user as owner of the service principal'
            'Remove the privileged directory role from the service principal'
            'Use PIM for just-in-time role activation instead of permanent assignments'
        )
    }
    @{
        id          = 'ROLE_BASED_SP_CONTROL'
        name        = 'Application-Control Role Reaches Privileged Service Principals'
        severity    = 'Critical'
        description = 'A user whose current built-in or custom role actions permit application or service-principal credential changes may be able to authenticate as an SP with a more sensitive directory role.'
        remediation = @(
            'Use PIM with approval workflow for application-control roles'
            'Scope built-in and custom application-control assignments as narrowly as possible'
            'Enable app instance lock where it can block the service-principal credential route'
            'Monitor SP credential changes in Entra audit logs'
            'Remove permanent Application Administrator assignments where possible'
        )
    }
    @{
        id          = 'UNOWNED_PRIVILEGED_APP'
        name        = 'Unowned Application with Dangerous Permissions'
        severity    = 'High'
        description = 'An application has high-impact permissions but no assigned owners — no accountability for credential rotation or access review.'
        remediation = @(
            'Assign a responsible owner to the application'
            'Review if the application is still needed'
            'Rotate or remove existing credentials'
            'Enable app instance property lock to prevent SP-level credential injection'
        )
    }
)

function Initialize-Config {
    param(
        [string]$EffectiveConfigPath = $ConfigPath,
        [int]$EffectiveInactiveDays = $InactiveDays
    )
    # Clone mutable defaults so repeated/test invocations do not leak overrides.
    $script:DangerousPermissions = @($script:DefaultDangerousPermissions | ForEach-Object { @{} + $_ })
    $script:PrivilegedRoles      = @($script:DefaultPrivilegedRoles | ForEach-Object { @{} + $_ })
    $script:AuditConfig          = $script:DefaultAuditConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
    $script:AttackPathDefs       = @($script:DefaultAttackPaths | ForEach-Object { @{} + $_ })

    $permFile   = Join-Path $EffectiveConfigPath 'dangerous-permissions.json'
    $rolesFile  = Join-Path $EffectiveConfigPath 'privileged-roles.json'
    $configFile = Join-Path $EffectiveConfigPath 'audit-config.json'
    $pathsFile  = Join-Path $EffectiveConfigPath 'attack-paths.json'

    if (Test-Path $permFile) {
        $json = Get-Content $permFile -Raw | ConvertFrom-Json
        if ($json.PSObject.Properties.Name -contains 'permissions') {
            $script:DangerousPermissions = @($json.permissions | ForEach-Object {
                @{
                    name          = $_.name
                    type          = $_.type
                    resourceAppId = if ($_.resourceAppId) { $_.resourceAppId } else { $script:MicrosoftGraphAppId }
                    resourceName  = if ($_.resourceName) { $_.resourceName } else { 'Microsoft Graph' }
                    risk          = $_.risk
                    reason        = $_.reason
                    attackAction  = $_.attackAction
                }
            })
            Write-Verbose "Loaded $(($script:DangerousPermissions).Count) dangerous permissions from config"
        }
    }

    if (Test-Path $rolesFile) {
        $json = Get-Content $rolesFile -Raw | ConvertFrom-Json
        if ($json.PSObject.Properties.Name -contains 'roles') {
            $script:PrivilegedRoles = @($json.roles | ForEach-Object {
                @{ name = $_.name; templateId = $_.templateId; tier = $_.tier }
            })
            Write-Verbose "Loaded $(($script:PrivilegedRoles).Count) privileged roles from config"
        }
    }

    if (Test-Path $configFile) {
        $json = Get-Content $configFile -Raw | ConvertFrom-Json
        if ($json.stalePrivilege.inactiveDays) {
            $script:AuditConfig.stalePrivilege.inactiveDays = [int]$json.stalePrivilege.inactiveDays
        }
        if ($null -ne $json.filters.excludeDisabledApps) {
            $script:AuditConfig.filters.excludeDisabledApps = [bool]$json.filters.excludeDisabledApps
        }
        if ($null -ne $json.filters.excludeFirstPartyMicrosoftApps) {
            $script:AuditConfig.filters.excludeFirstPartyMicrosoftApps = [bool]$json.filters.excludeFirstPartyMicrosoftApps
        }
        if ($null -ne $json.filters.excludeAppIds) {
            $script:AuditConfig.filters.excludeAppIds = @($json.filters.excludeAppIds)
        }
        if ($null -ne $json.consentRisk.flagUserConsentedApps) {
            $script:AuditConfig.consentRisk.flagUserConsentedApps = [bool]$json.consentRisk.flagUserConsentedApps
        }
        if ($null -ne $json.credentialHygiene.preferredCredentialTypes) {
            $script:AuditConfig.credentialHygiene.preferredCredentialTypes = @($json.credentialHygiene.preferredCredentialTypes)
        }
        if ($null -ne $json.credentialHygiene.riskyCredentialTypes) {
            $script:AuditConfig.credentialHygiene.riskyCredentialTypes = @($json.credentialHygiene.riskyCredentialTypes)
        }
        if ($null -ne $json.credentialHygiene.flagMultipleCredentials) {
            $script:AuditConfig.credentialHygiene.flagMultipleCredentials = [bool]$json.credentialHygiene.flagMultipleCredentials
        }
        if ($null -ne $json.credentialHygiene.flagExpiredCredentials) {
            $script:AuditConfig.credentialHygiene.flagExpiredCredentials = [bool]$json.credentialHygiene.flagExpiredCredentials
        }
        if ($json.output.truncateAfter) {
            $script:AuditConfig.output.truncateAfter = [int]$json.output.truncateAfter
        }
        if ($json.output.maxUsersInRoleAuditList) {
            $script:AuditConfig.output.maxUsersInRoleAuditList = [int]$json.output.maxUsersInRoleAuditList
        }
        Write-Verbose "Loaded audit config overrides from config"
    }

    if (Test-Path $pathsFile) {
        $json = Get-Content $pathsFile -Raw | ConvertFrom-Json
        if ($json.PSObject.Properties.Name -contains 'paths') {
            $script:AttackPathDefs = @($json.paths | ForEach-Object {
                @{
                    id          = $_.id
                    name        = $_.name
                    severity    = $_.severity
                    description = $_.description
                    remediation = @($_.remediation)
                }
            })
            Write-Verbose "Loaded $(($script:AttackPathDefs).Count) attack path definitions from config"
        }
    }

    # CLI parameter overrides config file
    if ($EffectiveInactiveDays -gt 0) {
        $script:AuditConfig.stalePrivilege.inactiveDays = $EffectiveInactiveDays
    }

    # Load Microsoft first-party app lookup (auto-downloads with 24h cache)
    $script:MicrosoftAppIds = Update-MicrosoftAppsLookup -CatalogConfigPath $EffectiveConfigPath
}

function Update-MicrosoftAppsLookup {
    param([string]$CatalogConfigPath = $ConfigPath)
    <#
    .SYNOPSIS
        Downloads and caches the Microsoft first-party app ID list from merill/microsoft-info.
        Returns a HashSet of known Microsoft app IDs for fast lookup.
    #>
    $cacheFile = Join-Path $CatalogConfigPath 'MicrosoftApps.json'
    $sourceUrl = 'https://raw.githubusercontent.com/merill/microsoft-info/main/_info/MicrosoftApps.json'
    $maxAgeHours = 24

    $needsDownload = $true
    if (Test-Path $cacheFile) {
        $fileAge = (Get-Date) - (Get-Item $cacheFile).LastWriteTime
        if ($fileAge.TotalHours -lt $maxAgeHours) {
            $needsDownload = $false
        }
    }

    if ($needsDownload) {
        try {
            Write-Verbose "Downloading Microsoft first-party app list from merill/microsoft-info..."
            $response = @(Invoke-RestMethod -Uri $sourceUrl -Method Get -ErrorAction Stop)
            $validEntries = @($response | Where-Object {
                if (-not $_.AppId) { return $false }
                try { [void][guid]::Parse([string]$_.AppId); return $true } catch { return $false }
            })
            if ($response.Count -eq 0 -or $validEntries.Count -ne $response.Count) {
                throw 'Downloaded Microsoft application data was empty or contained invalid app IDs.'
            }
            $tempCacheFile = "$cacheFile.tmp"
            $response | ConvertTo-Json -Depth 5 | Set-Content -Path $tempCacheFile -Encoding UTF8
            Move-Item -LiteralPath $tempCacheFile -Destination $cacheFile -Force
            Set-CoverageState -Source 'MicrosoftFirstPartyAppCatalog' -State Complete
            Write-Verbose "Cached $($response.Count) Microsoft app IDs to $cacheFile"
        } catch {
            Set-CoverageState -Source 'MicrosoftFirstPartyAppCatalog' -State Partial -Detail $_.Exception.Message
            Write-Verbose "Could not download Microsoft app list: $($_.Exception.Message). Using cached/fallback."
        }
    }

    # Build a HashSet of known Microsoft app IDs
    $appIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (Test-Path $cacheFile) {
        try {
            $apps = @(Get-Content $cacheFile -Raw | ConvertFrom-Json)
            foreach ($app in $apps) {
                if (-not $app.AppId) { throw 'The cached Microsoft app catalog contains an entry without AppId.' }
                [void]$appIds.Add([string]$app.AppId)
            }
            if (-not $script:Coverage.Contains('MicrosoftFirstPartyAppCatalog')) {
                Set-CoverageState -Source 'MicrosoftFirstPartyAppCatalog' -State Complete
            }
            Write-Verbose "Loaded $($appIds.Count) Microsoft first-party app IDs from cache"
        } catch {
            Set-CoverageState -Source 'MicrosoftFirstPartyAppCatalog' -State Unavailable -Detail "Cached catalog is invalid: $($_.Exception.Message)"
            $appIds.Clear()
        }
    } else {
        Set-CoverageState -Source 'MicrosoftFirstPartyAppCatalog' -State Unavailable -Detail 'No downloaded or cached catalog is available; owner-organization fallback only.'
        Write-Verbose "No Microsoft app list available — falling back to appOwnerOrganizationId filter only"
    }

    return $appIds
}

#endregion

#region ── Correctness and Coverage Helpers ──────────────────────────────────

function Reset-AuditCoverage {
    $script:Coverage = [ordered]@{}
}

function Set-CoverageState {
    param(
        [Parameter(Mandatory)][string]$Source,
        [ValidateSet('Complete', 'Partial', 'Unavailable')][string]$State,
        [string]$Detail
    )

    $rank = @{ Complete = 0; Partial = 1; Unavailable = 2 }
    if (-not $script:Coverage.Contains($Source)) {
        $script:Coverage[$Source] = [PSCustomObject]@{
            Source  = $Source
            State   = $State
            Details = [System.Collections.Generic.List[string]]::new()
        }
    } elseif ($rank[$State] -gt $rank[$script:Coverage[$Source].State]) {
        $script:Coverage[$Source].State = $State
    }

    if ($Detail -and -not $script:Coverage[$Source].Details.Contains($Detail)) {
        $script:Coverage[$Source].Details.Add($Detail)
    }
}

function Test-AuditCoverageComplete {
    param([string[]]$Sources)

    if (-not $Sources) { $Sources = @($script:Coverage.Keys) }
    foreach ($source in $Sources) {
        if (-not $script:Coverage.Contains($source) -or $script:Coverage[$source].State -ne 'Complete') {
            return $false
        }
    }
    return $true
}

function Get-AuditCoverageRows {
    return @($script:Coverage.Keys | ForEach-Object {
        $entry = $script:Coverage[$_]
        [PSCustomObject]@{
            Source = $entry.Source
            State  = $entry.State
            Detail = ($entry.Details -join '; ')
        }
    })
}

function Write-AuditCoverageSummary {
    $rows = Get-AuditCoverageRows
    if ($rows.Count -eq 0) { return }

    $incomplete = @($rows | Where-Object { $_.State -ne 'Complete' })
    if ($incomplete.Count -gt 0) {
        Write-Host ''
        Write-Host 'DATA COVERAGE: PARTIAL' -ForegroundColor DarkYellow
        $incomplete | Format-Table -Wrap | Out-String -Width 200 | Write-Host
        Write-Host '  A zero finding count is not a clean result for the sources listed above.' -ForegroundColor DarkYellow
    }
    Export-AuditCsv -Name 'DataCoverage' -Data $rows
}

function Test-ObjectHasProperty {
    param([object]$InputObject, [string]$Name)
    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject.Contains($Name) }
    return $InputObject.PSObject.Properties.Name -contains $Name
}

function Get-AppTenantType {
    param([object]$ServicePrincipal)

    $microsoftOwnerIds = @(
        'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
        '72f988bf-86f1-41af-91ab-2d7cd011db47'
        'cdc5aeea-15c5-4db6-b079-fcadd2505dc2'
    )
    $knownMicrosoft = $false
    if ($script:MicrosoftAppIds) { $knownMicrosoft = $script:MicrosoftAppIds.Contains([string]$ServicePrincipal.appId) }
    if ($knownMicrosoft -or $ServicePrincipal.appOwnerOrganizationId -in $microsoftOwnerIds) { return 'MicrosoftFirstParty' }
    if ($ServicePrincipal.appOwnerOrganizationId -and $ServicePrincipal.appOwnerOrganizationId -eq $script:ConnectedTenantId) { return 'HomeTenant' }
    if ($ServicePrincipal.appOwnerOrganizationId) { return 'ThirdParty' }
    return 'Unknown'
}

function Find-DangerousPermissionDefinition {
    param(
        [string]$Name,
        [ValidateSet('Application', 'Delegated')][string]$Type,
        [string]$ResourceAppId
    )
    return $script:DangerousPermissions | Where-Object {
        $_.name -eq $Name -and $_.type -eq $Type -and
        $_.resourceAppId -and $_.resourceAppId -eq $ResourceAppId
    } | Select-Object -First 1
}

function Get-RoleAllowedResourceActions {
    param([object]$RoleDefinition)
    $actions = @()
    foreach ($permissionSet in @($RoleDefinition.rolePermissions)) {
        $actions += @($permissionSet.allowedResourceActions)
    }
    return @($actions | Where-Object { $_ } | Select-Object -Unique)
}

function Test-RoleCanControlServicePrincipals {
    param([object]$RoleDefinition)

    $actions = Get-RoleAllowedResourceActions -RoleDefinition $RoleDefinition
    foreach ($action in $actions) {
        if ($action -match '^microsoft\.directory/servicePrincipals/(credentials|authentication|allProperties)/(update|allTasks)$') {
            return $true
        }
    }

    # The two established application administrator roles remain a safe fallback
    # when a tenant/API response omits rolePermissions.
    return $actions.Count -eq 0 -and $RoleDefinition.templateId -in $script:KnownApplicationControlRoleTemplateIds
}

function Test-RoleCanControlApplications {
    param([object]$RoleDefinition)
    foreach ($action in (Get-RoleAllowedResourceActions -RoleDefinition $RoleDefinition)) {
        if ($action -match '^microsoft\.directory/applications[^/]*/(credentials|authentication|allProperties)/(update|allTasks)$') {
            return $true
        }
    }
    return $false
}

function ConvertTo-AppInstanceLockEvidence {
    param([object]$LockConfiguration)

    if ($null -eq $LockConfiguration) {
        return [PSCustomObject]@{
            State                = 'NotConfigured'
            IsEnabled            = $false
            IsCredentialLocked   = $false
            LocksAllProperties   = $false
            LocksSigningUsage    = $false
            LocksVerifyUsage     = $false
        }
    }

    $enabled = [bool]$LockConfiguration.isEnabled
    $allProperties = [bool]$LockConfiguration.allProperties
    $signing = [bool]$LockConfiguration.credentialsWithUsageSign
    $verify = [bool]$LockConfiguration.credentialsWithUsageVerify
    # OAuth service principals use Verify credentials. A Sign-only lock protects
    # signing credentials but does not prove the OAuth credential-injection route
    # is blocked. allProperties covers both usage types.
    $credentialLocked = $enabled -and ($allProperties -or $verify)

    return [PSCustomObject]@{
        State                = if ($credentialLocked) { 'OAuthCredentialChangesLocked' } elseif ($enabled) { 'EnabledButOAuthCredentialsNotLocked' } else { 'Disabled' }
        IsEnabled            = $enabled
        IsCredentialLocked   = $credentialLocked
        LocksAllProperties   = $allProperties
        LocksSigningUsage    = $signing
        LocksVerifyUsage     = $verify
    }
}

function Resolve-UserConsentPolicyAssignment {
    param([object[]]$AssignedPolicies)

    $prefix = 'managePermissionGrantsForSelf.'
    $policyIds = @($AssignedPolicies | ForEach-Object {
        $value = [string]$_
        if ($value.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $value.Substring($prefix.Length)
        }
    } | Where-Object { $_ } | Select-Object -Unique)

    if ('microsoft-user-default-legacy' -in $policyIds) {
        return [PSCustomObject]@{ State = 'AllowedForAllApps'; Risk = 'HIGH'; PolicyIds = $policyIds }
    }
    if ('microsoft-user-default-low' -in $policyIds) {
        return [PSCustomObject]@{ State = 'RestrictedBuiltIn'; Risk = 'REVIEW'; PolicyIds = $policyIds }
    }
    if ($policyIds.Count -gt 0) {
        return [PSCustomObject]@{ State = 'CustomPolicy'; Risk = 'REVIEW'; PolicyIds = $policyIds }
    }
    return [PSCustomObject]@{ State = 'Disabled'; Risk = 'GOOD'; PolicyIds = @() }
}

function Test-UserIsGlobalAdministrator {
    param([string]$UserId, [object[]]$RoleAssignments)
    return [bool]($RoleAssignments | Where-Object {
        $_.PrincipalId -eq $UserId -and $_.PrincipalType -eq '#microsoft.graph.user' -and
        $_.RoleTemplateId -eq '62e90394-69f5-4237-9190-012177145e10'
    } | Select-Object -First 1)
}

function Test-UserAlreadyEquivalentToPermission {
    param([string]$UserId, [string]$Permission, [object[]]$RoleAssignments)

    $userTemplateIds = @($RoleAssignments | Where-Object {
        $_.PrincipalId -eq $UserId -and $_.PrincipalType -eq '#microsoft.graph.user'
    } | ForEach-Object { $_.RoleTemplateId } | Where-Object { $_ } | Select-Object -Unique)

    if ('62e90394-69f5-4237-9190-012177145e10' -in $userTemplateIds) { return $true }
    switch ($Permission) {
        'RoleManagement.ReadWrite.Directory' {
            return 'e8611ab8-c189-46e8-94e1-60213ab1f814' -in $userTemplateIds
        }
        'Application.ReadWrite.All' {
            return [bool](@(
                '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
                '158c047a-c907-4556-b7ef-446551a6b5f7'
            ) | Where-Object { $_ -in $userTemplateIds } | Select-Object -First 1)
        }
        default { return $false }
    }
}

function Test-RoleAssignmentAppliesToServicePrincipal {
    param([object]$RoleAssignment, [string]$ServicePrincipalId)
    if ($RoleAssignment.AppScopeId -and $RoleAssignment.AppScopeId -ne '/') { return $false }
    if (-not $RoleAssignment.DirectoryScopeId -or $RoleAssignment.DirectoryScopeId -eq '/') { return $true }
    return $RoleAssignment.DirectoryScopeId -in @("/$ServicePrincipalId", "/servicePrincipals/$ServicePrincipalId")
}

#endregion

#region ── Output Helpers ─────────────────────────────────────────────────────

function Write-Banner {
    param([string]$Title)
    $width = 78
    $line = '═' * $width
    Write-Host ""
    Write-Host "╔$line╗" -ForegroundColor Cyan
    Write-Host "║  $($Title.PadRight($width - 2))║" -ForegroundColor Cyan
    Write-Host "╚$line╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-SectionDivider {
    param([string]$Title)
    $line = '─' * 79
    Write-Host ""
    Write-Host $line -ForegroundColor DarkGray
    Write-Host "⚠  $Title" -ForegroundColor Yellow
    Write-Host $line -ForegroundColor DarkGray
    Write-Host ""
}

function Write-Recommendation {
    param([string[]]$Items)
    Write-Host ""
    Write-Host "  Remediation:" -ForegroundColor Green
    foreach ($item in $Items) {
        Write-Host "    • $item" -ForegroundColor Gray
    }
}

function Write-Reference {
    param([string]$Url)
    Write-Host ""
    Write-Host "Reference: $Url" -ForegroundColor DarkCyan
}

function Get-EntraAppUrl {
    param([string]$ObjectId, [string]$AppId)
    if ($ObjectId -and $AppId) {
        return "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/$ObjectId/appId/$AppId"
    } elseif ($ObjectId) {
        return "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/$ObjectId"
    }
    return ''
}

function Get-EntraUserUrl {
    param([string]$ObjectId)
    if ($ObjectId) {
        return "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/UserDetailsMenuBlade/~/Profile/userId/$ObjectId"
    }
    return ''
}

function Export-AuditCsv {
    param(
        [string]$Name,
        [object[]]$Data
    )
    if (-not $ExportPath -or $Data.Count -eq 0) { return }
    if (-not (Test-Path $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    }
    $file = Join-Path $ExportPath "$Name.csv"
    $Data | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
    Write-Host "  Exported: $file" -ForegroundColor DarkGreen
}

#endregion

#region ── Graph Connection ───────────────────────────────────────────────────

function Connect-GraphIfNeeded {
    $requiredScopes = @(
        'Application.Read.All'
        'Directory.Read.All'
        'RoleManagement.Read.Directory'
        'AuditLog.Read.All'
        'Policy.Read.All'
    )

    $context = $null
    try { $context = Get-MgContext } catch { Write-Verbose "No existing Microsoft Graph context: $($_.Exception.Message)" }

    if ($context) {
        $missing = $requiredScopes | Where-Object { $_ -notin $context.Scopes }
        if ($missing.Count -eq 0) {
            $script:ConnectedTenantId = $context.TenantId
            Write-Host "✓ Already connected to Microsoft Graph as $($context.Account)" -ForegroundColor Green
            return
        }
        Write-Host "⚠ Connected but missing scopes: $($missing -join ', ')" -ForegroundColor Yellow
        Write-Host "  Reconnecting with required scopes..." -ForegroundColor Yellow
    }

    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome
    $ctx = Get-MgContext
    $script:ConnectedTenantId = $ctx.TenantId
    Write-Host "✓ Connected as $($ctx.Account) (TenantId: $($ctx.TenantId))" -ForegroundColor Green
}

#endregion

#region ── Graph Data Queries ─────────────────────────────────────────────────

# Paginate through a Graph endpoint
function Get-AllGraphPages {
    param([string]$Uri)
    $results = [System.Collections.Generic.List[object]]::new()
    $response = Invoke-MgGraphRequest -Method GET -Uri $Uri
    if ($response.ContainsKey('value')) {
        foreach ($item in $response.value) { $results.Add($item) }
    }
    while ($response.ContainsKey('@odata.nextLink')) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $response.'@odata.nextLink'
        if ($response.ContainsKey('value')) {
            foreach ($item in $response.value) { $results.Add($item) }
        }
    }
    return @($results)
}

function Get-ServicePrincipalsWithAppRoles {
    # Cache results so the expensive Graph queries only run once in Full mode
    if ($null -ne $script:CachedDangerousApps) {
        Write-Host "  Using cached service principal data..." -ForegroundColor Gray
        return $script:CachedDangerousApps
    }

    Write-Host "  Querying service principals and permission grants..." -ForegroundColor Gray
    try {
        $sps = @(Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled&$top=999')
        Set-CoverageState -Source 'ServicePrincipals' -State Complete
    } catch {
        Set-CoverageState -Source 'ServicePrincipals' -State Unavailable -Detail $_.Exception.Message
        Write-Host "  ⚠ Service principals could not be queried; permission findings are unavailable." -ForegroundColor Yellow
        $script:CachedDangerousApps = @()
        return @()
    }
    $script:CachedServicePrincipals = $sps

    $totalAll = $sps.Count
    $microsoftSPs = @($sps | Where-Object { (Get-AppTenantType -ServicePrincipal $_) -eq 'MicrosoftFirstParty' })
    $homeTenantSPs = @($sps | Where-Object { (Get-AppTenantType -ServicePrincipal $_) -eq 'HomeTenant' })
    $crossTenantSPs = @($sps | Where-Object { (Get-AppTenantType -ServicePrincipal $_) -eq 'ThirdParty' })
    $unknownOwnerSPs = @($sps | Where-Object { (Get-AppTenantType -ServicePrincipal $_) -eq 'Unknown' })

    Write-Host "" -ForegroundColor Gray
    Write-Host "  Service Principal Summary:" -ForegroundColor Gray
    Write-Host "    Total:                    $totalAll" -ForegroundColor Gray
    Write-Host "    Microsoft first-party:    $($microsoftSPs.Count)" -ForegroundColor DarkGray
    Write-Host "    Home tenant:              $($homeTenantSPs.Count)" -ForegroundColor Gray
    Write-Host "    Third-party (cross-tenant):$($crossTenantSPs.Count)" -ForegroundColor Gray
    if ($unknownOwnerSPs.Count -gt 0) {
        Write-Host "    Unknown owner:            $($unknownOwnerSPs.Count)" -ForegroundColor DarkYellow
        Write-Host "    ⚠ Unknown owner apps require manual investigation$(if (-not $ExportPath) { ' — use -ExportPath to save the detailed list' })" -ForegroundColor DarkYellow
    }
    Write-Host "" -ForegroundColor Gray

    # Export unknown owner apps for investigation
    if ($unknownOwnerSPs.Count -gt 0) {
        $unknownExport = @($unknownOwnerSPs | ForEach-Object {
            [PSCustomObject]@{
                DisplayName        = $_.displayName
                AppId              = $_.appId
                ObjectId           = $_.id
                Type               = $_.servicePrincipalType
                Enabled            = $_.accountEnabled
                EntraPortalUrl     = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/$($_.id)/appId/$($_.appId)"
            }
        })
        Export-AuditCsv -Name 'UnknownOwnerApps' -Data $unknownExport
    }

    # Export SP classification summary
    $summaryData = @(
        [PSCustomObject]@{ Category = 'Total';                    Count = $totalAll;                Description = 'All service principals in the tenant' }
        [PSCustomObject]@{ Category = 'Microsoft first-party';    Count = $microsoftSPs.Count;      Description = 'Apps owned by Microsoft (merill/microsoft-info lookup + appOwnerOrganizationId)' }
        [PSCustomObject]@{ Category = 'Home tenant';              Count = $homeTenantSPs.Count;     Description = 'Apps registered in your organization' }
        [PSCustomObject]@{ Category = 'Third-party (cross-tenant)'; Count = $crossTenantSPs.Count;  Description = 'Apps from non-Microsoft external vendors' }
        [PSCustomObject]@{ Category = 'Unknown owner';            Count = $unknownOwnerSPs.Count;   Description = 'No appOwnerOrganizationId and not in Microsoft lookup' }
        [PSCustomObject]@{ Category = 'Scanned (non-Microsoft)';  Count = $homeTenantSPs.Count + $crossTenantSPs.Count + $unknownOwnerSPs.Count; Description = 'SPs scanned for dangerous permissions' }
    )
    Export-AuditCsv -Name 'Summary' -Data $summaryData

    # Apply documented filters before any per-service-principal calls.
    if ($script:AuditConfig.filters.excludeFirstPartyMicrosoftApps) {
        $sps = @($sps | Where-Object { (Get-AppTenantType -ServicePrincipal $_) -ne 'MicrosoftFirstParty' })
        Write-Host "  Scanning $($sps.Count) non-Microsoft SPs for dangerous permissions..." -ForegroundColor Gray
    }
    if ($script:AuditConfig.filters.excludeDisabledApps) {
        $sps = @($sps | Where-Object { $_.accountEnabled -ne $false })
    }
    if (@($script:AuditConfig.filters.excludeAppIds).Count -gt 0) {
        $sps = @($sps | Where-Object { $_.appId -notin $script:AuditConfig.filters.excludeAppIds })
    }

    $results = @()
    $total = $sps.Count
    $i = 0
    Set-CoverageState -Source 'ApplicationPermissionGrants' -State Complete
    Set-CoverageState -Source 'ResourcePermissionDefinitions' -State Complete
    foreach ($sp in $sps) {
        $i++
        if ($i % 100 -eq 0) { Write-Host "    Processing SP $i of $total..." -ForegroundColor DarkGray }
        try {
            $assignments = @(Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments?`$select=id,appRoleId,resourceId,resourceDisplayName")
        } catch {
            Set-CoverageState -Source 'ApplicationPermissionGrants' -State Partial -Detail "Failed for SP $($sp.id): $($_.Exception.Message)"
            continue
        }
        if ($assignments.Count -eq 0) { continue }

        foreach ($assignment in $assignments) {
            $resourceId = $assignment.resourceId
            if (-not $script:CachedResourceServicePrincipals.ContainsKey($resourceId)) {
                try {
                    $resSP = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$resourceId`?`$select=id,appId,displayName,appRoles,oauth2PermissionScopes"
                    $script:CachedResourceServicePrincipals[$resourceId] = $resSP
                } catch {
                    Set-CoverageState -Source 'ResourcePermissionDefinitions' -State Partial -Detail "Failed for resource SP ${resourceId}: $($_.Exception.Message)"
                    continue
                }
            }
            $resSP = $script:CachedResourceServicePrincipals[$resourceId]
            if (-not $resSP) { continue }
            $role = $resSP.appRoles | Where-Object { $_.id -eq $assignment.appRoleId } | Select-Object -First 1
            if (-not $role) { continue }
            $permDef = Find-DangerousPermissionDefinition -Name $role.value -Type Application -ResourceAppId $resSP.appId
            if ($permDef) {
                $results += [PSCustomObject]@{
                    SPId            = $sp.id
                    SPDisplayName   = $sp.displayName
                    AppId           = $sp.appId
                    AppTenantType   = Get-AppTenantType -ServicePrincipal $sp
                    ResourceSPId    = $resSP.id
                    ResourceAppId   = $resSP.appId
                    ResourceName    = $resSP.displayName
                    Permission      = $role.value
                    PermissionType  = 'Application'
                    Exploitability  = 'Direct'
                    ConsentType     = 'AdminConsent'
                    Risk            = $permDef.risk
                    Reason          = $permDef.reason
                    AttackAction    = $permDef.attackAction
                    AccountEnabled  = $sp.accountEnabled
                    EntraPortalUrl  = Get-EntraAppUrl -ObjectId $sp.id -AppId $sp.appId
                }
            }
        }
    }

    # Delegated grants need a signed-in user. They are exposure findings, not direct app-only takeover paths.
    $delegatedPerms = @($script:DangerousPermissions | Where-Object { $_.type -eq 'Delegated' })
    if ($delegatedPerms.Count -gt 0) {
        Write-Host "  Checking delegated permission grants..." -ForegroundColor Gray
        try {
            $grants = @(Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999')
            Set-CoverageState -Source 'DelegatedPermissionGrants' -State Complete
        } catch {
            Set-CoverageState -Source 'DelegatedPermissionGrants' -State Unavailable -Detail $_.Exception.Message
            $grants = @()
        }
        foreach ($grant in $grants) {
            if ($grant.consentType -notin @('AllPrincipals', 'Principal')) { continue }
            $grantedScopes = ($grant.scope -split ' ') | Where-Object { $_ }
            if (-not $script:CachedResourceServicePrincipals.ContainsKey($grant.resourceId)) {
                try {
                    $script:CachedResourceServicePrincipals[$grant.resourceId] = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($grant.resourceId)?`$select=id,appId,displayName"
                } catch {
                    Set-CoverageState -Source 'ResourcePermissionDefinitions' -State Partial -Detail "Failed for resource SP $($grant.resourceId): $($_.Exception.Message)"
                    continue
                }
            }
            $resourceSP = $script:CachedResourceServicePrincipals[$grant.resourceId]
            foreach ($dp in $delegatedPerms) {
                if ($dp.name -in $grantedScopes -and $dp.resourceAppId -eq $resourceSP.appId) {
                    $clientSP = $sps | Where-Object { $_.id -eq $grant.clientId } | Select-Object -First 1
                    if (-not $clientSP) { continue }
                    $results += [PSCustomObject]@{
                        SPId            = $clientSP.id
                        SPDisplayName   = $clientSP.displayName
                        AppId           = $clientSP.appId
                        AppTenantType   = Get-AppTenantType -ServicePrincipal $clientSP
                        ResourceSPId    = $resourceSP.id
                        ResourceAppId   = $resourceSP.appId
                        ResourceName    = $resourceSP.displayName
                        Permission      = $dp.name
                        PermissionType  = 'Delegated'
                        Exploitability  = 'Conditional'
                        ConsentType     = $grant.consentType
                        ConsentPrincipalId = $grant.principalId
                        Risk            = $dp.risk
                        Reason          = $dp.reason
                        AttackAction    = $dp.attackAction
                        AccountEnabled  = $clientSP.accountEnabled
                        EntraPortalUrl  = Get-EntraAppUrl -ObjectId $clientSP.id -AppId $clientSP.appId
                    }
                }
            }
        }
    }

    $script:CachedDangerousApps = $results
    return $results
}

function Get-PrivilegedRoleAssignments {
    if ($null -ne $script:CachedRoleAssignments) { return $script:CachedRoleAssignments }

    Write-Host "  Querying directory role assignments..." -ForegroundColor Gray
    $definitionSource = 'MicrosoftGraphBeta'
    try {
        $roleDefs = @(Get-AllGraphPages -Uri 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName,isBuiltIn,isEnabled,isPrivileged,rolePermissions,version&$top=999')
        Set-CoverageState -Source 'RoleDefinitions' -State Complete
    } catch {
        $betaError = $_.Exception.Message
        try {
            $roleDefs = @(Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName,isBuiltIn,isEnabled,rolePermissions,version&$top=999')
            $definitionSource = 'V1WithConfiguredSensitivityFallback'
            Set-CoverageState -Source 'RoleDefinitions' -State Partial -Detail "Beta isPrivileged unavailable; configured sensitive-role fallback used: $betaError"
        } catch {
            Set-CoverageState -Source 'RoleDefinitions' -State Unavailable -Detail $_.Exception.Message
            $script:CachedRoleAssignments = @()
            return @()
        }
    }

    try {
        $allAssignments = @(Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal&$top=999')
        Set-CoverageState -Source 'ActiveRoleAssignments' -State Complete
    } catch {
        Set-CoverageState -Source 'ActiveRoleAssignments' -State Unavailable -Detail $_.Exception.Message
        $script:CachedRoleAssignments = @()
        return @()
    }

    $configuredRoles = @{}
    foreach ($role in $script:PrivilegedRoles) { $configuredRoles[$role.templateId] = $role }
    $definitionEvidence = @{}
    foreach ($rd in $roleDefs) {
        $configured = if ($rd.templateId -and $configuredRoles.ContainsKey([string]$rd.templateId)) { $configuredRoles[[string]$rd.templateId] } else { $null }
        $graphSaysPrivileged = (Test-ObjectHasProperty -InputObject $rd -Name 'isPrivileged') -and [bool]$rd.isPrivileged
        $isSensitiveTarget = $graphSaysPrivileged -or $null -ne $configured
        $definitionEvidence[$rd.id] = [PSCustomObject]@{
            Id                          = $rd.id
            TemplateId                  = $rd.templateId
            DisplayName                 = $rd.displayName
            IsBuiltIn                   = [bool]$rd.isBuiltIn
            IsEnabled                   = if (Test-ObjectHasProperty -InputObject $rd -Name 'isEnabled') { [bool]$rd.isEnabled } else { $true }
            IsSensitiveTarget           = $isSensitiveTarget
            MicrosoftClassifiedPrivileged = $graphSaysPrivileged
            CanControlApplications      = Test-RoleCanControlApplications -RoleDefinition $rd
            CanControlServicePrincipals = Test-RoleCanControlServicePrincipals -RoleDefinition $rd
            AllowedResourceActions      = @(Get-RoleAllowedResourceActions -RoleDefinition $rd)
            Tier                        = if ($configured) { $configured.tier } else { if ($graphSaysPrivileged) { 'Microsoft privileged' } else { 'Application control' } }
            DefinitionSource            = $definitionSource
        }
    }
    $script:CachedRoleDefinitions = $definitionEvidence

    $results = @()
    foreach ($assignment in $allAssignments) {
        $definition = $definitionEvidence[$assignment.roleDefinitionId]
        if (-not $definition) {
            Set-CoverageState -Source 'RoleDefinitions' -State Partial -Detail "No definition returned for roleDefinitionId $($assignment.roleDefinitionId)"
            continue
        }
        if (-not ($definition.IsSensitiveTarget -or $definition.CanControlApplications -or $definition.CanControlServicePrincipals)) { continue }

        if ($assignment.principal.'@odata.type' -eq '#microsoft.graph.group') {
            Set-CoverageState -Source 'RoleGroupMemberships' -State Partial -Detail 'Role-assigned groups are listed, but their transitive user membership is not expanded in v0.5.2.'
        }
        $results += [PSCustomObject]@{
            PrincipalId          = $assignment.principalId
            PrincipalDisplayName = $assignment.principal.displayName
            PrincipalType        = $assignment.principal.'@odata.type'
            PrincipalUPN         = $assignment.principal.userPrincipalName
            PrincipalAppId       = $assignment.principal.appId
            RoleDefinitionId     = $assignment.roleDefinitionId
            RoleTemplateId       = $definition.TemplateId
            RoleName             = $definition.DisplayName
            RoleTier             = $definition.Tier
            IsSensitiveTarget    = $definition.IsSensitiveTarget
            MicrosoftClassifiedPrivileged = $definition.MicrosoftClassifiedPrivileged
            CanControlApplications = $definition.CanControlApplications
            CanControlServicePrincipals = $definition.CanControlServicePrincipals
            AllowedResourceActions = $definition.AllowedResourceActions
            DefinitionSource     = $definition.DefinitionSource
            DirectoryScopeId     = $assignment.directoryScopeId
            AppScopeId           = $assignment.appScopeId
        }
    }
    $script:CachedRoleAssignments = $results
    return $script:CachedRoleAssignments
}

function Get-ApplicationOwners {
    param([string[]]$AppIds)
    Write-Host "  Querying app owners..." -ForegroundColor Gray
    $results = @{}
    Set-CoverageState -Source 'ApplicationOwners' -State Complete
    foreach ($appId in $AppIds) {
        try {
            # Get the application object by appId, then its owners
            $apps = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$appId'&`$select=id,appId,displayName"
            $app = $apps | Select-Object -First 1
            if (-not $app) {
                $results[$appId] = [PSCustomObject]@{ Status = 'ApplicationObjectNotFound'; AppObjectId = $null; Owners = @() }
                Set-CoverageState -Source 'ApplicationOwners' -State Partial -Detail "No local application object was found for home-tenant appId $appId"
                continue
            }
            $owners = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/owners?`$select=id,displayName,userPrincipalName"
            $results[$appId] = [PSCustomObject]@{ Status = 'Complete'; AppObjectId = $app.id; Owners = @($owners) }
        } catch {
            $results[$appId] = [PSCustomObject]@{ Status = 'Unavailable'; AppObjectId = $null; Owners = @() }
            Set-CoverageState -Source 'ApplicationOwners' -State Partial -Detail "Failed for appId ${appId}: $($_.Exception.Message)"
        }
    }
    return $results
}

function Get-ServicePrincipalOwners {
    param([string[]]$SPIds)
    Write-Host "  Querying service principal owners..." -ForegroundColor Gray
    $results = @{}
    Set-CoverageState -Source 'ServicePrincipalOwners' -State Complete
    foreach ($spId in $SPIds) {
        try {
            $owners = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/owners?`$select=id,displayName,userPrincipalName"
            $results[$spId] = @($owners)
        } catch {
            Set-CoverageState -Source 'ServicePrincipalOwners' -State Partial -Detail "Failed for SP ${spId}: $($_.Exception.Message)"
        }
    }
    return $results
}

function Get-AppCredentials {
    param([string[]]$AppIds)
    Write-Host "  Querying app credentials..." -ForegroundColor Gray
    $results = @{}
    Set-CoverageState -Source 'ApplicationCredentials' -State Complete
    foreach ($appId in $AppIds) {
        try {
            $apps = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$appId'&`$select=id,appId,displayName,passwordCredentials,keyCredentials"
            $app = $apps | Select-Object -First 1
            if ($app) {
                $creds = @()
                if ($app.passwordCredentials) {
                    foreach ($pc in $app.passwordCredentials) {
                        $creds += [PSCustomObject]@{
                            Type         = 'Secret'
                            KeyId        = $pc.keyId
                            DisplayName  = $pc.displayName
                            StartDateTime = $pc.startDateTime
                            EndDateTime  = $pc.endDateTime
                            Expired      = if ($pc.endDateTime) { [datetime]$pc.endDateTime -lt (Get-Date) } else { $false }
                        }
                    }
                }
                if ($app.keyCredentials) {
                    foreach ($kc in $app.keyCredentials) {
                        $creds += [PSCustomObject]@{
                            Type         = 'Certificate'
                            KeyId        = $kc.keyId
                            DisplayName  = $kc.displayName
                            StartDateTime = $kc.startDateTime
                            EndDateTime  = $kc.endDateTime
                            Expired      = if ($kc.endDateTime) { [datetime]$kc.endDateTime -lt (Get-Date) } else { $false }
                        }
                    }
                }
                # Check for federated identity credentials
                try {
                    $fics = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/federatedIdentityCredentials"
                    foreach ($fic in $fics) {
                        $creds += [PSCustomObject]@{
                            Type         = 'Federated'
                            KeyId        = $fic.id
                            DisplayName  = $fic.name
                            StartDateTime = $null
                            EndDateTime  = $null
                            Expired      = $false
                        }
                    }
                } catch {
                    Set-CoverageState -Source 'FederatedIdentityCredentials' -State Partial -Detail "Failed for appId ${appId}: $($_.Exception.Message)"
                }
                $results[$appId] = $creds
            } else {
                Set-CoverageState -Source 'ApplicationCredentials' -State Partial -Detail "No local application object was found for appId $appId"
            }
        } catch {
            Set-CoverageState -Source 'ApplicationCredentials' -State Partial -Detail "Failed for appId ${appId}: $($_.Exception.Message)"
        }
    }
    return $results
}

function Get-SPDirectCredentials {
    param([string[]]$SPIds)
    Write-Host "  Querying SP-level credentials (hidden from portal)..." -ForegroundColor Gray
    $results = @{}
    Set-CoverageState -Source 'ServicePrincipalCredentials' -State Complete
    foreach ($spId in $SPIds) {
        try {
            $sp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId`?`$select=id,passwordCredentials,keyCredentials"
            $creds = @()
            if ($sp.passwordCredentials) {
                foreach ($pc in $sp.passwordCredentials) {
                    $creds += [PSCustomObject]@{
                        Type          = 'SP-Secret'
                        KeyId         = $pc.keyId
                        DisplayName   = $pc.displayName
                        StartDateTime = $pc.startDateTime
                        EndDateTime   = $pc.endDateTime
                        Expired       = if ($pc.endDateTime) { [datetime]$pc.endDateTime -lt (Get-Date) } else { $false }
                    }
                }
            }
            if ($sp.keyCredentials) {
                foreach ($kc in $sp.keyCredentials) {
                    $creds += [PSCustomObject]@{
                        Type          = 'SP-Certificate'
                        KeyId         = $kc.keyId
                        DisplayName   = $kc.displayName
                        StartDateTime = $kc.startDateTime
                        EndDateTime   = $kc.endDateTime
                        Expired       = if ($kc.endDateTime) { [datetime]$kc.endDateTime -lt (Get-Date) } else { $false }
                    }
                }
            }
            $results[$spId] = $creds
        } catch {
            Set-CoverageState -Source 'ServicePrincipalCredentials' -State Partial -Detail "Failed for SP ${spId}: $($_.Exception.Message)"
        }
    }
    return $results
}

function Get-AppInstanceLockStatus {
    param([string[]]$AppIds)
    Write-Host "  Querying app instance property lock status..." -ForegroundColor Gray
    $results = @{}
    Set-CoverageState -Source 'AppInstanceLocks' -State Complete
    foreach ($appId in $AppIds) {
        try {
            $apps = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$appId'&`$select=id,appId,servicePrincipalLockConfiguration"
            $app = $apps | Select-Object -First 1
            if ($app) {
                $results[$appId] = ConvertTo-AppInstanceLockEvidence -LockConfiguration $app.servicePrincipalLockConfiguration
            } else {
                $results[$appId] = [PSCustomObject]@{ State = 'NotLocallyObservable'; IsEnabled = $null; IsCredentialLocked = $null; LocksAllProperties = $null; LocksSigningUsage = $null; LocksVerifyUsage = $null }
                Set-CoverageState -Source 'AppInstanceLocks' -State Partial -Detail "No local application object exposes lock configuration for appId $appId"
            }
        } catch {
            $results[$appId] = [PSCustomObject]@{ State = 'Unavailable'; IsEnabled = $null; IsCredentialLocked = $null; LocksAllProperties = $null; LocksSigningUsage = $null; LocksVerifyUsage = $null }
            Set-CoverageState -Source 'AppInstanceLocks' -State Partial -Detail "Failed for appId ${appId}: $($_.Exception.Message)"
        }
    }
    return $results
}

function Get-SPSignInActivity {
    Write-Host "  Querying service principal sign-in activity..." -ForegroundColor Gray
    try {
        # servicePrincipalSignInActivities is currently available only in Microsoft Graph beta.
        $activities = Get-AllGraphPages -Uri 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities?$top=999'
        $lookup = @{}
        foreach ($a in $activities) {
            $lookup[$a.appId] = $a
        }
        Set-CoverageState -Source 'ServicePrincipalSignInActivity' -State Complete
        return $lookup
    } catch {
        Set-CoverageState -Source 'ServicePrincipalSignInActivity' -State Unavailable -Detail $_.Exception.Message
        Write-Host "  ⚠ Could not query sign-in activity. StalePrivilege cannot be evaluated safely." -ForegroundColor Yellow
        Write-Host "    Verify AuditLog.Read.All, licensing, and Microsoft Graph beta availability." -ForegroundColor DarkYellow
        return $null
    }
}

function Get-TenantConsentPolicy {
    Write-Host "  Querying tenant authorization policy..." -ForegroundColor Gray
    try {
        $policy = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
        Set-CoverageState -Source 'TenantAuthorizationPolicy' -State Complete
        return $policy
    } catch {
        Set-CoverageState -Source 'TenantAuthorizationPolicy' -State Unavailable -Detail $_.Exception.Message
        Write-Host "  ⚠ Could not query authorization policy." -ForegroundColor Yellow
        return $null
    }
}

function Get-UserConsentGrants {
    Write-Host "  Querying user consent grants..." -ForegroundColor Gray
    try {
        $grants = Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999'
        Set-CoverageState -Source 'UserConsentGrants' -State Complete
        return $grants | Where-Object { $_.consentType -eq 'Principal' }
    } catch {
        Set-CoverageState -Source 'UserConsentGrants' -State Unavailable -Detail $_.Exception.Message
        return @()
    }
}

function Get-AllUsers {
    Write-Host "  Querying all users..." -ForegroundColor Gray
    try {
        $users = Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName&$top=999'
        Set-CoverageState -Source 'Users' -State Complete
        return $users
    } catch {
        Set-CoverageState -Source 'Users' -State Unavailable -Detail $_.Exception.Message
        return @()
    }
}

#endregion

#region ── Mode: PermissionAudit ──────────────────────────────────────────────

function Invoke-PermissionAudit {
    Write-Banner "PERMISSION AUDIT -- Dangerous API Permission Grants"

    $dangerousApps = Get-ServicePrincipalsWithAppRoles

    if ($dangerousApps.Count -eq 0) {
        if (Test-AuditCoverageComplete -Sources @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions', 'DelegatedPermissionGrants')) {
            Write-Host "✓ No configured dangerous permissions found." -ForegroundColor Green
        } else {
            Write-Host "⚠ No findings in the evidence that was available; the permission audit is incomplete." -ForegroundColor Yellow
        }
        return @()
    }

    $applicationGrantCount = @($dangerousApps | Where-Object { $_.PermissionType -eq 'Application' }).Count
    $delegatedGrantCount = @($dangerousApps | Where-Object { $_.PermissionType -eq 'Delegated' }).Count
    Write-Host "Found $($dangerousApps.Count) dangerous grant(s): $applicationGrantCount application, $delegatedGrantCount delegated." -ForegroundColor Yellow
    Write-Host ""

    $formatted = $dangerousApps | Select-Object @{N='App Name';E={$_.SPDisplayName}},
        @{N='App ID';E={$_.AppId}}, @{N='Permission';E={$_.Permission}},
        @{N='Type';E={$_.PermissionType}}, @{N='Resource API';E={$_.ResourceName}},
        @{N='Exploitability';E={$_.Exploitability}}
    $formatted | Format-Table -AutoSize | Out-String | Write-Host

    Write-Host "⚠  Application grants are app-only capabilities. Delegated grants require a signed-in user" -ForegroundColor Yellow
    Write-Host "   and are reported as conditional exposure rather than credential-only takeover." -ForegroundColor Yellow
    Write-Reference 'https://learn.microsoft.com/graph/permissions-overview#best-practices-for-using-microsoft-graph-permissions'

    Export-AuditCsv -Name 'PermissionAudit' -Data $dangerousApps

    return $dangerousApps
}

#endregion

#region ── Mode: RoleAudit ────────────────────────────────────────────────────

function Invoke-RoleAudit {
    Write-Banner "ROLE AUDIT -- Privileged Role Membership"

    $roleAssignments = @(Get-PrivilegedRoleAssignments)
    $sensitiveRoleAssignments = @($roleAssignments | Where-Object { $_.IsSensitiveTarget })
    $allUsers = Get-AllUsers
    $roleAssignmentEvidenceComplete = Test-AuditCoverageComplete -Sources @('RoleDefinitions', 'ActiveRoleAssignments')

    # Group user role assignments
    $userRoles = @{}
    foreach ($ra in ($sensitiveRoleAssignments | Where-Object { $_.PrincipalType -eq '#microsoft.graph.user' })) {
        $upn = $ra.PrincipalUPN
        if (-not $upn) { $upn = $ra.PrincipalDisplayName }
        if (-not $userRoles.ContainsKey($ra.PrincipalId)) {
            $userRoles[$ra.PrincipalId] = [PSCustomObject]@{
                DisplayName = $ra.PrincipalDisplayName
                UPN         = $upn
                Roles       = [System.Collections.Generic.List[string]]::new()
            }
        }
        $userRoles[$ra.PrincipalId].Roles.Add($ra.RoleName)
    }

    $privilegedUserIds = $userRoles.Keys
    $canClassifyNonPrivileged = Test-AuditCoverageComplete -Sources @('RoleDefinitions', 'ActiveRoleAssignments', 'Users')
    $nonPrivilegedUsers = if ($canClassifyNonPrivileged) {
        @($allUsers | Where-Object { $_.id -notin $privilegedUserIds })
    } else {
        @()
    }

    # Display privileged users
    if ($roleAssignmentEvidenceComplete) {
        Write-Host "USERS IN SENSITIVE ROLES ($($userRoles.Count) users):" -ForegroundColor Green
    } else {
        Write-Host "SENSITIVE-ROLE USER ASSIGNMENTS OBSERVED ($($userRoles.Count) users; INCOMPLETE):" -ForegroundColor DarkYellow
    }
    Write-Host ""
    $pUsers = $userRoles.Values | ForEach-Object {
        [PSCustomObject]@{
            User    = $_.DisplayName
            UPN     = $_.UPN
            'Role(s)' = ($_.Roles -join ', ')
        }
    }
    $pUsers | Format-Table -AutoSize | Out-String | Write-Host

    # Display non-privileged users
    $totalNonPriv = ($nonPrivilegedUsers | Measure-Object).Count
    $truncateAfter = [Math]::Min([int]$script:AuditConfig.output.truncateAfter, [int]$script:AuditConfig.output.maxUsersInRoleAuditList)
    if (-not $canClassifyNonPrivileged) {
        Write-Host 'USERS WITHOUT SENSITIVE ROLES: NOT CLASSIFIED (role evidence is incomplete)' -ForegroundColor DarkYellow
    } else {
        Write-Host "USERS NOT IN ANY SENSITIVE ROLE ($totalNonPriv users):" -ForegroundColor Gray
    }
    Write-Host ""
    $displayUsers = $nonPrivilegedUsers | Select-Object -First $truncateAfter |
        ForEach-Object { [PSCustomObject]@{ User = $_.displayName; UPN = $_.userPrincipalName } }
    $displayUsers | Format-Table -AutoSize | Out-String | Write-Host

    if ($totalNonPriv -gt $truncateAfter) {
        Write-Host "... ($($totalNonPriv - $truncateAfter) more)" -ForegroundColor DarkGray
    }

    Write-Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference'

    # Also report SPs in privileged roles
    $spRoles = $sensitiveRoleAssignments | Where-Object { $_.PrincipalType -eq '#microsoft.graph.servicePrincipal' }
    if ($spRoles.Count -gt 0) {
        Write-Host ""
        Write-Host "SERVICE PRINCIPALS IN PRIVILEGED ROLES ($($spRoles.Count)):" -ForegroundColor Yellow
        $spRoles | ForEach-Object {
            [PSCustomObject]@{ 'SP Name' = $_.PrincipalDisplayName; Role = $_.RoleName; Tier = $_.RoleTier }
        } | Format-Table -AutoSize | Out-String | Write-Host
    }

    $groupRoles = @($sensitiveRoleAssignments | Where-Object { $_.PrincipalType -eq '#microsoft.graph.group' })
    if ($groupRoles.Count -gt 0) {
        Write-Host ''
        Write-Host "GROUPS ASSIGNED SENSITIVE ROLES ($($groupRoles.Count) assignments):" -ForegroundColor DarkYellow
        Write-Host '  Transitive members are not expanded in v0.5.2; data coverage is marked partial.' -ForegroundColor DarkYellow
        $groupRoleExport = @($groupRoles | ForEach-Object {
            [PSCustomObject]@{
                GroupName        = $_.PrincipalDisplayName
                GroupId          = $_.PrincipalId
                Role             = $_.RoleName
                DirectoryScopeId = $_.DirectoryScopeId
            }
        })
        $groupRoleExport | Format-Table -AutoSize | Out-String | Write-Host
        Export-AuditCsv -Name 'RoleAssignedGroups' -Data $groupRoleExport
    }

    # Export
    $exportData = @()
    foreach ($userId in $userRoles.Keys) {
        $u = $userRoles[$userId]
        $exportData += [PSCustomObject]@{
            DisplayName = $u.DisplayName; UPN = $u.UPN; Roles = ($u.Roles -join '; '); HasPrivilegedRole = $true
            EntraPortalUrl = Get-EntraUserUrl -ObjectId $userId
        }
    }
    foreach ($u in $nonPrivilegedUsers) {
        $exportData += [PSCustomObject]@{
            DisplayName = $u.displayName; UPN = $u.userPrincipalName; Roles = ''; HasPrivilegedRole = $false
            EntraPortalUrl = Get-EntraUserUrl -ObjectId $u.id
        }
    }
    Export-AuditCsv -Name 'RoleAudit' -Data $exportData

    return [PSCustomObject]@{ PrivilegedUsers = $userRoles; NonPrivilegedUsers = $nonPrivilegedUsers; SPRoles = $spRoles; GroupRoles = $groupRoles; RoleAssignments = $roleAssignments; SensitiveRoleAssignments = $sensitiveRoleAssignments; CoverageComplete = $canClassifyNonPrivileged }
}

#endregion

#region ── Mode: AttackPath ───────────────────────────────────────────────────

function Invoke-AttackPathAnalysis {
    Write-Banner "ATTACK PATH ANALYSIS -- Privilege Escalation via Applications & Service Principals"

    $dangerousApps = @(Get-ServicePrincipalsWithAppRoles)
    $directDangerousApps = @($dangerousApps | Where-Object { $_.PermissionType -eq 'Application' })
    $conditionalDangerousApps = @($dangerousApps | Where-Object { $_.PermissionType -eq 'Delegated' })
    $roleAssignments = @(Get-PrivilegedRoleAssignments)
    $roleEvidenceComplete = Test-AuditCoverageComplete -Sources @('RoleDefinitions', 'ActiveRoleAssignments')

    # SPs with privileged directory roles
    $privilegedSPs = @($roleAssignments | Where-Object { $_.PrincipalType -eq '#microsoft.graph.servicePrincipal' -and $_.IsSensitiveTarget })

    if ($directDangerousApps.Count -eq 0 -and $privilegedSPs.Count -eq 0) {
        if (Test-AuditCoverageComplete -Sources @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions', 'RoleDefinitions', 'ActiveRoleAssignments')) {
            Write-Host "✓ No direct application-permission or privileged-SP paths found." -ForegroundColor Green
        } else {
            Write-Host "⚠ No direct paths found in the available evidence; attack-path coverage is incomplete." -ForegroundColor Yellow
        }
        if ($conditionalDangerousApps.Count -gt 0) {
            Write-Host "  $($conditionalDangerousApps.Count) delegated permission exposure(s) remain listed in PermissionAudit; they require a signed-in user." -ForegroundColor DarkYellow
        }
        return @()
    }

    # Get owners for dangerous apps
    $appIds = @()
    $appOwners = @{}
    if ($directDangerousApps.Count -gt 0) {
        # Application ownership exists only for app registrations in this tenant.
        $appIds = @($directDangerousApps | Where-Object { $_.AppTenantType -eq 'HomeTenant' } | ForEach-Object { $_.AppId } | Select-Object -Unique)
        $appOwners = Get-ApplicationOwners -AppIds $appIds
    }

    # Collect all relevant SP IDs for credential and lock queries
    $allRelevantSPIds = @()
    if ($directDangerousApps.Count -gt 0) { $allRelevantSPIds += @($directDangerousApps | ForEach-Object { $_.SPId } | Select-Object -Unique) }
    if ($privilegedSPs.Count -gt 0) { $allRelevantSPIds += @($privilegedSPs | ForEach-Object { $_.PrincipalId } | Select-Object -Unique) }
    $allRelevantSPIds = @($allRelevantSPIds | Select-Object -Unique)

    # Get SP-level credentials and app instance lock status
    $spDirectCreds = @{}
    $appLockStatus = @{}
    if ($allRelevantSPIds.Count -gt 0) {
        $spDirectCreds = Get-SPDirectCredentials -SPIds $allRelevantSPIds
    }
    $privilegedTargetAppIds = @($privilegedSPs | ForEach-Object {
        $targetAssignment = $_
        if ($targetAssignment.PrincipalAppId) {
            $targetAssignment.PrincipalAppId
        } else {
            ($script:CachedServicePrincipals | Where-Object { $_.id -eq $targetAssignment.PrincipalId } | Select-Object -First 1).appId
        }
    } | Where-Object { $_ } | Select-Object -Unique)
    $lockAppIds = @($appIds + $privilegedTargetAppIds | Where-Object { $_ } | Select-Object -Unique)
    if ($lockAppIds.Count -gt 0) {
        $appLockStatus = Get-AppInstanceLockStatus -AppIds $lockAppIds
    }

    $paths = @()
    $pathNum = 0

    # ── PATH TYPE 1: App Owner Escalation ──────────────────────────────────
    foreach ($appId in $appOwners.Keys) {
        $ownerEvidence = $appOwners[$appId]
        if (-not $ownerEvidence -or $ownerEvidence.Status -ne 'Complete') { continue }
        $owners = @($ownerEvidence.Owners)
        $apps = $directDangerousApps | Where-Object { $_.AppId -eq $appId }
        foreach ($owner in $owners) {
            # Only an existing Global Administrator is already equivalent to every configured target.
            # A reader or narrower privileged role can still have a real privilege increase.
            $existingRoles = @($roleAssignments | Where-Object { $_.PrincipalId -eq $owner.id -and $_.PrincipalType -eq '#microsoft.graph.user' } | ForEach-Object { $_.RoleName } | Select-Object -Unique)
            foreach ($app in $apps) {
                if ($roleEvidenceComplete -and (Test-UserAlreadyEquivalentToPermission -UserId $owner.id -Permission $app.Permission -RoleAssignments $roleAssignments)) { continue }
                $pathNum++
                $spCreds = $spDirectCreds[$app.SPId]
                $spCredCount = if ($spCreds) { @($spCreds | Where-Object { -not $_.Expired }).Count } else { 0 }
                $lock = $appLockStatus[$appId]

                $pathDef = $script:AttackPathDefs | Where-Object { $_.id -eq 'APP_OWNER_ESCALATION' } | Select-Object -First 1
                $impactSeverity = if ($app.Risk) { [string]$app.Risk } elseif ($pathDef -and $pathDef.severity) { [string]$pathDef.severity } else { 'High' }
                $impactReason = if ($app.Reason) { [string]$app.Reason } else { "Can use the $($app.Permission) application permission" }
                $attackAction = if ($app.AttackAction) { [string]$app.AttackAction } else { "use the $($app.Permission) application permission" }
                $paths += [PSCustomObject]@{
                    PathNumber      = $pathNum
                    PathType        = 'App Owner Escalation'
                    PathId          = 'APP_OWNER_ESCALATION'
                    Severity        = $impactSeverity.ToUpperInvariant()
                    UserDisplayName = $owner.displayName
                    UserUPN         = $owner.userPrincipalName
                    UserRole        = if (-not $roleEvidenceComplete) { 'Unknown (role evidence incomplete)' } elseif ($existingRoles.Count -gt 0) { $existingRoles -join ', ' } else { 'None of the sensitive roles evaluated' }
                    AppName         = $app.SPDisplayName
                    AppId           = $app.AppId
                    Permission      = $app.Permission
                    PermissionType  = $app.PermissionType
                    Exploitability  = if ($roleEvidenceComplete) { 'Direct' } else { 'PotentialRoleUnknown' }
                    Action          = "Add app credential → authenticate as app → $attackAction"
                    Result          = $impactReason
                    SPDirectCreds   = $spCredCount
                    AppInstanceLock = if ($lock) { $lock.State } else { 'Unavailable' }
                    Remediation     = if ($pathDef) { $pathDef.remediation -join '; ' } else { 'Remove owner or reduce permissions' }
                    UserEntraUrl    = Get-EntraUserUrl -ObjectId $owner.id
                    AppEntraUrl     = Get-EntraAppUrl -ObjectId $app.SPId -AppId $app.AppId
                }
            }
        }
    }

    # ── PATH TYPE 2: Role-Based SP Control ─────────────────────────────────
    # Capability comes from the current role definition, so built-in role changes
    # and custom roles are handled without a hardcoded two-role assumption.
    $applicationControlAssignments = @($roleAssignments | Where-Object {
        $_.PrincipalType -eq '#microsoft.graph.user' -and ($_.CanControlServicePrincipals -or $_.CanControlApplications)
    })

    if ($applicationControlAssignments.Count -gt 0 -and $privilegedSPs.Count -gt 0) {
        foreach ($userId in @($applicationControlAssignments | ForEach-Object { $_.PrincipalId } | Select-Object -Unique)) {
            if (Test-UserIsGlobalAdministrator -UserId $userId -RoleAssignments $roleAssignments) { continue }
            $userAssignments = @($roleAssignments | Where-Object { $_.PrincipalId -eq $userId -and $_.PrincipalType -eq '#microsoft.graph.user' })

            foreach ($spGroup in ($privilegedSPs | Group-Object PrincipalId)) {
                $sp = $spGroup.Group | Select-Object -First 1
                $targetSP = $script:CachedServicePrincipals | Where-Object { $_.id -eq $sp.PrincipalId } | Select-Object -First 1
                $targetTenantType = if ($targetSP) { Get-AppTenantType -ServicePrincipal $targetSP } else { 'Unknown' }
                $applicableControl = @($applicationControlAssignments | Where-Object {
                    $_.PrincipalId -eq $userId -and (Test-RoleAssignmentAppliesToServicePrincipal -RoleAssignment $_ -ServicePrincipalId $sp.PrincipalId)
                })
                $applicableControl = @($applicableControl | Where-Object {
                    $_.CanControlServicePrincipals -or ($_.CanControlApplications -and $targetTenantType -eq 'HomeTenant')
                })
                if ($applicableControl.Count -eq 0) { continue }

                # Do not claim an escalation into roles the user already holds.
                $newTargetRoles = @($spGroup.Group | Where-Object {
                    $target = $_
                    -not ($userAssignments | Where-Object { $_.RoleDefinitionId -eq $target.RoleDefinitionId } | Select-Object -First 1)
                })
                if ($newTargetRoles.Count -eq 0) { continue }

                $targetAppId = if ($sp.PrincipalAppId) { $sp.PrincipalAppId } elseif ($targetSP) { $targetSP.appId } else { $null }
                $lock = if ($targetAppId) { $appLockStatus[$targetAppId] } else { $null }
                $canUseApplicationObject = $targetTenantType -eq 'HomeTenant' -and [bool]($applicableControl | Where-Object { $_.CanControlApplications } | Select-Object -First 1)
                $canUseServicePrincipalObject = [bool]($applicableControl | Where-Object { $_.CanControlServicePrincipals } | Select-Object -First 1)
                $servicePrincipalRouteLocked = $canUseServicePrincipalObject -and $lock -and $lock.IsCredentialLocked
                $isMitigated = $servicePrincipalRouteLocked -and -not $canUseApplicationObject
                $lockUnknown = $canUseServicePrincipalObject -and -not $canUseApplicationObject -and (-not $lock -or $lock.State -in @('Unavailable', 'NotLocallyObservable'))

                $pathNum++
                $spCreds = $spDirectCreds[$sp.PrincipalId]
                $spCredCount = if ($spCreds) { @($spCreds | Where-Object { -not $_.Expired }).Count } else { 0 }
                $controlRoleNames = @($applicableControl | ForEach-Object { $_.RoleName } | Select-Object -Unique)
                $targetRoleNames = @($newTargetRoles | ForEach-Object { $_.RoleName } | Select-Object -Unique)
                $pathDef = $script:AttackPathDefs | Where-Object { $_.id -eq 'ROLE_BASED_SP_CONTROL' } | Select-Object -First 1
                $paths += [PSCustomObject]@{
                    PathNumber      = $pathNum
                    PathType        = 'Role-Based SP Control'
                    PathId          = 'ROLE_BASED_SP_CONTROL'
                    Severity        = if ($isMitigated) { 'INFO' } elseif ($lockUnknown) { 'HIGH' } else { 'CRITICAL' }
                    Exploitability  = if ($isMitigated) { 'MitigatedByAppInstanceLock' } elseif ($lockUnknown) { 'PotentialLockUnknown' } else { 'Direct' }
                    UserDisplayName = $applicableControl[0].PrincipalDisplayName
                    UserUPN         = $applicableControl[0].PrincipalUPN
                    UserRole        = $controlRoleNames -join ', '
                    AppName         = $sp.PrincipalDisplayName
                    AppId           = $targetAppId
                    Permission      = $targetRoleNames -join ', '
                    PermissionType  = 'DirectoryRole'
                    Action          = if ($canUseApplicationObject) { "Add an application credential → authenticate as SP → use $($targetRoleNames -join ', ')" } else { "Add an SP credential → authenticate as SP → use $($targetRoleNames -join ', ')" }
                    Result          = if ($isMitigated) { 'CREDENTIAL-INJECTION ROUTE BLOCKED BY APP INSTANCE LOCK' } elseif ($lockUnknown) { 'POTENTIAL PRIVILEGE ESCALATION; LOCK EVIDENCE UNAVAILABLE' } else { 'PRIVILEGE ESCALATION VIA SP' }
                    SPDirectCreds   = $spCredCount
                    AppInstanceLock = if ($lock) { $lock.State } else { 'Unavailable' }
                    Remediation     = if ($pathDef) { $pathDef.remediation -join '; ' } else { 'Use PIM, scope application-control roles, and enable app instance lock' }
                    UserEntraUrl    = Get-EntraUserUrl -ObjectId $userId
                    AppEntraUrl     = Get-EntraAppUrl -ObjectId $sp.PrincipalId -AppId $targetAppId
                }
            }
        }
    }

    # ── Check for unowned privileged apps ──────────────────────────────────
    $unownedApps = @()
    foreach ($appId in $appIds) {
        $ownerEvidence = $appOwners[$appId]
        # Missing/failed evidence is not the same as a confirmed empty owner set.
        if ($ownerEvidence -and $ownerEvidence.Status -eq 'Complete' -and @($ownerEvidence.Owners).Count -eq 0) {
            $apps = $directDangerousApps | Where-Object { $_.AppId -eq $appId }
            $app = $apps | Select-Object -First 1
            $spCreds = $spDirectCreds[$app.SPId]
            $spCredCount = if ($spCreds) { @($spCreds | Where-Object { -not $_.Expired }).Count } else { 0 }
            $lock = $appLockStatus[$appId]
            $unownedApps += [PSCustomObject]@{
                AppName         = $app.SPDisplayName
                AppId           = $appId
                Permissions     = ($apps | ForEach-Object { $_.Permission }) -join ', '
                SPDirectCreds   = $spCredCount
                AppInstanceLock = if ($lock) { $lock.State } else { 'Unavailable' }
                AppTenantType   = $app.AppTenantType
                EntraUrl        = Get-EntraAppUrl -ObjectId $app.SPId -AppId $app.AppId
            }
        }
    }

    # ── Display Results ────────────────────────────────────────────────────
    if ($paths.Count -eq 0 -and $unownedApps.Count -eq 0) {
        if (Test-AuditCoverageComplete -Sources @('ApplicationOwners', 'RoleDefinitions', 'ActiveRoleAssignments', 'AppInstanceLocks')) {
            Write-Host "✓ No attack paths or confirmed unowned privileged apps found." -ForegroundColor Green
        } else {
            Write-Host "⚠ No paths found in the available evidence; attack-path coverage is incomplete." -ForegroundColor Yellow
        }
        return @()
    }

    if ($paths.Count -gt 0) {
        # Split paths by type for display
        $ownerPaths = @($paths | Where-Object { $_.PathType -eq 'App Owner Escalation' })
        $roleBasedPaths = @($paths | Where-Object { $_.PathType -eq 'Role-Based SP Control' })

        Write-Host "Found $($paths.Count) attack path(s): $($ownerPaths.Count) App Owner Escalation, $($roleBasedPaths.Count) Role-Based SP Control" -ForegroundColor Red
        Write-Host ""

        # Display App Owner Escalation paths with full box format
        foreach ($path in $ownerPaths) {
            Write-SectionDivider "PATH $($path.PathNumber): $($path.PathType) ($($path.Severity))"
            Write-Host "  ┌─────────────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkYellow
            Write-Host "  │  $($path.UserUPN)" -ForegroundColor White
            Write-Host "  │  Role: $($path.UserRole)" -ForegroundColor Gray
            if ($path.Exploitability -eq 'PotentialRoleUnknown') {
                Write-Host "  │  ⚠ Potential path: current role assignments could not be read" -ForegroundColor Yellow
            }
            Write-Host "  │                          ↓ owns" -ForegroundColor DarkGray
            Write-Host "  │  App: `"$($path.AppName)`"$(if ($path.AppId) { " ($($path.AppId))" })" -ForegroundColor White
            Write-Host "  │  Permission: $($path.Permission) ($($path.PermissionType))" -ForegroundColor Yellow
            if ($path.SPDirectCreds -gt 0) {
                Write-Host "  │  ⚠ SP has $($path.SPDirectCreds) direct credential(s) — hidden from portal" -ForegroundColor Red
            }
            Write-Host "  │  App Instance Lock: $($path.AppInstanceLock) — does not block app-registration owner credentials" -ForegroundColor DarkGray
            Write-Host "  │                          ↓ can exploit" -ForegroundColor DarkGray
            Write-Host "  │  Action: $($path.Action)" -ForegroundColor Red
            Write-Host "  │  Impact: $($path.Result)" -ForegroundColor Red
            Write-Host "  └─────────────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkYellow

            $pathDef = $script:AttackPathDefs | Where-Object { $_.id -eq 'APP_OWNER_ESCALATION' } | Select-Object -First 1
            if ($pathDef) {
                Write-Recommendation -Items $pathDef.remediation
            }
        }

        # Display Role-Based SP Control as a summary table (grouped by user)
        if ($roleBasedPaths.Count -gt 0) {
            Write-Host ""
            Write-SectionDivider "ROLE-BASED SP CONTROL ($($roleBasedPaths.Count) paths)"
            Write-Host "⚠  Users whose current built-in or custom roles can change application or SP credentials may" -ForegroundColor Yellow
            Write-Host "   control the $(@($roleBasedPaths | ForEach-Object { $_.AppName } | Select-Object -Unique).Count) service principals below that hold sensitive roles." -ForegroundColor Yellow
            Write-Host ""

            $roleBasedUsers = $roleBasedPaths | Group-Object UserUPN
            foreach ($userGroup in $roleBasedUsers) {
                $first = $userGroup.Group | Select-Object -First 1
                Write-Host "  $($first.UserDisplayName) ($($first.UserUPN))" -ForegroundColor White
                Write-Host "  Role: $($first.UserRole)  →  can control $($userGroup.Count) privileged SP(s):" -ForegroundColor Gray
                $userGroup.Group | Select-Object @{N='  SP Name';E={$_.AppName}},
                    @{N='SP Roles';E={$_.Permission}},
                    @{N='SP Direct Creds';E={$_.SPDirectCreds}},
                    @{N='Exploitability';E={$_.Exploitability}} |
                    Format-Table -AutoSize | Out-String | Write-Host
            }

            $pathDef = $script:AttackPathDefs | Where-Object { $_.id -eq 'ROLE_BASED_SP_CONTROL' } | Select-Object -First 1
            if ($pathDef) {
                Write-Recommendation -Items $pathDef.remediation
            }
        }

        Write-Reference 'https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5'
    }

    # Display unowned privileged apps
    if ($unownedApps.Count -gt 0) {
        Write-Host ""
        Write-SectionDivider "UNOWNED PRIVILEGED APPS ($($unownedApps.Count))"
        Write-Host "⚠  The following apps have dangerous permissions but NO assigned owners:" -ForegroundColor Yellow
        Write-Host ""
        $unownedApps | Select-Object @{N='App Name';E={$_.AppName}}, @{N='App ID';E={$_.AppId}},
            @{N='Permissions';E={$_.Permissions}}, @{N='SP Direct Creds';E={$_.SPDirectCreds}},
            @{N='Instance Lock';E={$_.AppInstanceLock}} |
            Format-Table -AutoSize | Out-String | Write-Host

        $pathDef = $script:AttackPathDefs | Where-Object { $_.id -eq 'UNOWNED_PRIVILEGED_APP' } | Select-Object -First 1
        if ($pathDef) {
            Write-Recommendation -Items $pathDef.remediation
        }
    }

    Write-Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-planning#protect-against-consent-grant-attacks'

    Export-AuditCsv -Name 'AttackPaths' -Data $paths
    if ($unownedApps.Count -gt 0) {
        Export-AuditCsv -Name 'UnownedPrivilegedApps' -Data $unownedApps
    }

    return $paths
}

#endregion

#region ── Mode: ShadowAdmins ─────────────────────────────────────────────────

function Invoke-ShadowAdminDetection {
    Write-Banner "SHADOW ADMIN DETECTION -- SP Owners with Indirect Privilege"

    $roleAssignments = @(Get-PrivilegedRoleAssignments)
    $spRoleAssignments = @($roleAssignments | Where-Object { $_.PrincipalType -eq '#microsoft.graph.servicePrincipal' -and $_.IsSensitiveTarget })

    if ($spRoleAssignments.Count -eq 0) {
        if (Test-AuditCoverageComplete -Sources @('RoleDefinitions', 'ActiveRoleAssignments')) {
            Write-Host "✓ No service principals hold configured sensitive directory roles." -ForegroundColor Green
        } else {
            Write-Host "⚠ No sensitive-role service principals were found in the available evidence; role coverage is incomplete." -ForegroundColor Yellow
        }
        return @()
    }

    # Get owners for SPs with roles
    $spIds = $spRoleAssignments | ForEach-Object { $_.PrincipalId } | Select-Object -Unique
    $spOwners = Get-ServicePrincipalOwners -SPIds $spIds

    # Get SP-level credentials
    $spDirectCreds = Get-SPDirectCredentials -SPIds $spIds

    $shadows = @()
    foreach ($spId in $spOwners.Keys) {
        $owners = $spOwners[$spId]
        $roles = $spRoleAssignments | Where-Object { $_.PrincipalId -eq $spId }
        $spCreds = $spDirectCreds[$spId]
        $spCredCount = if ($spCreds) { @($spCreds | Where-Object { -not $_.Expired }).Count } else { 0 }
        foreach ($owner in $owners) {
            if (Test-UserIsGlobalAdministrator -UserId $owner.id -RoleAssignments $roleAssignments) { continue }
            $ownerRoleAssignments = @($roleAssignments | Where-Object { $_.PrincipalId -eq $owner.id -and $_.PrincipalType -eq '#microsoft.graph.user' })
            foreach ($role in $roles) {
                if ($ownerRoleAssignments | Where-Object { $_.RoleDefinitionId -eq $role.RoleDefinitionId } | Select-Object -First 1) { continue }
                $shadows += [PSCustomObject]@{
                    UserDisplayName  = $owner.displayName
                    UserUPN          = $owner.userPrincipalName
                    SPDisplayName    = $role.PrincipalDisplayName
                    SPId             = $spId
                    SPRole           = $role.RoleName
                    SPDirectCreds    = $spCredCount
                    ExistingRoles    = @($ownerRoleAssignments | ForEach-Object { $_.RoleName } | Select-Object -Unique) -join ', '
                    Risk             = "User can reset SP credentials → activate as SP → use $($role.RoleName) role"
                    Remediation      = 'Remove user as SP owner or remove the SP role assignment'
                    UserEntraUrl     = Get-EntraUserUrl -ObjectId $owner.id
                    SPEntraUrl       = Get-EntraAppUrl -ObjectId $spId
                }
            }
        }
    }

    if ($shadows.Count -eq 0) {
        if (Test-AuditCoverageComplete -Sources @('RoleDefinitions', 'ActiveRoleAssignments', 'ServicePrincipalOwners')) {
            Write-Host "✓ No privilege-increasing SP owner paths found." -ForegroundColor Green
        } else {
            Write-Host "⚠ No shadow paths found in the available evidence; owner or role coverage is incomplete." -ForegroundColor Yellow
        }
        return @()
    }

    Write-Host "Found $($shadows.Count) shadow admin path(s):" -ForegroundColor Red
    Write-Host ""

    foreach ($s in $shadows) {
        Write-Host "  User:              $($s.UserUPN) (No privileged roles)" -ForegroundColor White
        Write-Host "  Owns SP:           `"$($s.SPDisplayName)`" (SP ID: $($s.SPId))" -ForegroundColor White
        Write-Host "  SP Has Role:       $($s.SPRole)" -ForegroundColor Yellow
        if ($s.SPDirectCreds -gt 0) {
            Write-Host "  SP Direct Creds:   ⚠ $($s.SPDirectCreds) credential(s) added directly to SP — hidden from portal" -ForegroundColor Red
        }
        Write-Host "  Risk:              $($s.Risk)" -ForegroundColor Red
        Write-Host "  Remediation:       $($s.Remediation)" -ForegroundColor Green
        Write-Host ""
    }

    Write-Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/privileged-roles-permissions'

    Export-AuditCsv -Name 'ShadowAdmins' -Data $shadows

    return $shadows
}

#endregion

#region ── Mode: StalePrivilege ───────────────────────────────────────────────

function Invoke-StalePrivilegeDetection {
    Write-Banner "STALE PRIVILEGE -- Dormant High-Privilege Apps with Valid Credentials"
    $script:StalePrivilegeDataAvailable = $null

    $dangerousApps = @(Get-ServicePrincipalsWithAppRoles | Where-Object { $_.PermissionType -eq 'Application' })
    if ($dangerousApps.Count -eq 0) {
        $script:StalePrivilegeDataAvailable = $true
        if (Test-AuditCoverageComplete -Sources @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions')) {
            Write-Host "✓ No apps with configured dangerous application permissions found." -ForegroundColor Green
        } else {
            Write-Host "⚠ No findings in the available evidence; stale-privilege coverage is incomplete." -ForegroundColor Yellow
        }
        return @()
    }

    $signInActivity = Get-SPSignInActivity
    if ($null -eq $signInActivity) {
        $script:StalePrivilegeDataAvailable = $false
        Write-Host "⚠ StalePrivilege skipped because service principal sign-in activity is unavailable." -ForegroundColor Yellow
        Write-Host "  No apps will be classified as stale or as having never signed in." -ForegroundColor Yellow
        return @()
    }
    $script:StalePrivilegeDataAvailable = $true

    $appIds = $dangerousApps | ForEach-Object { $_.AppId } | Select-Object -Unique
    $homeAppIds = @($dangerousApps | Where-Object { $_.AppTenantType -eq 'HomeTenant' } | ForEach-Object { $_.AppId } | Select-Object -Unique)
    $appCreds = if ($homeAppIds.Count -gt 0) { Get-AppCredentials -AppIds $homeAppIds } else { @{} }
    $spIds = @($dangerousApps | ForEach-Object { $_.SPId } | Select-Object -Unique)
    $spDirectCreds = Get-SPDirectCredentials -SPIds $spIds

    $inactiveDays = $script:AuditConfig.stalePrivilege.inactiveDays
    $cutoffDate = (Get-Date).AddDays(-$inactiveDays)
    $staleApps = @()

    foreach ($appId in $appIds) {
        $apps = $dangerousApps | Where-Object { $_.AppId -eq $appId }
        $creds = @($appCreds[$appId])
        foreach ($spId in @($apps | ForEach-Object { $_.SPId } | Select-Object -Unique)) {
            $creds += @($spDirectCreds[$spId])
        }

        # Check if any creds are still valid (not expired)
        $validCreds = @()
        if ($creds) { $validCreds = @($creds | Where-Object { $_ -and -not $_.Expired }) }
        if ($validCreds.Count -eq 0) { continue } # No valid creds — not exploitable

        # Check sign-in activity
        $activity = $signInActivity[$appId]
        $lastSignIn = $null
        $daysSinceSignIn = $null
        if ($activity) {
            $lastActivity = $activity.lastSignInActivity
            if ($lastActivity -and $lastActivity.lastSignInDateTime) {
                $lastSignIn = [datetime]$lastActivity.lastSignInDateTime
                $daysSinceSignIn = ((Get-Date) - $lastSignIn).Days
            }
        }

        $isStale = $false
        if (-not $lastSignIn) {
            $isStale = $true # Never signed in
        } elseif ($lastSignIn -lt $cutoffDate) {
            $isStale = $true
        }

        if (-not $isStale) { continue }

        foreach ($a in $apps) {
            $credType = ($validCreds | Select-Object -First 1).Type
            $credExpiry = ($validCreds | Select-Object -First 1).EndDateTime
            $staleApps += [PSCustomObject]@{
                AppName           = $a.SPDisplayName
                AppId             = $a.AppId
                Permission        = $a.Permission
                LastSignIn        = if ($daysSinceSignIn) { "$daysSinceSignIn days ago" } else { 'Never' }
                CredentialType    = $credType
                CredentialExpires = if ($credExpiry) { ([datetime]$credExpiry).ToString('yyyy-MM-dd') } else { 'N/A' }
                ValidCredCount    = $validCreds.Count
                EntraPortalUrl    = Get-EntraAppUrl -ObjectId $a.SPId -AppId $a.AppId
            }
        }
    }

    if ($staleApps.Count -eq 0) {
        if (Test-AuditCoverageComplete -Sources @('ServicePrincipalSignInActivity', 'ServicePrincipalCredentials')) {
            Write-Host "✓ No stale high-privilege apps found." -ForegroundColor Green
        } else {
            Write-Host "⚠ No stale apps found in the available evidence; credential coverage is incomplete." -ForegroundColor Yellow
        }
        return @()
    }

    Write-Host "Found $($staleApps.Count) stale high-privilege app(s):" -ForegroundColor Yellow
    Write-Host ""
    $staleApps | Select-Object @{N='App Name';E={$_.AppName}}, @{N='Dangerous Permission';E={$_.Permission}},
        @{N='Last Sign-In';E={$_.LastSignIn}}, @{N='Credential Type';E={$_.CredentialType}},
        @{N='Credential Expires';E={$_.CredentialExpires}} |
        Format-Table -AutoSize | Out-String | Write-Host

    Write-Host "⚠  These apps have dangerous permissions, valid credentials, and no recent activity." -ForegroundColor Yellow
    Write-Host "   They are prime targets for credential theft and privilege escalation." -ForegroundColor Yellow

    Write-Recommendation -Items @(
        'Disable or delete the app if no longer needed'
        'Remove the dangerous permissions'
        'Rotate and then revoke the credentials'
        'Set up alerts for sign-in activity on high-privilege apps'
    )

    Write-Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-application-permissions'

    Export-AuditCsv -Name 'StalePrivilege' -Data $staleApps

    return $staleApps
}

#endregion

#region ── Mode: ConsentRisk ──────────────────────────────────────────────────

function Invoke-ConsentRiskAssessment {
    Write-Banner "CONSENT RISK -- Tenant Consent Policy Assessment"

    $policy = Get-TenantConsentPolicy
    if (-not $policy) {
        Write-Host "⚠ Could not retrieve consent policy. Skipping." -ForegroundColor Yellow
        return @()
    }

    $findings = @()

    # Analyze default user role permissions
    $defaultPerms = $policy.defaultUserRolePermissions

    # Values are action-prefixed (managePermissionGrantsForSelf.<policy-id>), and
    # a custom policy is a real enabled state rather than "disabled".
    $consentState = Resolve-UserConsentPolicyAssignment -AssignedPolicies @($defaultPerms.permissionGrantPoliciesAssigned)
    $userConsentAllowed = $consentState.State -eq 'AllowedForAllApps'

    if ($consentState.State -eq 'AllowedForAllApps') {
        $findings += [PSCustomObject]@{
            Setting = 'User consent for apps'
            Value   = 'Allowed (all permissions)'
            Risk    = '⚠  CRITICAL'
        }
    } elseif ($consentState.State -eq 'RestrictedBuiltIn') {
        $findings += [PSCustomObject]@{
            Setting = 'User consent for apps'
            Value   = 'Allowed (verified publishers, low-risk only)'
            Risk    = 'ⓘ  REVIEW'
        }
    } elseif ($consentState.State -eq 'CustomPolicy') {
        $findings += [PSCustomObject]@{
            Setting = 'User consent for apps'
            Value   = "Custom policy: $($consentState.PolicyIds -join ', ')"
            Risk    = 'ⓘ  REVIEW'
        }
    } else {
        $findings += [PSCustomObject]@{
            Setting = 'User consent for apps'
            Value   = 'Disabled'
            Risk    = '✓  GOOD'
        }
    }

    # Users can register apps
    $canRegister = $defaultPerms.allowedToCreateApps
    $findings += [PSCustomObject]@{
        Setting = 'Users can register apps'
        Value   = if ($canRegister) { 'Yes' } else { 'No' }
        Risk    = if ($canRegister) { 'ⓘ  LOW' } else { '✓  GOOD' }
    }

    # Check if users can read other users
    $canReadOthers = $defaultPerms.allowedToReadOtherUsers
    $findings += [PSCustomObject]@{
        Setting = 'Users can read other users'
        Value   = if ($canReadOthers) { 'Yes' } else { 'No' }
        Risk    = if ($canReadOthers) { 'ⓘ  INFO' } else { 'ⓘ  INFO' }
    }

    Write-Host "TENANT CONSENT POLICY:" -ForegroundColor Cyan
    Write-Host ""
    $findings | Format-Table -AutoSize | Out-String | Write-Host

    # Check user-consented apps
    if ($script:AuditConfig.consentRisk.flagUserConsentedApps) {
        $userGrants = Get-UserConsentGrants
        if ($userGrants.Count -gt 0) {
            # Group by clientId
            $grantsByApp = $userGrants | Group-Object -Property clientId
            Write-Host "APPS WITH USER-CONSENTED (NOT ADMIN-CONSENTED) PERMISSIONS ($($grantsByApp.Count) apps):" -ForegroundColor Yellow
            Write-Host ""

            # Resolve every app for export; display truncation never truncates evidence.
            $consentData = @()
            $truncateAfter = $script:AuditConfig.output.truncateAfter
            Set-CoverageState -Source 'UserConsentClientResolution' -State Complete
            foreach ($group in $grantsByApp) {
                $displayName = '[unresolved]'
                try {
                    $sp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($group.Name)?`$select=displayName"
                    $displayName = $sp.displayName
                } catch {
                    Set-CoverageState -Source 'UserConsentClientResolution' -State Partial -Detail "Failed for client SP $($group.Name): $($_.Exception.Message)"
                }
                $scopes = @($group.Group | ForEach-Object { $_.scope } | Where-Object { $_ }) -join ' '
                $userCount = @($group.Group | ForEach-Object { $_.principalId } | Select-Object -Unique).Count
                $consentData += [PSCustomObject]@{
                    AppName          = $displayName
                    ClientSPId       = $group.Name
                    ResourceSPIds    = @($group.Group | ForEach-Object { $_.resourceId } | Select-Object -Unique) -join '; '
                    ConsentedScopes  = $scopes.Trim()
                    ConsentingUsers  = $userCount
                }
            }
            $consentData | Select-Object -First $truncateAfter | Format-Table -AutoSize | Out-String | Write-Host
            Export-AuditCsv -Name 'UserConsentGrants' -Data $consentData

            if ($grantsByApp.Count -gt $truncateAfter) {
                Write-Host "... ($($grantsByApp.Count - $truncateAfter) more)" -ForegroundColor DarkGray
            }
        } else {
            if (Test-AuditCoverageComplete -Sources @('UserConsentGrants')) {
                Write-Host "✓ No user-consented permission grants found." -ForegroundColor Green
            } else {
                Write-Host "⚠ User consent grants could not be evaluated completely." -ForegroundColor Yellow
            }
        }
    }

    if ($userConsentAllowed) {
        Write-Recommendation -Items @(
            'Set user consent to "Do not allow user consent" or "Allow for verified publishers only"'
            'Enable admin consent workflow so users can request access'
            'Review and revoke suspicious user-consented permissions above'
            'Configure risk-based consent evaluation policies'
        )
    }

    Write-Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent'

    Export-AuditCsv -Name 'ConsentRisk' -Data $findings

    return $findings
}

#endregion

#region ── Mode: CredentialHygiene ─────────────────────────────────────────────

function Invoke-CredentialHygieneAudit {
    Write-Banner "CREDENTIAL HYGIENE -- Credential Risk for High-Privilege Apps"

    $dangerousApps = Get-ServicePrincipalsWithAppRoles
    if ($dangerousApps.Count -eq 0) {
        if (Test-AuditCoverageComplete -Sources @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions', 'DelegatedPermissionGrants')) {
            Write-Host "✓ No apps with configured dangerous grants found." -ForegroundColor Green
        } else {
            Write-Host "⚠ No findings in the available evidence; credential-hygiene coverage is incomplete." -ForegroundColor Yellow
        }
        return @()
    }

    $appIds = $dangerousApps | ForEach-Object { $_.AppId } | Select-Object -Unique
    $homeAppIds = @($dangerousApps | Where-Object { $_.AppTenantType -eq 'HomeTenant' } | ForEach-Object { $_.AppId } | Select-Object -Unique)
    $appCreds = if ($homeAppIds.Count -gt 0) { Get-AppCredentials -AppIds $homeAppIds } else { @{} }

    # Also get SP-level credentials (added directly to SP object, hidden from portal)
    $spIds = @($dangerousApps | ForEach-Object { $_.SPId } | Select-Object -Unique)
    $spDirectCreds = Get-SPDirectCredentials -SPIds $spIds
    $appLockStatus = if ($homeAppIds.Count -gt 0) { Get-AppInstanceLockStatus -AppIds $homeAppIds } else { @{} }

    $results = @()
    foreach ($appId in $appIds) {
        $apps = $dangerousApps | Where-Object { $_.AppId -eq $appId }
        $app = $apps | Select-Object -First 1
        $creds = $appCreds[$appId]

        # SP-level credentials
        $spCreds = $spDirectCreds[$app.SPId]
        $spCredCount = if ($spCreds) { @($spCreds).Count } else { 0 }
        $spValidCreds = if ($spCreds) { @($spCreds | Where-Object { -not $_.Expired }).Count } else { 0 }

        # App instance lock
        $lock = $appLockStatus[$appId]

        if ((-not $creds -or $creds.Count -eq 0) -and $spCredCount -eq 0) {
            $results += [PSCustomObject]@{
                AppName          = $app.SPDisplayName
                AppId            = $app.AppId
                Permission       = ($apps | ForEach-Object { $_.Permission }) -join ', '
                CredType         = 'None'
                CredCount        = 0
                ExpiredCount     = 0
                SPDirectCreds    = 0
                AppInstanceLock  = if ($lock) { $lock.State } elseif ($app.AppTenantType -eq 'HomeTenant') { 'Unavailable' } else { 'NotLocallyObservable' }
                RiskLevel        = 'ⓘ  INFO (no credentials)'
                EntraPortalUrl   = Get-EntraAppUrl -ObjectId $app.SPId -AppId $app.AppId
            }
            continue
        }

        $credTypes = @()
        $certCount = 0; $expiredCount = 0; $totalCreds = 0
        if ($creds -and $creds.Count -gt 0) {
            $credTypes += ($creds | ForEach-Object { $_.Type } | Select-Object -Unique)
            $certCount = ($creds | Where-Object { $_.Type -eq 'Certificate' } | Measure-Object).Count
            $expiredCount = ($creds | Where-Object { $_.Expired } | Measure-Object).Count
            $totalCreds = $creds.Count
        }
        if ($spCredCount -gt 0) {
            $credTypes += ($spCreds | ForEach-Object { $_.Type } | Select-Object -Unique)
            $expiredCount += ($spCreds | Where-Object { $_.Expired } | Measure-Object).Count
            $totalCreds += $spCredCount
        }
        $credTypeStr = ($credTypes | Select-Object -Unique) -join ', '

        # Determine risk using the documented configuration values.
        $uniqueCredTypes = @($credTypes | Select-Object -Unique)
        $riskyTypes = @($script:AuditConfig.credentialHygiene.riskyCredentialTypes)
        $preferredTypes = @($script:AuditConfig.credentialHygiene.preferredCredentialTypes)
        $hasConfiguredRiskyType = [bool]($uniqueCredTypes | Where-Object { $_ -in $riskyTypes } | Select-Object -First 1)
        $onlyPreferredTypes = $uniqueCredTypes.Count -gt 0 -and @($uniqueCredTypes | Where-Object { $_ -notin $preferredTypes }).Count -eq 0
        $riskLevel = '✓  GOOD'
        if ($spValidCreds -gt 0) {
            $riskLevel = '⚠  CRITICAL (SP-level credentials — hidden from portal)'
        } elseif ($hasConfiguredRiskyType -and $script:AuditConfig.credentialHygiene.flagMultipleCredentials -and $totalCreds -gt 1) {
            $riskLevel = '⚠  CRITICAL (multiple credentials including configured risky types)'
        } elseif ($hasConfiguredRiskyType) {
            $riskLevel = '⚠  HIGH (configured risky credential type)'
        } elseif ($onlyPreferredTypes) {
            $riskLevel = '✓  GOOD (preferred credential type)'
        } elseif ($certCount -gt 0) {
            $riskLevel = '✓  MODERATE (certificate; permission remains dangerous)'
        }
        if ($script:AuditConfig.credentialHygiene.flagExpiredCredentials -and $expiredCount -gt 0) {
            $riskLevel += "; $expiredCount expired credential(s) should be removed"
        }

        $results += [PSCustomObject]@{
            AppName          = $app.SPDisplayName
            AppId            = $app.AppId
            Permission       = ($apps | ForEach-Object { $_.Permission }) -join ', '
            CredType         = $credTypeStr
            CredCount        = $totalCreds
            ExpiredCount     = $expiredCount
            SPDirectCreds    = $spValidCreds
            AppInstanceLock  = if ($lock) { $lock.State } elseif ($app.AppTenantType -eq 'HomeTenant') { 'Unavailable' } else { 'NotLocallyObservable' }
            RiskLevel        = $riskLevel
            EntraPortalUrl   = Get-EntraAppUrl -ObjectId $app.SPId -AppId $app.AppId
        }
    }

    $results | Select-Object @{N='App Name';E={$_.AppName}}, @{N='Permission';E={$_.Permission}},
        @{N='Cred Type';E={$_.CredType}}, @{N='Count';E={$_.CredCount}},
        @{N='Expired';E={$_.ExpiredCount}}, @{N='SP Creds';E={$_.SPDirectCreds}},
        @{N='Lock';E={$_.AppInstanceLock}}, @{N='Risk';E={$_.RiskLevel}} |
        Format-Table -AutoSize | Out-String | Write-Host

    # Summary
    $secretApps = ($results | Where-Object { $_.CredType -match 'Secret' } | Measure-Object).Count
    $certApps = ($results | Where-Object { $_.CredType -match 'Certificate' -and $_.CredType -notmatch 'Secret' } | Measure-Object).Count
    $fedApps = ($results | Where-Object { $_.CredType -match 'Federated' -and $_.CredType -notmatch 'Secret' -and $_.CredType -notmatch 'Certificate' } | Measure-Object).Count
    $totalExpired = ($results | Measure-Object -Property ExpiredCount -Sum).Sum
    $multiCred = ($results | Where-Object { $_.CredCount -gt 1 } | Measure-Object).Count
    $spCredApps = ($results | Where-Object { $_.SPDirectCreds -gt 0 } | Measure-Object).Count
    $unlocked = ($results | Where-Object { $_.AppInstanceLock -in @('Disabled', 'NotConfigured', 'EnabledButOAuthCredentialsNotLocked') -and $_.CredType -ne 'None' } | Measure-Object).Count

    Write-Host "SUMMARY:" -ForegroundColor Cyan
    Write-Host "  Apps using secrets:              $secretApps  ← migrate to certificates or managed identities" -ForegroundColor $(if ($secretApps -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Apps using certificates:         $certApps  ← review permission scope" -ForegroundColor Gray
    Write-Host "  Apps using federated/managed:    $fedApps  ← best practice ✓" -ForegroundColor Green
    Write-Host "  Total expired credentials:       $totalExpired  ← remove to reduce attack surface" -ForegroundColor $(if ($totalExpired -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Apps with multiple credentials:  $multiCred  ← investigate, may indicate credential sprawl" -ForegroundColor $(if ($multiCred -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Apps with SP-level credentials:  $spCredApps  ← HIDDEN from portal, investigate immediately" -ForegroundColor $(if ($spCredApps -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  App instance lock disabled:      $unlocked  ← enable to prevent SP credential injection" -ForegroundColor $(if ($unlocked -gt 0) { 'Yellow' } else { 'Green' })

    Write-Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/certificate-management'

    Export-AuditCsv -Name 'CredentialHygiene' -Data $results

    return $results
}

#endregion

#region ── Mode: Full ─────────────────────────────────────────────────────────

function Invoke-FullAudit {
    $summary = @{}

    $permResults = Invoke-PermissionAudit
    $summary['PermissionAudit'] = "$($permResults.Count) configured dangerous permission grant(s)"

    $roleResults = Invoke-RoleAudit
    $roleCoverageComplete = [bool]$roleResults.CoverageComplete
    $summary['RoleAudit'] = if ($roleCoverageComplete) {
        "$($roleResults.PrivilegedUsers.Count) users with sensitive-role assignments, $(($roleResults.NonPrivilegedUsers | Measure-Object).Count) confirmed without"
    } else {
        "Incomplete — $($roleResults.PrivilegedUsers.Count) sensitive-role user assignment(s) observed; other users not classified"
    }

    $attackResults = Invoke-AttackPathAnalysis
    $directAttackResults = @($attackResults | Where-Object { $_.Exploitability -eq 'Direct' })
    $potentialAttackResults = @($attackResults | Where-Object { $_.Exploitability -like 'Potential*' })
    $potentialLockResults = @($attackResults | Where-Object { $_.Exploitability -eq 'PotentialLockUnknown' })
    $potentialRoleResults = @($attackResults | Where-Object { $_.Exploitability -eq 'PotentialRoleUnknown' })
    $mitigatedAttackResults = @($attackResults | Where-Object { $_.Exploitability -eq 'MitigatedByAppInstanceLock' })
    $summary['AttackPaths'] = "$($directAttackResults.Count) direct, $($potentialAttackResults.Count) potential, $($mitigatedAttackResults.Count) blocked by app instance lock"

    $shadowResults = Invoke-ShadowAdminDetection
    $shadowRoleCoverageComplete = Test-AuditCoverageComplete -Sources @('RoleDefinitions', 'ActiveRoleAssignments')
    $shadowOwnerCoverageComplete = @($roleResults.SPRoles).Count -eq 0 -or (Test-AuditCoverageComplete -Sources 'ServicePrincipalOwners')
    $shadowCoverageComplete = $shadowRoleCoverageComplete -and $shadowOwnerCoverageComplete
    $summary['ShadowAdmins'] = if ($shadowCoverageComplete) {
        "$($shadowResults.Count) shadow admin detected"
    } else {
        "Incomplete — $($shadowResults.Count) shadow admin relationship(s) observed"
    }

    $staleResults = Invoke-StalePrivilegeDetection
    $summary['StalePrivilege'] = if ($script:StalePrivilegeDataAvailable -eq $false) {
        'Not evaluated (sign-in activity unavailable)'
    } else {
        "$($staleResults.Count) dormant high-privilege apps"
    }

    $consentResults = Invoke-ConsentRiskAssessment
    $criticalConsent = ($consentResults | Where-Object { $_.Risk -match 'CRITICAL|HIGH' } | Measure-Object).Count
    $summary['ConsentRisk'] = "$criticalConsent HIGH/CRITICAL consent policy issues"

    $credResults = Invoke-CredentialHygieneAudit
    $secretApps = ($credResults | Where-Object { $_.CredType -match 'Secret' } | Measure-Object).Count
    $spCredApps = ($credResults | Where-Object { $_.SPDirectCreds -gt 0 } | Measure-Object).Count
    $summary['CredentialHygiene'] = "$secretApps high-privilege apps using secrets, $spCredApps with SP-level credentials"

    # Print summary
    Write-Banner "FULL AUDIT SUMMARY"

    Write-Host "  Permission Audit:      $($summary['PermissionAudit'])" -ForegroundColor $(if ($permResults.Count -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Role Audit:            $($summary['RoleAudit'])" -ForegroundColor $(if ($roleCoverageComplete) { 'Gray' } else { 'DarkYellow' })
    Write-Host "  Attack Paths:          $($summary['AttackPaths'])" -ForegroundColor $(if ($directAttackResults.Count -gt 0) { 'Red' } elseif ($potentialAttackResults.Count -gt 0 -or $mitigatedAttackResults.Count -gt 0) { 'DarkYellow' } else { 'Green' })
    Write-Host "  Shadow Admins:         $($summary['ShadowAdmins'])" -ForegroundColor $(if (-not $shadowCoverageComplete) { 'DarkYellow' } elseif ($shadowResults.Count -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  Stale Privilege:       $($summary['StalePrivilege'])" -ForegroundColor $(if ($script:StalePrivilegeDataAvailable -eq $false) { 'DarkYellow' } elseif ($staleResults.Count -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Consent Risk:          $($summary['ConsentRisk'])" -ForegroundColor $(if ($criticalConsent -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Credential Hygiene:    $($summary['CredentialHygiene'])" -ForegroundColor $(if ($secretApps -gt 0 -or $spCredApps -gt 0) { 'Yellow' } else { 'Green' })

    # Overall risk indicator
    $riskScore = 0
    $riskScore += [Math]::Min($permResults.Count * 2, 4)
    $riskScore += [Math]::Min($directAttackResults.Count * 3, 6)
    $riskScore += [Math]::Min($potentialAttackResults.Count * 2, 4)
    $riskScore += [Math]::Min($shadowResults.Count * 3, 3)
    $riskScore += [Math]::Min($staleResults.Count, 3)
    $riskScore += [Math]::Min($criticalConsent * 2, 4)
    $riskScore = [Math]::Min($riskScore, 20)

    $filled = '█' * $riskScore
    $empty = '░' * (20 - $riskScore)

    $overallRisk = if ($riskScore -ge 14) { 'CRITICAL' } elseif ($riskScore -ge 8) { 'HIGH' } elseif ($riskScore -ge 4) { 'MEDIUM' } else { 'LOW' }
    $riskColor = if ($riskScore -ge 14) { 'Red' } elseif ($riskScore -ge 8) { 'Yellow' } elseif ($riskScore -ge 4) { 'DarkYellow' } else { 'Green' }

    Write-Host ""
    Write-Host "  OVERALL RISK:          $filled$empty  $overallRisk" -ForegroundColor $riskColor
    $coverageComplete = Test-AuditCoverageComplete
    Write-Host "  DATA COVERAGE:         $(if ($coverageComplete) { 'COMPLETE' } else { 'PARTIAL -- see details below' })" -ForegroundColor $(if ($coverageComplete) { 'Green' } else { 'DarkYellow' })

    # Top actions
    $actions = @()
    if ($directAttackResults.Count -gt 0) {
        $actions += "Remove or constrain the control relationships behind $($directAttackResults.Count) exploitable app path(s)"
    }
    if ($potentialLockResults.Count -gt 0) {
        $actions += "Verify app instance lock for $($potentialLockResults.Count) potential SP-control path(s) whose lock state is not locally observable"
    }
    if ($potentialRoleResults.Count -gt 0) {
        $actions += "Complete role evidence and validate $($potentialRoleResults.Count) potential app-owner path(s)"
    }
    if ($criticalConsent -gt 0) {
        $actions += 'Disable user consent or restrict to verified publishers'
    }
    if ($staleResults.Count -gt 0) {
        $actions += "Disable/delete $($staleResults.Count) dormant apps with dangerous permissions and valid credentials"
    }
    if ($shadowResults.Count -gt 0) {
        $actions += "Remove $($shadowResults.Count) shadow admin relationship(s)"
    }
    if ($secretApps -gt 0) {
        $actions += "Migrate $secretApps high-privilege app(s) from secrets to certificates"
    }
    if ($spCredApps -gt 0) {
        $actions += "Investigate $spCredApps app(s) with SP-level credentials (hidden from portal)"
    }

    if ($actions.Count -gt 0) {
        Write-Host ""
        Write-Host "  Top Actions:" -ForegroundColor White
        $actionNum = 0
        foreach ($action in ($actions | Select-Object -First 5)) {
            $actionNum++
            Write-Host "    $actionNum. $action" -ForegroundColor Gray
        }
    }

    # Export full audit summary CSV
    $summaryRows = @(
        [PSCustomObject]@{ Section = 'PermissionAudit';    Finding = $summary['PermissionAudit'];    Count = $permResults.Count }
        [PSCustomObject]@{ Section = 'RoleAudit';          Finding = $summary['RoleAudit'];          Count = $roleResults.PrivilegedUsers.Count }
        [PSCustomObject]@{ Section = 'AttackPaths';        Finding = $summary['AttackPaths'];        Count = "$($directAttackResults.Count) direct, $($potentialAttackResults.Count) potential" }
        [PSCustomObject]@{ Section = 'ShadowAdmins';       Finding = $summary['ShadowAdmins'];       Count = $shadowResults.Count }
        [PSCustomObject]@{ Section = 'StalePrivilege';     Finding = $summary['StalePrivilege'];     Count = $staleResults.Count }
        [PSCustomObject]@{ Section = 'ConsentRisk';        Finding = $summary['ConsentRisk'];        Count = $criticalConsent }
        [PSCustomObject]@{ Section = 'CredentialHygiene';  Finding = $summary['CredentialHygiene'];  Count = "$secretApps secrets, $spCredApps SP-creds" }
        [PSCustomObject]@{ Section = 'OverallRisk';        Finding = $overallRisk;                   Count = $riskScore }
        [PSCustomObject]@{ Section = 'DataCoverage';       Finding = $(if ($coverageComplete) { 'Complete' } else { 'Partial -- see DataCoverage.csv or console details' }); Count = '' }
    )
    $actionNum = 0
    foreach ($action in ($actions | Select-Object -First 5)) {
        $actionNum++
        $summaryRows += [PSCustomObject]@{ Section = "Action$actionNum"; Finding = $action; Count = '' }
    }
    Export-AuditCsv -Name 'FullAuditSummary' -Data $summaryRows
    Write-AuditCoverageSummary

    if ($ExportPath) {
        Write-Host ""
        Write-Host "  Full results exported to: $ExportPath" -ForegroundColor DarkGreen
    }
}

#endregion

#region ── Main Execution ─────────────────────────────────────────────────────

# Dot-sourcing loads the functions for Pester/advanced use without connecting to Graph.
if ($MyInvocation.InvocationName -eq '.') { return }

Reset-AuditCoverage

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
Write-Host "║  Privileged App Path Auditor                                                 ║" -ForegroundColor DarkCyan
Write-Host "║  Identifies privilege escalation paths through Entra ID applications         ║" -ForegroundColor DarkCyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
Write-Host ""

# Load configuration
Initialize-Config

# Verify required modules
$requiredModules = @(
    'Microsoft.Graph.Authentication'
    'Microsoft.Graph.Applications'
    'Microsoft.Graph.Identity.DirectoryManagement'
    'Microsoft.Graph.Identity.SignIns'
)

$missingModules = @()
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        $missingModules += $mod
    }
}

if ($missingModules.Count -gt 0) {
    Write-Host "⚠ Missing required modules:" -ForegroundColor Red
    foreach ($m in $missingModules) {
        Write-Host "  - $m" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "Install them with:" -ForegroundColor Yellow
    Write-Host "  Install-Module $($missingModules -join ', ') -Scope CurrentUser" -ForegroundColor Yellow
    exit 1
}

# Connect to Graph
Connect-GraphIfNeeded

Write-Host ""
Write-Host "Running mode: $Mode" -ForegroundColor Cyan
Write-Host ""

$startTime = Get-Date

switch ($Mode) {
    'PermissionAudit'   { Invoke-PermissionAudit }
    'RoleAudit'         { Invoke-RoleAudit }
    'AttackPath'        { Invoke-AttackPathAnalysis }
    'ShadowAdmins'      { Invoke-ShadowAdminDetection }
    'StalePrivilege'    { Invoke-StalePrivilegeDetection }
    'ConsentRisk'       { Invoke-ConsentRiskAssessment }
    'CredentialHygiene' { Invoke-CredentialHygieneAudit }
    'Full'              { Invoke-FullAudit }
}

if ($Mode -ne 'Full') {
    Write-AuditCoverageSummary
}

$elapsed = (Get-Date) - $startTime
Write-Host ""
Write-Host "Completed in $([math]::Round($elapsed.TotalSeconds, 1)) seconds." -ForegroundColor DarkGray

#endregion
