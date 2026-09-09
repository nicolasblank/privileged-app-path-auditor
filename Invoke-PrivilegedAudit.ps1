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
    Version: 0.6.0

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

$script:Version = '0.6.0'
$script:CachedDangerousApps = $null
$script:CachedRoleAssignments = $null
$script:CachedRoleDefinitions = $null
$script:CachedServicePrincipals = $null
$script:CachedResourceServicePrincipals = @{}
$script:StalePrivilegeDataAvailable = $null
$script:StalePrivilegeStatus = $null
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
            # Invoke-RestMethod can emit a JSON array as one pipeline object when it is
            # wrapped at the call site. Assign first, then enumerate it explicitly.
            $downloadedCatalog = Invoke-RestMethod -Uri $sourceUrl -Method Get -ErrorAction Stop
            $response = @($downloadedCatalog)
            $validEntries = @($response | Where-Object {
                if (($_ -isnot [pscustomobject] -and $_ -isnot [System.Collections.IDictionary]) -or $_.AppId -isnot [string]) { return $false }
                # The upstream catalog has occasionally contained encoding debris after
                # an otherwise valid GUID. Recover only an unambiguous leading GUID.
                $match = [regex]::Match([string]$_.AppId, '^(?<id>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')
                if (-not $match.Success) { return $false }
                $_.AppId = $match.Groups['id'].Value
                return $true
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
            $cachedCatalog = Get-Content $cacheFile -Raw -ErrorAction Stop | ConvertFrom-Json -NoEnumerate -ErrorAction Stop
            $apps = @($cachedCatalog)
            if ($apps.Count -eq 0) { throw 'The cached Microsoft app catalog is empty.' }
            foreach ($app in $apps) {
                $parsedAppId = [guid]::Empty
                if ($app -isnot [pscustomobject] -or $app.AppId -isnot [string] -or
                    $app.AppId.Length -ne 36 -or -not [guid]::TryParseExact($app.AppId, 'D', [ref]$parsedAppId)) {
                    throw 'The cached Microsoft app catalog contains an invalid entry or AppId.'
                }
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

$script:ModeCoverageCapture = $null

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
    foreach ($ledger in @($script:Coverage, $script:ModeCoverageCapture)) {
        if ($null -eq $ledger) { continue }
        if (-not $ledger.Contains($Source)) {
            $ledger[$Source] = [PSCustomObject]@{
                Source  = $Source
                State   = $State
                Details = [System.Collections.Generic.List[string]]::new()
            }
        } elseif ($rank[$State] -gt $rank[$ledger[$Source].State]) {
            $ledger[$Source].State = $State
        }

        if ($Detail -and -not $ledger[$Source].Details.Contains($Detail)) {
            $ledger[$Source].Details.Add($Detail)
        }
    }
}

function Get-PermissionCoverageSource {
    $sources = @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions')
    if (@($script:DangerousPermissions | Where-Object { $_.type -eq 'Delegated' }).Count -gt 0) {
        $sources += 'DelegatedPermissionGrants'
    }
    return $sources
}

function Test-AuditCoverageComplete {
    param([string[]]$Sources)

    $useModeCapture = $Sources -and $null -ne $script:ModeCoverageCapture
    if (-not $Sources) { $Sources = @($script:Coverage.Keys) }
    foreach ($source in $Sources) {
        $ledger = if ($useModeCapture -and $script:ModeCoverageCapture.Contains($source)) { $script:ModeCoverageCapture } else { $script:Coverage }
        if (-not $ledger.Contains($source) -or $ledger[$source].State -ne 'Complete') {
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
        if ($action -match '^microsoft\.directory/applications(\.myOrganization)?/(credentials|allProperties)/(update|allTasks)$') {
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
    if ($policyIds.Count -eq 1 -and 'microsoft-user-default-low' -in $policyIds) {
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
        $_.RoleTemplateId -eq '62e90394-69f5-4237-9190-012177145e10' -and
        (Test-RoleAssignmentIsTenantWide $_)
    } | Select-Object -First 1)
}

function Test-UserAlreadyEquivalentToPermission {
    param([string]$UserId, [string]$Permission, [object[]]$RoleAssignments, [string]$ResourceAppId)

    if ($ResourceAppId -ne $script:MicrosoftGraphAppId) { return $false }

    $userTemplateIds = @($RoleAssignments | Where-Object {
        $_.PrincipalId -eq $UserId -and $_.PrincipalType -eq '#microsoft.graph.user' -and
        (Test-RoleAssignmentIsTenantWide $_)
    } | ForEach-Object { $_.RoleTemplateId } | Where-Object { $_ } | Select-Object -Unique)

    # The modeled effect is granting application permissions, not every possible
    # use of an app-role assignment. Microsoft documents tenant-wide PRA/GA
    # authority for that effect. Bind this rule to Graph, never a same-named API.
    # Use resolved role template IDs and assignment scope, not display names.
    # https://learn.microsoft.com/entra/identity/enterprise-apps/grant-admin-consent
    if ($Permission -eq 'AppRoleAssignment.ReadWrite.All') {
        return $ResourceAppId -eq $script:MicrosoftGraphAppId -and [bool](@(
            'e8611ab8-c189-46e8-94e1-60213ab1f814'
            '62e90394-69f5-4237-9190-012177145e10'
        ) | Where-Object { $_ -in $userTemplateIds } | Select-Object -First 1)
    }
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

function Get-RoleImpactSeverity {
    param([object[]]$RoleAssignments)

    $tiers = @($RoleAssignments | ForEach-Object { [string]$_.RoleTier })
    if ($tiers -contains 'Critical') { return 'CRITICAL' }
    if ($tiers -contains 'High' -or $tiers -contains 'Microsoft privileged' -or $tiers -contains 'Application control') { return 'HIGH' }
    if ($tiers -contains 'Medium') { return 'MEDIUM' }
    return 'HIGH'
}

function ConvertTo-RoleDefinitionEvidence {
    param(
        [Parameter(Mandatory)][object]$RoleDefinition,
        [Parameter(Mandatory)][hashtable]$ConfiguredRoles,
        [Parameter(Mandatory)][string]$DefinitionSource
    )

    $configured = if ($RoleDefinition.templateId -and $ConfiguredRoles.ContainsKey([string]$RoleDefinition.templateId)) { $ConfiguredRoles[[string]$RoleDefinition.templateId] } else { $null }
    $graphSaysPrivileged = (Test-ObjectHasProperty -InputObject $RoleDefinition -Name 'isPrivileged') -and [bool]$RoleDefinition.isPrivileged
    return [PSCustomObject]@{
        Id                            = $RoleDefinition.id
        TemplateId                    = $RoleDefinition.templateId
        DisplayName                   = $RoleDefinition.displayName
        IsBuiltIn                     = [bool]$RoleDefinition.isBuiltIn
        IsEnabled                     = if (Test-ObjectHasProperty -InputObject $RoleDefinition -Name 'isEnabled') { [bool]$RoleDefinition.isEnabled } else { $true }
        IsSensitiveTarget             = $graphSaysPrivileged -or $null -ne $configured
        MicrosoftClassifiedPrivileged = $graphSaysPrivileged
        CanControlApplications        = Test-RoleCanControlApplications -RoleDefinition $RoleDefinition
        CanControlServicePrincipals   = Test-RoleCanControlServicePrincipals -RoleDefinition $RoleDefinition
        AllowedResourceActions        = @(Get-RoleAllowedResourceActions -RoleDefinition $RoleDefinition)
        Tier                          = if ($configured) { $configured.tier } else { if ($graphSaysPrivileged) { 'Microsoft privileged' } else { 'Application control' } }
        DefinitionSource              = $DefinitionSource
    }
}

function Test-RoleAssignmentAppliesToServicePrincipal {
    param([object]$RoleAssignment, [string]$ServicePrincipalId)
    return (Get-CredentialRouteScopeState -RoleAssignment $RoleAssignment -ObjectType servicePrincipals -ObjectId $ServicePrincipalId) -eq 'Match'
}

function Test-RoleAssignmentIsTenantWide {
    param([object]$RoleAssignment)
    return $RoleAssignment.DirectoryScopeId -eq '/' -and (-not $RoleAssignment.AppScopeId -or $RoleAssignment.AppScopeId -eq '/')
}

function Get-SupportedDirectoryScope {
    param([string]$Scope)
    if ($Scope -eq '/') { return '/' }
    if ($Scope -match '^/administrativeUnits/[^/]+$') { return $Scope }
    if ($Scope -match '^/(applications|servicePrincipals)/([^/]+)$') { return "/$($Matches[2])" }
    if ($Scope -match '^/[^/]+$') { return $Scope }
    return $null
}

function Test-RoleAssignmentCoversTarget {
    param([object]$ExistingAssignment, [object]$TargetAssignment)
    if (-not $ExistingAssignment.RoleDefinitionId -or $ExistingAssignment.RoleDefinitionId -ne $TargetAssignment.RoleDefinitionId) { return $false }
    foreach ($assignment in @($ExistingAssignment, $TargetAssignment)) {
        if ($assignment.AppScopeId -and $assignment.AppScopeId -ne '/') { return $false }
    }
    $existingScope = Get-SupportedDirectoryScope $ExistingAssignment.DirectoryScopeId
    $targetScope = Get-SupportedDirectoryScope $TargetAssignment.DirectoryScopeId
    return $existingScope -and $targetScope -and ($existingScope -eq '/' -or $existingScope -eq $targetScope)
}

function Get-RoleAssignmentScopeIssue {
    param([object]$RoleAssignment)
    $assignmentLabel = "Role $($RoleAssignment.RoleDefinitionId) assigned to $($RoleAssignment.PrincipalId)"
    if (-not $RoleAssignment.DirectoryScopeId) {
        "$assignmentLabel has missing directory scope"
    } elseif (-not (Get-SupportedDirectoryScope $RoleAssignment.DirectoryScopeId)) {
        "$assignmentLabel has unsupported directory scope '$($RoleAssignment.DirectoryScopeId)'"
    }
    if ($RoleAssignment.AppScopeId -and $RoleAssignment.AppScopeId -ne '/') {
        "$assignmentLabel has unsupported app-specific scope '$($RoleAssignment.AppScopeId)'"
    }
}

function Get-CredentialRouteScopeState {
    param(
        [object]$RoleAssignment,
        [ValidateSet('applications', 'servicePrincipals')][string]$ObjectType,
        [string]$ObjectId,
        [string]$OtherObjectId
    )
    if ($RoleAssignment.AppScopeId -and $RoleAssignment.AppScopeId -ne '/') { return 'Unknown' }
    $scope = [string]$RoleAssignment.DirectoryScopeId
    if (-not $scope) { return 'Unknown' }
    if ($scope -eq '/') { return 'Match' }
    # Exclude only understood nonmatching scopes. Unrecognized syntax does not
    # prove the authority inapplicable, even when the target object is resolved.
    if ($scope -match '^/administrativeUnits/[^/]+$') { return 'Excluded' }
    if ($scope -match '^/(applications|servicePrincipals)/([^/]+)$') {
        if ($Matches[1] -ne $ObjectType) { return 'Excluded' }
    } elseif ($scope -notmatch '^/[^/]+$') {
        return 'Unknown'
    }
    if ($ObjectId) {
        if ($scope -in @("/$ObjectId", "/$ObjectType/$ObjectId")) { return 'Match' }
        return 'Excluded'
    }
    if ($OtherObjectId -and $scope -eq "/$OtherObjectId") { return 'Excluded' }
    if ($scope -match '^/[^/]+$' -or $scope -match "^/$ObjectType/[^/]+$") { return 'Unknown' }
    return 'Unknown'
}

function Get-RoleCredentialRoutes {
    param([object[]]$Assignments, [string]$ServicePrincipalId, [string]$TenantType, [object]$ApplicationEvidence)

    foreach ($assignment in $Assignments) {
        if ($assignment.CanControlApplications -and $TenantType -notin @('ThirdParty', 'MicrosoftFirstParty')) {
            $actions = @($assignment.AllowedResourceActions | Where-Object {
                $_ -match '^microsoft\.directory/applications(\.myOrganization)?/(credentials|allProperties)/(update|allTasks)$'
            })
            $unrestricted = [bool]($actions | Where-Object { $_ -match '^microsoft\.directory/applications/' } | Select-Object -First 1)
            $audience = [string]$ApplicationEvidence.SignInAudience
            $scopeState = Get-CredentialRouteScopeState -RoleAssignment $assignment -ObjectType applications -ObjectId $ApplicationEvidence.ApplicationObjectId -OtherObjectId $ServicePrincipalId
            if ($actions.Count -gt 0 -and $scopeState -ne 'Excluded' -and ($unrestricted -or -not $audience -or $audience -eq 'AzureADMyOrg')) {
                $details = @()
                if (-not $ApplicationEvidence.ApplicationObjectId) { $details += 'Local application object ID is unresolved' }
                if (-not $unrestricted -and -not $audience) { $details += 'Application signInAudience is unknown for applications.myOrganization authority' }
                if ($scopeState -eq 'Unknown') { $details += 'Application route assignment scope cannot be confirmed' }
                [PSCustomObject]@{
                    Kind = 'Application'; Assignment = $assignment
                    State = if ($details.Count) { 'PotentialPrerequisiteUnknown' } else { 'Available' }
                    EvidenceDetail = $details -join '; '
                }
            }
        }
        if ($assignment.CanControlServicePrincipals) {
            $scopeState = Get-CredentialRouteScopeState -RoleAssignment $assignment -ObjectType servicePrincipals -ObjectId $ServicePrincipalId
            if ($scopeState -eq 'Excluded') { continue }
            $details = @()
            if ($scopeState -eq 'Unknown') { $details += 'Service principal route assignment scope cannot be confirmed' }
            $lockUnknown = -not $ApplicationEvidence -or $null -eq $ApplicationEvidence.IsCredentialLocked -or $ApplicationEvidence.State -in @('Unavailable', 'NotLocallyObservable')
            if ($lockUnknown) { $details += 'Service principal credential lock evidence is unknown' }
            if (-not $lockUnknown -and $ApplicationEvidence.IsCredentialLocked) { $details += 'Observed service principal credential route is blocked by app instance lock' }
            $state = if ($scopeState -eq 'Unknown') {
                'PotentialPrerequisiteUnknown'
            } elseif (-not $lockUnknown -and $ApplicationEvidence.IsCredentialLocked) {
                'Blocked'
            } elseif ($lockUnknown) {
                'PotentialLockUnknown'
            } else { 'Available' }
            [PSCustomObject]@{ Kind = 'ServicePrincipal'; Assignment = $assignment; State = $state; EvidenceDetail = $details -join '; ' }
        }
    }
}

function Get-CredentialPathAssessment {
    param([object[]]$Routes, [object]$ServicePrincipal, [bool]$RoleEvidenceComplete, [string[]]$RoleScopeIssues = @())

    $details = @($Routes | ForEach-Object { $_.EvidenceDetail } | Where-Object { $_ } | Select-Object -Unique)
    if (-not $RoleEvidenceComplete) { $details += 'Role definitions, assignments or group membership evidence is incomplete' }
    $details += $RoleScopeIssues
    $accountEnabled = $ServicePrincipal.accountEnabled -is [bool] -and $ServicePrincipal.accountEnabled
    if (-not $accountEnabled) {
        $details += if ($ServicePrincipal.accountEnabled -is [bool]) { 'Target service principal accountEnabled is false' } else { 'Target service principal accountEnabled evidence is missing' }
    }
    $availableRoutes = @($Routes | Where-Object State -eq 'Available')
    $isMitigated = $Routes.Count -gt 0 -and @($Routes | Where-Object State -ne 'Blocked').Count -eq 0
    # Blocked observed routes do not establish full mitigation when role evidence
    # could conceal a different route, or required scope/account evidence is missing.
    $state = if (-not $RoleEvidenceComplete -or $RoleScopeIssues.Count -gt 0) {
        'PotentialRoleUnknown'
    } elseif (-not $accountEnabled -or ($availableRoutes.Count -eq 0 -and @($Routes | Where-Object State -eq 'PotentialPrerequisiteUnknown').Count -gt 0)) {
        'PotentialPrerequisiteUnknown'
    } elseif ($isMitigated) {
        'MitigatedByAppInstanceLock'
    } elseif ($availableRoutes.Count -eq 0) {
        'PotentialLockUnknown'
    } else { 'Direct' }
    [PSCustomObject]@{ Exploitability = $state; EvidenceDetail = $details -join '; ' }
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
    param([string]$Uri, [string]$CoverageSource, [ref]$CollectionComplete)
    if ($null -ne $CollectionComplete) { $CollectionComplete.Value = $false }
    $complete = $true
    $results = [System.Collections.Generic.List[object]]::new()
    $pageUri = $Uri
    while ($pageUri) {
        try {
            $response = Invoke-MgGraphRequest -Method GET -Uri $pageUri
            if (($response -isnot [System.Collections.IDictionary] -and $response -isnot [PSCustomObject]) -or
                -not (Test-ObjectHasProperty -InputObject $response -Name 'value') -or
                $response.value -isnot [System.Collections.IList]) {
                throw "Invalid Graph collection page at ${pageUri}: expected a value array."
            }
            foreach ($item in $response.value) {
                if ($item -isnot [System.Collections.IDictionary] -and $item -isnot [PSCustomObject]) {
                    throw "Invalid Graph collection item at ${pageUri}: expected an object."
                }
            }
            $nextUri = $null
            if (Test-ObjectHasProperty -InputObject $response -Name '@odata.nextLink') {
                $nextUri = $response.'@odata.nextLink'
                if ($nextUri -isnot [string] -or [string]::IsNullOrWhiteSpace($nextUri)) {
                    throw "Invalid Graph next link at ${pageUri}: expected a nonempty string."
                }
            }
            foreach ($item in $response.value) { $results.Add($item) }
            $pageUri = $nextUri
        } catch {
            if (-not $CoverageSource -or $results.Count -eq 0) { throw }
            Set-CoverageState -Source $CoverageSource -State Partial -Detail "Pagination failed for ${Uri}: $($_.Exception.Message)"
            $complete = $false
            break
        }
    }
    if ($null -ne $CollectionComplete) { $CollectionComplete.Value = $complete }
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
        $sps = @(Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled&$top=999' -CoverageSource 'ServicePrincipals')
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
            $assignments = @(Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments?`$select=id,appRoleId,resourceId,resourceDisplayName" -CoverageSource 'ApplicationPermissionGrants')
        } catch {
            Set-CoverageState -Source 'ApplicationPermissionGrants' -State Partial -Detail "Failed for SP $($sp.id): $($_.Exception.Message)"
            continue
        }
        if ($assignments.Count -eq 0) { continue }

        foreach ($assignment in $assignments) {
            $resourceId = $assignment.resourceId
            if ($resourceId -isnot [string] -or [string]::IsNullOrWhiteSpace($resourceId) -or
                $assignment.appRoleId -isnot [string] -or [string]::IsNullOrWhiteSpace($assignment.appRoleId)) {
                Set-CoverageState -Source 'ResourcePermissionDefinitions' -State Partial -Detail "Missing resource or role identity for an assignment on SP $($sp.id)."
                continue
            }
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
            if ($resSP.id -isnot [string] -or $resSP.id -ne $resourceId -or
                $resSP.appId -isnot [string] -or [string]::IsNullOrWhiteSpace($resSP.appId) -or
                $resSP.appRoles -isnot [System.Collections.IList]) {
                Set-CoverageState -Source 'ResourcePermissionDefinitions' -State Partial -Detail "Missing or malformed identity or appRoles for resource SP ${resourceId}."
                continue
            }
            if ($assignment.appRoleId -eq '00000000-0000-0000-0000-000000000000') { continue }
            $role = $resSP.appRoles | Where-Object { $_.id -eq $assignment.appRoleId } | Select-Object -First 1
            if (-not $role -or $role.value -isnot [string] -or [string]::IsNullOrWhiteSpace($role.value)) {
                Set-CoverageState -Source 'ResourcePermissionDefinitions' -State Partial -Detail "Missing definition for granted role $($assignment.appRoleId) on resource SP ${resourceId}."
                continue
            }
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
                    ConsentPrincipalId = $null
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
            $grants = @(Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999' -CoverageSource 'DelegatedPermissionGrants')
            Set-CoverageState -Source 'DelegatedPermissionGrants' -State Complete
        } catch {
            Set-CoverageState -Source 'DelegatedPermissionGrants' -State Unavailable -Detail $_.Exception.Message
            $grants = @()
        }
        foreach ($grant in $grants) {
            if ($grant.consentType -notin @('AllPrincipals', 'Principal')) { continue }
            $grantedScopes = ($grant.scope -split ' ') | Where-Object { $_ }
            if ($grant.resourceId -isnot [string] -or [string]::IsNullOrWhiteSpace($grant.resourceId)) {
                Set-CoverageState -Source 'ResourcePermissionDefinitions' -State Partial -Detail "Missing resource identity for delegated grant $($grant.id)."
                continue
            }
            if (-not $script:CachedResourceServicePrincipals.ContainsKey($grant.resourceId)) {
                try {
                    $script:CachedResourceServicePrincipals[$grant.resourceId] = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($grant.resourceId)?`$select=id,appId,displayName"
                } catch {
                    Set-CoverageState -Source 'ResourcePermissionDefinitions' -State Partial -Detail "Failed for resource SP $($grant.resourceId): $($_.Exception.Message)"
                    continue
                }
            }
            $resourceSP = $script:CachedResourceServicePrincipals[$grant.resourceId]
            if ($resourceSP.id -isnot [string] -or $resourceSP.id -ne $grant.resourceId -or
                $resourceSP.appId -isnot [string] -or [string]::IsNullOrWhiteSpace($resourceSP.appId)) {
                Set-CoverageState -Source 'ResourcePermissionDefinitions' -State Partial -Detail "Missing or malformed identity for resource SP $($grant.resourceId)."
                continue
            }
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
    $definitionApiVersion = 'beta'
    try {
        # The role-definition collection currently documents only $filter support.
        # Request the collection without unsupported $select/$top options; the response
        # already includes isPrivileged and rolePermissions in beta.
        $roleDefs = @(Get-AllGraphPages -Uri 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions' -CoverageSource 'RoleDefinitions')
        Set-CoverageState -Source 'RoleDefinitions' -State Complete
    } catch {
        $betaError = $_.Exception.Message
        try {
            $roleDefs = @(Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions' -CoverageSource 'RoleDefinitions')
            $definitionSource = 'V1WithConfiguredSensitivityFallback'
            $definitionApiVersion = 'v1.0'
            Set-CoverageState -Source 'RoleDefinitions' -State Partial -Detail "Beta isPrivileged unavailable; configured sensitive-role fallback used: $betaError"
        } catch {
            Set-CoverageState -Source 'RoleDefinitions' -State Unavailable -Detail $_.Exception.Message
            $script:CachedRoleAssignments = @()
            return @()
        }
    }

    try {
        $allAssignments = @(Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal' -CoverageSource 'ActiveRoleAssignments')
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
        $definitionEvidence[$rd.id] = ConvertTo-RoleDefinitionEvidence -RoleDefinition $rd -ConfiguredRoles $configuredRoles -DefinitionSource $definitionSource
    }
    $script:CachedRoleDefinitions = $definitionEvidence

    $results = @()
    $failedDefinitionIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $groupExpansionCache = @{}
    $rawAssignmentKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $effectiveAssignmentKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Set-CoverageState -Source 'RoleGroupMemberships' -State Complete
    foreach ($assignment in $allAssignments) {
        $definition = $definitionEvidence[$assignment.roleDefinitionId]
        if (-not $definition) {
            if (-not $failedDefinitionIds.Contains([string]$assignment.roleDefinitionId)) {
                try {
                    $rd = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$definitionApiVersion/roleManagement/directory/roleDefinitions/$($assignment.roleDefinitionId)"
                    $definition = ConvertTo-RoleDefinitionEvidence -RoleDefinition $rd -ConfiguredRoles $configuredRoles -DefinitionSource "${definitionSource}ItemFallback"
                    $definitionEvidence[$assignment.roleDefinitionId] = $definition
                } catch {
                    [void]$failedDefinitionIds.Add([string]$assignment.roleDefinitionId)
                    Set-CoverageState -Source 'RoleDefinitions' -State Partial -Detail "No definition could be resolved for roleDefinitionId $($assignment.roleDefinitionId): $($_.Exception.Message)"
                }
            }
            if (-not $definition) { continue }
        }
        if (-not ($definition.IsSensitiveTarget -or $definition.CanControlApplications -or $definition.CanControlServicePrincipals)) { continue }

        $principalType = [string]$assignment.principal.'@odata.type'
        $isGroupAssignment = $principalType -eq '#microsoft.graph.group'
        if ($principalType -notin @('#microsoft.graph.user', '#microsoft.graph.servicePrincipal', '#microsoft.graph.group')) {
            Set-CoverageState -Source 'RoleGroupMemberships' -State Partial -Detail "Role assignment $($assignment.id) for principal $($assignment.principalId) has missing or unsupported principal type."
        }
        $assignmentSource = if ($isGroupAssignment) { 'RoleAssignedGroup' } else { 'Direct' }
        $sourceGroupId = if ($isGroupAssignment) { $assignment.principalId } else { $null }
        $sourceGroupName = if ($isGroupAssignment) { $assignment.principal.displayName } else { $null }
        $rawAssignmentKey = if ($assignment.id) {
            "id:$($assignment.id)"
        } else {
            "shape:$($assignment.principalId)`u{1f}$($assignment.roleDefinitionId)`u{1f}$($assignment.directoryScopeId)`u{1f}$($assignment.appScopeId)"
        }
        if ($rawAssignmentKeys.Add($rawAssignmentKey)) {
            $results += [PSCustomObject]@{
            RoleAssignmentId      = $assignment.id
            SourceAssignmentId    = $null
            AssignmentSource      = $assignmentSource
            SourceGroupId         = $sourceGroupId
            SourceGroupName       = $sourceGroupName
            MembershipPath        = $sourceGroupId
            PrincipalId          = $assignment.principalId
            PrincipalDisplayName = $assignment.principal.displayName
            PrincipalType        = $principalType
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

        if (-not $isGroupAssignment) { continue }
        $groupId = [string]$assignment.principalId
        if ([string]::IsNullOrWhiteSpace($groupId)) {
            Set-CoverageState -Source 'RoleGroupMemberships' -State Partial -Detail 'A role-assigned group is missing its principal ID.'
            continue
        }
        if (-not $groupExpansionCache.ContainsKey($groupId)) {
            $members = @()
            $expansionComplete = $false
            try {
                $members = @(Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/groups/$groupId/transitiveMembers/microsoft.graph.user?`$select=id,displayName,userPrincipalName&`$top=999" -CoverageSource 'RoleGroupMemberships' -CollectionComplete ([ref]$expansionComplete))
            } catch {
                Set-CoverageState -Source 'RoleGroupMemberships' -State Partial -Detail "Failed to expand role-assigned group ${groupId}: $($_.Exception.Message)"
            }
            $groupExpansionCache[$groupId] = [PSCustomObject]@{ Members = $members; Complete = $expansionComplete }
        }

        foreach ($member in @($groupExpansionCache[$groupId].Members)) {
            $memberId = [string]$member.id
            if ([string]::IsNullOrWhiteSpace($memberId)) {
                Set-CoverageState -Source 'RoleGroupMemberships' -State Partial -Detail "Role-assigned group ${groupId} returned a user without a usable ID."
                continue
            }
            $effectiveKey = @($memberId, $assignment.roleDefinitionId, $assignment.directoryScopeId, $assignment.appScopeId, $groupId, $assignment.id) -join "`u{1f}"
            if (-not $effectiveAssignmentKeys.Add($effectiveKey)) { continue }
            $results += [PSCustomObject]@{
                RoleAssignmentId      = $assignment.id
                SourceAssignmentId    = $assignment.id
                AssignmentSource      = 'RoleAssignedGroupMember'
                SourceGroupId         = $groupId
                SourceGroupName       = $assignment.principal.displayName
                MembershipPath        = "$groupId -> $memberId"
                PrincipalId          = $memberId
                PrincipalDisplayName = $member.displayName
                PrincipalType        = '#microsoft.graph.user'
                PrincipalUPN         = $member.userPrincipalName
                PrincipalAppId       = $null
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

function Resolve-CredentialValidity {
    param([object]$InputObject, [datetimeoffset]$Now = (Get-Date))

    $dates = @{}
    foreach ($property in @('StartDateTime', 'EndDateTime')) {
        $value = $InputObject.$property
        $text = if ($value -is [datetime] -or $value -is [datetimeoffset]) { $value.ToString('o') } else { [string]$value }
        $parsed = [datetimeoffset]::MinValue
        # Graph timestamps include a full calendar date, time, and timezone.
        # TryParse alone accepts time-only strings and silently supplies today's date.
        if ($text -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$' -and
            [datetimeoffset]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) {
            $dates[$property] = $parsed.ToUniversalTime()
        }
    }
    $expired = if ($dates.ContainsKey('EndDateTime')) { $dates.EndDateTime -le $Now } else { $null }
    $validity = if ($dates.Count -ne 2 -or $dates.StartDateTime -ge $dates.EndDateTime) {
        'Unknown'
    } elseif ($expired) {
        'Expired'
    } elseif ($dates.StartDateTime -gt $Now) {
        'Future'
    } else {
        'Current'
    }
    return [PSCustomObject]@{ Validity = $validity; IsCurrentlyValid = $validity -eq 'Current'; Expired = $expired }
}

function Get-AppCredentials {
    param([string[]]$AppIds, [hashtable]$EvidenceStatus = @{})
    Write-Host "  Querying app credentials..." -ForegroundColor Gray
    $results = @{}
    $now = [datetimeoffset](Get-Date)
    $EvidenceStatus.Clear()
    Set-CoverageState -Source 'ApplicationCredentials' -State Complete
    foreach ($appId in $AppIds) {
        $EvidenceStatus[$appId] = 'Unavailable'
        try {
            $apps = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$appId'&`$select=id,appId,displayName,passwordCredentials,keyCredentials"
            $app = $apps | Select-Object -First 1
            if ($app) {
                $EvidenceStatus[$appId] = 'Complete'
                if ($null -eq $app.passwordCredentials -or $null -eq $app.keyCredentials) {
                    $EvidenceStatus[$appId] = 'Partial'
                    Set-CoverageState -Source 'ApplicationCredentials' -State Partial -Detail "Credential properties missing for appId $appId"
                }
                $creds = @()
                if ($app.passwordCredentials) {
                    foreach ($pc in $app.passwordCredentials) {
                        $validity = Resolve-CredentialValidity -InputObject $pc -Now $now
                        $creds += [PSCustomObject]@{
                            Type         = 'Secret'
                            KeyId        = $pc.keyId
                            DisplayName  = $pc.displayName
                            StartDateTime = $pc.startDateTime
                            EndDateTime  = $pc.endDateTime
                            Expired      = $validity.Expired
                            Validity     = $validity.Validity
                            IsCurrentlyValid = $validity.IsCurrentlyValid
                        }
                    }
                }
                if ($app.keyCredentials) {
                    foreach ($kc in $app.keyCredentials) {
                        $validity = Resolve-CredentialValidity -InputObject $kc -Now $now
                        $creds += [PSCustomObject]@{
                            Type         = 'Certificate'
                            KeyId        = $kc.keyId
                            DisplayName  = $kc.displayName
                            StartDateTime = $kc.startDateTime
                            EndDateTime  = $kc.endDateTime
                            Expired      = $validity.Expired
                            Validity     = $validity.Validity
                            IsCurrentlyValid = $validity.IsCurrentlyValid
                        }
                    }
                }
                if (@($creds | Where-Object { $_.Validity -eq 'Unknown' }).Count -gt 0) {
                    $EvidenceStatus[$appId] = 'Partial'
                    Set-CoverageState -Source 'ApplicationCredentials' -State Partial -Detail "Credential date validity unknown for appId $appId"
                }
                # Check for federated identity credentials
                try {
                    if (-not $app.id) { throw 'Application object ID is missing' }
                    $ficComplete = $false
                    $fics = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/federatedIdentityCredentials" -CoverageSource 'FederatedIdentityCredentials' -CollectionComplete ([ref]$ficComplete)
                    if (-not $ficComplete) { $EvidenceStatus[$appId] = 'Partial' }
                    Set-CoverageState -Source 'FederatedIdentityCredentials' -State Complete
                    foreach ($fic in $fics) {
                        $creds += [PSCustomObject]@{
                            Type         = 'Federated'
                            KeyId        = $fic.id
                            DisplayName  = $fic.name
                            StartDateTime = $null
                            EndDateTime  = $null
                            Expired      = $false
                            Validity     = 'Timeless'
                            IsCurrentlyValid = $true
                        }
                    }
                } catch {
                    $EvidenceStatus[$appId] = 'Partial'
                    Set-CoverageState -Source 'FederatedIdentityCredentials' -State Partial -Detail "Failed for appId ${appId}: $($_.Exception.Message)"
                }
                $results[$appId] = $creds
            } else {
                Set-CoverageState -Source 'ApplicationCredentials' -State Partial -Detail "No local application object was found for appId $appId"
            }
        } catch {
            $EvidenceStatus[$appId] = 'Unavailable'
            Set-CoverageState -Source 'ApplicationCredentials' -State Partial -Detail "Failed for appId ${appId}: $($_.Exception.Message)"
        }
    }
    return $results
}

function Get-SPDirectCredentials {
    param([string[]]$SPIds, [hashtable]$EvidenceStatus = @{})
    Write-Host "  Querying SP-level credentials (hidden from portal)..." -ForegroundColor Gray
    $results = @{}
    $now = [datetimeoffset](Get-Date)
    $EvidenceStatus.Clear()
    Set-CoverageState -Source 'ServicePrincipalCredentials' -State Complete
    foreach ($spId in $SPIds) {
        $EvidenceStatus[$spId] = 'Unavailable'
        try {
            $sp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId`?`$select=id,passwordCredentials,keyCredentials"
            if ($null -eq $sp -or ($null -eq $sp.passwordCredentials -and $null -eq $sp.keyCredentials)) {
                throw 'Service principal credential properties are unavailable'
            }
            $EvidenceStatus[$spId] = 'Complete'
            if ($null -eq $sp.passwordCredentials -or $null -eq $sp.keyCredentials) {
                $EvidenceStatus[$spId] = 'Partial'
                Set-CoverageState -Source 'ServicePrincipalCredentials' -State Partial -Detail "Credential properties missing for SP $spId"
            }
            $creds = @()
            if ($sp.passwordCredentials) {
                foreach ($pc in $sp.passwordCredentials) {
                    $validity = Resolve-CredentialValidity -InputObject $pc -Now $now
                    $creds += [PSCustomObject]@{
                        Type          = 'SP-Secret'
                        KeyId         = $pc.keyId
                        DisplayName   = $pc.displayName
                        StartDateTime = $pc.startDateTime
                        EndDateTime   = $pc.endDateTime
                        Expired       = $validity.Expired
                        Validity      = $validity.Validity
                        IsCurrentlyValid = $validity.IsCurrentlyValid
                    }
                }
            }
            if ($sp.keyCredentials) {
                foreach ($kc in $sp.keyCredentials) {
                    $validity = Resolve-CredentialValidity -InputObject $kc -Now $now
                    $creds += [PSCustomObject]@{
                        Type          = 'SP-Certificate'
                        KeyId         = $kc.keyId
                        DisplayName   = $kc.displayName
                        StartDateTime = $kc.startDateTime
                        EndDateTime   = $kc.endDateTime
                        Expired       = $validity.Expired
                        Validity      = $validity.Validity
                        IsCurrentlyValid = $validity.IsCurrentlyValid
                    }
                }
            }
            if (@($creds | Where-Object { $_.Validity -eq 'Unknown' }).Count -gt 0) {
                $EvidenceStatus[$spId] = 'Partial'
                Set-CoverageState -Source 'ServicePrincipalCredentials' -State Partial -Detail "Credential date validity unknown for SP $spId"
            }
            $results[$spId] = $creds
        } catch {
            $EvidenceStatus[$spId] = 'Unavailable'
            Set-CoverageState -Source 'ServicePrincipalCredentials' -State Partial -Detail "Failed for SP ${spId}: $($_.Exception.Message)"
        }
    }
    return $results
}

function Resolve-CredentialCollectionEvidenceStatus {
    param([string]$ObjectId, [hashtable]$Credentials, [hashtable]$EvidenceStatus)

    if ($EvidenceStatus.ContainsKey($ObjectId)) { return $EvidenceStatus[$ObjectId] }
    if ($Credentials.ContainsKey($ObjectId) -and $null -ne $Credentials[$ObjectId]) { return 'Complete' }
    return 'Unavailable'
}

function Resolve-AppCredentialEvidenceStatus {
    param(
        [string]$AppId, [string]$AppTenantType, [string[]]$SPIds,
        [hashtable]$AppCredentials, [hashtable]$SPCredentials,
        [hashtable]$AppEvidence, [hashtable]$SPEvidence
    )

    $states = @(
        if ($AppTenantType -eq 'HomeTenant') {
            Resolve-CredentialCollectionEvidenceStatus -ObjectId $AppId -Credentials $AppCredentials -EvidenceStatus $AppEvidence
        } else {
            Set-CoverageState -Source 'ApplicationCredentials' -State Partial -Detail "Publisher application credentials are not locally observable for appId $AppId"
            'NotLocallyObservable'
        }
        foreach ($spId in $SPIds) {
            Resolve-CredentialCollectionEvidenceStatus -ObjectId $spId -Credentials $SPCredentials -EvidenceStatus $SPEvidence
        }
    )
    if (@($states | Where-Object { $_ -ne 'Complete' }).Count -eq 0) { return 'Complete' }
    if ('NotLocallyObservable' -in $states -and @($states | Where-Object { $_ -notin @('Complete', 'NotLocallyObservable') }).Count -eq 0) {
        return 'NotLocallyObservable'
    }
    if (@($states | Where-Object { $_ -in @('Complete', 'Partial') }).Count -gt 0) { return 'Partial' }
    return 'Unavailable'
}

function Get-AppInstanceLockStatus {
    param([string[]]$AppIds)
    Write-Host "  Querying app instance property lock status..." -ForegroundColor Gray
    $results = @{}
    Set-CoverageState -Source 'AppInstanceLocks' -State Complete
    foreach ($appId in $AppIds) {
        $app = $null
        $identityStatus = 'Unavailable'
        try {
            $apps = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$appId'&`$select=id,appId,signInAudience,servicePrincipalLockConfiguration"
            $app = $apps | Select-Object -First 1
            if ($app) {
                $identityStatus = if ($app.id) { 'Complete' } else { 'ApplicationObjectIdMissing' }
                if (-not (Test-ObjectHasProperty $app 'servicePrincipalLockConfiguration')) { throw 'Application lock configuration property is missing' }
                $results[$appId] = ConvertTo-AppInstanceLockEvidence -LockConfiguration $app.servicePrincipalLockConfiguration
            } else {
                $identityStatus = 'ApplicationObjectNotFound'
                $results[$appId] = [PSCustomObject]@{ State = 'NotLocallyObservable'; IsEnabled = $null; IsCredentialLocked = $null; LocksAllProperties = $null; LocksSigningUsage = $null; LocksVerifyUsage = $null }
                Set-CoverageState -Source 'AppInstanceLocks' -State Partial -Detail "No local application object exposes lock configuration for appId $appId"
            }
        } catch {
            $results[$appId] = [PSCustomObject]@{ State = 'Unavailable'; IsEnabled = $null; IsCredentialLocked = $null; LocksAllProperties = $null; LocksSigningUsage = $null; LocksVerifyUsage = $null }
            Set-CoverageState -Source 'AppInstanceLocks' -State Partial -Detail "Failed for appId ${appId}: $($_.Exception.Message)"
        }
        $results[$appId] | Add-Member -NotePropertyName ApplicationObjectId -NotePropertyValue $app.id
        $results[$appId] | Add-Member -NotePropertyName SignInAudience -NotePropertyValue $app.signInAudience
        $results[$appId] | Add-Member -NotePropertyName ApplicationIdentityStatus -NotePropertyValue $identityStatus
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
        if ($policy -isnot [System.Collections.IDictionary] -and $policy -isnot [PSCustomObject]) {
            throw 'Missing or malformed authorization policy response.'
        }
        $defaultPerms = $policy.defaultUserRolePermissions
        if ($defaultPerms -isnot [System.Collections.IDictionary] -and $defaultPerms -isnot [PSCustomObject]) { $defaultPerms = $null }
        $missingSettings = @(
            if ($defaultPerms.permissionGrantPoliciesAssigned -isnot [System.Collections.IList] -or
                @($defaultPerms.permissionGrantPoliciesAssigned | Where-Object { $_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
                'permissionGrantPoliciesAssigned'
            }
            if ($defaultPerms.allowedToCreateApps -isnot [bool]) { 'allowedToCreateApps' }
            if ($defaultPerms.allowedToReadOtherUsers -isnot [bool]) { 'allowedToReadOtherUsers' }
        )
        if ($missingSettings.Count -gt 0) {
            Set-CoverageState -Source 'TenantAuthorizationPolicy' -State Partial -Detail "Missing or malformed defaultUserRolePermissions settings: $($missingSettings -join ', ')."
        } else {
            Set-CoverageState -Source 'TenantAuthorizationPolicy' -State Complete
        }
        return $policy
    } catch {
        Set-CoverageState -Source 'TenantAuthorizationPolicy' -State Unavailable -Detail $_.Exception.Message
        Write-Host "  ⚠ Could not query authorization policy." -ForegroundColor Yellow
        return $null
    }
}

function Get-UserConsentGrants {
    Write-Host "  Querying single-user delegated permission grants..." -ForegroundColor Gray
    try {
        $grants = Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999' -CoverageSource 'UserConsentGrants'
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
        if (Test-AuditCoverageComplete -Sources @(Get-PermissionCoverageSource)) {
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
    $roleAssignmentEvidenceComplete = Test-AuditCoverageComplete -Sources @('RoleDefinitions', 'ActiveRoleAssignments', 'RoleGroupMemberships')

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
        if (-not $userRoles[$ra.PrincipalId].Roles.Contains([string]$ra.RoleName)) {
            $userRoles[$ra.PrincipalId].Roles.Add($ra.RoleName)
        }
    }

    $privilegedUserIds = $userRoles.Keys
    $canClassifyNonPrivileged = Test-AuditCoverageComplete -Sources @('RoleDefinitions', 'ActiveRoleAssignments', 'RoleGroupMemberships', 'Users')
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
        $groupRoleExport = @($groupRoles | ForEach-Object {
            [PSCustomObject]@{
                GroupName        = $_.PrincipalDisplayName
                GroupId          = $_.PrincipalId
                Role             = $_.RoleName
                DirectoryScopeId = $_.DirectoryScopeId
                AppScopeId       = $_.AppScopeId
                RoleAssignmentId = $_.RoleAssignmentId
            }
        })
        $groupRoleExport | Format-Table -AutoSize | Out-String | Write-Host
        Export-AuditCsv -Name 'RoleAssignedGroups' -Data $groupRoleExport
    }
    $groupMemberRoles = @($sensitiveRoleAssignments | Where-Object { $_.AssignmentSource -eq 'RoleAssignedGroupMember' })
    if ($groupMemberRoles.Count -gt 0) {
        $groupMemberExport = @($groupMemberRoles | ForEach-Object {
            [PSCustomObject]@{
                GroupId          = $_.SourceGroupId
                GroupName        = $_.SourceGroupName
                UserId           = $_.PrincipalId
                DisplayName      = $_.PrincipalDisplayName
                UPN              = $_.PrincipalUPN
                Role             = $_.RoleName
                RoleDefinitionId = $_.RoleDefinitionId
                DirectoryScopeId = $_.DirectoryScopeId
                AppScopeId       = $_.AppScopeId
                RoleAssignmentId = $_.SourceAssignmentId
                MembershipPath   = $_.MembershipPath
            }
        })
        Export-AuditCsv -Name 'RoleGroupMembers' -Data $groupMemberExport
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

function Get-RolePathDisplayOrder {
    param([object[]]$Paths)

    @($Paths) | Sort-Object `
        @{ Expression = {
            if ($_.Exploitability -eq 'Direct') { 0 }
            elseif ($_.Exploitability -like 'Potential*') { 1 }
            else { 2 }
        } },
        @{ Expression = {
            $severityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
            $rank = $severityOrder[[string]$_.Severity]
            if ($null -eq $rank) { 5 } else { $rank }
        } },
        @{ Expression = { [string]$_.UserObjectId } },
        @{ Expression = { [string]$_.UserUPN } },
        @{ Expression = { [string]$_.TargetObjectId } },
        @{ Expression = { [string]$_.AppName } },
        @{ Expression = { [string]$_.Permission } },
        @{ Expression = { [int]$_.PathNumber } }
}

function ConvertTo-SingleLineDisplayText {
    param([object]$Value)
    return ([string]$Value -replace '[\r\n]+', ' ').Trim()
}

function Get-RolePathChainLines {
    param([object]$Path)

    $stateLabel = if ($Path.Exploitability -eq 'Direct') { 'DIRECT' } elseif ($Path.Exploitability -like 'Potential*') { 'POTENTIAL' } else { 'MITIGATED' }
    $color = if ($stateLabel -eq 'DIRECT') { 'Red' } elseif ($stateLabel -eq 'POTENTIAL') { 'Yellow' } else { 'Green' }
    $severity = (ConvertTo-SingleLineDisplayText $Path.Severity).ToUpperInvariant()
    $route = ConvertTo-SingleLineDisplayText $Path.CredentialRoute
    if (-not $route) { $route = if ([string]$Path.Action -like 'Add an application credential*') { 'Application credential route' } else { 'SP credential route' } }
    $user = ConvertTo-SingleLineDisplayText $Path.UserUPN
    if (-not $user) { $user = ConvertTo-SingleLineDisplayText $Path.UserDisplayName }
    $role = ConvertTo-SingleLineDisplayText $Path.UserRole
    $app = ConvertTo-SingleLineDisplayText $Path.AppName
    $permission = ConvertTo-SingleLineDisplayText $Path.Permission
    $membershipPath = ConvertTo-SingleLineDisplayText $Path.RoleMembershipPath
    $result = switch ([string]$Path.Exploitability) {
        'Direct' { 'Exploitable privilege increase' }
        'PotentialRoleUnknown' { 'Potential — role evidence incomplete' }
        'PotentialLockUnknown' { 'Potential — lock evidence unavailable' }
        'PotentialPrerequisiteUnknown' { 'Potential — prerequisite evidence incomplete' }
        'MitigatedByAppInstanceLock' { 'Blocked on evaluated route by app instance lock' }
        default { 'Potential — prerequisite evidence incomplete' }
    }

    @(
        [PSCustomObject]@{ Text = "  [$stateLabel | $severity] $user"; Color = $color }
        [PSCustomObject]@{ Text = "    └─[Role: $role]→ $app"; Color = $color }
        [PSCustomObject]@{ Text = "       └─[$route]→ $permission"; Color = $color }
        if ($membershipPath) {
            [PSCustomObject]@{ Text = "       via group: $membershipPath"; Color = 'DarkGray' }
        }
        [PSCustomObject]@{ Text = "       Result: $result"; Color = $color }
    )
}

function Invoke-AttackPathAnalysis {
    Write-Banner "ATTACK PATH ANALYSIS -- Privilege Escalation via Applications & Service Principals"

    $dangerousApps = @(Get-ServicePrincipalsWithAppRoles)
    $directDangerousApps = @($dangerousApps | Where-Object { $_.PermissionType -eq 'Application' })
    $conditionalDangerousApps = @($dangerousApps | Where-Object { $_.PermissionType -eq 'Delegated' })
    $roleAssignments = @(Get-PrivilegedRoleAssignments)
    $roleEvidenceComplete = Test-AuditCoverageComplete -Sources @('RoleDefinitions', 'ActiveRoleAssignments', 'RoleGroupMemberships')

    # SPs with privileged directory roles
    $privilegedSPs = @($roleAssignments | Where-Object { $_.PrincipalType -eq '#microsoft.graph.servicePrincipal' -and $_.IsSensitiveTarget })

    if ($directDangerousApps.Count -eq 0 -and $privilegedSPs.Count -eq 0) {
        if (Test-AuditCoverageComplete -Sources @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions', 'RoleDefinitions', 'ActiveRoleAssignments', 'RoleGroupMemberships')) {
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
            # Suppress only confirmed equivalence for the modeled permission effect.
            # A reader or narrower privileged role can still have a real privilege increase.
            $existingRoles = @($roleAssignments | Where-Object { $_.PrincipalId -eq $owner.id -and $_.PrincipalType -eq '#microsoft.graph.user' } | ForEach-Object { $_.RoleName } | Select-Object -Unique)
            foreach ($app in $apps) {
                # An observed equivalent role is enough to rule out a privilege increase even
                # when unrelated role definitions or group expansion remain incomplete.
                if (Test-UserAlreadyEquivalentToPermission -UserId $owner.id -Permission $app.Permission -RoleAssignments $roleAssignments -ResourceAppId $app.ResourceAppId) { continue }
                $roleScopeIssues = @($roleAssignments | Where-Object {
                    $_.PrincipalId -eq $owner.id -and $_.PrincipalType -eq '#microsoft.graph.user'
                } | ForEach-Object {
                    $scopeIssues = @(Get-RoleAssignmentScopeIssue $_)
                    if ($scopeIssues.Count -gt 0) {
                        $tenantWideAssignment = $_.PSObject.Copy()
                        $tenantWideAssignment.DirectoryScopeId = '/'
                        $tenantWideAssignment.AppScopeId = $null
                        if (Test-UserAlreadyEquivalentToPermission -UserId $owner.id -Permission $app.Permission -RoleAssignments @($tenantWideAssignment) -ResourceAppId $app.ResourceAppId) { $scopeIssues }
                    }
                })
                $pathNum++
                $spCreds = $spDirectCreds[$app.SPId]
                $spCredCount = if ($spCreds) { @($spCreds | Where-Object { $_.IsCurrentlyValid -eq $true }).Count } else { 0 }
                $lock = $appLockStatus[$appId]
                $targetSP = $script:CachedServicePrincipals | Where-Object { $_.id -eq $app.SPId } | Select-Object -First 1
                $ownerRoute = [PSCustomObject]@{
                    State = if ($ownerEvidence.AppObjectId) { 'Available' } else { 'PotentialPrerequisiteUnknown' }
                    EvidenceDetail = if (-not $ownerEvidence.AppObjectId) { 'Local application object ID is unresolved for application ownership' } else { '' }
                }
                $assessment = Get-CredentialPathAssessment -Routes @($ownerRoute) -ServicePrincipal $targetSP -RoleEvidenceComplete $roleEvidenceComplete -RoleScopeIssues $roleScopeIssues

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
                    UserRole        = if (-not $roleEvidenceComplete -and $existingRoles.Count -gt 0) { "Observed: $($existingRoles -join ', '); additional role evidence incomplete" } elseif (-not $roleEvidenceComplete) { 'Unknown (role evidence incomplete)' } elseif ($existingRoles.Count -gt 0) { $existingRoles -join ', ' } else { 'None of the sensitive roles evaluated' }
                    AppName         = $app.SPDisplayName
                    AppId           = $app.AppId
                    Permission      = $app.Permission
                    PermissionType  = $app.PermissionType
                    Exploitability  = $assessment.Exploitability
                    EvidenceDetail  = $assessment.EvidenceDetail
                    RoleAssignmentSource = ''
                    RoleMembershipPath = ''
                    CredentialRoute = 'Application credential route'
                    UserObjectId    = $owner.id
                    TargetObjectId  = $app.SPId
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
                $targetAppId = if ($sp.PrincipalAppId) { $sp.PrincipalAppId } elseif ($targetSP) { $targetSP.appId } else { $null }
                $lock = if ($targetAppId) { $appLockStatus[$targetAppId] } else { $null }
                $controlAssignments = @($applicationControlAssignments | Where-Object { $_.PrincipalId -eq $userId })
                $routes = @(Get-RoleCredentialRoutes -Assignments $controlAssignments -ServicePrincipalId $sp.PrincipalId -TenantType $targetTenantType -ApplicationEvidence $lock)
                if ($routes.Count -eq 0) { continue }
                $applicableControl = @($routes | ForEach-Object { $_.Assignment })

                # Do not claim an escalation into roles the user already holds.
                $newTargetRoles = @($spGroup.Group | Where-Object {
                    $target = $_
                    -not ($userAssignments | Where-Object { Test-RoleAssignmentCoversTarget $_ $target } | Select-Object -First 1)
                })
                if ($newTargetRoles.Count -eq 0) { continue }

                $roleScopeIssues = @(
                    $newTargetRoles | ForEach-Object { Get-RoleAssignmentScopeIssue $_ }
                    $userAssignments | Where-Object {
                        $_.RoleDefinitionId -in $newTargetRoles.RoleDefinitionId -or $_.RoleTemplateId -eq '62e90394-69f5-4237-9190-012177145e10'
                    } | ForEach-Object { Get-RoleAssignmentScopeIssue $_ }
                )
                $assessment = Get-CredentialPathAssessment -Routes $routes -ServicePrincipal $targetSP -RoleEvidenceComplete $roleEvidenceComplete -RoleScopeIssues $roleScopeIssues
                $isMitigated = $assessment.Exploitability -eq 'MitigatedByAppInstanceLock'
                $selectedRoute = $routes | Sort-Object @{ Expression = { if ($_.State -eq 'Available') { 0 } elseif ($_.State -eq 'Blocked') { 2 } else { 1 } } } | Select-Object -First 1
                $canUseApplicationObject = $selectedRoute.Kind -eq 'Application'
                $routeKinds = @($routes | ForEach-Object Kind | Select-Object -Unique)
                $availableRouteKinds = @($routes | Where-Object State -eq 'Available' | ForEach-Object Kind | Select-Object -Unique)
                $credentialRoute = if ($availableRouteKinds.Count -eq 1) {
                    if ($availableRouteKinds[0] -eq 'Application') { 'Application credential route' } else { 'SP credential route' }
                } elseif ($availableRouteKinds.Count -gt 1 -or ($availableRouteKinds.Count -eq 0 -and $routeKinds.Count -gt 1)) {
                    'Multiple credential routes'
                } elseif ($routeKinds[0] -eq 'Application') {
                    'Application credential route'
                } else {
                    'SP credential route'
                }

                $pathNum++
                $spCreds = $spDirectCreds[$sp.PrincipalId]
                $spCredCount = if ($spCreds) { @($spCreds | Where-Object { $_.IsCurrentlyValid -eq $true }).Count } else { 0 }
                $controlRoleNames = @($applicableControl | ForEach-Object { $_.RoleName } | Select-Object -Unique)
                $controlSources = @($applicableControl | ForEach-Object { $_.AssignmentSource } | Where-Object { $_ } | Select-Object -Unique)
                $controlMembershipPaths = @($applicableControl | ForEach-Object { $_.MembershipPath } | Where-Object { $_ } | Select-Object -Unique)
                $controlRoleLabels = @($applicableControl | ForEach-Object {
                    if ($_.AssignmentSource -eq 'RoleAssignedGroupMember') { "$($_.RoleName) (via $($_.SourceGroupName))" } else { $_.RoleName }
                } | Select-Object -Unique)
                $targetRoleNames = @($newTargetRoles | ForEach-Object { $_.RoleName } | Select-Object -Unique)
                $targetImpactSeverity = Get-RoleImpactSeverity -RoleAssignments $newTargetRoles
                $pathDef = $script:AttackPathDefs | Where-Object { $_.id -eq 'ROLE_BASED_SP_CONTROL' } | Select-Object -First 1
                $paths += [PSCustomObject]@{
                    PathNumber      = $pathNum
                    PathType        = 'Role-Based SP Control'
                    PathId          = 'ROLE_BASED_SP_CONTROL'
                    Severity        = if ($isMitigated) { 'INFO' } else { $targetImpactSeverity }
                    Exploitability  = $assessment.Exploitability
                    EvidenceDetail  = @($assessment.EvidenceDetail, @($controlMembershipPaths | ForEach-Object { "Role membership path: $_" })) | Where-Object { $_ } | Join-String -Separator '; '
                    RoleAssignmentSource = $controlSources -join ', '
                    RoleMembershipPath = $controlMembershipPaths -join '; '
                    CredentialRoute = $credentialRoute
                    UserObjectId    = $userId
                    TargetObjectId  = $sp.PrincipalId
                    UserDisplayName = $applicableControl[0].PrincipalDisplayName
                    UserUPN         = $applicableControl[0].PrincipalUPN
                    UserRole        = $controlRoleLabels -join ', '
                    AppName         = $sp.PrincipalDisplayName
                    AppId           = $targetAppId
                    Permission      = $targetRoleNames -join ', '
                    PermissionType  = 'DirectoryRole'
                    Action          = if ($canUseApplicationObject) { "Add an application credential → authenticate as SP → use $($targetRoleNames -join ', ')" } else { "Add an SP credential → authenticate as SP → use $($targetRoleNames -join ', ')" }
                    Result          = if ($isMitigated) { 'CREDENTIAL-INJECTION ROUTE BLOCKED BY APP INSTANCE LOCK' } elseif ($assessment.Exploitability -eq 'PotentialLockUnknown') { 'POTENTIAL PRIVILEGE ESCALATION; LOCK EVIDENCE UNAVAILABLE' } elseif ($assessment.Exploitability -like 'Potential*') { 'POTENTIAL PRIVILEGE ESCALATION; SEE EVIDENCE DETAIL' } else { 'PRIVILEGE ESCALATION VIA SP' }
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
            $spCredCount = if ($spCreds) { @($spCreds | Where-Object { $_.IsCurrentlyValid -eq $true }).Count } else { 0 }
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
        if (Test-AuditCoverageComplete -Sources @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions', 'ApplicationOwners', 'RoleDefinitions', 'ActiveRoleAssignments', 'RoleGroupMemberships', 'AppInstanceLocks')) {
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
        $directPathCount = @($paths | Where-Object { $_.Exploitability -eq 'Direct' }).Count
        $potentialPathCount = @($paths | Where-Object { $_.Exploitability -like 'Potential*' }).Count
        $mitigatedPathCount = @($paths | Where-Object { $_.Exploitability -eq 'MitigatedByAppInstanceLock' }).Count

        Write-Host "Found $($paths.Count) attack path(s): $($ownerPaths.Count) App Owner Escalation, $($roleBasedPaths.Count) Role-Based SP Control" -ForegroundColor Red
        Write-Host "  Evidence: $directPathCount direct, $potentialPathCount potential, $mitigatedPathCount blocked by app instance lock" -ForegroundColor DarkYellow
        Write-Host ""

        # Display App Owner Escalation paths with full box format
        foreach ($path in $ownerPaths) {
            Write-SectionDivider "PATH $($path.PathNumber): $($path.PathType) ($($path.Severity))"
            Write-Host "  ┌─────────────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkYellow
            Write-Host "  │  $($path.UserUPN)" -ForegroundColor White
            Write-Host "  │  Role: $($path.UserRole)" -ForegroundColor Gray
            if ($path.Exploitability -eq 'PotentialRoleUnknown') {
                Write-Host "  │  ⚠ Potential path: additional role evidence is incomplete" -ForegroundColor Yellow
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

        # Display Role-Based SP Control as a compact summary with bounded detail.
        if ($roleBasedPaths.Count -gt 0) {
            Write-Host ""
            Write-SectionDivider "ROLE-BASED SP CONTROL ($($roleBasedPaths.Count) paths)"
            Write-Host "⚠  Users whose current built-in or custom roles can change application or SP credentials may" -ForegroundColor Yellow
            Write-Host "   control the $(@($roleBasedPaths | ForEach-Object { if ($_.TargetObjectId) { $_.TargetObjectId } elseif ($_.AppId) { $_.AppId } else { $_.AppName } } | Select-Object -Unique).Count) service principals below that hold sensitive roles." -ForegroundColor Yellow
            Write-Host ""

            $roleSummary = @($roleBasedPaths | Group-Object { if ($_.UserObjectId) { $_.UserObjectId } elseif ($_.UserUPN) { $_.UserUPN } else { $_.UserDisplayName } } | ForEach-Object {
                $userGroup = $_
                $first = $userGroup.Group | Select-Object -First 1
                [PSCustomObject]@{
                    User = ConvertTo-SingleLineDisplayText $(if ($first.UserUPN) { $first.UserUPN } else { $first.UserDisplayName })
                    'Role(s)' = @($userGroup.Group.UserRole | ForEach-Object { ConvertTo-SingleLineDisplayText $_ } | Select-Object -Unique) -join ', '
                    Targets = @($userGroup.Group | ForEach-Object { if ($_.TargetObjectId) { $_.TargetObjectId } elseif ($_.AppId) { $_.AppId } else { $_.AppName } } | Select-Object -Unique).Count
                    Direct = @($userGroup.Group | Where-Object Exploitability -eq Direct).Count
                    Potential = @($userGroup.Group | Where-Object Exploitability -like 'Potential*').Count
                    Mitigated = @($userGroup.Group | Where-Object Exploitability -eq MitigatedByAppInstanceLock).Count
                }
            } | Sort-Object User)
            $roleSummary | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

            $orderedRolePaths = @(Get-RolePathDisplayOrder -Paths $roleBasedPaths)
            $truncateAfter = [Math]::Max(1, [int]$script:AuditConfig.output.truncateAfter)
            $displayedRolePaths = @($orderedRolePaths | Select-Object -First $truncateAfter)
            Write-Host "PATH CHAINS (showing $($displayedRolePaths.Count) of $($orderedRolePaths.Count))" -ForegroundColor White
            foreach ($path in $displayedRolePaths) {
                foreach ($line in @(Get-RolePathChainLines -Path $path)) {
                    Write-Host $line.Text -ForegroundColor $line.Color
                }
                Write-Host ''
            }
            if ($orderedRolePaths.Count -gt $displayedRolePaths.Count) {
                $remaining = $orderedRolePaths.Count - $displayedRolePaths.Count
                $guidance = if ($script:ExportPath) { "complete evidence exported to $($script:ExportPath)" } else { 'rerun with -ExportPath for complete evidence' }
                Write-Host "... ($remaining more role-control paths; $guidance)" -ForegroundColor DarkGray
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
        if (Test-AuditCoverageComplete -Sources @('RoleDefinitions', 'ActiveRoleAssignments', 'RoleGroupMemberships')) {
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
        $spCredCount = if ($spCreds) { @($spCreds | Where-Object { $_.IsCurrentlyValid -eq $true }).Count } else { 0 }
        foreach ($owner in $owners) {
            if (Test-UserIsGlobalAdministrator -UserId $owner.id -RoleAssignments $roleAssignments) { continue }
            $ownerRoleAssignments = @($roleAssignments | Where-Object { $_.PrincipalId -eq $owner.id -and $_.PrincipalType -eq '#microsoft.graph.user' })
            foreach ($role in $roles) {
                if ($ownerRoleAssignments | Where-Object { Test-RoleAssignmentCoversTarget $_ $role } | Select-Object -First 1) { continue }
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
        if (Test-AuditCoverageComplete -Sources @('RoleDefinitions', 'ActiveRoleAssignments', 'RoleGroupMemberships', 'ServicePrincipalOwners')) {
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
    $script:StalePrivilegeStatus = 'Complete'

    $dangerousApps = @(Get-ServicePrincipalsWithAppRoles | Where-Object { $_.PermissionType -eq 'Application' })
    $permissionEvidenceComplete = Test-AuditCoverageComplete -Sources @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions')
    $script:StalePrivilegeDataAvailable = $permissionEvidenceComplete
    if (-not $permissionEvidenceComplete) { $script:StalePrivilegeStatus = 'Permission coverage is incomplete' }
    if ($dangerousApps.Count -eq 0) {
        if ($permissionEvidenceComplete) {
            Write-Host "✓ No apps with configured dangerous application permissions found." -ForegroundColor Green
        } else {
            Write-Host "⚠ No findings in the available evidence; permission coverage is incomplete." -ForegroundColor Yellow
        }
        return @()
    }

    $signInActivity = Get-SPSignInActivity
    if ($null -eq $signInActivity) {
        $script:StalePrivilegeDataAvailable = $false
        $script:StalePrivilegeStatus = 'Not evaluated (sign-in activity unavailable)'
        if (-not $permissionEvidenceComplete) { $script:StalePrivilegeStatus += '; permission coverage is incomplete' }
        Write-Host "⚠ StalePrivilege skipped because service principal sign-in activity is unavailable." -ForegroundColor Yellow
        Write-Host "  No apps will be classified as stale or as having never signed in." -ForegroundColor Yellow
        return @()
    }

    $appIds = $dangerousApps | ForEach-Object { $_.AppId } | Select-Object -Unique
    $homeAppIds = @($dangerousApps | Where-Object { $_.AppTenantType -eq 'HomeTenant' } | ForEach-Object { $_.AppId } | Select-Object -Unique)
    $appEvidence = @{}
    $spEvidence = @{}
    $appCreds = if ($homeAppIds.Count -gt 0) { Get-AppCredentials -AppIds $homeAppIds -EvidenceStatus $appEvidence } else { @{} }
    $spIds = @($dangerousApps | ForEach-Object { $_.SPId } | Select-Object -Unique)
    $spDirectCreds = Get-SPDirectCredentials -SPIds $spIds -EvidenceStatus $spEvidence

    $inactiveDays = $script:AuditConfig.stalePrivilege.inactiveDays
    $cutoffDate = (Get-Date).AddDays(-$inactiveDays)
    $staleApps = @()

    foreach ($appId in $appIds) {
        $apps = $dangerousApps | Where-Object { $_.AppId -eq $appId }
        $app = $apps | Select-Object -First 1
        $appSPIds = @($apps | ForEach-Object { $_.SPId } | Select-Object -Unique)
        $credentialEvidence = Resolve-AppCredentialEvidenceStatus -AppId $appId -AppTenantType $app.AppTenantType -SPIds $appSPIds -AppCredentials $appCreds -SPCredentials $spDirectCreds -AppEvidence $appEvidence -SPEvidence $spEvidence
        if ($credentialEvidence -ne 'Complete') {
            $script:StalePrivilegeDataAvailable = $false
            $script:StalePrivilegeStatus = if ($permissionEvidenceComplete) { 'Credential coverage is incomplete' } else { 'Permission and credential coverage is incomplete' }
        }
        $creds = @($appCreds[$appId])
        foreach ($spId in @($apps | ForEach-Object { $_.SPId } | Select-Object -Unique)) {
            $creds += @($spDirectCreds[$spId])
        }

        $validCreds = @()
        if ($creds) { $validCreds = @($creds | Where-Object { $_ -and $_.IsCurrentlyValid -eq $true }) }
        if ($validCreds.Count -eq 0) { continue }

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
                CredentialExpires = if ($credExpiry) { ([datetimeoffset]$credExpiry).ToUniversalTime().ToString('yyyy-MM-dd') } else { 'N/A' }
                ValidCredCount    = $validCreds.Count
                EntraPortalUrl    = Get-EntraAppUrl -ObjectId $a.SPId -AppId $a.AppId
            }
        }
    }

    if ($staleApps.Count -eq 0) {
        if ($script:StalePrivilegeDataAvailable -and (Test-AuditCoverageComplete -Sources @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions', 'ServicePrincipalSignInActivity', 'ServicePrincipalCredentials'))) {
            Write-Host "✓ No stale high-privilege apps found." -ForegroundColor Green
        } else {
            $coverageReason = if ($script:StalePrivilegeDataAvailable) { 'stale-privilege coverage is incomplete' } else { $script:StalePrivilegeStatus.ToLowerInvariant() }
            Write-Host "⚠ No stale apps found in the available evidence; $coverageReason." -ForegroundColor Yellow
        }
        return @()
    }

    if (-not $script:StalePrivilegeDataAvailable) {
        Write-Host "⚠ Stale findings and valid credential counts are observed lower bounds; $($script:StalePrivilegeStatus.ToLowerInvariant())." -ForegroundColor Yellow
    }
    $staleAppCount = @($staleApps | Select-Object -ExpandProperty AppId -Unique).Count
    Write-Host "Found $staleAppCount stale high-privilege app(s):" -ForegroundColor Yellow
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

    $findings = @()
    $userConsentAllowed = $false
    $policy = Get-TenantConsentPolicy
    if ($null -eq $policy) {
        Write-Host "⚠ Could not retrieve consent policy. Policy settings are unavailable." -ForegroundColor Yellow
    } else {
        # Analyze default user role permissions
        $defaultPerms = $policy.defaultUserRolePermissions
        if ($defaultPerms -isnot [System.Collections.IDictionary] -and $defaultPerms -isnot [PSCustomObject]) { $defaultPerms = $null }

        # Values are action-prefixed (managePermissionGrantsForSelf.<policy-id>), and
        # a custom policy is a real enabled state rather than "disabled".
        $assignmentsKnown = $defaultPerms.permissionGrantPoliciesAssigned -is [System.Collections.IList] -and
            @($defaultPerms.permissionGrantPoliciesAssigned | Where-Object { $_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_) }).Count -eq 0
        $consentState = if ($assignmentsKnown) {
            Resolve-UserConsentPolicyAssignment -AssignedPolicies @($defaultPerms.permissionGrantPoliciesAssigned)
        } else {
            [PSCustomObject]@{ State = 'Unknown'; PolicyIds = @() }
        }
        $userConsentAllowed = $consentState.State -eq 'AllowedForAllApps'

        if ($consentState.State -eq 'Unknown') {
            $findings += [PSCustomObject]@{
                Setting = 'User consent for apps'
                Value   = 'Unknown'
                Risk    = 'REVIEW'
            }
        } elseif ($consentState.State -eq 'AllowedForAllApps') {
            $findings += [PSCustomObject]@{
                Setting = 'User consent for apps'
                Value   = "Allowed for all apps (user-consentable permissions); policies: $($consentState.PolicyIds -join ', ')"
                Risk    = '⚠  CRITICAL'
            }
        } elseif ($consentState.State -eq 'RestrictedBuiltIn') {
            $findings += [PSCustomObject]@{
                Setting = 'User consent for apps'
                Value   = "Allowed (verified publishers, low-risk only); policies: $($consentState.PolicyIds -join ', ')"
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
            Value   = if ($canRegister -isnot [bool]) { 'Unknown' } elseif ($canRegister) { 'Yes' } else { 'No' }
            Risk    = if ($canRegister -isnot [bool]) { 'REVIEW' } elseif ($canRegister) { 'ⓘ  LOW' } else { '✓  GOOD' }
        }

        # Check if users can read other users
        $canReadOthers = $defaultPerms.allowedToReadOtherUsers
        $findings += [PSCustomObject]@{
            Setting = 'Users can read other users'
            Value   = if ($canReadOthers -isnot [bool]) { 'Unknown' } elseif ($canReadOthers) { 'Yes' } else { 'No' }
            Risk    = if ($canReadOthers -isnot [bool]) { 'REVIEW' } else { 'ⓘ  INFO' }
        }

        Write-Host "TENANT CONSENT POLICY:" -ForegroundColor Cyan
        Write-Host ""
        $findings | Format-Table -AutoSize | Out-String | Write-Host
    }

    if ($script:AuditConfig.consentRisk.flagUserConsentedApps) {
        $userGrants = @(Get-UserConsentGrants)
        if ($userGrants.Count -gt 0) {
            Write-Host "SINGLE-USER DELEGATED PERMISSION GRANTS ($($userGrants.Count) grants):" -ForegroundColor Yellow
            Write-Host ""

            $clientDisplayNames = @{}
            $truncateAfter = $script:AuditConfig.output.truncateAfter
            Set-CoverageState -Source 'UserConsentClientResolution' -State Complete
            $consentData = @(foreach ($grant in $userGrants) {
                $clientId = [string]$grant.clientId
                if (-not $clientDisplayNames.ContainsKey($clientId)) {
                    $clientDisplayNames[$clientId] = '[unresolved]'
                    try {
                        $sp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($clientId)?`$select=displayName"
                        if ($sp.displayName -isnot [string] -or [string]::IsNullOrWhiteSpace($sp.displayName)) {
                            throw 'Missing or malformed client displayName.'
                        }
                        $clientDisplayNames[$clientId] = $sp.displayName
                    } catch {
                        Set-CoverageState -Source 'UserConsentClientResolution' -State Partial -Detail "Failed for client SP $($clientId): $($_.Exception.Message)"
                    }
                }
                [PSCustomObject]@{
                    GrantId          = $grant.id
                    ClientSPId       = $clientId
                    ResourceSPId     = $grant.resourceId
                    ConsentPrincipalId = $grant.principalId
                    ConsentType      = $grant.consentType
                    ConsentedScopes  = $grant.scope
                    AppName          = $clientDisplayNames[$clientId]
                }
            })
            $consentData | Select-Object -First $truncateAfter | Format-Table -AutoSize | Out-String | Write-Host
            Export-AuditCsv -Name 'UserConsentGrants' -Data $consentData

            if ($consentData.Count -gt $truncateAfter) {
                Write-Host "... ($($consentData.Count - $truncateAfter) more)" -ForegroundColor DarkGray
            }
        } else {
            if (Test-AuditCoverageComplete -Sources @('UserConsentGrants')) {
                Write-Host "✓ No single-user delegated permission grants found." -ForegroundColor Green
            } else {
                Write-Host "⚠ Single-user delegated permission grants could not be evaluated completely." -ForegroundColor Yellow
            }
        }
    }

    if ($userConsentAllowed) {
        Write-Recommendation -Items @(
            'Set user consent to "Do not allow user consent" or "Allow for verified publishers only"'
            'Enable admin consent workflow so users can request access'
            'Review and revoke suspicious single-user delegated permission grants above'
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
        if (Test-AuditCoverageComplete -Sources @(Get-PermissionCoverageSource)) {
            Write-Host "✓ No apps with configured dangerous grants found." -ForegroundColor Green
        } else {
            Write-Host "⚠ No findings in the available evidence; credential-hygiene coverage is incomplete." -ForegroundColor Yellow
        }
        return @()
    }

    $appIds = $dangerousApps | ForEach-Object { $_.AppId } | Select-Object -Unique
    $homeAppIds = @($dangerousApps | Where-Object { $_.AppTenantType -eq 'HomeTenant' } | ForEach-Object { $_.AppId } | Select-Object -Unique)
    $appEvidence = @{}
    $spEvidence = @{}
    $appCreds = if ($homeAppIds.Count -gt 0) { Get-AppCredentials -AppIds $homeAppIds -EvidenceStatus $appEvidence } else { @{} }

    # Also get SP-level credentials (added directly to SP object, hidden from portal)
    $spIds = @($dangerousApps | ForEach-Object { $_.SPId } | Select-Object -Unique)
    $spDirectCreds = Get-SPDirectCredentials -SPIds $spIds -EvidenceStatus $spEvidence
    $appLockStatus = if ($homeAppIds.Count -gt 0) { Get-AppInstanceLockStatus -AppIds $homeAppIds } else { @{} }

    $results = @()
    foreach ($appId in $appIds) {
        $apps = $dangerousApps | Where-Object { $_.AppId -eq $appId }
        $app = $apps | Select-Object -First 1
        $creds = $appCreds[$appId]
        $credentialEvidence = Resolve-AppCredentialEvidenceStatus -AppId $appId -AppTenantType $app.AppTenantType -SPIds $app.SPId -AppCredentials $appCreds -SPCredentials $spDirectCreds -AppEvidence $appEvidence -SPEvidence $spEvidence
        $credentialsComplete = $credentialEvidence -eq 'Complete'
        $spCredentialsComplete = (Resolve-CredentialCollectionEvidenceStatus -ObjectId $app.SPId -Credentials $spDirectCreds -EvidenceStatus $spEvidence) -eq 'Complete'

        # SP-level credentials
        $spCreds = $spDirectCreds[$app.SPId]
        $spCredCount = if ($spCreds) { @($spCreds).Count } else { 0 }
        $spValidCreds = if ($spCreds) { @($spCreds | Where-Object { $_.IsCurrentlyValid -eq $true }).Count } else { 0 }

        # App instance lock
        $lock = $appLockStatus[$appId]

        if ((-not $creds -or $creds.Count -eq 0) -and $spCredCount -eq 0) {
            $results += [PSCustomObject]@{
                AppName          = $app.SPDisplayName
                AppId            = $app.AppId
                Permission       = ($apps | ForEach-Object { $_.Permission }) -join ', '
                CredType         = if ($credentialsComplete) { 'None' } else { 'Unknown' }
                CredCount        = if ($credentialsComplete) { 0 } else { 'Unknown' }
                ExpiredCount     = if ($credentialsComplete) { 0 } else { 'Unknown' }
                SPDirectCreds    = if ($spCredentialsComplete) { 0 } else { 'Unknown' }
                AppInstanceLock  = if ($lock) { $lock.State } elseif ($app.AppTenantType -eq 'HomeTenant') { 'Unavailable' } else { 'NotLocallyObservable' }
                RiskLevel        = if ($credentialsComplete) { 'ⓘ  INFO (no credentials)' } else { 'REVIEW (credential evidence incomplete; credential counts unknown)' }
                EntraPortalUrl   = Get-EntraAppUrl -ObjectId $app.SPId -AppId $app.AppId
                CredentialEvidence = $credentialEvidence
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
        if (-not $credentialsComplete) {
            if ($riskLevel -match 'GOOD|MODERATE') { $riskLevel = 'REVIEW' } else { $riskLevel += '; REVIEW' }
            $riskLevel += ' (credential evidence incomplete; observed counts are lower bounds)'
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
            SPDirectCreds    = if ($spCredentialsComplete -or $spValidCreds -gt 0) { $spValidCreds } else { 'Unknown' }
            AppInstanceLock  = if ($lock) { $lock.State } elseif ($app.AppTenantType -eq 'HomeTenant') { 'Unavailable' } else { 'NotLocallyObservable' }
            RiskLevel        = $riskLevel
            EntraPortalUrl   = Get-EntraAppUrl -ObjectId $app.SPId -AppId $app.AppId
            CredentialEvidence = $credentialEvidence
        }
    }

    $results | Select-Object @{N='App Name';E={$_.AppName}}, @{N='Permission';E={$_.Permission}},
        @{N='Cred Type';E={$_.CredType}}, @{N='Count';E={$_.CredCount}},
        @{N='Expired';E={$_.ExpiredCount}}, @{N='SP Creds';E={$_.SPDirectCreds}},
        @{N='Lock';E={$_.AppInstanceLock}}, @{N='Risk';E={$_.RiskLevel}}, @{N='Credential Evidence';E={$_.CredentialEvidence}} |
        Format-Table -AutoSize | Out-String | Write-Host

    # Summary
    $secretApps = ($results | Where-Object { $_.CredType -match 'Secret' } | Measure-Object).Count
    $certApps = ($results | Where-Object { $_.CredType -match 'Certificate' -and $_.CredType -notmatch 'Secret' } | Measure-Object).Count
    $fedApps = ($results | Where-Object { $_.CredType -match 'Federated' -and $_.CredType -notmatch 'Secret' -and $_.CredType -notmatch 'Certificate' } | Measure-Object).Count
    $totalExpired = ($results | Where-Object { $_.ExpiredCount -is [int] } | Measure-Object -Property ExpiredCount -Sum).Sum
    $multiCred = ($results | Where-Object { $_.CredCount -is [int] -and $_.CredCount -gt 1 } | Measure-Object).Count
    $spCredApps = ($results | Where-Object { $_.SPDirectCreds -is [int] -and $_.SPDirectCreds -gt 0 } | Measure-Object).Count
    $unlocked = ($results | Where-Object { $_.AppInstanceLock -in @('Disabled', 'NotConfigured', 'EnabledButOAuthCredentialsNotLocked') -and $_.CredType -ne 'None' } | Measure-Object).Count

    Write-Host "SUMMARY:" -ForegroundColor Cyan
    if (@($results | Where-Object { $_.CredentialEvidence -ne 'Complete' }).Count -gt 0) {
        Write-Host "  REVIEW: Credential evidence is incomplete. Numeric totals below are observed lower bounds; Unknown is not zero." -ForegroundColor Yellow
    }
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

function Invoke-WithModeCoverage {
    param(
        [scriptblock]$Action,
        [System.Collections.IDictionary]$Coverage
    )

    $previousCapture = $script:ModeCoverageCapture
    $script:ModeCoverageCapture = $Coverage
    try {
        & $Action
    } finally {
        $script:ModeCoverageCapture = $previousCapture
    }
}

function Get-ModeCoverage {
    param(
        [string[]]$RequiredSources,
        [string[]]$OptionalSources,
        [int]$ObservedCount = 0,
        [string[]]$EvidenceDetail,
        [System.Collections.IDictionary]$LocalCoverage
    )

    $sources = @(@($RequiredSources) + @($OptionalSources | Where-Object {
        $_ -and $(if ($null -eq $LocalCoverage) { $script:Coverage.Contains($_) } else {
            $LocalCoverage.Contains($_) -or ($_ -eq 'MicrosoftFirstPartyAppCatalog' -and $script:Coverage.Contains($_))
        })
    }) | Select-Object -Unique)
    $details = @()
    $hasGap = @($EvidenceDetail | Where-Object { $_ }).Count -gt 0
    $hasEvidence = $ObservedCount -gt 0
    foreach ($source in $sources) {
        $ledger = if ($null -ne $LocalCoverage -and $LocalCoverage.Contains($source)) { $LocalCoverage } else { $script:Coverage }
        if (-not $ledger.Contains($source)) {
            $hasGap = $true
            $details += "${source}: Missing (required evidence not recorded)"
            continue
        }
        $entry = $ledger[$source]
        if ($entry.State -ne 'Complete') { $hasGap = $true }
        if ($entry.State -in @('Complete', 'Partial')) { $hasEvidence = $true }
        $details += "${source}: $($entry.State)$(if ($entry.Details.Count -gt 0) { ' (' + ($entry.Details -join '; ') + ')' })"
    }
    [PSCustomObject]@{
        CoverageState = if (-not $hasGap) { 'Complete' } elseif ($hasEvidence) { 'Partial' } else { 'Unavailable' }
        CoverageDetail = (@($details) + @($EvidenceDetail | Where-Object { $_ })) -join '; '
    }
}

function Invoke-FullAudit {
    $summary = @{}
    $modeCoverage = @{}
    $applicationSources = @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions')
    $permissionSources = @(Get-PermissionCoverageSource)
    $roleSources = @('RoleDefinitions', 'ActiveRoleAssignments', 'RoleGroupMemberships')
    $filteredCatalog = @('MicrosoftFirstPartyAppCatalog' | Where-Object { $script:AuditConfig.filters.excludeFirstPartyMicrosoftApps })

    $localCoverage = [ordered]@{}
    $permResults = Invoke-WithModeCoverage -Coverage $localCoverage -Action { Invoke-PermissionAudit }
    $modeCoverage['PermissionAudit'] = Get-ModeCoverage -LocalCoverage $localCoverage -RequiredSources $permissionSources -OptionalSources $filteredCatalog -ObservedCount $permResults.Count
    $summary['PermissionAudit'] = "$($permResults.Count) configured dangerous permission grant(s)"

    $localCoverage = [ordered]@{}
    $roleResults = Invoke-WithModeCoverage -Coverage $localCoverage -Action { Invoke-RoleAudit }
    $roleDetail = if ($roleResults.CoverageComplete -eq $false) { 'RoleAudit: users without sensitive roles could not be classified' }
    $modeCoverage['RoleAudit'] = Get-ModeCoverage -LocalCoverage $localCoverage -RequiredSources ($roleSources + 'Users') -ObservedCount ($roleResults.PrivilegedUsers.Count + @($roleResults.NonPrivilegedUsers).Count) -EvidenceDetail $roleDetail
    $roleCoverageComplete = $modeCoverage['RoleAudit'].CoverageState -eq 'Complete'
    $summary['RoleAudit'] = if ($roleCoverageComplete) {
        "$($roleResults.PrivilegedUsers.Count) users with sensitive-role assignments, $(($roleResults.NonPrivilegedUsers | Measure-Object).Count) confirmed without"
    } else {
        "Incomplete — $($roleResults.PrivilegedUsers.Count) sensitive-role user assignment(s) observed; other users not classified"
    }

    $localCoverage = [ordered]@{}
    $attackResults = Invoke-WithModeCoverage -Coverage $localCoverage -Action { Invoke-AttackPathAnalysis }
    $directAttackResults = @($attackResults | Where-Object { $_.Exploitability -eq 'Direct' })
    $potentialAttackResults = @($attackResults | Where-Object { $_.Exploitability -like 'Potential*' })
    $potentialLockResults = @($attackResults | Where-Object { $_.Exploitability -eq 'PotentialLockUnknown' })
    $potentialRoleResults = @($attackResults | Where-Object { $_.Exploitability -eq 'PotentialRoleUnknown' })
    $potentialPrerequisiteResults = @($attackResults | Where-Object { $_.Exploitability -eq 'PotentialPrerequisiteUnknown' })
    $mitigatedAttackResults = @($attackResults | Where-Object { $_.Exploitability -eq 'MitigatedByAppInstanceLock' })
    $applicationCandidates = @($permResults | Where-Object { $_.PermissionType -eq 'Application' })
    $attackOptional = @($filteredCatalog)
    if ($applicationCandidates.Count -gt 0 -or @($roleResults.SPRoles).Count -gt 0 -or $attackResults.Count -gt 0) {
        $attackOptional += @('MicrosoftFirstPartyAppCatalog', 'ApplicationOwners', 'ServicePrincipalOwners', 'ServicePrincipalCredentials', 'AppInstanceLocks')
    }
    $modeCoverage['AttackPaths'] = Get-ModeCoverage -LocalCoverage $localCoverage -RequiredSources ($applicationSources + $roleSources) -OptionalSources $attackOptional -ObservedCount $attackResults.Count
    $summary['AttackPaths'] = "$($directAttackResults.Count) direct, $($potentialAttackResults.Count) potential, $($mitigatedAttackResults.Count) blocked by app instance lock"

    $localCoverage = [ordered]@{}
    $shadowResults = Invoke-WithModeCoverage -Coverage $localCoverage -Action { Invoke-ShadowAdminDetection }
    $shadowOptional = @()
    if (@($roleResults.SPRoles).Count -gt 0 -or $shadowResults.Count -gt 0) {
        $shadowOptional = @('ServicePrincipalOwners', 'ServicePrincipalCredentials')
    }
    $modeCoverage['ShadowAdmins'] = Get-ModeCoverage -LocalCoverage $localCoverage -RequiredSources $roleSources -OptionalSources $shadowOptional -ObservedCount $shadowResults.Count
    $shadowCoverageComplete = $modeCoverage['ShadowAdmins'].CoverageState -eq 'Complete'
    $summary['ShadowAdmins'] = if ($shadowCoverageComplete) {
        "$($shadowResults.Count) shadow admin detected"
    } else {
        "Incomplete — $($shadowResults.Count) shadow admin relationship(s) observed"
    }

    $localCoverage = [ordered]@{}
    $staleResults = Invoke-WithModeCoverage -Coverage $localCoverage -Action { Invoke-StalePrivilegeDetection }
    $staleAppCount = @($staleResults | Select-Object -ExpandProperty AppId -Unique).Count
    $staleOptional = @($filteredCatalog)
    if ($applicationCandidates.Count -gt 0 -or $staleAppCount -gt 0) {
        $staleOptional += @('MicrosoftFirstPartyAppCatalog', 'ServicePrincipalSignInActivity', 'ApplicationCredentials', 'FederatedIdentityCredentials', 'ServicePrincipalCredentials')
    }
    $staleDetail = if ($script:StalePrivilegeDataAvailable -eq $false) { "StalePrivilege: $($script:StalePrivilegeStatus)" }
    $modeCoverage['StalePrivilege'] = Get-ModeCoverage -LocalCoverage $localCoverage -RequiredSources $applicationSources -OptionalSources $staleOptional -ObservedCount $staleAppCount -EvidenceDetail $staleDetail
    $summary['StalePrivilege'] = if ($script:StalePrivilegeDataAvailable -eq $false) {
        if ($script:StalePrivilegeStatus -like 'Not evaluated*') {
            $script:StalePrivilegeStatus
        } elseif ($script:StalePrivilegeStatus -match 'coverage is incomplete') {
            $evidenceKinds = @(
                if ($script:StalePrivilegeStatus -match 'permission') { 'permission' }
                if ($script:StalePrivilegeStatus -match 'credential') { 'credential' }
            )
            "Incomplete ($($evidenceKinds -join ' and ') evidence); $staleAppCount dormant high-privilege apps observed"
        } else {
            'Not evaluated (sign-in activity unavailable)'
        }
    } else {
        "$staleAppCount dormant high-privilege apps"
    }

    $localCoverage = [ordered]@{}
    $consentResults = Invoke-WithModeCoverage -Coverage $localCoverage -Action { Invoke-ConsentRiskAssessment }
    $criticalConsent = ($consentResults | Where-Object { $_.Risk -match 'CRITICAL|HIGH' } | Measure-Object).Count
    $reviewConsent = @($consentResults | Where-Object { $_.Risk -match 'REVIEW' }).Count
    $consentSources = @('TenantAuthorizationPolicy')
    $consentOptional = @()
    if ($script:AuditConfig.consentRisk.flagUserConsentedApps) {
        $consentSources += 'UserConsentGrants'
        $consentOptional += 'UserConsentClientResolution'
    }
    $modeCoverage['ConsentRisk'] = Get-ModeCoverage -LocalCoverage $localCoverage -RequiredSources $consentSources -OptionalSources $consentOptional -ObservedCount $consentResults.Count
    $summary['ConsentRisk'] = "$criticalConsent HIGH/CRITICAL consent policy issues, $reviewConsent requiring review"

    $localCoverage = [ordered]@{}
    $credResults = Invoke-WithModeCoverage -Coverage $localCoverage -Action { Invoke-CredentialHygieneAudit }
    $secretApps = ($credResults | Where-Object { $_.CredType -match 'Secret' } | Measure-Object).Count
    $spCredApps = ($credResults | Where-Object { $_.SPDirectCreds -is [int] -and $_.SPDirectCreds -gt 0 } | Measure-Object).Count
    $credentialReview = @($credResults | Where-Object { $_.CredentialEvidence -ne 'Complete' -or $_.RiskLevel -match 'REVIEW' }).Count
    $credentialDetail = @($credResults | Where-Object { $_.CredentialEvidence -ne 'Complete' } | ForEach-Object {
        "CredentialEvidence: $(if ($_.CredentialEvidence) { $_.CredentialEvidence } else { 'Missing' })"
    } | Select-Object -Unique)
    $credentialOptional = @($filteredCatalog)
    if ($permResults.Count -gt 0 -or $credResults.Count -gt 0) {
        $credentialOptional += @('MicrosoftFirstPartyAppCatalog', 'ApplicationCredentials', 'FederatedIdentityCredentials', 'ServicePrincipalCredentials')
        if (@($permResults | Where-Object { $_.AppTenantType -eq 'HomeTenant' }).Count -gt 0) {
            $credentialOptional += 'AppInstanceLocks'
        }
    }
    $modeCoverage['CredentialHygiene'] = Get-ModeCoverage -LocalCoverage $localCoverage -RequiredSources $permissionSources -OptionalSources $credentialOptional -ObservedCount $credResults.Count -EvidenceDetail $credentialDetail
    $summary['CredentialHygiene'] = "$secretApps high-privilege apps using secrets, $spCredApps with SP-level credentials"
    if ($credentialReview -gt 0) { $summary['CredentialHygiene'] = "$credentialReview requiring review; $($summary['CredentialHygiene'])" }

    foreach ($mode in @($summary.Keys)) {
        $state = $modeCoverage[$mode].CoverageState
        if ($state -ne 'Complete') {
            if ($mode -eq 'StalePrivilege' -and $state -eq 'Partial' -and $summary[$mode] -match '^(Incomplete|Not evaluated)') { continue }
            $qualifier = if ($state -eq 'Unavailable') { 'Unavailable' } else { 'Incomplete' }
            $summary[$mode] = "$qualifier coverage; observed counts are lower bounds: $($summary[$mode])"
        }
    }

    # Print summary
    Write-Banner "FULL AUDIT SUMMARY"

    Write-Host "  Permission Audit:      $($summary['PermissionAudit'])" -ForegroundColor $(if ($modeCoverage['PermissionAudit'].CoverageState -ne 'Complete') { 'DarkYellow' } elseif ($permResults.Count -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Role Audit:            $($summary['RoleAudit'])" -ForegroundColor $(if ($roleCoverageComplete) { 'Gray' } else { 'DarkYellow' })
    Write-Host "  Attack Paths:          $($summary['AttackPaths'])" -ForegroundColor $(if ($directAttackResults.Count -gt 0) { 'Red' } elseif ($modeCoverage['AttackPaths'].CoverageState -ne 'Complete' -or $potentialAttackResults.Count -gt 0 -or $mitigatedAttackResults.Count -gt 0) { 'DarkYellow' } else { 'Green' })
    Write-Host "  Shadow Admins:         $($summary['ShadowAdmins'])" -ForegroundColor $(if ($shadowResults.Count -gt 0) { 'Red' } elseif (-not $shadowCoverageComplete) { 'DarkYellow' } else { 'Green' })
    Write-Host "  Stale Privilege:       $($summary['StalePrivilege'])" -ForegroundColor $(if ($modeCoverage['StalePrivilege'].CoverageState -ne 'Complete') { 'DarkYellow' } elseif ($staleResults.Count -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Consent Risk:          $($summary['ConsentRisk'])" -ForegroundColor $(if ($modeCoverage['ConsentRisk'].CoverageState -ne 'Complete') { 'DarkYellow' } elseif ($criticalConsent -gt 0 -or $reviewConsent -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Credential Hygiene:    $($summary['CredentialHygiene'])" -ForegroundColor $(if ($modeCoverage['CredentialHygiene'].CoverageState -ne 'Complete') { 'DarkYellow' } elseif ($secretApps -gt 0 -or $spCredApps -gt 0 -or $credentialReview -gt 0) { 'Yellow' } else { 'Green' })

    Write-Host ""
    $coverageComplete = (Test-AuditCoverageComplete) -and @($modeCoverage.Values | Where-Object { $_.CoverageState -ne 'Complete' }).Count -eq 0
    $overallCoverageState = if ($coverageComplete) { 'Complete' } elseif (@($modeCoverage.Values | Where-Object { $_.CoverageState -ne 'Unavailable' }).Count -gt 0) { 'Partial' } else { 'Unavailable' }
    $modeCoverage['DataCoverage'] = [PSCustomObject]@{
        CoverageState = $overallCoverageState
        CoverageDetail = (@($modeCoverage.Keys | Sort-Object | ForEach-Object { "${_}: $($modeCoverage[$_].CoverageState)" }) -join '; ')
    }
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
        $actions += "Complete role evidence and validate $($potentialRoleResults.Count) potential application-control path(s)"
    }
    if ($potentialPrerequisiteResults.Count -gt 0) {
        $actions += "Validate application identity, assignment scope and accountEnabled prerequisites for $($potentialPrerequisiteResults.Count) potential path(s)"
    }
    if ($criticalConsent -gt 0) {
        $actions += 'Disable user consent or restrict to verified publishers'
    }
    if ($staleAppCount -gt 0) {
        $actions += "Disable/delete $staleAppCount dormant apps with dangerous permissions and valid credentials"
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
        [PSCustomObject]@{ Section = 'StalePrivilege';     Finding = $summary['StalePrivilege'];     Count = $staleAppCount }
        [PSCustomObject]@{ Section = 'ConsentRisk';        Finding = $summary['ConsentRisk'];        Count = $criticalConsent }
        [PSCustomObject]@{ Section = 'CredentialHygiene';  Finding = $summary['CredentialHygiene'];  Count = "$secretApps secrets, $spCredApps SP-creds" }
        [PSCustomObject]@{ Section = 'DataCoverage';       Finding = $(if ($coverageComplete) { 'Complete' } else { "$overallCoverageState -- see per-mode CoverageDetail and DataCoverage.csv or console details" }); Count = '' }
    )
    foreach ($row in $summaryRows) {
        $row | Add-Member -NotePropertyName CoverageState -NotePropertyValue $modeCoverage[$row.Section].CoverageState
        $row | Add-Member -NotePropertyName CoverageDetail -NotePropertyValue $modeCoverage[$row.Section].CoverageDetail
    }
    $actionNum = 0
    foreach ($action in ($actions | Select-Object -First 5)) {
        $actionNum++
        $summaryRows += [PSCustomObject]@{ Section = "Action$actionNum"; Finding = $action; Count = ''; CoverageState = ''; CoverageDetail = '' }
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
