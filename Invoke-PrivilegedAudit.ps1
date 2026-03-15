<#
.SYNOPSIS
    Identifies privilege escalation paths through Entra ID app registrations, maps shadow admin
    relationships, and audits privileged role membership.

.DESCRIPTION
    Connects to Microsoft Entra ID via Microsoft Graph, identifies app registrations and service
    principals with permissions equivalent to Global Administrator, and reports which users hold
    privileged directory roles versus those who don't.

    Modes:
      PermissionAudit    - Apps with GA-equivalent permissions
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

.LINK
    https://github.com/yourusername/privilidged-app-path
#>

[CmdletBinding()]
param(
    [ValidateSet('PermissionAudit', 'RoleAudit', 'AttackPath', 'ShadowAdmins', 'StalePrivilege', 'ConsentRisk', 'CredentialHygiene', 'Full')]
    [string]$Mode = 'Full',

    [string]$ExportPath,

    [int]$InactiveDays,

    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Configuration Loading ──────────────────────────────────────────────

# Hardcoded defaults — these are used if no config files exist
$script:DefaultDangerousPermissions = @(
    @{ name = 'RoleManagement.ReadWrite.Directory'; type = 'Application'; risk = 'Critical'; reason = 'Can assign any Entra ID role to any principal, including Global Administrator' }
    @{ name = 'AppRoleAssignment.ReadWrite.All';    type = 'Application'; risk = 'Critical'; reason = 'Can grant itself or any app any application permission' }
    @{ name = 'Application.ReadWrite.All';          type = 'Application'; risk = 'Critical'; reason = 'Can modify any app registration credentials and impersonate it' }
    @{ name = 'Directory.ReadWrite.All';            type = 'Application'; risk = 'High';     reason = 'Near-full write access to all directory objects' }
    @{ name = 'Directory.AccessAsUser.All';         type = 'Delegated';   risk = 'Critical'; reason = 'Full directory access as the signed-in user' }
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
        preferredCredentialTypes = @('Certificate', 'FederatedIdentityCredential')
        riskyCredentialTypes    = @('Password')
        flagMultipleCredentials = $true
        flagExpiredCredentials  = $true
    }
    output = @{
        truncateAfter = 50
    }
}

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
)

function Load-Config {
    $script:DangerousPermissions = $script:DefaultDangerousPermissions
    $script:PrivilegedRoles      = $script:DefaultPrivilegedRoles
    $script:AuditConfig          = $script:DefaultAuditConfig
    $script:AttackPathDefs       = $script:DefaultAttackPaths

    $permFile   = Join-Path $ConfigPath 'dangerous-permissions.json'
    $rolesFile  = Join-Path $ConfigPath 'privileged-roles.json'
    $configFile = Join-Path $ConfigPath 'audit-config.json'
    $pathsFile  = Join-Path $ConfigPath 'attack-paths.json'

    if (Test-Path $permFile) {
        $json = Get-Content $permFile -Raw | ConvertFrom-Json
        if ($json.permissions) {
            $script:DangerousPermissions = @($json.permissions | ForEach-Object {
                @{ name = $_.name; type = $_.type; risk = $_.risk; reason = $_.reason }
            })
            Write-Verbose "Loaded $(($script:DangerousPermissions).Count) dangerous permissions from config"
        }
    }

    if (Test-Path $rolesFile) {
        $json = Get-Content $rolesFile -Raw | ConvertFrom-Json
        if ($json.roles) {
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
        if ($json.filters.excludeAppIds) {
            $script:AuditConfig.filters.excludeAppIds = @($json.filters.excludeAppIds)
        }
        if ($null -ne $json.consentRisk.flagUserConsentedApps) {
            $script:AuditConfig.consentRisk.flagUserConsentedApps = [bool]$json.consentRisk.flagUserConsentedApps
        }
        if ($json.output.truncateAfter) {
            $script:AuditConfig.output.truncateAfter = [int]$json.output.truncateAfter
        }
        Write-Verbose "Loaded audit config overrides from config"
    }

    if (Test-Path $pathsFile) {
        $json = Get-Content $pathsFile -Raw | ConvertFrom-Json
        if ($json.paths) {
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
    if ($InactiveDays -gt 0) {
        $script:AuditConfig.stalePrivilege.inactiveDays = $InactiveDays
    }
}

#endregion

#region ── Output Helpers ─────────────────────────────────────────────────────

function Write-Banner {
    param([string]$Title)
    $width = 78
    $line = '═' * $width
    Write-Host ""
    Write-Host "╔$line╗" -ForegroundColor Cyan
    Write-Host "║  $($Title.PadRight($width - 3))║" -ForegroundColor Cyan
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
        'RoleManagement.Directory.Read.All'
        'AuditLog.Read.All'
        'Policy.Read.All'
    )

    $context = $null
    try { $context = Get-MgContext } catch { }

    if ($context) {
        $missing = $requiredScopes | Where-Object { $_ -notin $context.Scopes }
        if ($missing.Count -eq 0) {
            Write-Host "✓ Already connected to Microsoft Graph as $($context.Account)" -ForegroundColor Green
            return
        }
        Write-Host "⚠ Connected but missing scopes: $($missing -join ', ')" -ForegroundColor Yellow
        Write-Host "  Reconnecting with required scopes..." -ForegroundColor Yellow
    }

    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome
    $ctx = Get-MgContext
    Write-Host "✓ Connected as $($ctx.Account) (TenantId: $($ctx.TenantId))" -ForegroundColor Green
}

#endregion

#region ── Graph Data Queries ─────────────────────────────────────────────────

# Paginate through a Graph endpoint
function Get-AllGraphPages {
    param([string]$Uri)
    $results = @()
    $response = Invoke-MgGraphRequest -Method GET -Uri $Uri
    if ($response.value) { $results += $response.value }
    while ($response.'@odata.nextLink') {
        $response = Invoke-MgGraphRequest -Method GET -Uri $response.'@odata.nextLink'
        if ($response.value) { $results += $response.value }
    }
    return $results
}

function Get-ServicePrincipalsWithAppRoles {
    Write-Host "  Querying service principals and app role assignments..." -ForegroundColor Gray
    $sps = Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled&$top=999'

    # Filter first-party Microsoft apps if configured
    $microsoftPublisherId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
    if ($script:AuditConfig.filters.excludeFirstPartyMicrosoftApps) {
        $sps = $sps | Where-Object { $_.appOwnerOrganizationId -ne $microsoftPublisherId }
    }
    if ($script:AuditConfig.filters.excludeAppIds.Count -gt 0) {
        $sps = $sps | Where-Object { $_.appId -notin $script:AuditConfig.filters.excludeAppIds }
    }

    # Get app role assignments for each SP (these are the application permissions granted)
    $dangerousNames = $script:DangerousPermissions | ForEach-Object { $_.name }
    $results = @()
    $total = ($sps | Measure-Object).Count
    $i = 0
    foreach ($sp in $sps) {
        $i++
        if ($i % 100 -eq 0) { Write-Host "    Processing SP $i of $total..." -ForegroundColor DarkGray }
        try {
            $assignments = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments?`$select=id,appRoleId,resourceDisplayName"
        } catch {
            continue
        }
        if ($assignments.Count -eq 0) { continue }

        # Resolve appRoleIds to permission names
        # We need the resource SP to look up the role name
        $resourceSPs = @{}
        foreach ($assignment in $assignments) {
            $resourceId = $assignment.resourceId
            if (-not $resourceSPs.ContainsKey($resourceId)) {
                try {
                    $resSP = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$resourceId`?`$select=id,appRoles"
                    $resourceSPs[$resourceId] = $resSP
                } catch {
                    continue
                }
            }
        }

        foreach ($assignment in $assignments) {
            $resourceId = $assignment.resourceId
            $resSP = $resourceSPs[$resourceId]
            if (-not $resSP) { continue }
            $role = $resSP.appRoles | Where-Object { $_.id -eq $assignment.appRoleId } | Select-Object -First 1
            if (-not $role) { continue }
            if ($role.value -in $dangerousNames) {
                $permDef = $script:DangerousPermissions | Where-Object { $_.name -eq $role.value } | Select-Object -First 1
                $results += [PSCustomObject]@{
                    SPId            = $sp.id
                    SPDisplayName   = $sp.displayName
                    AppId           = $sp.appId
                    Permission      = $role.value
                    PermissionType  = $permDef.type
                    Risk            = $permDef.risk
                    Reason          = $permDef.reason
                    AccountEnabled  = $sp.accountEnabled
                }
            }
        }
    }

    # Also check delegated permissions (oauth2PermissionGrants) for Directory.AccessAsUser.All
    $delegatedPerms = $script:DangerousPermissions | Where-Object { $_.type -eq 'Delegated' }
    if ($delegatedPerms.Count -gt 0) {
        Write-Host "  Checking delegated permission grants..." -ForegroundColor Gray
        $grants = Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999'
        foreach ($grant in $grants) {
            if ($grant.consentType -ne 'AllPrincipals') { continue }
            $grantedScopes = ($grant.scope -split ' ') | Where-Object { $_ }
            foreach ($dp in $delegatedPerms) {
                if ($dp.name -in $grantedScopes) {
                    $clientSP = $sps | Where-Object { $_.id -eq $grant.clientId } | Select-Object -First 1
                    if (-not $clientSP) { continue }
                    $results += [PSCustomObject]@{
                        SPId            = $clientSP.id
                        SPDisplayName   = $clientSP.displayName
                        AppId           = $clientSP.appId
                        Permission      = $dp.name
                        PermissionType  = 'Delegated'
                        Risk            = $dp.risk
                        Reason          = $dp.reason
                        AccountEnabled  = $clientSP.accountEnabled
                    }
                }
            }
        }
    }

    return $results
}

function Get-PrivilegedRoleAssignments {
    Write-Host "  Querying directory role assignments..." -ForegroundColor Gray
    $roleTemplateIds = $script:PrivilegedRoles | ForEach-Object { $_.templateId }

    $allAssignments = Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal&$top=999'

    $roleDefinitions = @{}
    foreach ($role in $script:PrivilegedRoles) {
        $roleDefinitions[$role.templateId] = $role.name
    }

    # Also get role definitions to map roleDefinitionId to templateId
    $roleDefs = Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName'
    $roleDefIdToTemplate = @{}
    foreach ($rd in $roleDefs) {
        $roleDefIdToTemplate[$rd.id] = $rd.templateId
    }

    $results = @()
    foreach ($assignment in $allAssignments) {
        $templateId = $roleDefIdToTemplate[$assignment.roleDefinitionId]
        if (-not $templateId -or $templateId -notin $roleTemplateIds) { continue }
        $roleName = $roleDefinitions[$templateId]
        $results += [PSCustomObject]@{
            PrincipalId          = $assignment.principalId
            PrincipalDisplayName = $assignment.principal.displayName
            PrincipalType        = $assignment.principal.'@odata.type'
            PrincipalUPN         = $assignment.principal.userPrincipalName
            RoleDefinitionId     = $assignment.roleDefinitionId
            RoleTemplateId       = $templateId
            RoleName             = $roleName
            RoleTier             = ($script:PrivilegedRoles | Where-Object { $_.templateId -eq $templateId }).tier
            DirectoryScopeId     = $assignment.directoryScopeId
        }
    }
    return $results
}

function Get-ApplicationOwners {
    param([string[]]$AppIds)
    Write-Host "  Querying app owners..." -ForegroundColor Gray
    $results = @{}
    foreach ($appId in $AppIds) {
        try {
            # Get the application object by appId, then its owners
            $apps = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$appId'&`$select=id,appId,displayName"
            $app = $apps | Select-Object -First 1
            if (-not $app) { continue }
            $owners = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/owners?`$select=id,displayName,userPrincipalName"
            $results[$appId] = @($owners)
        } catch {
            continue
        }
    }
    return $results
}

function Get-ServicePrincipalOwners {
    param([string[]]$SPIds)
    Write-Host "  Querying service principal owners..." -ForegroundColor Gray
    $results = @{}
    foreach ($spId in $SPIds) {
        try {
            $owners = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/owners?`$select=id,displayName,userPrincipalName"
            $results[$spId] = @($owners)
        } catch {
            continue
        }
    }
    return $results
}

function Get-AppCredentials {
    param([string[]]$AppIds)
    Write-Host "  Querying app credentials..." -ForegroundColor Gray
    $results = @{}
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
                } catch { }
                $results[$appId] = $creds
            }
        } catch {
            continue
        }
    }
    return $results
}

function Get-SPSignInActivity {
    Write-Host "  Querying service principal sign-in activity..." -ForegroundColor Gray
    try {
        $activities = Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/reports/servicePrincipalSignInActivities?$top=999'
        $lookup = @{}
        foreach ($a in $activities) {
            $lookup[$a.appId] = $a
        }
        return $lookup
    } catch {
        Write-Host "  ⚠ Could not query sign-in activity (may require Entra ID P1/P2). Stale detection will be limited." -ForegroundColor Yellow
        return @{}
    }
}

function Get-TenantConsentPolicy {
    Write-Host "  Querying tenant authorization policy..." -ForegroundColor Gray
    try {
        $policy = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
        return $policy
    } catch {
        Write-Host "  ⚠ Could not query authorization policy." -ForegroundColor Yellow
        return $null
    }
}

function Get-UserConsentGrants {
    Write-Host "  Querying user consent grants..." -ForegroundColor Gray
    $grants = Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999'
    # Filter to user (Principal) consent
    return $grants | Where-Object { $_.consentType -eq 'Principal' }
}

function Get-AllUsers {
    Write-Host "  Querying all users..." -ForegroundColor Gray
    return Get-AllGraphPages -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName&$top=999'
}

#endregion

#region ── Mode: PermissionAudit ──────────────────────────────────────────────

function Invoke-PermissionAudit {
    Write-Banner "PERMISSION AUDIT — Apps with Global Admin-Equivalent Permissions"

    $dangerousApps = Get-ServicePrincipalsWithAppRoles

    if ($dangerousApps.Count -eq 0) {
        Write-Host "✓ No apps found with Global Admin-equivalent permissions." -ForegroundColor Green
        return @()
    }

    Write-Host "Found $($dangerousApps.Count) app(s) with dangerous permissions:" -ForegroundColor Yellow
    Write-Host ""

    $formatted = $dangerousApps | Select-Object @{N='App Name';E={$_.SPDisplayName}},
        @{N='App ID';E={$_.AppId}}, @{N='Permission';E={$_.Permission}},
        @{N='Type';E={$_.PermissionType}}
    $formatted | Format-Table -AutoSize | Out-String | Write-Host

    Write-Host "⚠  These permissions allow an app to assign roles, modify any application," -ForegroundColor Yellow
    Write-Host "   or write to the directory — effectively equivalent to Global Administrator." -ForegroundColor Yellow
    Write-Reference 'https://learn.microsoft.com/graph/permissions-overview#best-practices-for-using-microsoft-graph-permissions'

    Export-AuditCsv -Name 'PermissionAudit' -Data $dangerousApps

    return $dangerousApps
}

#endregion

#region ── Mode: RoleAudit ────────────────────────────────────────────────────

function Invoke-RoleAudit {
    Write-Banner "ROLE AUDIT — Privileged Role Membership"

    $roleAssignments = Get-PrivilegedRoleAssignments
    $allUsers = Get-AllUsers

    # Group user role assignments
    $userRoles = @{}
    foreach ($ra in ($roleAssignments | Where-Object { $_.PrincipalType -eq '#microsoft.graph.user' })) {
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
    $nonPrivilegedUsers = $allUsers | Where-Object { $_.id -notin $privilegedUserIds }

    # Display privileged users
    Write-Host "USERS IN PRIVILEGED ROLES ($($userRoles.Count) users):" -ForegroundColor Green
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
    $truncateAfter = $script:AuditConfig.output.truncateAfter
    Write-Host "USERS NOT IN ANY PRIVILEGED ROLE ($totalNonPriv users):" -ForegroundColor Gray
    Write-Host ""
    $displayUsers = $nonPrivilegedUsers | Select-Object -First $truncateAfter |
        ForEach-Object { [PSCustomObject]@{ User = $_.displayName; UPN = $_.userPrincipalName } }
    $displayUsers | Format-Table -AutoSize | Out-String | Write-Host

    if ($totalNonPriv -gt $truncateAfter) {
        Write-Host "... ($($totalNonPriv - $truncateAfter) more)" -ForegroundColor DarkGray
    }

    Write-Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference'

    # Also report SPs in privileged roles
    $spRoles = $roleAssignments | Where-Object { $_.PrincipalType -eq '#microsoft.graph.servicePrincipal' }
    if ($spRoles.Count -gt 0) {
        Write-Host ""
        Write-Host "SERVICE PRINCIPALS IN PRIVILEGED ROLES ($($spRoles.Count)):" -ForegroundColor Yellow
        $spRoles | ForEach-Object {
            [PSCustomObject]@{ 'SP Name' = $_.PrincipalDisplayName; Role = $_.RoleName; Tier = $_.RoleTier }
        } | Format-Table -AutoSize | Out-String | Write-Host
    }

    # Export
    $exportData = @()
    foreach ($u in $userRoles.Values) {
        $exportData += [PSCustomObject]@{
            DisplayName = $u.DisplayName; UPN = $u.UPN; Roles = ($u.Roles -join '; '); HasPrivilegedRole = $true
        }
    }
    foreach ($u in $nonPrivilegedUsers) {
        $exportData += [PSCustomObject]@{
            DisplayName = $u.displayName; UPN = $u.userPrincipalName; Roles = ''; HasPrivilegedRole = $false
        }
    }
    Export-AuditCsv -Name 'RoleAudit' -Data $exportData

    return [PSCustomObject]@{ PrivilegedUsers = $userRoles; NonPrivilegedUsers = $nonPrivilegedUsers; SPRoles = $spRoles; RoleAssignments = $roleAssignments }
}

#endregion

#region ── Mode: AttackPath ───────────────────────────────────────────────────

function Invoke-AttackPathAnalysis {
    Write-Banner "ATTACK PATH ANALYSIS — User → App Owner → Privilege Escalation"

    $dangerousApps = Get-ServicePrincipalsWithAppRoles
    if ($dangerousApps.Count -eq 0) {
        Write-Host "✓ No dangerous apps found. No attack paths to analyze." -ForegroundColor Green
        return @()
    }

    $roleAssignments = Get-PrivilegedRoleAssignments
    $privilegedUserIds = @($roleAssignments | Where-Object { $_.PrincipalType -eq '#microsoft.graph.user' } | ForEach-Object { $_.PrincipalId }) | Select-Object -Unique

    # Get owners for dangerous apps
    $appIds = $dangerousApps | ForEach-Object { $_.AppId } | Select-Object -Unique
    $appOwners = Get-ApplicationOwners -AppIds $appIds

    $paths = @()
    $pathNum = 0

    foreach ($appId in $appOwners.Keys) {
        $owners = $appOwners[$appId]
        $apps = $dangerousApps | Where-Object { $_.AppId -eq $appId }
        foreach ($owner in $owners) {
            if ($owner.id -in $privilegedUserIds) { continue } # Already an admin — not an escalation
            foreach ($app in $apps) {
                $pathNum++
                $pathDef = $script:AttackPathDefs | Where-Object { $_.id -eq 'APP_OWNER_ESCALATION' } | Select-Object -First 1
                $paths += [PSCustomObject]@{
                    PathNumber      = $pathNum
                    PathType        = 'App Owner Escalation'
                    Severity        = 'CRITICAL'
                    UserDisplayName = $owner.displayName
                    UserUPN         = $owner.userPrincipalName
                    UserRole        = 'None (regular user)'
                    AppName         = $app.SPDisplayName
                    AppId           = $app.AppId
                    Permission      = $app.Permission
                    PermissionType  = $app.PermissionType
                    Action          = "Add secret → authenticate as app → exploit $($app.Permission)"
                    Result          = 'GLOBAL ADMIN EQUIVALENT ACCESS'
                    Remediation     = if ($pathDef) { $pathDef.remediation -join '; ' } else { 'Remove owner or reduce permissions' }
                }
            }
        }
    }

    if ($paths.Count -eq 0) {
        Write-Host "✓ No attack paths found. No non-admin users own apps with dangerous permissions." -ForegroundColor Green
        return @()
    }

    Write-Host "Found $($paths.Count) attack path(s):" -ForegroundColor Red
    Write-Host ""

    foreach ($path in $paths) {
        Write-SectionDivider "PATH $($path.PathNumber): $($path.PathType) ($($path.Severity))"
        Write-Host "  ┌─────────────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkYellow
        Write-Host "  │  $($path.UserUPN)" -ForegroundColor White
        Write-Host "  │  Role: $($path.UserRole)" -ForegroundColor Gray
        Write-Host "  │                          ↓ owns" -ForegroundColor DarkGray
        Write-Host "  │  App: `"$($path.AppName)`" ($($path.AppId))" -ForegroundColor White
        Write-Host "  │  Permission: $($path.Permission) ($($path.PermissionType))" -ForegroundColor Yellow
        Write-Host "  │                          ↓ can exploit" -ForegroundColor DarkGray
        Write-Host "  │  Action: $($path.Action)" -ForegroundColor Red
        Write-Host "  │  Result: $($path.Result)" -ForegroundColor Red
        Write-Host "  └─────────────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkYellow

        $pathDef = $script:AttackPathDefs | Where-Object { $_.id -eq 'APP_OWNER_ESCALATION' } | Select-Object -First 1
        if ($pathDef) {
            Write-Recommendation -Items $pathDef.remediation
        }
    }

    Write-Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-planning#protect-against-consent-grant-attacks'

    Export-AuditCsv -Name 'AttackPaths' -Data $paths

    return $paths
}

#endregion

#region ── Mode: ShadowAdmins ─────────────────────────────────────────────────

function Invoke-ShadowAdminDetection {
    Write-Banner "SHADOW ADMIN DETECTION — SP Owners with Indirect Privilege"

    $roleAssignments = Get-PrivilegedRoleAssignments
    $spRoleAssignments = $roleAssignments | Where-Object { $_.PrincipalType -eq '#microsoft.graph.servicePrincipal' }

    if ($spRoleAssignments.Count -eq 0) {
        Write-Host "✓ No service principals hold privileged directory roles." -ForegroundColor Green
        return @()
    }

    $privilegedUserIds = @($roleAssignments | Where-Object { $_.PrincipalType -eq '#microsoft.graph.user' } | ForEach-Object { $_.PrincipalId }) | Select-Object -Unique

    # Get owners for SPs with roles
    $spIds = $spRoleAssignments | ForEach-Object { $_.PrincipalId } | Select-Object -Unique
    $spOwners = Get-ServicePrincipalOwners -SPIds $spIds

    $shadows = @()
    foreach ($spId in $spOwners.Keys) {
        $owners = $spOwners[$spId]
        $roles = $spRoleAssignments | Where-Object { $_.PrincipalId -eq $spId }
        foreach ($owner in $owners) {
            if ($owner.id -in $privilegedUserIds) { continue } # Already an admin
            foreach ($role in $roles) {
                $shadows += [PSCustomObject]@{
                    UserDisplayName  = $owner.displayName
                    UserUPN          = $owner.userPrincipalName
                    SPDisplayName    = $role.PrincipalDisplayName
                    SPId             = $spId
                    SPRole           = $role.RoleName
                    Risk             = "User can reset SP credentials → activate as SP → use $($role.RoleName) role"
                    Remediation      = 'Remove user as SP owner or remove the SP role assignment'
                }
            }
        }
    }

    if ($shadows.Count -eq 0) {
        Write-Host "✓ No shadow admin paths found. No non-admin users own SPs with privileged roles." -ForegroundColor Green
        return @()
    }

    Write-Host "Found $($shadows.Count) shadow admin path(s):" -ForegroundColor Red
    Write-Host ""

    foreach ($s in $shadows) {
        Write-Host "  User:              $($s.UserUPN) (No privileged roles)" -ForegroundColor White
        Write-Host "  Owns SP:           `"$($s.SPDisplayName)`" (SP ID: $($s.SPId))" -ForegroundColor White
        Write-Host "  SP Has Role:       $($s.SPRole)" -ForegroundColor Yellow
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
    Write-Banner "STALE PRIVILEGE — Dormant High-Privilege Apps with Valid Credentials"

    $dangerousApps = Get-ServicePrincipalsWithAppRoles
    if ($dangerousApps.Count -eq 0) {
        Write-Host "✓ No dangerous apps found." -ForegroundColor Green
        return @()
    }

    $signInActivity = Get-SPSignInActivity
    $appIds = $dangerousApps | ForEach-Object { $_.AppId } | Select-Object -Unique
    $appCreds = Get-AppCredentials -AppIds $appIds

    $inactiveDays = $script:AuditConfig.stalePrivilege.inactiveDays
    $cutoffDate = (Get-Date).AddDays(-$inactiveDays)
    $staleApps = @()

    foreach ($appId in $appIds) {
        $apps = $dangerousApps | Where-Object { $_.AppId -eq $appId }
        $app = $apps | Select-Object -First 1
        $creds = $appCreds[$appId]

        # Check if any creds are still valid (not expired)
        $validCreds = @()
        if ($creds) { $validCreds = @($creds | Where-Object { -not $_.Expired }) }
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
            }
        }
    }

    if ($staleApps.Count -eq 0) {
        Write-Host "✓ No stale high-privilege apps found." -ForegroundColor Green
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
    Write-Banner "CONSENT RISK — Tenant Consent Policy Assessment"

    $policy = Get-TenantConsentPolicy
    if (-not $policy) {
        Write-Host "⚠ Could not retrieve consent policy. Skipping." -ForegroundColor Yellow
        return @()
    }

    $findings = @()

    # Analyze default user role permissions
    $defaultPerms = $policy.defaultUserRolePermissions

    # User consent setting
    $userConsentAllowed = $defaultPerms.permissionGrantPoliciesAssigned -contains 'microsoft-user-default-legacy'
    $userConsentRestricted = $defaultPerms.permissionGrantPoliciesAssigned -contains 'microsoft-user-default-low'
    $userConsentDisabled = -not $userConsentAllowed -and -not $userConsentRestricted

    if ($userConsentAllowed) {
        $findings += [PSCustomObject]@{
            Setting = 'User consent for apps'
            Value   = 'Allowed (all permissions)'
            Risk    = '⚠  CRITICAL'
        }
    } elseif ($userConsentRestricted) {
        $findings += [PSCustomObject]@{
            Setting = 'User consent for apps'
            Value   = 'Allowed (verified publishers, low-risk only)'
            Risk    = 'ⓘ  LOW'
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

    # Users can add gallery apps
    $canAddGallery = $defaultPerms.allowedToCreateSecurityGroups
    # Actually check if users can read other users
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

            # Resolve SP names
            $consentData = @()
            $truncateAfter = $script:AuditConfig.output.truncateAfter
            $displayed = 0
            foreach ($group in $grantsByApp) {
                if ($displayed -ge $truncateAfter) { break }
                try {
                    $sp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($group.Name)?`$select=displayName"
                    $scopes = ($group.Group | ForEach-Object { $_.scope }) -join ' '
                    $userCount = ($group.Group | ForEach-Object { $_.principalId } | Select-Object -Unique).Count
                    $consentData += [PSCustomObject]@{
                        'App Name'        = $sp.displayName
                        'Consented Scopes' = $scopes.Trim()
                        'Consented By'    = "$userCount user(s)"
                    }
                    $displayed++
                } catch { continue }
            }
            $consentData | Format-Table -AutoSize | Out-String | Write-Host

            if ($grantsByApp.Count -gt $truncateAfter) {
                Write-Host "... ($($grantsByApp.Count - $truncateAfter) more)" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "✓ No user-consented permission grants found." -ForegroundColor Green
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
    Write-Banner "CREDENTIAL HYGIENE — Credential Risk for High-Privilege Apps"

    $dangerousApps = Get-ServicePrincipalsWithAppRoles
    if ($dangerousApps.Count -eq 0) {
        Write-Host "✓ No dangerous apps found." -ForegroundColor Green
        return @()
    }

    $appIds = $dangerousApps | ForEach-Object { $_.AppId } | Select-Object -Unique
    $appCreds = Get-AppCredentials -AppIds $appIds

    $results = @()
    foreach ($appId in $appIds) {
        $apps = $dangerousApps | Where-Object { $_.AppId -eq $appId }
        $app = $apps | Select-Object -First 1
        $creds = $appCreds[$appId]

        if (-not $creds -or $creds.Count -eq 0) {
            $results += [PSCustomObject]@{
                AppName        = $app.SPDisplayName
                AppId          = $app.AppId
                Permission     = ($apps | ForEach-Object { $_.Permission }) -join ', '
                CredType       = 'None'
                CredCount      = 0
                ExpiredCount   = 0
                RiskLevel      = 'ⓘ  INFO (no credentials)'
            }
            continue
        }

        $credTypes = ($creds | ForEach-Object { $_.Type } | Select-Object -Unique) -join ', '
        $secretCount = ($creds | Where-Object { $_.Type -eq 'Secret' } | Measure-Object).Count
        $certCount = ($creds | Where-Object { $_.Type -eq 'Certificate' } | Measure-Object).Count
        $fedCount = ($creds | Where-Object { $_.Type -eq 'Federated' } | Measure-Object).Count
        $expiredCount = ($creds | Where-Object { $_.Expired } | Measure-Object).Count
        $totalActive = $creds.Count - $expiredCount

        # Determine risk
        $riskLevel = '✓  GOOD'
        if ($secretCount -gt 0 -and $creds.Count -gt 1) {
            $riskLevel = '⚠  CRITICAL (multiple creds including secrets)'
        } elseif ($secretCount -gt 0) {
            $riskLevel = '⚠  HIGH (secret, not cert)'
        } elseif ($certCount -gt 0) {
            $riskLevel = '✓  MODERATE (cert is better, but permission is dangerous)'
        }
        if ($fedCount -gt 0 -and $secretCount -eq 0 -and $certCount -eq 0) {
            $riskLevel = '✓  GOOD (federated/managed identity)'
        }

        $results += [PSCustomObject]@{
            AppName        = $app.SPDisplayName
            AppId          = $app.AppId
            Permission     = ($apps | ForEach-Object { $_.Permission }) -join ', '
            CredType       = $credTypes
            CredCount      = $creds.Count
            ExpiredCount   = $expiredCount
            RiskLevel      = $riskLevel
        }
    }

    $results | Select-Object @{N='App Name';E={$_.AppName}}, @{N='Permission';E={$_.Permission}},
        @{N='Cred Type';E={$_.CredType}}, @{N='Count';E={$_.CredCount}},
        @{N='Expired';E={$_.ExpiredCount}}, @{N='Risk';E={$_.RiskLevel}} |
        Format-Table -AutoSize | Out-String | Write-Host

    # Summary
    $secretApps = ($results | Where-Object { $_.CredType -match 'Secret' } | Measure-Object).Count
    $certApps = ($results | Where-Object { $_.CredType -match 'Certificate' -and $_.CredType -notmatch 'Secret' } | Measure-Object).Count
    $fedApps = ($results | Where-Object { $_.CredType -match 'Federated' -and $_.CredType -notmatch 'Secret' -and $_.CredType -notmatch 'Certificate' } | Measure-Object).Count
    $totalExpired = ($results | Measure-Object -Property ExpiredCount -Sum).Sum
    $multiCred = ($results | Where-Object { $_.CredCount -gt 1 } | Measure-Object).Count

    Write-Host "SUMMARY:" -ForegroundColor Cyan
    Write-Host "  Apps using secrets:              $secretApps  ← migrate to certificates or managed identities" -ForegroundColor $(if ($secretApps -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Apps using certificates:         $certApps  ← review permission scope" -ForegroundColor Gray
    Write-Host "  Apps using federated/managed:    $fedApps  ← best practice ✓" -ForegroundColor Green
    Write-Host "  Total expired credentials:       $totalExpired  ← remove to reduce attack surface" -ForegroundColor $(if ($totalExpired -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Apps with multiple credentials:  $multiCred  ← investigate, may indicate credential sprawl" -ForegroundColor $(if ($multiCred -gt 0) { 'Yellow' } else { 'Green' })

    Write-Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/certificate-management'

    Export-AuditCsv -Name 'CredentialHygiene' -Data $results

    return $results
}

#endregion

#region ── Mode: Full ─────────────────────────────────────────────────────────

function Invoke-FullAudit {
    $summary = @{}

    $permResults = Invoke-PermissionAudit
    $summary['PermissionAudit'] = "$($permResults.Count) apps with GA-equivalent permissions"

    $roleResults = Invoke-RoleAudit
    $summary['RoleAudit'] = "$($roleResults.PrivilegedUsers.Count) users in privileged roles, $(($roleResults.NonPrivilegedUsers | Measure-Object).Count) not"

    $attackResults = Invoke-AttackPathAnalysis
    $summary['AttackPaths'] = "$($attackResults.Count) critical escalation paths found"

    $shadowResults = Invoke-ShadowAdminDetection
    $summary['ShadowAdmins'] = "$($shadowResults.Count) shadow admin detected"

    $staleResults = Invoke-StalePrivilegeDetection
    $summary['StalePrivilege'] = "$($staleResults.Count) dormant high-privilege apps"

    $consentResults = Invoke-ConsentRiskAssessment
    $criticalConsent = ($consentResults | Where-Object { $_.Risk -match 'CRITICAL|HIGH' } | Measure-Object).Count
    $summary['ConsentRisk'] = "$criticalConsent HIGH/CRITICAL consent policy issues"

    $credResults = Invoke-CredentialHygieneAudit
    $secretApps = ($credResults | Where-Object { $_.CredType -match 'Secret' } | Measure-Object).Count
    $summary['CredentialHygiene'] = "$secretApps high-privilege apps using secrets"

    # Print summary
    Write-Banner "FULL AUDIT SUMMARY"

    Write-Host "  Permission Audit:      $($summary['PermissionAudit'])" -ForegroundColor $(if ($permResults.Count -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Role Audit:            $($summary['RoleAudit'])" -ForegroundColor Gray
    Write-Host "  Attack Paths:          $($summary['AttackPaths'])" -ForegroundColor $(if ($attackResults.Count -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  Shadow Admins:         $($summary['ShadowAdmins'])" -ForegroundColor $(if ($shadowResults.Count -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  Stale Privilege:       $($summary['StalePrivilege'])" -ForegroundColor $(if ($staleResults.Count -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Consent Risk:          $($summary['ConsentRisk'])" -ForegroundColor $(if ($criticalConsent -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Credential Hygiene:    $($summary['CredentialHygiene'])" -ForegroundColor $(if ($secretApps -gt 0) { 'Yellow' } else { 'Green' })

    # Overall risk indicator
    $riskScore = 0
    $riskScore += [Math]::Min($permResults.Count * 2, 4)
    $riskScore += [Math]::Min($attackResults.Count * 3, 6)
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

    # Top actions
    $actions = @()
    if ($attackResults.Count -gt 0) {
        $actions += "Remove non-admin owners from apps with dangerous permissions ($($attackResults.Count) paths)"
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

    if ($actions.Count -gt 0) {
        Write-Host ""
        Write-Host "  Top Actions:" -ForegroundColor White
        $actionNum = 0
        foreach ($action in ($actions | Select-Object -First 5)) {
            $actionNum++
            Write-Host "    $actionNum. $action" -ForegroundColor Gray
        }
    }

    if ($ExportPath) {
        Write-Host ""
        Write-Host "  Full results exported to: $ExportPath" -ForegroundColor DarkGreen
    }
}

#endregion

#region ── Main Execution ─────────────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
Write-Host "║  Privileged App Path Auditor                                               ║" -ForegroundColor DarkCyan
Write-Host "║  Identifies privilege escalation paths through Entra ID applications        ║" -ForegroundColor DarkCyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
Write-Host ""

# Load configuration
Load-Config

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

$elapsed = (Get-Date) - $startTime
Write-Host ""
Write-Host "Completed in $([math]::Round($elapsed.TotalSeconds, 1)) seconds." -ForegroundColor DarkGray

#endregion
