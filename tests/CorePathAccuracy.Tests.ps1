BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'Invoke-PrivilegedAudit.ps1')

    function New-CoreRole {
        param([string]$Id, [string[]]$Actions = @(), [string]$TemplateId, [bool]$Sensitive = $false)
        [PSCustomObject]@{
            id = $Id; displayName = $Id; templateId = $TemplateId
            isBuiltIn = [bool]$TemplateId; isEnabled = $true; isPrivileged = $Sensitive
            rolePermissions = @([PSCustomObject]@{ allowedResourceActions = $Actions })
        }
    }

    function New-CoreAssignment {
        param([string]$Role = 'control', [string]$Principal = 'operator', [string]$Scope = '/', [string]$Type = 'user', [string]$AppScope)
        [PSCustomObject]@{
            roleDefinitionId = $Role; principalId = $Principal; directoryScopeId = $Scope; appScopeId = $AppScope
            principal = [PSCustomObject]@{
                '@odata.type' = "#microsoft.graph.$Type"; displayName = $Principal
                userPrincipalName = "$Principal@contoso.test"; appId = if ($Type -eq 'servicePrincipal') { 'client-id' } else { $null }
            }
        }
    }
}

Describe 'Core path accuracy through real collectors' {
    BeforeEach {
        $script:CachedDangerousApps = $null
        $script:CachedRoleAssignments = $null
        $script:CachedRoleDefinitions = $null
        $script:CachedServicePrincipals = $null
        $script:CachedResourceServicePrincipals = @{}
        $script:DangerousPermissions = $script:DefaultDangerousPermissions
        $script:PrivilegedRoles = $script:DefaultPrivilegedRoles
        $script:AuditConfig = $script:DefaultAuditConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        $script:AuditConfig.filters.excludeDisabledApps = $false
        $script:ConnectedTenantId = 'tenant-home'
        $script:MicrosoftAppIds = [System.Collections.Generic.HashSet[string]]::new()
        Reset-AuditCoverage
        $script:coreSP = [PSCustomObject]@{ id = 'sp-id'; appId = 'client-id'; displayName = 'Target'; appOwnerOrganizationId = 'tenant-home'; servicePrincipalType = 'Application'; accountEnabled = $true }
        $script:coreApp = [PSCustomObject]@{ id = 'application-id'; appId = 'client-id'; signInAudience = 'AzureADMyOrg'; servicePrincipalLockConfiguration = $null }
        $script:coreDefinitions = @(
            (New-CoreRole 'control' @('microsoft.directory/applications/credentials/update'))
            (New-CoreRole 'target' -TemplateId 'e8611ab8-c189-46e8-94e1-60213ab1f814' -Sensitive $true)
        )
        $script:coreAssignments = @((New-CoreAssignment), (New-CoreAssignment -Role target -Principal sp-id -Type servicePrincipal))
        $script:coreOwner = $false
        $script:coreAppFailure = $false
        $script:coreLockFailure = $false
        $script:coreActivePartial = $false
        Mock Write-Host {}
        Mock Write-Banner {}
        Mock Write-SectionDivider {}
        Mock Write-Recommendation {}
        Mock Write-Reference {}
        Mock Export-AuditCsv {}
        Mock Get-SPDirectCredentials { @{} }
        Mock Get-AllGraphPages {
            param($Uri)
            if ($Uri -match '/roleDefinitions$') { return $script:coreDefinitions }
            if ($Uri -match '/roleAssignments\?') {
                if ($script:coreActivePartial) { Set-CoverageState -Source ActiveRoleAssignments -State Partial -Detail 'synthetic incomplete assignment collection' }
                return $script:coreAssignments
            }
            if ($Uri -match '/servicePrincipals\?') { return @($script:coreSP) }
            if ($Uri -match '/sp-id/appRoleAssignments') {
                if ($script:coreOwner) { return @([PSCustomObject]@{ appRoleId = 'permission-id'; resourceId = 'graph-sp'; resourceDisplayName = 'Microsoft Graph' }) }
                return @()
            }
            if ($Uri -match '/oauth2PermissionGrants') { return @() }
            if ($Uri -match '/applications\?') {
                if ($script:coreAppFailure -or ($script:coreLockFailure -and $Uri -match 'servicePrincipalLockConfiguration')) { throw 'synthetic application lookup failure' }
                return @($script:coreApp | Where-Object { $null -ne $_ })
            }
            if ($Uri -match '/(applications/application-id|servicePrincipals/sp-id)/owners\?') {
                if ($script:coreOwner) { return @([PSCustomObject]@{ id = 'operator'; displayName = 'Operator'; userPrincipalName = 'operator@contoso.test' }) }
                return @()
            }
            throw "Unexpected synthetic URI: $Uri"
        }
        Mock Invoke-MgGraphRequest {
            param($Uri)
            if ($Uri -match '/servicePrincipals/graph-sp') {
                return [PSCustomObject]@{ id = 'graph-sp'; appId = $script:MicrosoftGraphAppId; appRoles = @([PSCustomObject]@{ id = 'permission-id'; value = 'RoleManagement.ReadWrite.Directory' }) }
            }
            throw "Unexpected synthetic request: $Uri"
        }
    }

    It 'does not grant application credential authority for <Action>' -ForEach @(
        @{ Action = 'microsoft.directory/applications/authentication/update' }
        @{ Action = 'microsoft.directory/applications.myOrganization/authentication/update' }
        @{ Action = 'microsoft.directory/applications.unknownSubtype/credentials/update' }
        @{ Action = 'microsoft.directory/applications/owners/update' }
    ) {
        $script:coreDefinitions[0] = New-CoreRole control @($Action)
        Test-RoleCanControlApplications $script:coreDefinitions[0] | Should -BeFalse
        @(Invoke-AttackPathAnalysis).Count | Should -Be 0
    }

    It 'retains credential-capable action <Action>' -ForEach @(
        @{ Action = 'microsoft.directory/applications/credentials/update' }
        @{ Action = 'microsoft.directory/applications/allProperties/update' }
        @{ Action = 'microsoft.directory/servicePrincipals/authentication/update' }
        @{ Action = 'microsoft.directory/servicePrincipals/credentials/update' }
    ) {
        $script:coreDefinitions[0] = New-CoreRole control @($Action)
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 1
        $paths[0].Exploitability | Should -Be Direct
    }

    It 'restricts myOrganization credentials for audience <Audience>' -ForEach @(
        @{ Audience = 'AzureADMyOrg'; Expected = 'Direct'; Count = 1 }
        @{ Audience = 'AzureADMultipleOrgs'; Expected = $null; Count = 0 }
        @{ Audience = 'AzureADandPersonalMicrosoftAccount'; Expected = $null; Count = 0 }
        @{ Audience = $null; Expected = 'PotentialPrerequisiteUnknown'; Count = 1 }
    ) {
        $script:coreDefinitions[0] = New-CoreRole control @('microsoft.directory/applications.myOrganization/credentials/update')
        $script:coreApp.signInAudience = $Audience
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be $Count
        if ($Count) { $paths[0].Exploitability | Should -Be $Expected }
    }

    It 'evaluates <Object> authority against its own object ID at <Scope>' -ForEach @(
        @{ Object = 'applications'; Scope = '/application-id'; Count = 1 }
        @{ Object = 'applications'; Scope = '/applications/application-id'; Count = 1 }
        @{ Object = 'applications'; Scope = '/sp-id'; Count = 0 }
        @{ Object = 'applications'; Scope = '/servicePrincipals/sp-id'; Count = 0 }
        @{ Object = 'applications'; Scope = '/administrativeUnits/au'; Count = 0 }
        @{ Object = 'servicePrincipals'; Scope = '/sp-id'; Count = 1 }
        @{ Object = 'servicePrincipals'; Scope = '/servicePrincipals/sp-id'; Count = 1 }
        @{ Object = 'servicePrincipals'; Scope = '/application-id'; Count = 0 }
        @{ Object = 'servicePrincipals'; Scope = '/applications/application-id'; Count = 0 }
    ) {
        $script:coreDefinitions[0] = New-CoreRole control @("microsoft.directory/$Object/credentials/update")
        $script:coreAssignments[0].directoryScopeId = $Scope
        @(Invoke-AttackPathAnalysis).Count | Should -Be $Count
    }

    It 'does not prove tenant authority from absent scope' {
        $script:coreAssignments[0].directoryScopeId = $null
        Test-RoleAssignmentAppliesToServicePrincipal ([PSCustomObject]@{ DirectoryScopeId = $null; AppScopeId = $null }) sp-id | Should -BeFalse
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 1
        $paths[0].Exploitability | Should -Be PotentialPrerequisiteUnknown
        $paths[0].EvidenceDetail | Should -Match 'scope'
    }

    It 'does not prove service principal authority from absent scope' {
        $script:coreDefinitions[0] = New-CoreRole control @('microsoft.directory/servicePrincipals/credentials/update')
        $script:coreAssignments[0].directoryScopeId = $null
        $path = @(Invoke-AttackPathAnalysis)[0]
        $path.Exploitability | Should -Be PotentialPrerequisiteUnknown
        $path.EvidenceDetail | Should -Match 'scope'
    }

    It 'does not treat app scope as tenant-wide credential authority' {
        $script:coreAssignments[0].appScopeId = '/external-scope'
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 1
        $paths[0].Exploitability | Should -Be PotentialPrerequisiteUnknown
        $paths[0].EvidenceDetail | Should -Match 'scope'
    }

    It 'requires confirmed tenant-wide permission equivalence at <Scope> with app scope <AppScope>' -ForEach @(
        @{ Scope = '/'; AppScope = $null; Equivalent = $true; Expected = $null }
        @{ Scope = '/administrativeUnits/au'; AppScope = $null; Equivalent = $false; Expected = 'Direct' }
        @{ Scope = $null; AppScope = $null; Equivalent = $false; Expected = 'PotentialRoleUnknown' }
        @{ Scope = '/'; AppScope = '/external-scope'; Equivalent = $false; Expected = 'PotentialRoleUnknown' }
        @{ Scope = '/unknown/scope'; AppScope = $null; Equivalent = $false; Expected = 'PotentialRoleUnknown' }
    ) {
        $script:coreOwner = $true
        $script:coreAssignments = @((New-CoreAssignment -Role target -Scope $Scope -AppScope $AppScope))
        $roles = @(Get-PrivilegedRoleAssignments)
        Test-UserAlreadyEquivalentToPermission operator RoleManagement.ReadWrite.Directory $roles -ResourceAppId $script:MicrosoftGraphAppId | Should -Be $Equivalent
        $paths = @((Invoke-AttackPathAnalysis) | Where-Object PathId -eq APP_OWNER_ESCALATION)
        $paths.Count | Should -Be ([int](-not $Equivalent))
        if ($paths.Count) {
            $paths[0].Exploitability | Should -Be $Expected
            if ($Expected -eq 'PotentialRoleUnknown') { $paths[0].EvidenceDetail | Should -Match 'scope' }
        }
    }

    It 'requires confirmed tenant-wide Global Administrator at <Scope>' -ForEach @(
        @{ Scope = '/'; Equivalent = $true }
        @{ Scope = '/administrativeUnits/au'; Equivalent = $false }
        @{ Scope = $null; Equivalent = $false }
    ) {
        $script:coreDefinitions += New-CoreRole ga -TemplateId '62e90394-69f5-4237-9190-012177145e10' -Sensitive $true
        $script:coreAssignments += New-CoreAssignment -Role ga -Scope $Scope
        Test-UserIsGlobalAdministrator operator @(Get-PrivilegedRoleAssignments) | Should -Be $Equivalent
        @(Invoke-AttackPathAnalysis).Count | Should -Be ([int](-not $Equivalent))
    }

    It 'compares existing scope <Existing> to target scope <Target> in role paths and ShadowAdmins' -ForEach @(
        @{ Existing = '/administrativeUnits/au'; Target = '/'; Count = 1; Expected = 'Direct' }
        @{ Existing = '/'; Target = '/administrativeUnits/au'; Count = 0; Expected = $null }
        @{ Existing = '/administrativeUnits/au'; Target = '/administrativeUnits/au'; Count = 0; Expected = $null }
        @{ Existing = '/administrativeUnits/other'; Target = '/administrativeUnits/au'; Count = 1; Expected = 'Direct' }
        @{ Existing = $null; Target = '/'; Count = 1; Expected = 'PotentialRoleUnknown' }
        @{ Existing = '/'; Target = $null; Count = 1; Expected = 'PotentialRoleUnknown' }
        @{ Existing = '/unknown/scope'; Target = '/unknown/scope'; Count = 1; Expected = 'PotentialRoleUnknown' }
    ) {
        $script:coreAssignments[1].directoryScopeId = $Target
        $script:coreAssignments += New-CoreAssignment -Role target -Scope $Existing
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be $Count
        if ($Count) {
            $paths[0].Exploitability | Should -Be $Expected
            if ($Expected -eq 'PotentialRoleUnknown') { $paths[0].EvidenceDetail | Should -Match 'scope' }
        }
        $script:coreOwner = $true
        @(Invoke-ShadowAdminDetection).Count | Should -Be $Count
    }

    It 'does not infer a local application object from home tenant when <Lookup>' -ForEach @(
        @{ Lookup = 'empty'; IdentityStatus = 'ApplicationObjectNotFound' }
        @{ Lookup = 'failed'; IdentityStatus = 'Unavailable' }
    ) {
        $script:coreApp = $null
        $script:coreAppFailure = $Lookup -eq 'failed'
        $evidence = Get-AppInstanceLockStatus -AppIds client-id
        $evidence['client-id'].ApplicationIdentityStatus | Should -Be $IdentityStatus
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 1
        $paths[0].Exploitability | Should -Be PotentialPrerequisiteUnknown
        $paths[0].EvidenceDetail | Should -Match 'application object'
    }

    It 'returns the resolved registration identity and audience from the lock collector' {
        $evidence = (Get-AppInstanceLockStatus -AppIds client-id)['client-id']
        $evidence.ApplicationObjectId | Should -Be application-id
        $evidence.SignInAudience | Should -Be AzureADMyOrg
        $evidence.ApplicationIdentityStatus | Should -Be Complete
        Should -Invoke Get-AllGraphPages -ParameterFilter { $Uri -match '\$select=id,appId,signInAudience,servicePrincipalLockConfiguration' } -Times 1
    }

    It 'does not prove registration identity from a response without an object ID' {
        $script:coreApp.PSObject.Properties.Remove('id')
        $evidence = (Get-AppInstanceLockStatus -AppIds client-id)['client-id']
        $evidence.ApplicationIdentityStatus | Should -Be ApplicationObjectIdMissing
        $path = @(Invoke-AttackPathAnalysis)[0]
        $path.Exploitability | Should -Be PotentialPrerequisiteUnknown
        $path.EvidenceDetail | Should -Match 'application object ID'
    }

    It 'allows proven app authority to bypass unknown SP locks without losing identity' {
        $script:coreDefinitions[0] = New-CoreRole control @('microsoft.directory/applications.myOrganization/credentials/update', 'microsoft.directory/servicePrincipals/credentials/update')
        $script:coreApp.PSObject.Properties.Remove('servicePrincipalLockConfiguration')
        $evidence = (Get-AppInstanceLockStatus -AppIds client-id)['client-id']
        $evidence.ApplicationObjectId | Should -Be application-id
        $evidence.State | Should -Be Unavailable
        $path = @(Invoke-AttackPathAnalysis)[0]
        $path.Exploitability | Should -Be Direct
        $path.Action | Should -Match 'application credential'
        $path.EvidenceDetail | Should -Match 'lock'
    }

    It 'keeps an SP-only route potential when local lock configuration is omitted' {
        $script:coreDefinitions[0] = New-CoreRole control @('microsoft.directory/servicePrincipals/credentials/update')
        $script:coreApp.PSObject.Properties.Remove('servicePrincipalLockConfiguration')
        $path = @(Invoke-AttackPathAnalysis)[0]
        $path.Exploitability | Should -Be PotentialLockUnknown
        $path.Result | Should -Be 'POTENTIAL PRIVILEGE ESCALATION; LOCK EVIDENCE UNAVAILABLE'
        $path.EvidenceDetail | Should -Match 'lock'
    }

    It 'does not infer accountEnabled from an expanded role principal when SP inventory is missing' {
        $script:coreSP = $null
        $path = @(Invoke-AttackPathAnalysis)[0]
        $path.Exploitability | Should -Be PotentialPrerequisiteUnknown
        $path.EvidenceDetail | Should -Match 'accountEnabled'
    }

    It 'retains general application authority over a local multitenant registration' {
        $script:coreApp.signInAudience = 'AzureADMultipleOrgs'
        @(Invoke-AttackPathAnalysis)[0].Exploitability | Should -Be Direct
    }

    It 'does not infer an application route to an external publisher' {
        $script:coreSP.appOwnerOrganizationId = 'tenant-other'
        $script:coreApp = $null
        @(Invoke-AttackPathAnalysis).Count | Should -Be 0
    }

    It 'keeps partial <Source> evidence potential without discarding observed control' -ForEach @(
        @{ Source = 'ActiveRoleAssignments' }
        @{ Source = 'RoleDefinitions' }
    ) {
        if ($Source -eq 'ActiveRoleAssignments') { $script:coreActivePartial = $true }
        else { $script:coreAssignments += New-CoreAssignment -Role unresolved-role -Principal other-user }
        $path = @(Invoke-AttackPathAnalysis)[0]
        $script:Coverage[$Source].State | Should -Be Partial
        $path.Exploitability | Should -Be PotentialRoleUnknown
        $path.EvidenceDetail | Should -Match 'role'
    }

    It 'requires app scope compatibility for role and ShadowAdmins equivalence' {
        $script:coreAssignments += New-CoreAssignment -Role target -AppScope '/external-scope'
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 1
        $paths[0].Exploitability | Should -Be PotentialRoleUnknown
        $paths[0].EvidenceDetail | Should -Match 'scope'
        $script:coreOwner = $true
        @(Invoke-ShadowAdminDetection).Count | Should -Be 1
    }

    It 'keeps scope uncertainty specific to the candidate <Route>' -ForEach @(
        @{ Route = 'role' }; @{ Route = 'owner' }
    ) {
        $script:coreAssignments += New-CoreAssignment -Role target -Principal other-user -Scope $null
        if ($Route -eq 'owner') {
            $script:coreOwner = $true
            $script:coreAssignments = @($script:coreAssignments | Where-Object principalId -ne operator)
        }
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 1
        $paths[0].Exploitability | Should -Be Direct
    }

    It 'does not prove a delta into an unknown target scope without an existing matching role' {
        $script:coreAssignments[1].directoryScopeId = $null
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 1
        $paths[0].Exploitability | Should -Be PotentialRoleUnknown
        $paths[0].EvidenceDetail | Should -Match 'scope'
    }

    It 'applies tenant-wide Global Administrator equivalence to ShadowAdmins' {
        $script:coreOwner = $true
        $script:coreDefinitions += New-CoreRole ga -TemplateId '62e90394-69f5-4237-9190-012177145e10' -Sensitive $true
        $script:coreAssignments += New-CoreAssignment -Role ga -Scope '/administrativeUnits/au'
        @(Invoke-ShadowAdminDetection).Count | Should -Be 1
        $script:CachedRoleAssignments = $null
        $script:coreAssignments[-1].directoryScopeId = '/'
        @(Invoke-ShadowAdminDetection).Count | Should -Be 0
    }

    It 'keeps incomplete group evidence potential for role control with lock <Lock>' -ForEach @(
        @{ Lock = 'known'; State = 'PotentialRoleUnknown' }
        @{ Lock = 'unknown'; State = 'PotentialRoleUnknown' }
    ) {
        $script:coreDefinitions[0] = New-CoreRole control @('microsoft.directory/servicePrincipals/credentials/update')
        $script:coreAssignments += New-CoreAssignment -Role target -Principal group-id -Type group
        $script:coreLockFailure = $Lock -eq 'unknown'
        $path = @(Invoke-AttackPathAnalysis)[0]
        $path.Exploitability | Should -Be $State
        $path.EvidenceDetail | Should -Match 'role'
        if ($Lock -eq 'unknown') { $path.EvidenceDetail | Should -Match 'lock' }
    }

    It 'keeps <Mode> paths potential when accountEnabled is <Enabled>' -ForEach @(
        @{ Mode = 'role'; Enabled = $false }
        @{ Mode = 'role'; Enabled = $null }
        @{ Mode = 'owner'; Enabled = $false }
        @{ Mode = 'owner'; Enabled = $null }
    ) {
        if ($null -eq $Enabled) { $script:coreSP.PSObject.Properties.Remove('accountEnabled') } else { $script:coreSP.accountEnabled = $Enabled }
        if ($Mode -eq 'owner') { $script:coreOwner = $true; $script:coreAssignments = @() }
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 1
        $paths[0].Exploitability | Should -Be PotentialPrerequisiteUnknown
        $paths[0].EvidenceDetail | Should -Match 'accountEnabled'
        $paths[0].Action | Should -Not -Match 're.?enable'
    }

    It 'preserves route alternatives for <Audience> app authority and <Lock> SP lock' -ForEach @(
        @{ Audience = 'AzureADMyOrg'; Lock = 'locked'; State = 'Direct' }
        @{ Audience = 'AzureADMyOrg'; Lock = 'unknown'; State = 'PotentialPrerequisiteUnknown' }
        @{ Audience = $null; Lock = 'locked'; State = 'PotentialPrerequisiteUnknown' }
        @{ Audience = 'AzureADMultipleOrgs'; Lock = 'locked'; State = 'MitigatedByAppInstanceLock' }
        @{ Audience = 'AzureADMultipleOrgs'; Lock = 'unlocked'; State = 'Direct' }
    ) {
        $script:coreDefinitions[0] = New-CoreRole control @('microsoft.directory/applications.myOrganization/credentials/update', 'microsoft.directory/servicePrincipals/credentials/update')
        $script:coreApp.signInAudience = $Audience
        $script:coreApp.servicePrincipalLockConfiguration = [PSCustomObject]@{ isEnabled = $Lock -eq 'locked'; allProperties = $Lock -eq 'locked' }
        $script:coreLockFailure = $Lock -eq 'unknown'
        $path = @(Invoke-AttackPathAnalysis)[0]
        $path.Exploitability | Should -Be $State
    }

    It 'does not call missing scoped application identity a proven match at <Scope>' -ForEach @(
        @{ Scope = '/application-id'; Count = 1 }
        @{ Scope = '/applications/application-id'; Count = 1 }
        @{ Scope = '/servicePrincipals/sp-id'; Count = 0 }
        @{ Scope = '/sp-id'; Count = 0 }
        @{ Scope = '/administrativeUnits/au'; Count = 0 }
    ) {
        $script:coreApp = $null
        $script:coreAssignments[0].directoryScopeId = $Scope
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be $Count
        if ($Count) { $paths[0].Exploitability | Should -Be PotentialPrerequisiteUnknown; $paths[0].EvidenceDetail | Should -Match 'scope' }
    }

    It 'exports additive evidence on both row types regardless of first row type' {
        $script:coreOwner = $true
        $script:coreAssignments += New-CoreAssignment -Role target -Principal group-id -Type group
        $script:coreLockFailure = $true
        $script:coreDefinitions[0] = New-CoreRole control @('microsoft.directory/servicePrincipals/credentials/update')
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 2
        foreach ($path in $paths) {
            $path.PSObject.Properties.Name | Should -Contain EvidenceDetail
            $path.EvidenceDetail | Should -Match 'role'
        }
        $csv = @($paths | ConvertTo-Csv | ConvertFrom-Csv)
        ($csv | Where-Object PathId -eq ROLE_BASED_SP_CONTROL).EvidenceDetail | Should -Match 'lock'
        $reverseCsv = @($paths[1], $paths[0]) | ConvertTo-Csv | ConvertFrom-Csv
        ($reverseCsv | Where-Object PathId -eq APP_OWNER_ESCALATION).EvidenceDetail | Should -Match 'role'
    }

    It 'does not infer full mitigation from blocked observed routes when role evidence is incomplete' {
        $script:coreDefinitions[0] = New-CoreRole control @('microsoft.directory/applications.myOrganization/credentials/update', 'microsoft.directory/servicePrincipals/credentials/update')
        $script:coreApp.signInAudience = 'AzureADMultipleOrgs'
        $script:coreApp.servicePrincipalLockConfiguration = [PSCustomObject]@{ isEnabled = $true; allProperties = $true }
        $script:coreAssignments += New-CoreAssignment -Role target -Principal group-id -Type group
        $path = @(Invoke-AttackPathAnalysis)[0]
        $path.Exploitability | Should -Be PotentialRoleUnknown
        $path.Severity | Should -Not -Be INFO
        $path.EvidenceDetail | Should -Match 'role'
    }

    It 'keeps the prerequisite potential count and review action in Full mode' {
        $script:coreSP.accountEnabled = $false
        $script:coreSummary = @()
        Mock Invoke-PermissionAudit { @() }
        Mock Invoke-RoleAudit { [PSCustomObject]@{ PrivilegedUsers = @(); NonPrivilegedUsers = @(); SPRoles = @(); CoverageComplete = $true } }
        Mock Invoke-ShadowAdminDetection { @() }
        Mock Invoke-StalePrivilegeDetection { $script:StalePrivilegeDataAvailable = $true; @() }
        Mock Invoke-ConsentRiskAssessment { @() }
        Mock Invoke-CredentialHygieneAudit { @() }
        Mock Write-AuditCoverageSummary {}
        Mock Export-AuditCsv {
            param($Name, $Data)
            if ($Name -eq 'FullAuditSummary') { $script:coreSummary = @($Data) }
        }
        Invoke-FullAudit
        ($script:coreSummary | Where-Object Section -eq AttackPaths).Count | Should -Be '0 direct, 1 potential'
        ($script:coreSummary | Where-Object Section -like 'Action*').Finding | Should -Match 'accountEnabled prerequisites for 1 potential path'
    }
}