BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'Invoke-PrivilegedAudit.ps1')

    function Invoke-MgGraphRequest {
        param($Method, $Uri)
        throw "Unmocked Graph request: $Method $Uri"
    }

    function Reset-PaginationTestState {
        $script:CachedDangerousApps = $null
        $script:CachedRoleAssignments = $null
        $script:CachedRoleDefinitions = $null
        $script:CachedServicePrincipals = $null
        $script:CachedResourceServicePrincipals = @{}
        $script:DangerousPermissions = @($script:DefaultDangerousPermissions | ForEach-Object { @{} + $_ })
        $script:PrivilegedRoles = @($script:DefaultPrivilegedRoles | ForEach-Object { @{} + $_ })
        $script:AuditConfig = $script:DefaultAuditConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        $script:ConnectedTenantId = 'tenant-home'
        $script:MicrosoftAppIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        Reset-AuditCoverage

        $script:PaginationUris = @{
            ServicePrincipals = 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled&$top=999'
            ApplicationPermissionGrants = 'https://graph.microsoft.com/v1.0/servicePrincipals/client-sp/appRoleAssignments?$select=id,appRoleId,resourceId,resourceDisplayName'
            DelegatedPermissionGrants = 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999'
            RoleDefinitions = 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions'
            V1RoleDefinitions = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions'
            ActiveRoleAssignments = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal'
        }
        $script:PaginationUris.UserConsentGrants = $script:PaginationUris.DelegatedPermissionGrants
        $script:PaginationResponses = @{}
        $script:PaginationResponses[$script:PaginationUris.ServicePrincipals] = @{ value = @(
            @{ id = 'client-sp'; appId = 'client-app'; displayName = 'Synthetic client'; appOwnerOrganizationId = 'tenant-home'; servicePrincipalType = 'Application'; accountEnabled = $true }
        ) }
        $script:PaginationResponses[$script:PaginationUris.ApplicationPermissionGrants] = @{ value = @(
            @{ id = 'app-grant'; appRoleId = 'permission-role'; resourceId = 'graph-sp'; resourceDisplayName = 'Microsoft Graph' }
        ) }
        $script:PaginationResponses[$script:PaginationUris.DelegatedPermissionGrants] = @{ value = @(
            @{ id = 'delegated-grant'; clientId = 'client-sp'; resourceId = 'graph-sp'; consentType = 'Principal'; principalId = 'user-one'; scope = 'Directory.AccessAsUser.All' }
        ) }
        $script:PaginationResponses[$script:PaginationUris.RoleDefinitions] = @{ value = @(
            @{ id = 'sensitive-role'; templateId = '62e90394-69f5-4237-9190-012177145e10'; displayName = 'Synthetic privileged role'; isPrivileged = $true; rolePermissions = @() }
        ) }
        $script:PaginationResponses[$script:PaginationUris.V1RoleDefinitions] = $script:PaginationResponses[$script:PaginationUris.RoleDefinitions]
        $script:PaginationResponses[$script:PaginationUris.ActiveRoleAssignments] = @{ value = @(
            @{ id = 'active-assignment'; principalId = 'client-sp'; roleDefinitionId = 'sensitive-role'; directoryScopeId = '/'; appScopeId = $null; principal = @{ '@odata.type' = '#microsoft.graph.servicePrincipal'; displayName = 'Synthetic client'; appId = 'client-app' } }
        ) }
        $script:PaginationResource = @{
            id = 'graph-sp'; appId = $script:MicrosoftGraphAppId; displayName = 'Microsoft Graph'
            appRoles = @(@{ id = 'permission-role'; value = 'Application.ReadWrite.All' })
        }
    }

    function Add-PaginationFailure {
        param([string]$Source, [switch]$EmptyFirstPage)
        $uri = $script:PaginationUris[$Source]
        $nextUri = "https://graph.microsoft.com/v1.0/pagination-fixture/$Source"
        if ($EmptyFirstPage) { $script:PaginationResponses[$uri].value = @() }
        $script:PaginationResponses[$uri]['@odata.nextLink'] = $nextUri
        $script:PaginationResponses[$nextUri] = 'Synthetic later-page failure'
    }
}

Describe 'Pagination array contract and explicit retention opt-in' {
    BeforeEach {
        Reset-PaginationTestState
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Method -ne 'GET') { throw 'Only GET is allowed' }
            if (-not $script:PaginationResponses.ContainsKey($Uri)) { throw "Unexpected synthetic URI: $Uri" }
            $response = $script:PaginationResponses[$Uri]
            if ($response -is [string]) { throw $response }
            return $response
        }
    }

    It 'returns every page in order without changing the default item API' {
        $script:PaginationResponses['first'] = @{ value = @(@{ id = 'one' }); '@odata.nextLink' = 'second' }
        $script:PaginationResponses['second'] = @{ value = @(); '@odata.nextLink' = 'third' }
        $script:PaginationResponses['third'] = @{ value = @(@{ id = 'two' }, @{ id = 'three' }) }
        $items = @(Get-AllGraphPages -Uri 'first')
        $items.Count | Should -Be 3
        $items.id | Should -Be @('one', 'two', 'three')
        $script:Coverage.Count | Should -Be 0
        Should -Invoke Invoke-MgGraphRequest -Times 3 -Exactly
    }

    It 'preserves empty and singleton collection behavior' {
        $script:PaginationResponses['empty'] = @{ value = @() }
        @(Get-AllGraphPages -Uri 'empty').Count | Should -Be 0
        $items = @(Get-AllGraphPages -Uri $script:PaginationUris.ApplicationPermissionGrants)
        $items.Count | Should -Be 1
        $items[0].id | Should -Be 'app-grant'
    }

    It 'still throws on a later failure without a coverage opt-in' {
        Add-PaginationFailure -Source ApplicationPermissionGrants
        { Get-AllGraphPages -Uri $script:PaginationUris.ApplicationPermissionGrants } | Should -Throw '*Synthetic later-page failure*'
        $script:Coverage.Count | Should -Be 0
    }

    It 'retains items with Partial coverage only when explicitly opted in' {
        Add-PaginationFailure -Source ApplicationPermissionGrants
        $items = @(Get-AllGraphPages -Uri $script:PaginationUris.ApplicationPermissionGrants -CoverageSource 'ApplicationPermissionGrants')
        $items.Count | Should -Be 1
        $items[0].id | Should -Be 'app-grant'
        $script:Coverage.ApplicationPermissionGrants.State | Should -Be 'Partial'
        $script:Coverage.ApplicationPermissionGrants.Details -join '; ' | Should -Match 'Synthetic later-page failure'
        Set-CoverageState -Source ApplicationPermissionGrants -State Complete
        Test-AuditCoverageComplete -Sources ApplicationPermissionGrants | Should -BeFalse
    }

    It 'does not suppress an opted-in first-page failure' {
        $script:PaginationResponses['first'] = 'Synthetic first-page failure'
        { Get-AllGraphPages -Uri 'first' -CoverageSource 'ServicePrincipals' } | Should -Throw '*Synthetic first-page failure*'
    }

    It 'does not suppress failure after an empty first page with no retained evidence' {
        Add-PaginationFailure -Source ServicePrincipals -EmptyFirstPage
        { Get-AllGraphPages -Uri $script:PaginationUris.ServicePrincipals -CoverageSource 'ServicePrincipals' } | Should -Throw '*Synthetic later-page failure*'
        Test-AuditCoverageComplete -Sources ServicePrincipals | Should -BeFalse
    }
}

Describe 'Collector pagination accuracy with mocked Graph pages' {
    BeforeEach {
        Reset-PaginationTestState
        Mock Write-Host {}
        Mock Export-AuditCsv {}
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Method -ne 'GET') { throw 'Only GET is allowed' }
            if ($Uri -like 'https://graph.microsoft.com/v1.0/servicePrincipals/graph-sp?*') { return $script:PaginationResource }
            if (-not $script:PaginationResponses.ContainsKey($Uri)) { throw "Unexpected synthetic URI: $Uri" }
            $response = $script:PaginationResponses[$Uri]
            if ($response -is [string]) { throw $response }
            return $response
        }
    }

    It 'keeps successful multi-page collections Complete and observes later-page grants and roles' {
        foreach ($source in @('ServicePrincipals', 'ApplicationPermissionGrants', 'DelegatedPermissionGrants', 'RoleDefinitions', 'ActiveRoleAssignments')) {
            $uri = $script:PaginationUris[$source]
            $nextUri = "https://graph.microsoft.com/v1.0/pagination-fixture/$source"
            $script:PaginationResponses[$nextUri] = @{ value = $script:PaginationResponses[$uri].value }
            $script:PaginationResponses[$uri] = @{ value = @(); '@odata.nextLink' = $nextUri }
        }
        $permissions = @(Get-ServicePrincipalsWithAppRoles)
        $permissions.Count | Should -Be 2
        $permissions.Permission | Should -Contain 'Application.ReadWrite.All'
        $permissions.Permission | Should -Contain 'Directory.AccessAsUser.All'
        @(Get-PrivilegedRoleAssignments).Count | Should -Be 1
        @(Get-UserConsentGrants).Count | Should -Be 1
        Test-AuditCoverageComplete | Should -BeTrue
    }

    It 'retains a dangerous application grant when <Source> pagination fails' -ForEach @(
        @{ Source = 'ServicePrincipals' }
        @{ Source = 'ApplicationPermissionGrants' }
    ) {
        Add-PaginationFailure -Source $Source
        $permissions = @(Get-ServicePrincipalsWithAppRoles)
        @($permissions | Where-Object Permission -eq 'Application.ReadWrite.All').Count | Should -Be 1
        $script:CachedServicePrincipals.id | Should -Contain 'client-sp'
        $script:Coverage[$Source].State | Should -Be 'Partial'
        Test-AuditCoverageComplete -Sources $Source | Should -BeFalse
    }

    It 'retains delegated exposure without making it app-only evidence after a page failure' {
        Add-PaginationFailure -Source DelegatedPermissionGrants
        $permissions = @(Get-ServicePrincipalsWithAppRoles)
        $delegated = @($permissions | Where-Object PermissionType -eq 'Delegated')
        $delegated.Count | Should -Be 1
        $delegated[0].Exploitability | Should -Be 'Conditional'
        $script:Coverage.DelegatedPermissionGrants.State | Should -Be 'Partial'
    }

    It 'retains observed role evidence when <Source> pagination fails' -ForEach @(
        @{ Source = 'RoleDefinitions' }
        @{ Source = 'ActiveRoleAssignments' }
    ) {
        Add-PaginationFailure -Source $Source
        $roles = @(Get-PrivilegedRoleAssignments)
        $roles.Count | Should -Be 1
        $roles[0].RoleDefinitionId | Should -Be 'sensitive-role'
        $roles[0].PrincipalId | Should -Be 'client-sp'
        $roles[0].DefinitionSource | Should -Be 'MicrosoftGraphBeta'
        $script:CachedRoleDefinitions['sensitive-role'].IsSensitiveTarget | Should -BeTrue
        $script:Coverage[$Source].State | Should -Be 'Partial'
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly -ParameterFilter { $Uri -eq $script:PaginationUris.V1RoleDefinitions }
    }

    It 'retains role evidence when both definitions and assignments have later failures' {
        Add-PaginationFailure -Source RoleDefinitions
        Add-PaginationFailure -Source ActiveRoleAssignments
        @(Get-PrivilegedRoleAssignments).Count | Should -Be 1
        $script:Coverage.RoleDefinitions.State | Should -Be 'Partial'
        $script:Coverage.ActiveRoleAssignments.State | Should -Be 'Partial'
    }

    It 'retains v1 fallback role definitions with Partial coverage' {
        $script:PaginationResponses[$script:PaginationUris.RoleDefinitions] = 'Synthetic beta first-page failure'
        Add-PaginationFailure -Source V1RoleDefinitions
        $roles = @(Get-PrivilegedRoleAssignments)
        $roles.Count | Should -Be 1
        $roles[0].DefinitionSource | Should -Be 'V1WithConfiguredSensitivityFallback'
        $script:Coverage.RoleDefinitions.State | Should -Be 'Partial'
    }

    It 'retains observed user consent grants with Partial coverage' {
        Add-PaginationFailure -Source UserConsentGrants
        $grants = @(Get-UserConsentGrants)
        $grants.Count | Should -Be 1
        $grants[0].id | Should -Be 'delegated-grant'
        $script:Coverage.UserConsentGrants.State | Should -Be 'Partial'
    }

    It 'keeps <Source> Unavailable when its first page fails' -ForEach @(
        @{ Source = 'ServicePrincipals'; Collector = 'Get-ServicePrincipalsWithAppRoles' }
        @{ Source = 'DelegatedPermissionGrants'; Collector = 'Get-ServicePrincipalsWithAppRoles' }
        @{ Source = 'RoleDefinitions'; Collector = 'Get-PrivilegedRoleAssignments' }
        @{ Source = 'ActiveRoleAssignments'; Collector = 'Get-PrivilegedRoleAssignments' }
        @{ Source = 'UserConsentGrants'; Collector = 'Get-UserConsentGrants' }
    ) {
        $script:PaginationResponses[$script:PaginationUris[$Source]] = 'Synthetic first-page failure'
        if ($Source -eq 'RoleDefinitions') { $script:PaginationResponses[$script:PaginationUris.V1RoleDefinitions] = 'Synthetic fallback failure' }
        $null = & $Collector
        $script:Coverage[$Source].State | Should -Be 'Unavailable'
        Test-AuditCoverageComplete -Sources $Source | Should -BeFalse
    }

    It 'does not mark <Source> Complete after an empty first page and later failure' -ForEach @(
        @{ Source = 'ServicePrincipals'; Collector = 'Get-ServicePrincipalsWithAppRoles'; State = 'Unavailable' }
        @{ Source = 'ApplicationPermissionGrants'; Collector = 'Get-ServicePrincipalsWithAppRoles'; State = 'Partial' }
        @{ Source = 'DelegatedPermissionGrants'; Collector = 'Get-ServicePrincipalsWithAppRoles'; State = 'Unavailable' }
        @{ Source = 'RoleDefinitions'; Collector = 'Get-PrivilegedRoleAssignments'; State = 'Unavailable' }
        @{ Source = 'ActiveRoleAssignments'; Collector = 'Get-PrivilegedRoleAssignments'; State = 'Unavailable' }
        @{ Source = 'UserConsentGrants'; Collector = 'Get-UserConsentGrants'; State = 'Unavailable' }
    ) {
        Add-PaginationFailure -Source $Source -EmptyFirstPage
        if ($Source -eq 'RoleDefinitions') { $script:PaginationResponses[$script:PaginationUris.V1RoleDefinitions] = 'Synthetic fallback failure' }
        $null = & $Collector
        $script:Coverage[$Source].State | Should -Be $State
        Test-AuditCoverageComplete -Sources $Source | Should -BeFalse
    }
}

Describe 'P1 final gates through mocked Graph pages' {
    BeforeEach {
        Reset-PaginationTestState
        $script:PaginationResponses[$script:PaginationUris.DelegatedPermissionGrants] = @{ value = @() }
        $script:PaginationResponses[$script:PaginationUris.ActiveRoleAssignments].value = @(
            @{ id = 'owner-role'; principalId = 'owner'; roleDefinitionId = 'sensitive-role'; directoryScopeId = '/'; appScopeId = $null; principal = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Owner'; userPrincipalName = 'owner@contoso.test' } }
        )
        $script:p1ValidCredentials = $false
        Mock Write-Host {}
        Mock Export-AuditCsv {}
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Method -ne 'GET') { throw 'Only GET is allowed' }
            if ($script:PaginationResponses.ContainsKey($Uri)) {
                $response = $script:PaginationResponses[$Uri]
                if ($response -is [string]) { throw $response }
                return $response
            }
            if ($Uri -like 'https://graph.microsoft.com/v1.0/servicePrincipals/graph-sp?*') { return $script:PaginationResource }
            if ($Uri -match '/applications\?') {
                return @{ value = @(@{ id = 'client-object'; appId = 'client-app'; signInAudience = 'AzureADMyOrg'; servicePrincipalLockConfiguration = $null; passwordCredentials = @(); keyCredentials = @() }) }
            }
            if ($Uri -match '/applications/client-object/owners\?') {
                return @{ value = @(@{ id = 'owner'; displayName = 'Owner'; userPrincipalName = 'owner@contoso.test' }) }
            }
            if ($Uri -match '/applications/client-object/federatedIdentityCredentials') { return @{ value = @() } }
            if ($Uri -match '/servicePrincipals/client-sp\?') {
                $credentials = @(if ($script:p1ValidCredentials) { @{ keyId = 'secret'; startDateTime = (Get-Date).AddDays(-10).ToString('o'); endDateTime = (Get-Date).AddDays(30).ToString('o') } })
                return @{ id = 'client-sp'; passwordCredentials = $credentials; keyCredentials = @() }
            }
            if ($Uri -match '/reports/servicePrincipalSignInActivities') { return @{ value = @() } }
            throw "Unexpected synthetic URI: $Uri"
        }
    }

    It 'does not emit clean final path or stale results after incomplete <Source>' -ForEach @(
        @{ Source = 'ServicePrincipals' }
        @{ Source = 'ApplicationPermissionGrants' }
        @{ Source = 'ResourcePermissionDefinitions' }
    ) {
        if ($Source -eq 'ResourcePermissionDefinitions') {
            $script:PaginationResponses[$script:PaginationUris.ApplicationPermissionGrants]['@odata.nextLink'] = 'https://graph.microsoft.com/v1.0/pagination-fixture/extra-grant'
            $script:PaginationResponses['https://graph.microsoft.com/v1.0/pagination-fixture/extra-grant'] = @{ value = @(@{ id = 'unresolved-grant'; appRoleId = 'other-role'; resourceId = 'unavailable-resource' }) }
        } else { Add-PaginationFailure -Source $Source }
        @(Invoke-AttackPathAnalysis).Count | Should -Be 0
        $script:CachedDangerousApps.Permission | Should -Contain 'Application.ReadWrite.All'
        $script:Coverage[$Source].State | Should -Be Partial
        Should -Invoke Write-Host -Times 0 -Exactly -ParameterFilter { $ForegroundColor -eq 'Green' -and "$Object" -match 'No attack paths' }
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match 'attack-path coverage is incomplete' }
        @(Invoke-StalePrivilegeDetection).Count | Should -Be 0
        $script:StalePrivilegeDataAvailable | Should -BeFalse
        $script:StalePrivilegeStatus | Should -Match 'permission.*incomplete'
        $script:StalePrivilegeStatus | Should -Not -Match 'credential|sign-in'
        Should -Invoke Write-Host -Times 0 -Exactly -ParameterFilter { $ForegroundColor -eq 'Green' -and "$Object" -match 'No stale' }
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match 'No stale.*permission.*incomplete' }
        Test-AuditCoverageComplete -Sources @('ApplicationCredentials', 'FederatedIdentityCredentials', 'ServicePrincipalCredentials', 'ServicePrincipalSignInActivity') | Should -BeTrue
    }

    It 'keeps complete equivalent-owner and empty-credential negatives clean' {
        @(Invoke-AttackPathAnalysis).Count | Should -Be 0
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { $ForegroundColor -eq 'Green' -and "$Object" -match 'No attack paths' }
        @(Invoke-StalePrivilegeDetection).Count | Should -Be 0
        $script:StalePrivilegeDataAvailable | Should -BeTrue
        $script:StalePrivilegeStatus | Should -Be Complete
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { $ForegroundColor -eq 'Green' -and "$Object" -match 'No stale' }
    }

    It 'keeps early no-dangerous-app stale availability coherent for <Source>' -ForEach @(
        @{ Source = 'ServicePrincipals' }
        @{ Source = 'ApplicationPermissionGrants' }
        @{ Source = 'ResourcePermissionDefinitions' }
        @{ Source = 'Complete' }
    ) {
        if ($Source -eq 'ResourcePermissionDefinitions') {
            $script:PaginationResponses[$script:PaginationUris.ApplicationPermissionGrants].value[0].resourceId = 'unavailable-resource'
        }
        else {
            $script:PaginationResponses[$script:PaginationUris.ApplicationPermissionGrants].value = @()
            if ($Source -ne 'Complete') { Add-PaginationFailure -Source $Source }
        }
        @(Invoke-StalePrivilegeDetection).Count | Should -Be 0
        $script:StalePrivilegeDataAvailable | Should -Be ($Source -eq 'Complete')
        if ($Source -eq 'Complete') { $script:StalePrivilegeStatus | Should -Be Complete }
        else {
            $script:StalePrivilegeStatus | Should -Match 'permission.*incomplete'
            $script:StalePrivilegeStatus | Should -Not -Match 'credential|sign-in'
            Should -Invoke Write-Host -Times 0 -Exactly -ParameterFilter { $ForegroundColor -eq 'Green' -and "$Object" -match 'No apps' }
        }
    }

    It 'retains observed stale findings and correct incomplete reason' {
        Add-PaginationFailure -Source ApplicationPermissionGrants
        $script:p1ValidCredentials = $true
        $rows = @(Invoke-StalePrivilegeDetection)
        $rows.Count | Should -Be 1
        $rows[0].ValidCredCount | Should -Be 1
        $script:StalePrivilegeDataAvailable | Should -BeFalse
        $script:StalePrivilegeStatus | Should -Match 'permission.*incomplete'
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match 'lower bounds.*permission.*incomplete' }
        Should -Invoke Write-Host -Times 0 -Exactly -ParameterFilter { "$Object" -match 'credential coverage is incomplete' }
    }

    It 'reports permission incompleteness in the Full stale summary for <Scenario>' -ForEach @(
        @{ Scenario = 'empty credentials'; ExpectedCount = 0 }
        @{ Scenario = 'observed stale'; ExpectedCount = 1 }
        @{ Scenario = 'no dangerous apps'; ExpectedCount = 0 }
    ) {
        Mock Invoke-PermissionAudit { @() }
        Mock Invoke-RoleAudit { @{ CoverageComplete = $true; PrivilegedUsers = @(); NonPrivilegedUsers = @(); SPRoles = @() } }
        Mock Invoke-AttackPathAnalysis { @() }
        Mock Invoke-ShadowAdminDetection { @() }
        Mock Invoke-ConsentRiskAssessment { @() }
        Mock Invoke-CredentialHygieneAudit { @() }
        if ($Scenario -eq 'no dangerous apps') { $script:PaginationResponses[$script:PaginationUris.ApplicationPermissionGrants].value = @() }
        Add-PaginationFailure -Source ApplicationPermissionGrants
        $script:p1ValidCredentials = $Scenario -eq 'observed stale'
        $null = Invoke-FullAudit
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            "$Object" -match "Stale Privilege:.*Incomplete \(permission evidence\); $ExpectedCount dormant high-privilege apps observed" -and $ForegroundColor -eq 'DarkYellow'
        }
        Should -Invoke Export-AuditCsv -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'FullAuditSummary' -and ($Data | Where-Object Section -eq StalePrivilege).Finding -match 'Incomplete \(permission evidence\)' -and ($Data | Where-Object Section -eq StalePrivilege).Count -eq $ExpectedCount
        }
    }

    It 'evaluates role-control scope <ExistingScope> with retained <Source> pages as <Expected>' -ForEach @(
        @{ Source = 'RoleDefinitions'; ExistingScope = '/'; Expected = 'Equivalent' }
        @{ Source = 'RoleDefinitions'; ExistingScope = '/administrativeUnits/au'; Expected = 'PotentialRoleUnknown' }
        @{ Source = 'RoleDefinitions'; ExistingScope = $null; Expected = 'PotentialRoleUnknown' }
        @{ Source = 'ActiveRoleAssignments'; ExistingScope = '/'; Expected = 'Equivalent' }
        @{ Source = 'ActiveRoleAssignments'; ExistingScope = '/administrativeUnits/au'; Expected = 'PotentialRoleUnknown' }
        @{ Source = 'ActiveRoleAssignments'; ExistingScope = $null; Expected = 'PotentialRoleUnknown' }
    ) {
        $script:PaginationResponses[$script:PaginationUris.ApplicationPermissionGrants].value = @()
        $script:PaginationResponses[$script:PaginationUris.RoleDefinitions].value[0].templateId = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
        $script:PaginationResponses[$script:PaginationUris.RoleDefinitions].value += @{ id = 'control'; displayName = 'Control'; rolePermissions = @(@{ allowedResourceActions = @('microsoft.directory/applications/credentials/update') }) }
        $script:PaginationResponses[$script:PaginationUris.ActiveRoleAssignments].value[0].directoryScopeId = $ExistingScope
        $script:PaginationResponses[$script:PaginationUris.ActiveRoleAssignments].value += @(
            @{ principalId = 'owner'; roleDefinitionId = 'control'; directoryScopeId = '/'; principal = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Owner'; userPrincipalName = 'owner@contoso.test' } }
            @{ principalId = 'client-sp'; roleDefinitionId = 'sensitive-role'; directoryScopeId = '/'; principal = @{ '@odata.type' = '#microsoft.graph.servicePrincipal'; displayName = 'Synthetic client'; appId = 'client-app' } }
        )
        Add-PaginationFailure -Source $Source
        $paths = @(Invoke-AttackPathAnalysis)
        $script:Coverage[$Source].State | Should -Be Partial
        if ($Expected -eq 'Equivalent') { $paths.Count | Should -Be 0 }
        else {
            $paths.Count | Should -Be 1
            $paths[0].PathId | Should -Be ROLE_BASED_SP_CONTROL
            $paths[0].Exploitability | Should -Be $Expected
            $paths[0].EvidenceDetail | Should -Match 'role'
            if (-not $ExistingScope) { $paths[0].EvidenceDetail | Should -Match 'scope' }
        }
    }

    It 'evaluates <ExistingScope> scope with retained <Source> role pages as <Expected>' -ForEach @(
        @{ Source = 'RoleDefinitions'; ExistingScope = '/'; Expected = 'Equivalent' }
        @{ Source = 'RoleDefinitions'; ExistingScope = '/administrativeUnits/au'; Expected = 'PotentialRoleUnknown' }
        @{ Source = 'RoleDefinitions'; ExistingScope = $null; Expected = 'PotentialRoleUnknown' }
        @{ Source = 'ActiveRoleAssignments'; ExistingScope = '/'; Expected = 'Equivalent' }
        @{ Source = 'ActiveRoleAssignments'; ExistingScope = '/administrativeUnits/au'; Expected = 'PotentialRoleUnknown' }
        @{ Source = 'ActiveRoleAssignments'; ExistingScope = $null; Expected = 'PotentialRoleUnknown' }
    ) {
        $script:PaginationResponses[$script:PaginationUris.ActiveRoleAssignments].value[0].directoryScopeId = $ExistingScope
        Add-PaginationFailure -Source $Source
        $paths = @(Invoke-AttackPathAnalysis)
        $script:Coverage[$Source].State | Should -Be Partial
        if ($Expected -eq 'Equivalent') { $paths.Count | Should -Be 0 }
        else {
            $paths.Count | Should -Be 1
            $paths[0].PathId | Should -Be APP_OWNER_ESCALATION
            $paths[0].Exploitability | Should -Be $Expected
            $paths[0].EvidenceDetail | Should -Match 'role'
            if (-not $ExistingScope) { $paths[0].EvidenceDetail | Should -Match 'scope' }
        }
    }
}