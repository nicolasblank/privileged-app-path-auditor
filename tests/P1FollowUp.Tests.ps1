BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'Invoke-PrivilegedAudit.ps1')

    function New-FollowUpAssignment {
        param([string]$Role = 'control', [string]$Principal = 'operator', [string]$Type = 'user', [string]$Scope = '/', [string]$AppScope)
        @{
            roleDefinitionId = $Role; principalId = $Principal; directoryScopeId = $Scope; appScopeId = $AppScope
            principal = @{ '@odata.type' = "#microsoft.graph.$Type"; displayName = $Principal; userPrincipalName = "$Principal@example.test"; appId = 'client-app' }
        }
    }
}

Describe 'Independent-review P1 follow-up through Graph collectors' {
    BeforeEach {
        Reset-AuditCoverage
        $script:CachedDangerousApps = $null
        $script:CachedRoleAssignments = $null
        $script:CachedRoleDefinitions = $null
        $script:CachedServicePrincipals = $null
        $script:CachedResourceServicePrincipals = @{}
        $script:DangerousPermissions = @($script:DefaultDangerousPermissions | ForEach-Object { @{} + $_ })
        $script:PrivilegedRoles = $script:DefaultPrivilegedRoles
        $script:AuditConfig = $script:DefaultAuditConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        $script:ConnectedTenantId = 'home-tenant'
        $script:MicrosoftAppIds = [System.Collections.Generic.HashSet[string]]::new()
        $script:followUpSP = @{ id = 'client-sp'; appId = 'client-app'; displayName = 'Synthetic client'; appOwnerOrganizationId = 'home-tenant'; accountEnabled = $true }
        $script:followUpApp = @{ id = 'app-object'; appId = 'client-app'; signInAudience = 'AzureADMyOrg'; servicePrincipalLockConfiguration = @{ isEnabled = $true; allProperties = $true } }
        $script:followUpDefinitions = @(
            @{ id = 'control'; displayName = 'Credential operator'; isBuiltIn = $false; isPrivileged = $false; rolePermissions = @(@{ allowedResourceActions = @('microsoft.directory/servicePrincipals/credentials/update') }) }
            @{ id = 'target'; displayName = 'Synthetic target role'; templateId = 'fe930be7-5e62-47db-91af-98c3a49a38b1'; isBuiltIn = $true; isPrivileged = $true; rolePermissions = @() }
        )
        $script:followUpAssignments = @((New-FollowUpAssignment), (New-FollowUpAssignment -Role target -Principal client-sp -Type servicePrincipal))
        $script:followUpPartialSource = $null
        $script:followUpOwnerGrant = $false
        $script:followUpResourceAppId = $script:MicrosoftGraphAppId
        $script:followUpExport = @{}
        Mock Write-Host {}
        Mock Export-AuditCsv { param($Name, $Data); $script:followUpExport[$Name] = @($Data) }
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Method -ne 'GET') { throw 'Only read-only synthetic requests are allowed' }
            if ($Uri -match '/followup-failed-page') { throw 'Synthetic later role page failed' }
            if ($Uri -match '/roleDefinitions$') {
                $response = @{ value = @($script:followUpDefinitions) }
                if ($script:followUpPartialSource -eq 'RoleDefinitions') { $response['@odata.nextLink'] = 'https://graph.microsoft.com/beta/followup-failed-page' }
                return $response
            }
            if ($Uri -match '/roleDefinitions/') { throw 'Synthetic role definition is unavailable' }
            if ($Uri -match '/roleAssignments\?') {
                $response = @{ value = @($script:followUpAssignments) }
                if ($script:followUpPartialSource -eq 'ActiveRoleAssignments') { $response['@odata.nextLink'] = 'https://graph.microsoft.com/v1.0/followup-failed-page' }
                return $response
            }
            if ($Uri -match '/servicePrincipals\?') { return @{ value = @($script:followUpSP) } }
            if ($Uri -match '/client-sp/appRoleAssignments\?') {
                return @{ value = @(if ($script:followUpOwnerGrant) { @{ appRoleId = 'grant-role'; resourceId = 'resource-sp' } }) }
            }
            if ($Uri -match '/servicePrincipals/resource-sp\?') {
                return @{ id = 'resource-sp'; appId = $script:followUpResourceAppId; displayName = 'Synthetic resource'; appRoles = @(@{ id = 'grant-role'; value = 'AppRoleAssignment.ReadWrite.All' }) }
            }
            if ($Uri -match '/oauth2PermissionGrants\?') { return @{ value = @() } }
            if ($Uri -match '/applications\?') { return @{ value = @($script:followUpApp) } }
            if ($Uri -match '/applications/app-object/owners\?') { return @{ value = @(@{ id = 'operator'; displayName = 'Owner'; userPrincipalName = 'operator@example.test' }) } }
            if ($Uri -match '/servicePrincipals/client-sp\?') { return @{ id = 'client-sp'; passwordCredentials = @(); keyCredentials = @() } }
            throw "Unexpected synthetic URI: $Uri"
        }
    }

    It 'retains a locked observed route as potential, not INFO, with incomplete <Source>' -ForEach @(
        @{ Source = 'RoleDefinitions' }
        @{ Source = 'ActiveRoleAssignments' }
        @{ Source = 'RoleGroupMemberships' }
    ) {
        if ($Source -eq 'RoleGroupMemberships') {
            $script:followUpAssignments += New-FollowUpAssignment -Role control -Principal role-group -Type group
        } else { $script:followUpPartialSource = $Source }
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 1
        $paths[0].Exploitability | Should -Be 'PotentialRoleUnknown'
        $paths[0].Severity | Should -Be 'HIGH'
        $paths[0].AppInstanceLock | Should -Be 'OAuthCredentialChangesLocked'
        $paths[0].EvidenceDetail | Should -Match 'incomplete'
        $paths[0].EvidenceDetail | Should -Match 'blocked.*lock'
        $script:Coverage[$Source].State | Should -Be 'Partial'
        $script:followUpExport.AttackPaths[0].Exploitability | Should -Be 'PotentialRoleUnknown'
    }

    It 'does not downgrade unknown target-role scope to INFO merely because a route is locked' {
        $script:followUpAssignments[1].directoryScopeId = '/unknown/target-scope'
        $path = @(Invoke-AttackPathAnalysis)[0]
        $path.Exploitability | Should -Be 'PotentialRoleUnknown'
        $path.Severity | Should -Not -Be 'INFO'
        $path.EvidenceDetail | Should -Match 'scope'
    }

    It 'retains confirmed mitigation when role and control-scope evidence is complete' {
        $path = @(Invoke-AttackPathAnalysis)[0]
        $path.Exploitability | Should -Be 'MitigatedByAppInstanceLock'
        $path.Severity | Should -Be 'INFO'
        $path.AppInstanceLock | Should -Be 'OAuthCredentialChangesLocked'
    }

    It 'does not label missing account prerequisites fully mitigated' {
        $script:followUpSP.accountEnabled = $null
        $path = @(Invoke-AttackPathAnalysis)[0]
        $path.Exploitability | Should -Be 'PotentialPrerequisiteUnknown'
        $path.Severity | Should -Not -Be 'INFO'
    }

    It 'retains unsupported <Object> control scope <Scope> with app scope <AppScope> as uncertain' -ForEach @(
        @{ Object = 'applications'; Scope = '/unknown/scope'; AppScope = $null }
        @{ Object = 'servicePrincipals'; Scope = '/unknown/scope'; AppScope = $null }
        @{ Object = 'applications'; Scope = '/applications/app-object/unsupported'; AppScope = $null }
        @{ Object = 'servicePrincipals'; Scope = '/servicePrincipals/client-sp/unsupported'; AppScope = $null }
        @{ Object = 'applications'; Scope = '/'; AppScope = '/external-scope' }
        @{ Object = 'servicePrincipals'; Scope = '/'; AppScope = '/external-scope' }
    ) {
        $script:followUpDefinitions[0].rolePermissions[0].allowedResourceActions = @("microsoft.directory/$Object/credentials/update")
        $script:followUpAssignments[0].directoryScopeId = $Scope
        $script:followUpAssignments[0].appScopeId = $AppScope
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 1
        $paths[0].Exploitability | Should -Be 'PotentialPrerequisiteUnknown'
        $paths[0].EvidenceDetail | Should -Match 'scope'
        $paths[0].Severity | Should -Not -Be 'INFO'
        Should -Invoke Write-Host -Times 0 -Exactly -ParameterFilter { "$Object" -match '^✓ No attack paths' }
    }

    It 'preserves known <Object> scope mismatch <Scope> as excluded' -ForEach @(
        @{ Object = 'applications'; Scope = '/other-object' }
        @{ Object = 'applications'; Scope = '/client-sp' }
        @{ Object = 'applications'; Scope = '/servicePrincipals/client-sp' }
        @{ Object = 'applications'; Scope = '/administrativeUnits/au-one' }
        @{ Object = 'servicePrincipals'; Scope = '/other-object' }
        @{ Object = 'servicePrincipals'; Scope = '/app-object' }
        @{ Object = 'servicePrincipals'; Scope = '/applications/app-object' }
        @{ Object = 'servicePrincipals'; Scope = '/administrativeUnits/au-one' }
    ) {
        $script:followUpDefinitions[0].rolePermissions[0].allowedResourceActions = @("microsoft.directory/$Object/credentials/update")
        $script:followUpAssignments[0].directoryScopeId = $Scope
        @(Invoke-AttackPathAnalysis).Count | Should -Be 0
    }

    It 'preserves a proven application alternative while retaining uncertainty on another control assignment' {
        $script:followUpAssignments[0].directoryScopeId = '/unknown/scope'
        $script:followUpDefinitions += @{ id = 'app-control'; displayName = 'App operator'; isPrivileged = $false; rolePermissions = @(@{ allowedResourceActions = @('microsoft.directory/applications/credentials/update') }) }
        $script:followUpAssignments += New-FollowUpAssignment -Role app-control
        $path = @(Invoke-AttackPathAnalysis)[0]
        $path.Exploitability | Should -Be 'Direct'
        $path.EvidenceDetail | Should -Match 'scope'
        $path.Action | Should -Match 'application credential'
    }

    It 'evaluates grant-equivalence for <Role> at <Scope> on <Resource> as <Expected>' -ForEach @(
        @{ Role = 'PRA'; Scope = '/'; Resource = 'Graph'; Expected = 'Equivalent' }
        @{ Role = 'GA'; Scope = '/'; Resource = 'Graph'; Expected = 'Equivalent' }
        @{ Role = 'PRA'; Scope = '/app-object'; Resource = 'Graph'; Expected = 'Direct' }
        @{ Role = 'PRA'; Scope = '/administrativeUnits/au-one'; Resource = 'Graph'; Expected = 'Direct' }
        @{ Role = 'PRA'; Scope = $null; Resource = 'Graph'; Expected = 'PotentialRoleUnknown' }
        @{ Role = 'PRA'; Scope = '/unknown/scope'; Resource = 'Graph'; Expected = 'PotentialRoleUnknown' }
        @{ Role = 'ApplicationAdmin'; Scope = '/'; Resource = 'Graph'; Expected = 'Direct' }
        @{ Role = 'PRA'; Scope = '/'; Resource = 'Custom'; Expected = 'Direct' }
        @{ Role = 'GA'; Scope = '/'; Resource = 'Custom'; Expected = 'Direct' }
        @{ Role = 'CustomNamedPRA'; Scope = '/'; Resource = 'Graph'; Expected = 'Direct' }
    ) {
        $templates = @{ PRA = 'e8611ab8-c189-46e8-94e1-60213ab1f814'; GA = '62e90394-69f5-4237-9190-012177145e10'; ApplicationAdmin = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'; CustomNamedPRA = $null }
        $script:followUpOwnerGrant = $true
        $script:followUpDefinitions = @(@{ id = 'actor'; displayName = 'Privileged Role Administrator'; templateId = $templates[$Role]; isBuiltIn = $Role -ne 'CustomNamedPRA'; isPrivileged = $true; rolePermissions = @() })
        $script:followUpAssignments = @((New-FollowUpAssignment -Role actor -Scope $Scope))
        if ($Resource -eq 'Custom') {
            $script:followUpResourceAppId = '11111111-2222-3333-4444-555555555555'
            $script:DangerousPermissions += @{ name = 'AppRoleAssignment.ReadWrite.All'; type = 'Application'; resourceAppId = $script:followUpResourceAppId; risk = 'Critical'; reason = 'Synthetic custom resource grant' }
        }
        $paths = @(Invoke-AttackPathAnalysis)
        if ($Expected -eq 'Equivalent') { $paths.Count | Should -Be 0 } else {
            $paths.Count | Should -Be 1
            $paths[0].PathId | Should -Be 'APP_OWNER_ESCALATION'
            $paths[0].Exploitability | Should -Be $Expected
            if ($Expected -eq 'PotentialRoleUnknown') { $paths[0].EvidenceDetail | Should -Match 'scope' }
        }
    }

    It 'does not suppress an owner path when the claimed PRA role definition cannot be resolved' {
        $script:followUpOwnerGrant = $true
        $script:followUpDefinitions = @()
        $script:followUpAssignments = @((New-FollowUpAssignment -Role missing-pra))
        $path = @(Invoke-AttackPathAnalysis)[0]
        $path.Exploitability | Should -Be 'PotentialRoleUnknown'
        $script:Coverage.RoleDefinitions.State | Should -Be 'Partial'
    }

    It 'does not infer the new permission resource when resource identity is absent' {
        $pra = [pscustomobject]@{ PrincipalId = 'operator'; PrincipalType = '#microsoft.graph.user'; RoleTemplateId = 'e8611ab8-c189-46e8-94e1-60213ab1f814'; DirectoryScopeId = '/'; AppScopeId = $null }
        Test-UserAlreadyEquivalentToPermission operator AppRoleAssignment.ReadWrite.All @($pra) | Should -BeFalse
    }
}
