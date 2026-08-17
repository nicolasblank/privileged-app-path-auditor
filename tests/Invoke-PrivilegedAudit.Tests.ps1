BeforeAll {
    $script:scriptPath = Join-Path $PSScriptRoot '..' 'Invoke-PrivilegedAudit.ps1'
    $script:repoRoot = Split-Path $script:scriptPath -Parent
    $tokens = $null
    $script:parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $script:scriptPath,
        [ref]$tokens,
        [ref]$script:parseErrors
    ) | Out-Null

    . $script:scriptPath

    function Reset-TestState {
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
    }
}

Describe 'Script and repository contracts' {
    BeforeEach { Reset-TestState }
    It 'parses without errors' {
        $script:parseErrors | Should -BeNullOrEmpty
    }

    It 'reports version 0.5.2' {
        $script:Version | Should -Be '0.5.2'
    }

    It 'can be dot-sourced without executing Graph connection code' {
        Get-Command Invoke-AttackPathAnalysis -ErrorAction Stop | Should -Not -BeNullOrEmpty
    }

    It 'has a parseable schema for every checked-in configuration file' {
        foreach ($configFile in Get-ChildItem (Join-Path $script:repoRoot 'config') -Filter '*.json' | Where-Object Name -ne 'MicrosoftApps.json') {
            $config = Get-Content $configFile.FullName -Raw | ConvertFrom-Json
            $schemaPath = Join-Path $configFile.DirectoryName ([string]$config.'$schema')
            Test-Path $schemaPath | Should -BeTrue -Because "$($configFile.Name) references it"
            Test-Json -Json (Get-Content $configFile.FullName -Raw) -SchemaFile $schemaPath | Should -BeTrue
        }
    }

    It 'defines a three-operating-system CI matrix' {
        $workflow = Get-Content (Join-Path $script:repoRoot '.github/workflows/test.yml') -Raw
        $workflow | Should -Match 'ubuntu-latest'
        $workflow | Should -Match 'windows-latest'
        $workflow | Should -Match 'macos-latest'
    }

    It 'includes the 2026 privileged-role classification changes in the fallback policy' {
        $roleConfig = Get-Content (Join-Path $script:repoRoot 'config/privileged-roles.json') -Raw | ConvertFrom-Json
        $templateIds = @($roleConfig.roles.templateId)
        $templateIds | Should -Contain '1fe13547-53f6-408d-ac04-7f8eed167b38' # AI Reader
        $templateIds | Should -Contain '45d8d3c5-c802-45c6-b32a-1d70b5e1e86e' # Identity Governance Administrator
        $templateIds | Should -Contain '1981f584-96e9-4a6f-95b0-f522373f8fae' # Tenant Governance Administrator
    }
}

Describe 'Application instance lock interpretation' {
    BeforeEach { Reset-TestState }
    It 'does not call a signing-only lock sufficient for OAuth credentials' {
        $result = ConvertTo-AppInstanceLockEvidence ([PSCustomObject]@{
            isEnabled = $true; allProperties = $false
            credentialsWithUsageSign = $true; credentialsWithUsageVerify = $false
        })
        $result.IsCredentialLocked | Should -BeFalse
        $result.State | Should -Be 'EnabledButOAuthCredentialsNotLocked'
    }

    It 'treats allProperties as protecting credential changes' {
        $result = ConvertTo-AppInstanceLockEvidence ([PSCustomObject]@{
            isEnabled = $true; allProperties = $true
            credentialsWithUsageSign = $false; credentialsWithUsageVerify = $false
        })
        $result.IsCredentialLocked | Should -BeTrue
    }

    It 'recognizes verify-only protection used by OAuth service principals' {
        $result = ConvertTo-AppInstanceLockEvidence ([PSCustomObject]@{
            isEnabled = $true; allProperties = $false
            credentialsWithUsageSign = $false; credentialsWithUsageVerify = $true
        })
        $result.IsCredentialLocked | Should -BeTrue
        $result.State | Should -Be 'OAuthCredentialChangesLocked'
    }

    It 'distinguishes absent configuration from disabled configuration' {
        (ConvertTo-AppInstanceLockEvidence $null).State | Should -Be 'NotConfigured'
        (ConvertTo-AppInstanceLockEvidence ([PSCustomObject]@{ isEnabled = $false })).State | Should -Be 'Disabled'
    }
}

Describe 'User consent policy interpretation' {
    BeforeEach { Reset-TestState }
    It 'recognizes the action-prefixed legacy built-in policy' {
        $result = Resolve-UserConsentPolicyAssignment @('managePermissionGrantsForSelf.microsoft-user-default-legacy')
        $result.State | Should -Be 'AllowedForAllApps'
        $result.Risk | Should -Be 'HIGH'
    }

    It 'recognizes the action-prefixed low-risk built-in policy' {
        (Resolve-UserConsentPolicyAssignment @('managePermissionGrantsForSelf.microsoft-user-default-low')).State |
            Should -Be 'RestrictedBuiltIn'
    }

    It 'reports a custom self-consent policy as custom instead of disabled' {
        $result = Resolve-UserConsentPolicyAssignment @('managePermissionGrantsForSelf.contoso-verified-apps')
        $result.State | Should -Be 'CustomPolicy'
        $result.PolicyIds | Should -Contain 'contoso-verified-apps'
    }

    It 'ignores unrelated default-user actions' {
        (Resolve-UserConsentPolicyAssignment @('microsoft.directory/users/read')).State | Should -Be 'Disabled'
    }
}

Describe 'Permission semantics and tenant classification' {
    BeforeEach { Reset-TestState }
    It 'binds a dangerous permission to both grant type and resource API' {
        Find-DangerousPermissionDefinition -Name 'Application.ReadWrite.All' -Type Application -ResourceAppId $script:MicrosoftGraphAppId |
            Should -Not -BeNullOrEmpty
        Find-DangerousPermissionDefinition -Name 'Application.ReadWrite.All' -Type Application -ResourceAppId '11111111-1111-1111-1111-111111111111' |
            Should -BeNullOrEmpty
        Find-DangerousPermissionDefinition -Name 'Application.ReadWrite.All' -Type Delegated -ResourceAppId $script:MicrosoftGraphAppId |
            Should -BeNullOrEmpty
    }

    It 'distinguishes home, third-party, unknown, and Microsoft service principals' {
        (Get-AppTenantType ([PSCustomObject]@{ appId = 'a'; appOwnerOrganizationId = 'tenant-home' })) | Should -Be 'HomeTenant'
        (Get-AppTenantType ([PSCustomObject]@{ appId = 'b'; appOwnerOrganizationId = 'tenant-other' })) | Should -Be 'ThirdParty'
        (Get-AppTenantType ([PSCustomObject]@{ appId = 'c'; appOwnerOrganizationId = $null })) | Should -Be 'Unknown'
        (Get-AppTenantType ([PSCustomObject]@{ appId = 'd'; appOwnerOrganizationId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' })) | Should -Be 'MicrosoftFirstParty'
    }

    It 'keeps delegated and application findings separate and excludes disabled apps when configured' {
        $script:AuditConfig.filters.excludeFirstPartyMicrosoftApps = $false
        $script:AuditConfig.filters.excludeDisabledApps = $true

        Mock Export-AuditCsv {}
        Mock Write-Host {}
        Mock Get-AllGraphPages {
            param($Uri)
            if ($Uri -match '/servicePrincipals\?') {
                return @(
                    [PSCustomObject]@{ id = 'client-on'; appId = 'app-on'; displayName = 'Enabled'; appOwnerOrganizationId = 'tenant-home'; servicePrincipalType = 'Application'; accountEnabled = $true },
                    [PSCustomObject]@{ id = 'client-off'; appId = 'app-off'; displayName = 'Disabled'; appOwnerOrganizationId = 'tenant-home'; servicePrincipalType = 'Application'; accountEnabled = $false }
                )
            }
            if ($Uri -match 'client-on/appRoleAssignments') {
                return @([PSCustomObject]@{ appRoleId = 'role-1'; resourceId = 'graph-sp'; resourceDisplayName = 'Microsoft Graph' })
            }
            if ($Uri -match 'oauth2PermissionGrants') {
                return @(
                    [PSCustomObject]@{ clientId = 'client-on'; resourceId = 'graph-sp'; consentType = 'AllPrincipals'; principalId = $null; scope = 'Directory.AccessAsUser.All' },
                    [PSCustomObject]@{ clientId = 'client-on'; resourceId = 'graph-sp'; consentType = 'Principal'; principalId = 'user-1'; scope = 'Directory.AccessAsUser.All' }
                )
            }
            throw "Unexpected URI: $Uri"
        }
        Mock Invoke-MgGraphRequest {
            return [PSCustomObject]@{
                id = 'graph-sp'; appId = $script:MicrosoftGraphAppId; displayName = 'Microsoft Graph'
                appRoles = @([PSCustomObject]@{ id = 'role-1'; value = 'Application.ReadWrite.All' })
            }
        }

        $result = @(Get-ServicePrincipalsWithAppRoles)
        $result.Count | Should -Be 3
        @($result | Where-Object PermissionType -eq 'Application').Count | Should -Be 1
        @($result | Where-Object PermissionType -eq 'Delegated').Count | Should -Be 2
        @($result | Where-Object PermissionType -eq 'Delegated' | Select-Object -ExpandProperty Exploitability -Unique) | Should -Be @('Conditional')
        ($result | Where-Object ConsentType -eq 'Principal').ConsentPrincipalId | Should -Be 'user-1'
        $result.AppId | Should -Not -Contain 'app-off'
    }
}

Describe 'Current and custom role handling' {
    BeforeEach { Reset-TestState }
    It 'detects service-principal control from current role actions' {
        $role = [PSCustomObject]@{
            templateId = $null
            rolePermissions = @([PSCustomObject]@{ allowedResourceActions = @('microsoft.directory/servicePrincipals/credentials/update') })
        }
        Test-RoleCanControlServicePrincipals $role | Should -BeTrue
        Test-RoleCanControlApplications $role | Should -BeFalse
    }

    It 'detects application-object control separately from service-principal control' {
        $role = [PSCustomObject]@{
            templateId = $null
            rolePermissions = @([PSCustomObject]@{ allowedResourceActions = @('microsoft.directory/applications/credentials/update') })
        }
        Test-RoleCanControlApplications $role | Should -BeTrue
        Test-RoleCanControlServicePrincipals $role | Should -BeFalse
    }

    It 'does not confuse an agent-only action with ordinary service-principal control' {
        $role = [PSCustomObject]@{
            templateId = 'db506228-d27e-4b7d-95e5-295956d6615f'
            rolePermissions = @([PSCustomObject]@{ allowedResourceActions = @('microsoft.directory/agentIdentities/authentication/update') })
        }
        Test-RoleCanControlServicePrincipals $role | Should -BeFalse
    }

    It 'respects tenant and target-specific assignment scope' {
        Test-RoleAssignmentAppliesToServicePrincipal ([PSCustomObject]@{ DirectoryScopeId = '/'; AppScopeId = $null }) 'sp-1' | Should -BeTrue
        Test-RoleAssignmentAppliesToServicePrincipal ([PSCustomObject]@{ DirectoryScopeId = '/servicePrincipals/sp-1'; AppScopeId = $null }) 'sp-1' | Should -BeTrue
        Test-RoleAssignmentAppliesToServicePrincipal ([PSCustomObject]@{ DirectoryScopeId = '/administrativeUnits/au-1'; AppScopeId = $null }) 'sp-1' | Should -BeFalse
    }

    It 'uses permission-specific existing-role equivalence rather than any privileged-role membership' {
        $assignments = @(
            [PSCustomObject]@{ PrincipalId = 'pra'; PrincipalType = '#microsoft.graph.user'; RoleTemplateId = 'e8611ab8-c189-46e8-94e1-60213ab1f814' },
            [PSCustomObject]@{ PrincipalId = 'reader'; PrincipalType = '#microsoft.graph.user'; RoleTemplateId = '1fe13547-53f6-408d-ac04-7f8eed167b38' },
            [PSCustomObject]@{ PrincipalId = 'apps'; PrincipalType = '#microsoft.graph.user'; RoleTemplateId = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' }
        )
        Test-UserAlreadyEquivalentToPermission 'pra' 'RoleManagement.ReadWrite.Directory' $assignments | Should -BeTrue
        Test-UserAlreadyEquivalentToPermission 'reader' 'RoleManagement.ReadWrite.Directory' $assignments | Should -BeFalse
        Test-UserAlreadyEquivalentToPermission 'apps' 'Application.ReadWrite.All' $assignments | Should -BeTrue
        Test-UserAlreadyEquivalentToPermission 'apps' 'RoleManagement.ReadWrite.Directory' $assignments | Should -BeFalse
    }

    It 'uses the reachable role tier for role-control path severity' {
        Get-RoleImpactSeverity @([PSCustomObject]@{ RoleTier = 'Medium' }) | Should -Be 'MEDIUM'
        Get-RoleImpactSeverity @([PSCustomObject]@{ RoleTier = 'High' }) | Should -Be 'HIGH'
        Get-RoleImpactSeverity @(
            [PSCustomObject]@{ RoleTier = 'High' },
            [PSCustomObject]@{ RoleTier = 'Critical' }
        ) | Should -Be 'CRITICAL'
    }

    It 'loads live beta classification and custom application-control roles' {
        Mock Write-Host {}
        Mock Get-AllGraphPages {
            param($Uri)
            if ($Uri -match 'roleDefinitions') {
                $Uri | Should -Not -Match '\?'
                return @(
                    [PSCustomObject]@{ id = 'rd-ai'; templateId = '1fe13547-53f6-408d-ac04-7f8eed167b38'; displayName = 'AI Reader'; isBuiltIn = $true; isEnabled = $true; isPrivileged = $true; rolePermissions = @() },
                    [PSCustomObject]@{ id = 'rd-custom'; templateId = $null; displayName = 'Custom SP Credential Operator'; isBuiltIn = $false; isEnabled = $true; isPrivileged = $false; rolePermissions = @([PSCustomObject]@{ allowedResourceActions = @('microsoft.directory/servicePrincipals/credentials/update') }) }
                )
            }
            if ($Uri -match 'roleAssignments') {
                $Uri | Should -Be 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal'
                return @(
                    [PSCustomObject]@{ roleDefinitionId = 'rd-ai'; principalId = 'sp-ai'; directoryScopeId = '/'; appScopeId = $null; principal = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.servicePrincipal'; displayName = 'AI SP'; appId = 'ai-app' } },
                    [PSCustomObject]@{ roleDefinitionId = 'rd-custom'; principalId = 'user-1'; directoryScopeId = '/'; appScopeId = $null; principal = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Operator'; userPrincipalName = 'operator@contoso.test' } }
                )
            }
            throw "Unexpected URI: $Uri"
        }

        $result = @(Get-PrivilegedRoleAssignments)
        ($result | Where-Object RoleDefinitionId -eq 'rd-ai').IsSensitiveTarget | Should -BeTrue
        ($result | Where-Object RoleDefinitionId -eq 'rd-custom').CanControlServicePrincipals | Should -BeTrue
        ($result | Where-Object RoleDefinitionId -eq 'rd-custom').IsSensitiveTarget | Should -BeFalse
    }
}

Describe 'Coverage reporting' {
    BeforeEach { Reset-TestState }
    It 'never upgrades a partial source back to complete' {
        Set-CoverageState -Source 'Example' -State Complete
        Set-CoverageState -Source 'Example' -State Partial -Detail 'one failure'
        Set-CoverageState -Source 'Example' -State Complete
        $script:Coverage.Example.State | Should -Be 'Partial'
        Test-AuditCoverageComplete -Sources 'Example' | Should -BeFalse
    }

    It 'marks a failed top-level service-principal query unavailable instead of clean' {
        Mock Write-Host {}
        Mock Get-AllGraphPages { throw 'Graph unavailable' }

        @(Get-ServicePrincipalsWithAppRoles).Count | Should -Be 0
        $script:Coverage.ServicePrincipals.State | Should -Be 'Unavailable'
    }

    It 'does not call a missing local application object unowned' {
        Mock Write-Host {}
        Mock Get-AllGraphPages { return @() }

        $result = Get-ApplicationOwners -AppIds 'home-app'
        $result['home-app'].Status | Should -Be 'ApplicationObjectNotFound'
        $script:Coverage.ApplicationOwners.State | Should -Be 'Partial'
    }
}

Describe 'Attack-path regression fixture' {
    BeforeEach { Reset-TestState }
    It 'keeps real privilege deltas, excludes delegated owner takeover, and applies lock mitigation' {
        Mock Write-Banner {}
        Mock Write-Host {}
        Mock Write-SectionDivider {}
        Mock Write-Recommendation {}
        Mock Write-Reference {}
        Mock Export-AuditCsv {}
        Mock Get-ServicePrincipalsWithAppRoles {
            return @(
                [PSCustomObject]@{ SPId = 'danger-sp'; SPDisplayName = 'Danger App'; AppId = 'danger-app'; AppTenantType = 'HomeTenant'; Permission = 'Application.ReadWrite.All'; PermissionType = 'Application'; Risk = 'Critical'; Reason = 'Can modify app credentials'; AttackAction = 'add credentials to another app' },
                [PSCustomObject]@{ SPId = 'danger-sp'; SPDisplayName = 'Danger App'; AppId = 'danger-app'; AppTenantType = 'HomeTenant'; Permission = 'Directory.AccessAsUser.All'; PermissionType = 'Delegated' }
            )
        }
        Mock Get-PrivilegedRoleAssignments {
            Set-CoverageState -Source 'RoleDefinitions' -State Complete
            Set-CoverageState -Source 'ActiveRoleAssignments' -State Complete
            Set-CoverageState -Source 'RoleGroupMemberships' -State Complete
            return @(
                [PSCustomObject]@{ PrincipalId = 'reader'; PrincipalType = '#microsoft.graph.user'; PrincipalDisplayName = 'Reader'; PrincipalUPN = 'reader@contoso.test'; RoleDefinitionId = 'rd-reader'; RoleTemplateId = '1fe13547-53f6-408d-ac04-7f8eed167b38'; RoleName = 'AI Reader'; IsSensitiveTarget = $true; CanControlServicePrincipals = $false },
                [PSCustomObject]@{ PrincipalId = 'ga'; PrincipalType = '#microsoft.graph.user'; PrincipalDisplayName = 'GA'; PrincipalUPN = 'ga@contoso.test'; RoleDefinitionId = 'rd-ga'; RoleTemplateId = '62e90394-69f5-4237-9190-012177145e10'; RoleName = 'Global Administrator'; IsSensitiveTarget = $true; CanControlServicePrincipals = $false },
                [PSCustomObject]@{ PrincipalId = 'operator'; PrincipalType = '#microsoft.graph.user'; PrincipalDisplayName = 'Operator'; PrincipalUPN = 'operator@contoso.test'; RoleDefinitionId = 'rd-control'; RoleName = 'Custom SP Operator'; IsSensitiveTarget = $false; CanControlApplications = $false; CanControlServicePrincipals = $true; DirectoryScopeId = '/'; AppScopeId = $null },
                [PSCustomObject]@{ PrincipalId = 'app-operator'; PrincipalType = '#microsoft.graph.user'; PrincipalDisplayName = 'App Operator'; PrincipalUPN = 'appoperator@contoso.test'; RoleDefinitionId = 'rd-app-control'; RoleName = 'Custom Application Credential Operator'; IsSensitiveTarget = $false; CanControlApplications = $true; CanControlServicePrincipals = $false; DirectoryScopeId = '/'; AppScopeId = $null },
                [PSCustomObject]@{ PrincipalId = 'target-sp'; PrincipalType = '#microsoft.graph.servicePrincipal'; PrincipalDisplayName = 'Privileged Third Party SP'; PrincipalAppId = $null; RoleDefinitionId = 'rd-target'; RoleTemplateId = 'e8611ab8-c189-46e8-94e1-60213ab1f814'; RoleName = 'Privileged Role Administrator'; RoleTier = 'Critical'; IsSensitiveTarget = $true },
                [PSCustomObject]@{ PrincipalId = 'home-target-sp'; PrincipalType = '#microsoft.graph.servicePrincipal'; PrincipalDisplayName = 'Privileged Home SP'; PrincipalAppId = 'home-target-app'; RoleDefinitionId = 'rd-target'; RoleTemplateId = 'e8611ab8-c189-46e8-94e1-60213ab1f814'; RoleName = 'Privileged Role Administrator'; RoleTier = 'Critical'; IsSensitiveTarget = $true }
            )
        }
        Mock Get-ApplicationOwners {
            return @{ 'danger-app' = [PSCustomObject]@{ Status = 'Complete'; Owners = @(
                [PSCustomObject]@{ id = 'reader'; displayName = 'Reader'; userPrincipalName = 'reader@contoso.test' },
                [PSCustomObject]@{ id = 'ga'; displayName = 'GA'; userPrincipalName = 'ga@contoso.test' }
            ) } }
        }
        Mock Get-SPDirectCredentials { return @{} }
        Mock Get-AppInstanceLockStatus {
            return @{
                'danger-app' = [PSCustomObject]@{ State = 'NotConfigured'; IsCredentialLocked = $false }
                'target-app' = [PSCustomObject]@{ State = 'OAuthCredentialChangesLocked'; IsCredentialLocked = $true }
                'home-target-app' = [PSCustomObject]@{ State = 'OAuthCredentialChangesLocked'; IsCredentialLocked = $true }
            }
        }
        $script:CachedServicePrincipals = @(
            [PSCustomObject]@{ id = 'target-sp'; appId = 'target-app'; appOwnerOrganizationId = 'tenant-other' },
            [PSCustomObject]@{ id = 'home-target-sp'; appId = 'home-target-app'; appOwnerOrganizationId = 'tenant-home' }
        )

        $result = @(Invoke-AttackPathAnalysis)
        @($result | Where-Object PathType -eq 'App Owner Escalation').Count | Should -Be 1
        ($result | Where-Object PathType -eq 'App Owner Escalation').UserUPN | Should -Be 'reader@contoso.test'
        ($result | Where-Object PathType -eq 'App Owner Escalation').PermissionType | Should -Be 'Application'
        ($result | Where-Object PathType -eq 'App Owner Escalation').Severity | Should -Be 'CRITICAL'
        ($result | Where-Object PathType -eq 'App Owner Escalation').Result | Should -Be 'Can modify app credentials'
        ($result | Where-Object { $_.PathType -eq 'Role-Based SP Control' -and $_.UserUPN -eq 'operator@contoso.test' -and $_.AppId -eq 'target-app' }).Exploitability | Should -Be 'MitigatedByAppInstanceLock'
        ($result | Where-Object { $_.PathType -eq 'Role-Based SP Control' -and $_.UserUPN -eq 'appoperator@contoso.test' -and $_.AppId -eq 'home-target-app' }).Exploitability | Should -Be 'Direct'
    }

    It 'marks an owner path potential and preserves permission impact when role evidence is unavailable' {
        Mock Write-Banner {}
        Mock Write-Host {}
        Mock Write-SectionDivider {}
        Mock Write-Recommendation {}
        Mock Write-Reference {}
        Mock Export-AuditCsv {}
        Mock Get-ServicePrincipalsWithAppRoles {
            return @([PSCustomObject]@{
                SPId = 'directory-sp'; SPDisplayName = 'Directory Writer'; AppId = 'directory-app'; AppTenantType = 'HomeTenant'
                Permission = 'Directory.ReadWrite.All'; PermissionType = 'Application'; Risk = 'High'
                Reason = 'Near-full write access to directory objects, subject to protected-operation restrictions'
                AttackAction = 'modify directory objects allowed by Directory.ReadWrite.All'
            })
        }
        Mock Get-PrivilegedRoleAssignments {
            Set-CoverageState -Source 'RoleDefinitions' -State Unavailable -Detail 'denied'
            Set-CoverageState -Source 'ActiveRoleAssignments' -State Unavailable -Detail 'denied'
            return @()
        }
        Mock Get-ApplicationOwners {
            return @{ 'directory-app' = [PSCustomObject]@{ Status = 'Complete'; Owners = @(
                [PSCustomObject]@{ id = 'owner'; displayName = 'Owner'; userPrincipalName = 'owner@contoso.test' }
            ) } }
        }
        Mock Get-SPDirectCredentials { return @{} }
        Mock Get-AppInstanceLockStatus { return @{ 'directory-app' = [PSCustomObject]@{ State = 'Disabled'; IsCredentialLocked = $false } } }
        $script:CachedServicePrincipals = @([PSCustomObject]@{ id = 'directory-sp'; appId = 'directory-app'; appOwnerOrganizationId = 'tenant-home' })

        $result = @(Invoke-AttackPathAnalysis)
        $result.Count | Should -Be 1
        $result[0].Exploitability | Should -Be 'PotentialRoleUnknown'
        $result[0].UserRole | Should -Match '^Unknown'
        $result[0].Severity | Should -Be 'HIGH'
        $result[0].Result | Should -Be 'Near-full write access to directory objects, subject to protected-operation restrictions'
        $result[0].Result | Should -Not -Match 'GLOBAL ADMIN'
    }

    It 'does not query application owners or report unowned status for a third-party SP' {
        Mock Write-Banner {}
        Mock Write-Host {}
        Mock Write-Reference {}
        Mock Export-AuditCsv {}
        Mock Get-ServicePrincipalsWithAppRoles {
            return @([PSCustomObject]@{ SPId = 'third-sp'; SPDisplayName = 'Vendor'; AppId = 'vendor-app'; AppTenantType = 'ThirdParty'; Permission = 'Application.ReadWrite.All'; PermissionType = 'Application' })
        }
        Mock Get-PrivilegedRoleAssignments { return @() }
        Mock Get-ApplicationOwners { param($AppIds); $AppIds.Count | Should -Be 0; return @{} }
        Mock Get-SPDirectCredentials { return @{} }

        @(Invoke-AttackPathAnalysis).Count | Should -Be 0
        Should -Invoke Export-AuditCsv -ParameterFilter { $Name -eq 'UnownedPrivilegedApps' } -Times 0
    }
}

Describe 'Configuration behavior' {
    BeforeEach { Reset-TestState }
    It 'loads every documented behavioral option' {
        Mock Update-MicrosoftAppsLookup { return [System.Collections.Generic.HashSet[string]]::new() }

        Initialize-Config -EffectiveConfigPath (Join-Path $script:repoRoot 'config') -EffectiveInactiveDays 0

        $script:AuditConfig.filters.excludeDisabledApps | Should -BeFalse
        $script:AuditConfig.output.maxUsersInRoleAuditList | Should -Be 500
        $script:AuditConfig.credentialHygiene.preferredCredentialTypes | Should -Contain 'Federated'
        $script:AuditConfig.credentialHygiene.riskyCredentialTypes | Should -Contain 'SP-Secret'
        $script:DangerousPermissions[0].resourceAppId | Should -Be $script:MicrosoftGraphAppId
        $script:DangerousPermissions[0].attackAction | Should -Not -BeNullOrEmpty
    }

    It 'honors intentionally empty configured lists instead of restoring defaults' {
        $configPath = Join-Path $TestDrive 'empty-lists'
        New-Item -ItemType Directory -Path $configPath | Out-Null
        @'
{
  "filters": { "excludeAppIds": [] },
  "credentialHygiene": {
    "preferredCredentialTypes": [],
    "riskyCredentialTypes": [],
    "flagMultipleCredentials": false,
    "flagExpiredCredentials": false
  }
}
'@ | Set-Content (Join-Path $configPath 'audit-config.json')
        Mock Update-MicrosoftAppsLookup { return [System.Collections.Generic.HashSet[string]]::new() }

        Initialize-Config -EffectiveConfigPath $configPath -EffectiveInactiveDays 0

        @($script:AuditConfig.filters.excludeAppIds).Count | Should -Be 0
        @($script:AuditConfig.credentialHygiene.preferredCredentialTypes).Count | Should -Be 0
        @($script:AuditConfig.credentialHygiene.riskyCredentialTypes).Count | Should -Be 0
        $script:AuditConfig.credentialHygiene.flagMultipleCredentials | Should -BeFalse
        $script:AuditConfig.credentialHygiene.flagExpiredCredentials | Should -BeFalse
    }
}

Describe 'Graph collection and caching' {
    BeforeEach { Reset-TestState }

    It 'follows every Graph pagination link' {
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Uri -eq 'page-1') {
                return @{ value = @([PSCustomObject]@{ id = 'one' }); '@odata.nextLink' = 'page-2' }
            }
            if ($Uri -eq 'page-2') {
                return @{ value = @([PSCustomObject]@{ id = 'two' }) }
            }
            throw "Unexpected URI: $Uri"
        }

        $result = @(Get-AllGraphPages -Uri 'page-1')
        $result.id | Should -Be @('one', 'two')
        Should -Invoke Invoke-MgGraphRequest -Times 2 -Exactly
    }

    It 'resolves a shared resource service principal only once' {
        $script:AuditConfig.filters.excludeFirstPartyMicrosoftApps = $false
        $script:DangerousPermissions = @($script:DefaultDangerousPermissions | Where-Object type -eq 'Application')
        Mock Write-Host {}
        Mock Export-AuditCsv {}
        Mock Get-AllGraphPages {
            param($Uri)
            if ($Uri -match '/servicePrincipals\?') {
                return @(
                    [PSCustomObject]@{ id = 'client-1'; appId = 'app-1'; displayName = 'One'; appOwnerOrganizationId = 'tenant-home'; accountEnabled = $true },
                    [PSCustomObject]@{ id = 'client-2'; appId = 'app-2'; displayName = 'Two'; appOwnerOrganizationId = 'tenant-home'; accountEnabled = $true }
                )
            }
            if ($Uri -match 'appRoleAssignments') {
                return @([PSCustomObject]@{ appRoleId = 'role-1'; resourceId = 'graph-sp' })
            }
            throw "Unexpected URI: $Uri"
        }
        Mock Invoke-MgGraphRequest {
            return [PSCustomObject]@{
                id = 'graph-sp'; appId = $script:MicrosoftGraphAppId; displayName = 'Microsoft Graph'
                appRoles = @([PSCustomObject]@{ id = 'role-1'; value = 'Application.ReadWrite.All' })
            }
        }

        @(Get-ServicePrincipalsWithAppRoles).Count | Should -Be 2
        Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly
    }

    It 'marks a per-client grant failure partial while retaining other findings' {
        $script:AuditConfig.filters.excludeFirstPartyMicrosoftApps = $false
        $script:DangerousPermissions = @($script:DefaultDangerousPermissions | Where-Object type -eq 'Application')
        Mock Write-Host {}
        Mock Export-AuditCsv {}
        Mock Get-AllGraphPages {
            param($Uri)
            if ($Uri -match '/servicePrincipals\?') {
                return @(
                    [PSCustomObject]@{ id = 'good'; appId = 'app-good'; displayName = 'Good'; appOwnerOrganizationId = 'tenant-home'; accountEnabled = $true },
                    [PSCustomObject]@{ id = 'failed'; appId = 'app-failed'; displayName = 'Failed'; appOwnerOrganizationId = 'tenant-home'; accountEnabled = $true }
                )
            }
            if ($Uri -match 'failed/appRoleAssignments') { throw 'client denied' }
            if ($Uri -match 'good/appRoleAssignments') { return @([PSCustomObject]@{ appRoleId = 'role-1'; resourceId = 'graph-sp' }) }
            throw "Unexpected URI: $Uri"
        }
        Mock Invoke-MgGraphRequest {
            return [PSCustomObject]@{
                id = 'graph-sp'; appId = $script:MicrosoftGraphAppId; displayName = 'Microsoft Graph'
                appRoles = @([PSCustomObject]@{ id = 'role-1'; value = 'Application.ReadWrite.All' })
            }
        }

        @(Get-ServicePrincipalsWithAppRoles).Count | Should -Be 1
        $script:Coverage.ApplicationPermissionGrants.State | Should -Be 'Partial'
    }
}

Describe 'Microsoft first-party catalog cache' {
    BeforeEach { Reset-TestState }

    It 'validates and atomically stores a downloaded catalog' {
        $catalogPath = Join-Path $TestDrive 'download'
        New-Item -ItemType Directory -Path $catalogPath | Out-Null
        Mock Invoke-RestMethod {
            return @(
                [PSCustomObject]@{ AppId = '00000003-0000-0000-c000-000000000000'; AppDisplayName = 'Microsoft Graph' },
                [PSCustomObject]@{ AppId = '00000002-0000-0000-c000-000000000000'; AppDisplayName = 'Azure AD Graph' },
                [PSCustomObject]@{ AppId = "00000004-0000-0000-c000-000000000000$([char]0x00A0)"; AppDisplayName = 'Recoverable suffix' }
            )
        }

        $result = Update-MicrosoftAppsLookup -CatalogConfigPath $catalogPath
        $result.Count | Should -Be 3
        $result.Contains('00000003-0000-0000-c000-000000000000') | Should -BeTrue
        $result.Contains('00000002-0000-0000-c000-000000000000') | Should -BeTrue
        $result.Contains('00000004-0000-0000-c000-000000000000') | Should -BeTrue
        Test-Path (Join-Path $catalogPath 'MicrosoftApps.json') | Should -BeTrue
        Test-Path (Join-Path $catalogPath 'MicrosoftApps.json.tmp') | Should -BeFalse
        $script:Coverage.MicrosoftFirstPartyAppCatalog.State | Should -Be 'Complete'
    }

    It 'marks catalog coverage unavailable when download and cache are unavailable' {
        $catalogPath = Join-Path $TestDrive 'missing'
        New-Item -ItemType Directory -Path $catalogPath | Out-Null
        Mock Invoke-RestMethod { throw 'network unavailable' }

        (Update-MicrosoftAppsLookup -CatalogConfigPath $catalogPath).Count | Should -Be 0
        $script:Coverage.MicrosoftFirstPartyAppCatalog.State | Should -Be 'Unavailable'
    }
}

Describe 'Role fallback and evidence safety' {
    BeforeEach { Reset-TestState }

    It 'falls back to v1 role definitions and marks classification partial when beta is unavailable' {
        Mock Write-Host {}
        Mock Get-AllGraphPages {
            param($Uri)
            if ($Uri -match '/beta/.*/roleDefinitions') { throw 'beta unavailable' }
            if ($Uri -match '/v1\.0/.*/roleDefinitions') {
                return @([PSCustomObject]@{
                    id = 'rd-app-admin'; templateId = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
                    displayName = 'Application Administrator'; isBuiltIn = $true; isEnabled = $true; rolePermissions = @()
                })
            }
            if ($Uri -match 'roleAssignments') {
                return @([PSCustomObject]@{
                    roleDefinitionId = 'rd-app-admin'; principalId = 'user-1'; directoryScopeId = '/'; appScopeId = $null
                    principal = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Apps'; userPrincipalName = 'apps@contoso.test' }
                })
            }
            throw "Unexpected URI: $Uri"
        }

        $result = @(Get-PrivilegedRoleAssignments)
        $result[0].IsSensitiveTarget | Should -BeTrue
        $result[0].CanControlServicePrincipals | Should -BeTrue
        $result[0].DefinitionSource | Should -Be 'V1WithConfiguredSensitivityFallback'
        $script:Coverage.RoleDefinitions.State | Should -Be 'Partial'
    }

    It 'resolves an assignment definition omitted from the collection with an item lookup' {
        Mock Write-Host {}
        Mock Get-AllGraphPages {
            param($Uri)
            if ($Uri -match 'roleDefinitions') { return @() }
            if ($Uri -match 'roleAssignments') {
                return @([PSCustomObject]@{
                    roleDefinitionId = 'omitted-definition'; principalId = 'user-1'; directoryScopeId = '/'; appScopeId = $null
                    principal = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.user'; displayName = 'User'; userPrincipalName = 'user@contoso.test' }
                })
            }
            throw "Unexpected URI: $Uri"
        }
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            $Uri | Should -Be 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions/omitted-definition'
            return [PSCustomObject]@{
                id = 'omitted-definition'; templateId = '62e90394-69f5-4237-9190-012177145e10'
                displayName = 'Global Administrator'; isBuiltIn = $true; isEnabled = $true; isPrivileged = $true; rolePermissions = @()
            }
        }

        $result = @(Get-PrivilegedRoleAssignments)
        $result.Count | Should -Be 1
        $result[0].DefinitionSource | Should -Be 'MicrosoftGraphBetaItemFallback'
        $script:Coverage.RoleDefinitions.State | Should -Be 'Complete'
        Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly
    }

    It 'marks role-assigned group expansion as partial' {
        Mock Write-Host {}
        Mock Get-AllGraphPages {
            param($Uri)
            if ($Uri -match 'roleDefinitions') {
                return @([PSCustomObject]@{ id = 'rd-ga'; templateId = '62e90394-69f5-4237-9190-012177145e10'; displayName = 'Global Administrator'; isBuiltIn = $true; isEnabled = $true; isPrivileged = $true; rolePermissions = @() })
            }
            return @([PSCustomObject]@{
                roleDefinitionId = 'rd-ga'; principalId = 'group-1'; directoryScopeId = '/'; appScopeId = $null
                principal = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.group'; displayName = 'Tier Zero Group' }
            })
        }

        @(Get-PrivilegedRoleAssignments).Count | Should -Be 1
        $script:Coverage.RoleGroupMemberships.State | Should -Be 'Partial'
    }

    It 'does not label all users non-privileged when role evidence is unavailable' {
        Mock Write-Banner {}
        Mock Write-Host {}
        Mock Write-Reference {}
        Mock Export-AuditCsv {}
        Mock Get-PrivilegedRoleAssignments {
            Set-CoverageState -Source 'RoleDefinitions' -State Unavailable -Detail 'denied'
            Set-CoverageState -Source 'ActiveRoleAssignments' -State Unavailable -Detail 'denied'
            return @()
        }
        Mock Get-AllUsers {
            Set-CoverageState -Source 'Users' -State Complete
            return @([PSCustomObject]@{ id = 'user-1'; displayName = 'User'; userPrincipalName = 'user@contoso.test' })
        }

        $result = Invoke-RoleAudit
        @($result.NonPrivilegedUsers).Count | Should -Be 0
    }
}

Describe 'Owner, consent, and lock query states' {
    BeforeEach { Reset-TestState }

    It 'confirms an empty owner set only after both application queries succeed' {
        Mock Write-Host {}
        Mock Get-AllGraphPages {
            param($Uri)
            if ($Uri -match '/applications\?') { return @([PSCustomObject]@{ id = 'object-1'; appId = 'app-1' }) }
            if ($Uri -match '/owners') { return @() }
            throw "Unexpected URI: $Uri"
        }

        $result = Get-ApplicationOwners -AppIds 'app-1'
        $result['app-1'].Status | Should -Be 'Complete'
        @($result['app-1'].Owners).Count | Should -Be 0
        $script:Coverage.ApplicationOwners.State | Should -Be 'Complete'
    }

    It 'returns an unavailable lock state when the application query fails' {
        Mock Write-Host {}
        Mock Get-AllGraphPages { throw 'lock query denied' }

        $result = Get-AppInstanceLockStatus -AppIds 'app-1'
        $result['app-1'].State | Should -Be 'Unavailable'
        $script:Coverage.AppInstanceLocks.State | Should -Be 'Partial'
    }

    It 'does not call an unobservable publisher lock disabled' {
        Mock Write-Host {}
        Mock Get-AllGraphPages { return @() }

        $result = Get-AppInstanceLockStatus -AppIds 'third-party-app'
        $result['third-party-app'].State | Should -Be 'NotLocallyObservable'
        $result['third-party-app'].IsCredentialLocked | Should -BeNullOrEmpty
        $script:Coverage.AppInstanceLocks.State | Should -Be 'Partial'
    }

    It 'shows a custom tenant consent policy for review' {
        $script:AuditConfig.consentRisk.flagUserConsentedApps = $false
        Mock Write-Banner {}
        Mock Write-Host {}
        Mock Write-Reference {}
        Mock Export-AuditCsv {}
        Mock Get-TenantConsentPolicy {
            return [PSCustomObject]@{ defaultUserRolePermissions = [PSCustomObject]@{
                permissionGrantPoliciesAssigned = @('managePermissionGrantsForSelf.contoso-low-risk')
                allowedToCreateApps = $false; allowedToReadOtherUsers = $true
            } }
        }

        $result = @(Invoke-ConsentRiskAssessment)
        ($result | Where-Object Setting -eq 'User consent for apps').Value | Should -Be 'Custom policy: contoso-low-risk'
        ($result | Where-Object Setting -eq 'User consent for apps').Risk | Should -Be 'ⓘ  REVIEW'
    }

    It 'marks user consent grant retrieval unavailable instead of returning a trusted empty set' {
        Mock Write-Host {}
        Mock Get-AllGraphPages { throw 'grant query denied' }

        @(Get-UserConsentGrants).Count | Should -Be 0
        $script:Coverage.UserConsentGrants.State | Should -Be 'Unavailable'
    }
}

Describe 'Stale privilege safety' {
    BeforeEach { Reset-TestState }

    It 'queries the beta sign-in activity endpoint and records complete coverage' {
        Mock Write-Host {}
        Mock Get-AllGraphPages {
            param($Uri)
            $Uri | Should -Be 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities?$top=999'
            return @([PSCustomObject]@{ appId = 'app-1' })
        }

        $result = Get-SPSignInActivity
        $result.ContainsKey('app-1') | Should -BeTrue
        $script:Coverage.ServicePrincipalSignInActivity.State | Should -Be 'Complete'
    }

    It 'returns unavailable rather than classifying every app never-used when activity fails' {
        Mock Write-Host {}
        Mock Get-AllGraphPages { throw 'activity unavailable' }

        Get-SPSignInActivity | Should -BeNullOrEmpty
        $script:Coverage.ServicePrincipalSignInActivity.State | Should -Be 'Unavailable'
    }

    It 'stops before credential lookup when sign-in activity is unavailable' {
        Mock Write-Banner {}
        Mock Write-Host {}
        Mock Get-ServicePrincipalsWithAppRoles {
            return @([PSCustomObject]@{ AppId = 'app-1'; SPId = 'sp-1'; SPDisplayName = 'Danger'; AppTenantType = 'HomeTenant'; Permission = 'Application.ReadWrite.All'; PermissionType = 'Application' })
        }
        Mock Get-SPSignInActivity { return $null }
        Mock Get-AppCredentials { throw 'must not run' }
        Mock Get-SPDirectCredentials { throw 'must not run' }

        @(Invoke-StalePrivilegeDetection).Count | Should -Be 0
        $script:StalePrivilegeDataAvailable | Should -BeFalse
        Should -Invoke Get-AppCredentials -Times 0 -Exactly
        Should -Invoke Get-SPDirectCredentials -Times 0 -Exactly
    }
}

Describe 'Credential hygiene configuration' {
    BeforeEach { Reset-TestState }

    It 'applies configured risky credential types' {
        Mock Write-Banner {}
        Mock Write-Host {}
        Mock Write-Reference {}
        Mock Export-AuditCsv {}
        Mock Get-ServicePrincipalsWithAppRoles {
            return @([PSCustomObject]@{ AppId = 'app-1'; SPId = 'sp-1'; SPDisplayName = 'Danger'; AppTenantType = 'HomeTenant'; Permission = 'Application.ReadWrite.All'; PermissionType = 'Application' })
        }
        Mock Get-AppCredentials { return @{ 'app-1' = @([PSCustomObject]@{ Type = 'Secret'; Expired = $false }) } }
        Mock Get-SPDirectCredentials { return @{ 'sp-1' = @() } }
        Mock Get-AppInstanceLockStatus { return @{ 'app-1' = [PSCustomObject]@{ State = 'NotConfigured'; IsCredentialLocked = $false } } }

        $result = @(Invoke-CredentialHygieneAudit)
        $result[0].RiskLevel | Should -Match 'HIGH.*configured risky credential type'
    }

    It 'honors disabling the multiple-credential escalation rule' {
        $script:AuditConfig.credentialHygiene.flagMultipleCredentials = $false
        Mock Write-Banner {}
        Mock Write-Host {}
        Mock Write-Reference {}
        Mock Export-AuditCsv {}
        Mock Get-ServicePrincipalsWithAppRoles {
            return @([PSCustomObject]@{ AppId = 'app-1'; SPId = 'sp-1'; SPDisplayName = 'Danger'; AppTenantType = 'HomeTenant'; Permission = 'Application.ReadWrite.All'; PermissionType = 'Application' })
        }
        Mock Get-AppCredentials { return @{ 'app-1' = @([PSCustomObject]@{ Type = 'Secret'; Expired = $false }, [PSCustomObject]@{ Type = 'Secret'; Expired = $false }) } }
        Mock Get-SPDirectCredentials { return @{ 'sp-1' = @() } }
        Mock Get-AppInstanceLockStatus { return @{ 'app-1' = [PSCustomObject]@{ State = 'NotConfigured'; IsCredentialLocked = $false } } }

        $result = @(Invoke-CredentialHygieneAudit)
        $result[0].RiskLevel | Should -Match 'HIGH'
        $result[0].RiskLevel | Should -Not -Match 'multiple credentials'
    }
}

Describe 'Full-mode orchestration' {
    BeforeEach { Reset-TestState }

    It 'runs every audit mode and produces the summary without findings' {
        Mock Write-Banner {}
        Mock Write-Host {}
        Mock Export-AuditCsv {}
        Mock Write-AuditCoverageSummary {}
        Mock Invoke-PermissionAudit { return @() }
        Mock Invoke-RoleAudit { return [PSCustomObject]@{ PrivilegedUsers = @{}; NonPrivilegedUsers = @() } }
        Mock Invoke-AttackPathAnalysis { return @() }
        Mock Invoke-ShadowAdminDetection { return @() }
        Mock Invoke-StalePrivilegeDetection { $script:StalePrivilegeDataAvailable = $true; return @() }
        Mock Invoke-ConsentRiskAssessment { return @() }
        Mock Invoke-CredentialHygieneAudit { return @() }

        Invoke-FullAudit

        Should -Invoke Invoke-PermissionAudit -Times 1 -Exactly
        Should -Invoke Invoke-RoleAudit -Times 1 -Exactly
        Should -Invoke Invoke-AttackPathAnalysis -Times 1 -Exactly
        Should -Invoke Invoke-ShadowAdminDetection -Times 1 -Exactly
        Should -Invoke Invoke-StalePrivilegeDetection -Times 1 -Exactly
        Should -Invoke Invoke-ConsentRiskAssessment -Times 1 -Exactly
        Should -Invoke Invoke-CredentialHygieneAudit -Times 1 -Exactly
        Should -Invoke Write-AuditCoverageSummary -Times 1 -Exactly
    }
}
