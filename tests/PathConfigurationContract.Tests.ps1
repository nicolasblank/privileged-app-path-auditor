BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'Invoke-PrivilegedAudit.ps1')

    function Invoke-MgGraphRequest {
        param($Method, $Uri)
        throw "Unmocked Graph request: $Method $Uri"
    }

    $script:contractPathIds = @(
        'APP_OWNER_ESCALATION', 'SHADOW_ADMIN_SP', 'CONSENT_GRANT_ATTACK',
        'STALE_APP_EXPLOITATION', 'CREDENTIAL_THEFT_SECRET',
        'ROLE_BASED_SP_CONTROL', 'UNOWNED_PRIVILEGED_APP'
    )
}

Describe 'Attack-path catalogue runtime contract' {
    BeforeEach {
        Reset-AuditCoverage
        $script:CachedDangerousApps = $null
        $script:CachedRoleAssignments = $null
        $script:CachedRoleDefinitions = $null
        $script:CachedServicePrincipals = $null
        $script:CachedResourceServicePrincipals = @{}
        $script:ConnectedTenantId = 'home-tenant'
        $script:ExportPath = $null
        $script:contractExports = @{}
        $script:contractConfigPath = Join-Path $TestDrive 'catalogue'
        New-Item -ItemType Directory -Path $script:contractConfigPath -Force | Out-Null
        $script:contractSentinels = @($script:contractPathIds | ForEach-Object {
            @{
                id = $_; name = "SENTINEL-NAME-$_"; severity = 'Medium'
                description = "SENTINEL-DESCRIPTION-$_"
                remediation = @("SENTINEL-REMEDIATION-$_", "SENTINEL-SECOND-$_")
                chain = @("SENTINEL-CHAIN-$_")
                detection = @{ method = "SENTINEL-DETECTOR-$_"; graphQueries = @('GET /sentinel-detector') }
                references = @("https://example.test/SENTINEL-REFERENCE-$_")
            }
        })
        @{ paths = $script:contractSentinels } | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath (Join-Path $script:contractConfigPath 'attack-paths.json')

        Mock Update-MicrosoftAppsLookup { return ,([System.Collections.Generic.HashSet[string]]::new()) }
        Mock Invoke-RestMethod { throw 'No network allowed' }
        Mock Write-Host {}
        Mock Write-Recommendation {}
        Mock Write-Reference {}
        Mock Export-AuditCsv { param($Name, $Data); $script:contractExports[$Name] = @($Data) }

        $script:contractGrant = $true
        $script:contractHasOwner = $true
        $script:contractSP = @{
            id = 'client-sp'; appId = 'client-app'; displayName = 'Synthetic client'
            appOwnerOrganizationId = 'home-tenant'; accountEnabled = $true
        }
        $script:contractApp = @{
            id = 'app-object'; appId = 'client-app'; signInAudience = 'AzureADMyOrg'
            servicePrincipalLockConfiguration = @{ isEnabled = $false }
        }
        $script:contractDefinitions = @(
            @{ id = 'control'; displayName = 'Credential operator'; isBuiltIn = $false; isPrivileged = $false; rolePermissions = @(@{ allowedResourceActions = @('microsoft.directory/servicePrincipals/credentials/update') }) }
            @{ id = 'target'; displayName = 'Synthetic target role'; templateId = 'fe930be7-5e62-47db-91af-98c3a49a38b1'; isBuiltIn = $true; isPrivileged = $true; rolePermissions = @() }
        )
        $script:contractAssignments = @()
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Method -ne 'GET') { throw 'Only synthetic GET requests are allowed' }
            if ($Uri -match '/roleDefinitions$') { return @{ value = @($script:contractDefinitions) } }
            if ($Uri -match '/roleAssignments\?') { return @{ value = @($script:contractAssignments) } }
            if ($Uri -match '/servicePrincipals\?') { return @{ value = @($script:contractSP) } }
            if ($Uri -match '/client-sp/appRoleAssignments\?') {
                return @{ value = @(if ($script:contractGrant) { @{ appRoleId = 'grant-role'; resourceId = 'resource-sp' } }) }
            }
            if ($Uri -match '/servicePrincipals/resource-sp\?') {
                return @{ id = 'resource-sp'; appId = $script:MicrosoftGraphAppId; displayName = 'Synthetic resource'; appRoles = @(@{ id = 'grant-role'; value = 'AppRoleAssignment.ReadWrite.All' }) }
            }
            if ($Uri -match '/oauth2PermissionGrants\?') { return @{ value = @() } }
            if ($Uri -match '/applications\?') { return @{ value = @($script:contractApp) } }
            if ($Uri -match '/applications/app-object/owners\?') {
                return @{ value = @(if ($script:contractHasOwner) { @{ id = 'operator'; displayName = 'Synthetic owner'; userPrincipalName = 'operator@example.test' } }) }
            }
            if ($Uri -match '/servicePrincipals/client-sp\?') { return @{ id = 'client-sp'; passwordCredentials = @(); keyCredentials = @() } }
            throw "Unexpected synthetic URI: $Uri"
        }
        Initialize-Config -EffectiveConfigPath $script:contractConfigPath -EffectiveInactiveDays 0
    }

    AfterEach {
        Should -Invoke Update-MicrosoftAppsLookup -Times 1 -Exactly -ParameterFilter { $CatalogConfigPath -eq $script:contractConfigPath }
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly -ParameterFilter { $Uri -match 'sentinel-detector' }
        ($script:contractExports | ConvertTo-Json -Depth 10) | Should -Not -Match 'SENTINEL-(NAME|DESCRIPTION|CHAIN|DETECTOR|REFERENCE)'
        Should -Invoke Write-Host -Times 0 -Exactly -ParameterFilter { "$Object" -match 'SENTINEL-(NAME|DESCRIPTION|CHAIN|DETECTOR|REFERENCE)' }
        Should -Invoke Write-Reference -Times 0 -Exactly -ParameterFilter { $Url -like '*example.test*' }
    }

    It 'loads all seven IDs through Initialize-Config retaining only five runtime fields' {
        @($script:AttackPathDefs).Count | Should -Be 7
        @($script:AttackPathDefs.id) | Should -Be $script:contractPathIds
        foreach ($definition in $script:AttackPathDefs) {
            @($definition.Keys | Sort-Object) | Should -Be @('description', 'id', 'name', 'remediation', 'severity')
            $definition.name | Should -Be "SENTINEL-NAME-$($definition.id)"
            $definition.description | Should -Be "SENTINEL-DESCRIPTION-$($definition.id)"
            $definition.severity | Should -Be 'Medium'
            $definition.remediation | Should -Be @("SENTINEL-REMEDIATION-$($definition.id)", "SENTINEL-SECOND-$($definition.id)")
            foreach ($metadataField in @('chain', 'detection', 'references')) {
                $definition.ContainsKey($metadataField) | Should -BeFalse
            }
        }
    }

    It 'uses owner remediation and <ExpectedSeverity> severity with permission Risk <PermissionRisk>' -ForEach @(
        @{ PermissionRisk = 'Critical'; ExpectedSeverity = 'CRITICAL' }
        @{ PermissionRisk = $null; ExpectedSeverity = 'MEDIUM' }
    ) {
        ($script:DangerousPermissions | Where-Object { $_.name -eq 'AppRoleAssignment.ReadWrite.All' -and $_.type -eq 'Application' }).risk = $PermissionRisk
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 1
        $paths[0].PathId | Should -Be 'APP_OWNER_ESCALATION'
        $paths[0].PathType | Should -Be 'App Owner Escalation'
        $paths[0].Exploitability | Should -Be 'Direct'
        $paths[0].Severity | Should -Be $ExpectedSeverity
        $paths[0].Remediation | Should -Be 'SENTINEL-REMEDIATION-APP_OWNER_ESCALATION; SENTINEL-SECOND-APP_OWNER_ESCALATION'
        $script:contractExports.AttackPaths[0].Severity | Should -Be $ExpectedSeverity
        Should -Invoke Write-Recommendation -Times 1 -Exactly -ParameterFilter { $Items -contains 'SENTINEL-REMEDIATION-APP_OWNER_ESCALATION' }
        Test-AuditCoverageComplete -Sources @('RoleDefinitions', 'ActiveRoleAssignments', 'RoleGroupMemberships', 'ApplicationOwners', 'AppInstanceLocks') | Should -BeTrue
    }

    It 'uses role-control remediation but <ExpectedSeverity> from target tier or mitigation, not catalogue severity' -ForEach @(
        @{ Locked = $false; ExpectedSeverity = 'HIGH'; ExpectedState = 'Direct' }
        @{ Locked = $true; ExpectedSeverity = 'INFO'; ExpectedState = 'MitigatedByAppInstanceLock' }
    ) {
        $script:contractGrant = $false
        $script:contractApp.servicePrincipalLockConfiguration = @{ isEnabled = $Locked; allProperties = $Locked }
        $script:contractAssignments = @(
            @{ roleDefinitionId = 'control'; principalId = 'operator'; directoryScopeId = '/'; appScopeId = $null; principal = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Operator'; userPrincipalName = 'operator@example.test' } }
            @{ roleDefinitionId = 'target'; principalId = 'client-sp'; directoryScopeId = '/'; appScopeId = $null; principal = @{ '@odata.type' = '#microsoft.graph.servicePrincipal'; displayName = 'Synthetic client'; appId = 'client-app' } }
        )
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 1
        $paths[0].PathId | Should -Be 'ROLE_BASED_SP_CONTROL'
        $paths[0].PathType | Should -Be 'Role-Based SP Control'
        $paths[0].Exploitability | Should -Be $ExpectedState
        $paths[0].Severity | Should -Be $ExpectedSeverity
        $paths[0].Remediation | Should -Be 'SENTINEL-REMEDIATION-ROLE_BASED_SP_CONTROL; SENTINEL-SECOND-ROLE_BASED_SP_CONTROL'
        $script:contractExports.AttackPaths[0].Remediation | Should -Be $paths[0].Remediation
        Should -Invoke Write-Recommendation -Times 1 -Exactly -ParameterFilter { $Items -contains 'SENTINEL-REMEDIATION-ROLE_BASED_SP_CONTROL' }
        Test-AuditCoverageComplete -Sources @('RoleDefinitions', 'ActiveRoleAssignments', 'RoleGroupMemberships', 'AppInstanceLocks') | Should -BeTrue
    }

    It 'uses unowned remediation only for console recommendations, not a path or export severity/remediation' {
        $script:contractHasOwner = $false
        @(Invoke-AttackPathAnalysis).Count | Should -Be 0
        @($script:contractExports.AttackPaths).Count | Should -Be 0
        $unowned = @($script:contractExports.UnownedPrivilegedApps)
        $unowned.Count | Should -Be 1
        $unowned[0].AppId | Should -Be 'client-app'
        $unowned[0].PSObject.Properties.Name | Should -Not -Contain 'Severity'
        $unowned[0].PSObject.Properties.Name | Should -Not -Contain 'Remediation'
        ($unowned | ConvertTo-Json -Depth 10) | Should -Not -Match 'SENTINEL'
        Should -Invoke Write-Recommendation -Times 1 -Exactly -ParameterFilter { $Items -contains 'SENTINEL-REMEDIATION-UNOWNED_PRIVILEGED_APP' }
        Test-AuditCoverageComplete -Sources @('ApplicationOwners') | Should -BeTrue
    }

    It 'does not create detectors from catalogue metadata when complete evidence has no dangerous grant or role' {
        $script:contractGrant = $false
        @(Invoke-AttackPathAnalysis).Count | Should -Be 0
        Should -Invoke Export-AuditCsv -Times 0 -Exactly -ParameterFilter { $Name -in @('AttackPaths', 'UnownedPrivilegedApps') }
        Should -Invoke Write-Recommendation -Times 0 -Exactly
        Test-AuditCoverageComplete -Sources @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions', 'RoleDefinitions', 'ActiveRoleAssignments', 'RoleGroupMemberships') | Should -BeTrue
    }

    It 'limits catalogue variable references to initialization and the three attack-path lookups' {
        $tokens = $null
        $parseErrors = $null
        $sourceAst = [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $PSScriptRoot '..' 'Invoke-PrivilegedAudit.ps1'), [ref]$tokens, [ref]$parseErrors
        )
        $parseErrors | Should -BeNullOrEmpty
        $references = $sourceAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $node.VariablePath.UserPath -match '(^|:)AttackPathDefs$'
        }, $true)
        $referencingFunctions = @($references | ForEach-Object {
            $ancestor = $_.Parent
            while ($ancestor -and $ancestor -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) {
                $ancestor = $ancestor.Parent
            }
            $ancestor | Should -Not -BeNullOrEmpty
            $ancestor.Name
        } | Sort-Object -Unique)
        $referencingFunctions | Should -Be @('Initialize-Config', 'Invoke-AttackPathAnalysis')
        $lookupIds = @((Get-Command Invoke-AttackPathAnalysis).ScriptBlock.Ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.BinaryExpressionAst] -and
                $node.Operator -eq [System.Management.Automation.Language.TokenKind]::Ieq -and
                $node.Left -is [System.Management.Automation.Language.MemberExpressionAst] -and
                $node.Left.Member.Value -eq 'id' -and
                $node.Right -is [System.Management.Automation.Language.StringConstantExpressionAst]
        }, $true) | ForEach-Object { $_.Right.Value } | Sort-Object -Unique)
        $lookupIds | Should -Be @('APP_OWNER_ESCALATION', 'ROLE_BASED_SP_CONTROL', 'UNOWNED_PRIVILEGED_APP')
    }

    It 'does not use <Id> metadata to configure nonempty <Mode> output' -ForEach @(
        @{ Id = 'SHADOW_ADMIN_SP'; Mode = 'Invoke-ShadowAdminDetection'; Export = 'ShadowAdmins'; Count = 1 }
        @{ Id = 'CONSENT_GRANT_ATTACK'; Mode = 'Invoke-ConsentRiskAssessment'; Export = 'ConsentRisk'; Count = 3 }
        @{ Id = 'STALE_APP_EXPLOITATION'; Mode = 'Invoke-StalePrivilegeDetection'; Export = 'StalePrivilege'; Count = 1 }
        @{ Id = 'CREDENTIAL_THEFT_SECRET'; Mode = 'Invoke-CredentialHygieneAudit'; Export = 'CredentialHygiene'; Count = 1 }
    ) {
        $script:contractAssignments = @(
            @{ roleDefinitionId = 'target'; principalId = 'client-sp'; directoryScopeId = '/'; appScopeId = $null; principal = @{ '@odata.type' = '#microsoft.graph.servicePrincipal'; displayName = 'Synthetic client'; appId = 'client-app' } }
        )
        Mock Get-ServicePrincipalOwners {
            Set-CoverageState -Source 'ServicePrincipalOwners' -State Complete
            return @{ 'client-sp' = @(@{ id = 'operator'; displayName = 'Synthetic owner'; userPrincipalName = 'operator@example.test' }) }
        }
        Mock Get-AppCredentials {
            param($AppIds, $EvidenceStatus)
            $EvidenceStatus['client-app'] = 'Complete'
            Set-CoverageState -Source 'ApplicationCredentials' -State Complete
            return @{ 'client-app' = @([pscustomobject]@{
                Type = 'Secret'; IsCurrentlyValid = $true; Expired = $false
                StartDateTime = (Get-Date).AddDays(-1); EndDateTime = (Get-Date).AddDays(30)
            }) }
        }
        Mock Get-SPDirectCredentials {
            param($SPIds, $EvidenceStatus)
            if ($null -ne $EvidenceStatus) { $EvidenceStatus['client-sp'] = 'Complete' }
            Set-CoverageState -Source 'ServicePrincipalCredentials' -State Complete
            return @{ 'client-sp' = @() }
        }
        Mock Get-SPSignInActivity {
            Set-CoverageState -Source 'ServicePrincipalSignInActivity' -State Complete
            return @{ 'client-app' = @{ lastSignInActivity = @{ lastSignInDateTime = (Get-Date).AddDays(-120).ToString('o') } } }
        }
        Mock Get-TenantConsentPolicy {
            Set-CoverageState -Source 'TenantAuthorizationPolicy' -State Complete
            return @{ defaultUserRolePermissions = @{
                permissionGrantPoliciesAssigned = @('managePermissionGrantsForSelf.microsoft-user-default-legacy')
                allowedToCreateApps = $false; allowedToReadOtherUsers = $true
            } }
        }
        Mock Get-UserConsentGrants {
            Set-CoverageState -Source 'UserConsentGrants' -State Complete
            return @()
        }

        $rows = @(& $Mode)
        $rows.Count | Should -Be $Count
        @($script:contractExports[$Export]).Count | Should -Be $Count
        ($rows | ConvertTo-Json -Depth 10) | Should -Not -Match 'SENTINEL|MEDIUM'
        Should -Invoke Write-Recommendation -Times 0 -Exactly -ParameterFilter { ($Items -join '; ') -match 'SENTINEL' }
        Should -Invoke Write-Reference -Times 1 -Exactly
        switch ($Id) {
            'SHADOW_ADMIN_SP' {
                $rows[0].Remediation | Should -Be 'Remove user as SP owner or remove the SP role assignment'
                Test-AuditCoverageComplete -Sources @('RoleDefinitions', 'ActiveRoleAssignments', 'RoleGroupMemberships', 'ServicePrincipalOwners') | Should -BeTrue
            }
            'CONSENT_GRANT_ATTACK' {
                ($rows | Where-Object Setting -eq 'User consent for apps').Risk | Should -Match 'CRITICAL'
                Should -Invoke Write-Recommendation -Times 1 -Exactly
                Test-AuditCoverageComplete -Sources @('TenantAuthorizationPolicy', 'UserConsentGrants') | Should -BeTrue
            }
            'STALE_APP_EXPLOITATION' {
                $rows[0].ValidCredCount | Should -Be 1
                $rows[0].LastSignIn | Should -Match '120 days ago'
                $rows[0].PSObject.Properties.Name | Should -Not -Contain 'Severity'
                $rows[0].PSObject.Properties.Name | Should -Not -Contain 'Remediation'
                $script:StalePrivilegeDataAvailable | Should -BeTrue
                Should -Invoke Write-Recommendation -Times 1 -Exactly
            }
            'CREDENTIAL_THEFT_SECRET' {
                $rows[0].RiskLevel | Should -Match 'HIGH'
                $rows[0].CredType | Should -Be 'Secret'
                $rows[0].CredentialEvidence | Should -Be 'Complete'
            }
        }
    }
}

Describe 'Checked-in audit option description contracts' {
    BeforeAll {
        $script:contractAuditConfig = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..' 'config' 'audit-config.json') -Raw | ConvertFrom-Json
    }

    It 'limits the direct-SP credential critical claim to currently valid credentials' {
        $description = $script:contractAuditConfig.credentialHygiene.description
        $description | Should -Match 'currently valid'
        $description | Should -Not -Match 'Any direct SP credential'
    }

    It 'describes single-user consent scope without inferring who approved it' {
        $description = $script:contractAuditConfig.consentRisk.description
        $description | Should -Match 'single-user'
        $description | Should -Match 'approv'
        $description | Should -Not -Match 'not admin consent'
    }
}