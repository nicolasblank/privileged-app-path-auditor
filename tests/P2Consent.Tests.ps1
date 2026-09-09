BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'Invoke-PrivilegedAudit.ps1')

    function Invoke-MgGraphRequest {
        param($Method, $Uri)
        throw "Unmocked Graph request: $Method $Uri"
    }

    function Reset-P2ConsentState {
        $script:AuditConfig = $script:DefaultAuditConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        $script:AuditConfig.consentRisk.flagUserConsentedApps = $true
        $script:AuditConfig.output.truncateAfter = 20
        Reset-AuditCoverage
        $script:ConsentExports = @{}
        $script:ConsentConsole = [System.Collections.Generic.List[string]]::new()
        $script:ConsentPolicyUri = 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
        $script:ConsentGrantsUri = 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999'
        $script:ConsentClientUri = 'https://graph.microsoft.com/v1.0/servicePrincipals/client-one?$select=displayName'
        $script:ConsentResponses = @{}
        $script:ConsentResponses[$script:ConsentPolicyUri] = @{
            defaultUserRolePermissions = @{
                permissionGrantPoliciesAssigned = @('managePermissionGrantsForSelf.microsoft-user-default-low')
                allowedToCreateApps = $false
                allowedToReadOtherUsers = $true
            }
        }
        $script:ConsentResponses[$script:ConsentGrantsUri] = @{ value = @(
            @{ id = 'grant-one'; clientId = 'client-one'; resourceId = 'resource-one'; principalId = 'beneficiary-one'; consentType = 'Principal'; scope = 'Files.Read Mail.Read' }
            @{ id = 'grant-two'; clientId = 'client-one'; resourceId = 'resource-two'; principalId = 'beneficiary-one'; consentType = 'Principal'; scope = 'Files.Read' }
            @{ id = 'grant-three'; clientId = 'client-one'; resourceId = 'resource-one'; principalId = 'beneficiary-two'; consentType = 'Principal'; scope = 'Mail.Send' }
            @{ id = 'grant-tenant'; clientId = 'client-one'; resourceId = 'resource-one'; principalId = $null; consentType = 'AllPrincipals'; scope = 'Directory.Read.All' }
        ) }
        $script:ConsentResponses[$script:ConsentClientUri] = @{ displayName = 'Synthetic client' }
    }
}

Describe 'P2 additive user consent policy interpretation' {
    It 'preserves <Label> classification and every effective self-consent policy ID' -ForEach @(
        @{ Label = 'disabled'; Ids = @(); State = 'Disabled'; Risk = 'GOOD' }
        @{ Label = 'legacy'; Ids = @('microsoft-user-default-legacy'); State = 'AllowedForAllApps'; Risk = 'HIGH' }
        @{ Label = 'low-risk'; Ids = @('microsoft-user-default-low'); State = 'RestrictedBuiltIn'; Risk = 'REVIEW' }
        @{ Label = 'custom'; Ids = @('custom-one'); State = 'CustomPolicy'; Risk = 'REVIEW' }
        @{ Label = 'low-risk plus custom'; Ids = @('microsoft-user-default-low', 'custom-one'); State = 'CustomPolicy'; Risk = 'REVIEW' }
        @{ Label = 'custom plus low-risk'; Ids = @('custom-one', 'microsoft-user-default-low'); State = 'CustomPolicy'; Risk = 'REVIEW' }
        @{ Label = 'multiple unknown policies'; Ids = @('custom-one', 'custom-two'); State = 'CustomPolicy'; Risk = 'REVIEW' }
        @{ Label = 'legacy plus custom'; Ids = @('microsoft-user-default-legacy', 'custom-one'); State = 'AllowedForAllApps'; Risk = 'HIGH' }
        @{ Label = 'legacy plus low-risk'; Ids = @('microsoft-user-default-legacy', 'microsoft-user-default-low'); State = 'AllowedForAllApps'; Risk = 'HIGH' }
    ) {
        $assigned = @($Ids | ForEach-Object { "managePermissionGrantsForSelf.$_" })
        $result = Resolve-UserConsentPolicyAssignment -AssignedPolicies $assigned
        $result.State | Should -Be $State
        $result.Risk | Should -Be $Risk
        @($result.PolicyIds).Count | Should -Be $Ids.Count
        foreach ($policyId in $Ids) { $result.PolicyIds | Should -Contain $policyId }
    }

    It 'allows a sole effective low-risk policy despite duplicates and unrelated actions' {
        $result = Resolve-UserConsentPolicyAssignment @(
            'managePermissionGrantsForSelf.microsoft-user-default-low'
            'managePermissionGrantsForSelf.microsoft-user-default-low'
            'managePermissionGrantsForOwnedResource.custom-one'
            'microsoft.directory/users/read'
        )
        $result.State | Should -Be 'RestrictedBuiltIn'
        @($result.PolicyIds).Count | Should -Be 1
    }
}

Describe 'P2 consent mode with real collectors and mocked Graph' {
    BeforeEach {
        Reset-P2ConsentState
        Mock Write-Banner {}
        Mock Write-Reference {}
        Mock Write-Host { param($Object) $script:ConsentConsole.Add([string]$Object) }
        Mock Export-AuditCsv { param($Name, $Data) $script:ConsentExports[$Name] = @($Data) }
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Method -ne 'GET') { throw 'Only GET is allowed' }
            if (-not $script:ConsentResponses.ContainsKey($Uri)) { throw "Unexpected synthetic URI: $Uri" }
            $response = $script:ConsentResponses[$Uri]
            if ($response -is [string]) { throw $response }
            return $response
        }
    }

    It 'reviews additive <Label> assignments without claiming low-risk-only authority' -ForEach @(
        @{ Label = 'low-risk plus custom'; Ids = @('microsoft-user-default-low', 'custom-one') }
        @{ Label = 'multiple unknown'; Ids = @('custom-one', 'custom-two') }
    ) {
        $script:ConsentResponses[$script:ConsentPolicyUri].defaultUserRolePermissions.permissionGrantPoliciesAssigned = @(
            $Ids | ForEach-Object { "managePermissionGrantsForSelf.$_" }
        )
        $findings = @(Invoke-ConsentRiskAssessment)
        $finding = $findings | Where-Object Setting -eq 'User consent for apps'
        $finding.Risk | Should -Match 'REVIEW'
        $finding.Value | Should -Not -Match 'low-risk only|Disabled'
        foreach ($policyId in $Ids) { $finding.Value | Should -Match ([regex]::Escape($policyId)) }
    }

    It 'labels legacy authority as user-consentable and preserves all assigned IDs' {
        $script:ConsentResponses[$script:ConsentPolicyUri].defaultUserRolePermissions.permissionGrantPoliciesAssigned = @(
            'managePermissionGrantsForSelf.microsoft-user-default-legacy'
            'managePermissionGrantsForSelf.custom-one'
        )
        $finding = Invoke-ConsentRiskAssessment | Where-Object Setting -eq 'User consent for apps'
        $finding.Value | Should -Match 'user-consentable'
        $finding.Value | Should -Not -Match 'Allowed \(all permissions\)'
        $finding.Value | Should -Match 'microsoft-user-default-legacy'
        $finding.Value | Should -Match 'custom-one'
        $finding.Risk | Should -Match 'CRITICAL|HIGH'
        ($script:ConsentConsole -join "`n") | Should -Not -Match '(?i)user-consented|user.approved|not admin.consented'
    }

    It 'keeps the settings row shape and names and exposes the sole low-risk policy ID' {
        $findings = @(Invoke-ConsentRiskAssessment)
        $findings.Count | Should -Be 3
        $findings.Setting | Should -Be @('User consent for apps', 'Users can register apps', 'Users can read other users')
        foreach ($finding in $findings) {
            @($finding.PSObject.Properties.Name) | Should -Be @('Setting', 'Value', 'Risk')
        }
        $findings[0].Value | Should -Match 'low-risk only'
        $findings[0].Value | Should -Match 'microsoft-user-default-low'
        $script:ConsentExports.ConsentRisk.Count | Should -Be 3
    }

    It 'exports every observed Principal grant without merging resources scopes or beneficiaries' {
        $null = Invoke-ConsentRiskAssessment
        $rows = $script:ConsentExports.UserConsentGrants
        $rows.Count | Should -Be 3
        foreach ($grant in $script:ConsentResponses[$script:ConsentGrantsUri].value | Where-Object consentType -eq 'Principal') {
            $row = @($rows | Where-Object GrantId -eq $grant.id)
            $row.Count | Should -Be 1
            $row[0].ClientSPId | Should -Be $grant.clientId
            $row[0].ResourceSPId | Should -Be $grant.resourceId
            $row[0].ConsentPrincipalId | Should -Be $grant.principalId
            $row[0].ConsentType | Should -Be $grant.consentType
            $row[0].ConsentedScopes | Should -BeExactly $grant.scope
            $row[0].AppName | Should -Be 'Synthetic client'
        }
        $rows.GrantId | Should -Not -Contain 'grant-tenant'
        $script:Coverage.UserConsentGrants.State | Should -Be 'Complete'
    }

    It 'does not attribute an admin-created Principal grant to its beneficiary as approver' {
        $script:ConsentResponses[$script:ConsentGrantsUri].value = @($script:ConsentResponses[$script:ConsentGrantsUri].value[0])
        $null = Invoke-ConsentRiskAssessment
        $row = $script:ConsentExports.UserConsentGrants[0]
        $row.ConsentPrincipalId | Should -Be 'beneficiary-one'
        @($row.PSObject.Properties.Name | Sort-Object) | Should -Be @(
            'AppName', 'ClientSPId', 'ConsentedScopes', 'ConsentPrincipalId', 'ConsentType', 'GrantId', 'ResourceSPId' | Sort-Object
        )
        $console = $script:ConsentConsole -join "`n"
        $console | Should -Match '(?i)single-user delegated'
        $console | Should -Not -Match '(?i)user-consented|user.approved|not admin.consented|consenting.?users'
    }

    It 'resolves the display name once per client while retaining all of its grants' {
        $null = Invoke-ConsentRiskAssessment
        Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Uri -eq $script:ConsentClientUri }
        $script:ConsentExports.UserConsentGrants.Count | Should -Be 3
        $script:Coverage.UserConsentClientResolution.State | Should -Be 'Complete'
    }

    It 'truncates only the displayed grant rows' {
        $script:AuditConfig.output.truncateAfter = 1
        $null = Invoke-ConsentRiskAssessment
        $script:ConsentExports.UserConsentGrants.Count | Should -Be 3
        $console = $script:ConsentConsole -join "`n"
        $console | Should -Match 'grant-one'
        $console | Should -Not -Match 'grant-two|grant-three'
        $console | Should -Match '2 more'
    }

    It 'retains every grant tuple when its client cannot be resolved and caches the failed lookup' {
        $script:ConsentResponses[$script:ConsentClientUri] = 'Synthetic client lookup denied'
        $null = Invoke-ConsentRiskAssessment
        $rows = $script:ConsentExports.UserConsentGrants
        $rows.Count | Should -Be 3
        $rows.GrantId | Should -Be @('grant-one', 'grant-two', 'grant-three')
        @($rows | Where-Object AppName -ne '[unresolved]').Count | Should -Be 0
        $script:Coverage.UserConsentClientResolution.State | Should -Be 'Partial'
        $script:Coverage.UserConsentGrants.State | Should -Be 'Complete'
        Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Uri -eq $script:ConsentClientUri }
    }

    It 'retains later-page grants and marks a subsequent pagination failure partial' {
        $nextUri = 'https://graph.microsoft.com/v1.0/consent-fixture/page-two'
        $failedUri = 'https://graph.microsoft.com/v1.0/consent-fixture/page-three'
        $script:ConsentResponses[$script:ConsentGrantsUri]['@odata.nextLink'] = $nextUri
        $script:ConsentResponses[$nextUri] = @{
            value = @(@{ id = 'grant-four'; clientId = 'client-two'; resourceId = 'resource-three'; principalId = 'beneficiary-three'; consentType = 'Principal'; scope = 'User.Read' })
            '@odata.nextLink' = $failedUri
        }
        $script:ConsentResponses[$failedUri] = 'Synthetic page failure'
        $script:ConsentResponses['https://graph.microsoft.com/v1.0/servicePrincipals/client-two?$select=displayName'] = @{ displayName = 'Second synthetic client' }
        $null = Invoke-ConsentRiskAssessment
        $script:ConsentExports.UserConsentGrants.GrantId | Should -Be @('grant-one', 'grant-two', 'grant-three', 'grant-four')
        $script:Coverage.UserConsentGrants.State | Should -Be 'Partial'
        ($script:Coverage.UserConsentGrants.Details -join '; ') | Should -Match 'Synthetic page failure'
        $script:Coverage.TenantAuthorizationPolicy.State | Should -Be 'Complete'
    }

    It 'continues grant collection after policy failure without fabricating policy findings' {
        $script:ConsentResponses[$script:ConsentPolicyUri] = 'Synthetic policy denied'
        $findings = @(Invoke-ConsentRiskAssessment)
        $findings.Count | Should -Be 0
        $script:ConsentExports.UserConsentGrants.Count | Should -Be 3
        $script:Coverage.TenantAuthorizationPolicy.State | Should -Be 'Unavailable'
        $script:Coverage.UserConsentGrants.State | Should -Be 'Complete'
        @($script:ConsentExports.ConsentRisk).Count | Should -Be 0
        ($script:ConsentConsole -join "`n") | Should -Not -Match 'Disabled|GOOD|Skipping'
        Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Uri -eq $script:ConsentGrantsUri }
    }

    It 'retains policy findings when the independent grants source is unavailable' {
        $script:ConsentResponses[$script:ConsentGrantsUri] = 'Synthetic grants denied'
        $findings = @(Invoke-ConsentRiskAssessment)
        $findings.Count | Should -Be 3
        $script:ConsentExports.ContainsKey('UserConsentGrants') | Should -BeFalse
        $script:Coverage.TenantAuthorizationPolicy.State | Should -Be 'Complete'
        $script:Coverage.UserConsentGrants.State | Should -Be 'Unavailable'
        ($script:ConsentConsole -join "`n") | Should -Not -Match '(?i)No .*grants found'
    }

    It 'does not query grants when the inventory flag is false and policy failure is <PolicyFails>' -ForEach @(
        @{ PolicyFails = $false }
        @{ PolicyFails = $true }
    ) {
        $script:AuditConfig.consentRisk.flagUserConsentedApps = $false
        if ($PolicyFails) { $script:ConsentResponses[$script:ConsentPolicyUri] = 'Synthetic policy denied' }
        $null = Invoke-ConsentRiskAssessment
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly -ParameterFilter { $Uri -match '/oauth2PermissionGrants|/servicePrincipals/' }
        $script:Coverage.Contains('UserConsentGrants') | Should -BeFalse
    }

    It 'accepts a successful <Label> grant collection as complete and empty' -ForEach @(
        @{ Label = 'PSCustomObject empty value'; Response = [pscustomobject]@{ value = @() } }
        @{ Label = 'empty value'; Response = @{ value = @() } }
    ) {
        $script:ConsentResponses[$script:ConsentGrantsUri] = $Response
        @(Get-UserConsentGrants).Count | Should -Be 0
        $findings = @(Invoke-ConsentRiskAssessment)
        $findings.Count | Should -Be 3
        $script:Coverage.UserConsentGrants.State | Should -Be 'Complete'
        $script:ConsentExports.ContainsKey('UserConsentGrants') | Should -BeFalse
        ($script:ConsentConsole -join "`n") | Should -Match '(?i)No single-user delegated permission grants found'
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly -ParameterFilter { $Uri -match '/servicePrincipals/' }
    }

    It 'preserves unavailable coverage for a missing Graph response rather than a successful empty page' {
        $script:ConsentResponses[$script:ConsentGrantsUri] = $null
        $null = Invoke-ConsentRiskAssessment
        $script:Coverage.UserConsentGrants.State | Should -Be 'Unavailable'
        $script:ConsentExports.ContainsKey('UserConsentGrants') | Should -BeFalse
        ($script:ConsentConsole -join "`n") | Should -Not -Match '(?i)No .*grants found'
    }
}