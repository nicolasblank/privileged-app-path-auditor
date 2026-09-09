BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'Invoke-PrivilegedAudit.ps1')

    function Invoke-MgGraphRequest {
        param($Method, $Uri)
        throw "Unmocked Graph request: $Method $Uri"
    }

    function Reset-MissingEvidenceFixture {
        Reset-AuditCoverage
        $script:AuditConfig = $script:DefaultAuditConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        $script:DangerousPermissions = @($script:DefaultDangerousPermissions | Where-Object type -eq Application)
        $script:ConnectedTenantId = 'home'
        $script:MicrosoftAppIds = [System.Collections.Generic.HashSet[string]]::new()
        $script:CachedDangerousApps = $null
        $script:CachedResourceServicePrincipals = @{}
        $script:MissingExports = @{}
        $script:MissingResponses = @{}
        $script:PolicyUri = 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
        $script:GrantsUri = 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999'
        $script:ClientUri = 'https://graph.microsoft.com/v1.0/servicePrincipals/client?$select=displayName'
        $script:ResourceUri = 'https://graph.microsoft.com/v1.0/servicePrincipals/resource?$select=id,appId,displayName,appRoles,oauth2PermissionScopes'
        $script:NextUri = 'https://graph.microsoft.com/v1.0/synthetic/page-two'
        $script:MissingResponses[$script:PolicyUri] = @{
            defaultUserRolePermissions = @{
                permissionGrantPoliciesAssigned = @()
                allowedToCreateApps = $false
                allowedToReadOtherUsers = $true
            }
        }
        $script:MissingResponses[$script:GrantsUri] = @{ value = @(
            @{ id = 'grant-one'; clientId = 'client'; resourceId = 'resource'; principalId = 'user-one'; consentType = 'Principal'; scope = 'Mail.Read' }
            @{ id = 'grant-two'; clientId = 'client'; resourceId = 'other-resource'; principalId = 'user-two'; consentType = 'Principal'; scope = 'Files.Read' }
        ) }
        $script:MissingResponses[$script:ClientUri] = @{ displayName = 'Synthetic client' }
        $script:MissingResponses['https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled&$top=999'] = @{ value = @(
            @{ id = 'client'; appId = 'client-app'; displayName = 'Synthetic client'; appOwnerOrganizationId = 'home'; servicePrincipalType = 'Application'; accountEnabled = $true }
        ) }
        $script:AssignmentsUri = 'https://graph.microsoft.com/v1.0/servicePrincipals/client/appRoleAssignments?$select=id,appRoleId,resourceId,resourceDisplayName'
        $script:MissingResponses[$script:AssignmentsUri] = @{ value = @(@{ id = 'assignment'; appRoleId = 'dangerous-role'; resourceId = 'resource'; resourceDisplayName = 'Graph' }) }
        $script:MissingResponses[$script:ResourceUri] = @{
            id = 'resource'; appId = $script:MicrosoftGraphAppId; displayName = 'Graph'
            appRoles = @(@{ id = 'dangerous-role'; value = 'Application.ReadWrite.All' })
            oauth2PermissionScopes = @()
        }
    }

    function Get-MissingSummaryRow {
        param([string]$Section)
        $script:MissingExports.FullAuditSummary | Where-Object Section -eq $Section
    }
}

Describe 'P2 missing Graph evidence integration' {
    BeforeEach {
        Reset-MissingEvidenceFixture
        Mock Write-Host {}
        Mock Write-Banner {}
        Mock Write-Reference {}
        Mock Write-Recommendation {}
        Mock Write-AuditCoverageSummary {}
        Mock Export-AuditCsv { param($Name, $Data) $script:MissingExports[$Name] = @($Data) }
        Mock Invoke-RestMethod { throw 'Network forbidden' }
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Method -ne 'GET') { throw 'Only GET is allowed' }
            if (-not $script:MissingResponses.ContainsKey($Uri)) { throw "Unexpected synthetic URI: $Uri" }
            return $script:MissingResponses[$Uri]
        }
        Mock Invoke-RoleAudit { [pscustomobject]@{ PrivilegedUsers = @{}; NonPrivilegedUsers = @(); SPRoles = @(); CoverageComplete = $true } }
        Mock Invoke-AttackPathAnalysis { @() }
        Mock Invoke-ShadowAdminDetection { @() }
        Mock Invoke-StalePrivilegeDetection { @() }
        Mock Invoke-CredentialHygieneAudit { @() }
    }

    It 'keeps Full permission coverage partial for <Label> resource evidence' -ForEach @(
        @{ Label = 'null'; Missing = 'null' }
        @{ Label = 'missing identity'; Missing = 'id' }
        @{ Label = 'missing API identity'; Missing = 'appId' }
        @{ Label = 'missing role definitions'; Missing = 'appRoles' }
        @{ Label = 'null role definitions'; Missing = 'nullRoles' }
        @{ Label = 'malformed role definitions'; Missing = 'malformedRoles' }
        @{ Label = 'unresolved granted role'; Missing = 'unknownRole' }
        @{ Label = 'missing granted role value'; Missing = 'roleValue' }
        @{ Label = 'mismatched resource identity'; Missing = 'wrongId' }
    ) {
        switch ($Missing) {
            null { $script:MissingResponses[$script:ResourceUri] = $null }
            nullRoles { $script:MissingResponses[$script:ResourceUri].appRoles = $null }
            malformedRoles { $script:MissingResponses[$script:ResourceUri].appRoles = @{ id = 'dangerous-role'; value = 'Application.ReadWrite.All' } }
            unknownRole { $script:MissingResponses[$script:ResourceUri].appRoles = @() }
            roleValue { $script:MissingResponses[$script:ResourceUri].appRoles[0].Remove('value') }
            wrongId { $script:MissingResponses[$script:ResourceUri].id = 'wrong-resource' }
            default { $script:MissingResponses[$script:ResourceUri].Remove($Missing) }
        }
        Invoke-FullAudit
        $script:Coverage.ResourcePermissionDefinitions.State | Should -Be Partial
        Test-AuditCoverageComplete -Sources ResourcePermissionDefinitions | Should -BeFalse
        $row = Get-MissingSummaryRow PermissionAudit
        $row.CoverageState | Should -Be Partial
        $row.Finding | Should -Match 'Incomplete.*observed'
        Should -Invoke Write-Host -Times 0 -Exactly -ParameterFilter { "$Object" -match 'No configured dangerous permissions found' }
    }

    It 'retains a dangerous grant from another resource when one resource is null' {
        $script:MissingResponses[$script:AssignmentsUri].value += @{ id = 'missing-assignment'; appRoleId = 'missing-role'; resourceId = 'missing-resource' }
        $script:MissingResponses['https://graph.microsoft.com/v1.0/servicePrincipals/missing-resource?$select=id,appId,displayName,appRoles,oauth2PermissionScopes'] = $null
        Invoke-FullAudit
        $script:MissingExports.PermissionAudit.Count | Should -Be 1
        $script:MissingExports.PermissionAudit[0].Permission | Should -Be Application.ReadWrite.All
        (Get-MissingSummaryRow PermissionAudit).Count | Should -Be 1
        (Get-MissingSummaryRow PermissionAudit).CoverageState | Should -Be Partial
    }

    It 'accepts the default zero role without inventing permission evidence' {
        $script:MissingResponses[$script:AssignmentsUri].value[0].appRoleId = '00000000-0000-0000-0000-000000000000'
        $script:MissingResponses[$script:ResourceUri].appRoles = @()
        @(Get-ServicePrincipalsWithAppRoles).Count | Should -Be 0
        $script:Coverage.ResourcePermissionDefinitions.State | Should -Be Complete
    }

    It 'keeps delegated resource identity failures partial without losing usable application grants: <Missing>' -ForEach @(
        @{ Missing = 'null' }
        @{ Missing = 'id' }
        @{ Missing = 'appId' }
    ) {
        $script:DangerousPermissions += @($script:DefaultDangerousPermissions | Where-Object type -eq Delegated)
        $script:MissingResponses[$script:GrantsUri].value = @(@{
            id = 'delegated-grant'; clientId = 'client'; resourceId = 'delegated-resource'
            principalId = 'user-one'; consentType = 'Principal'; scope = 'Directory.AccessAsUser.All'
        })
        $resource = @{ id = 'delegated-resource'; appId = $script:MicrosoftGraphAppId; displayName = 'Graph' }
        if ($Missing -eq 'null') { $resource = $null } else { $resource.Remove($Missing) }
        $script:MissingResponses['https://graph.microsoft.com/v1.0/servicePrincipals/delegated-resource?$select=id,appId,displayName'] = $resource
        Invoke-FullAudit
        $script:MissingExports.PermissionAudit.Count | Should -Be 1
        $script:MissingExports.PermissionAudit[0].PermissionType | Should -Be Application
        $script:Coverage.ResourcePermissionDefinitions.State | Should -Be Partial
        (Get-MissingSummaryRow PermissionAudit).CoverageState | Should -Be Partial
    }

    It 'keeps a resolved non-dangerous role complete without broadening permission matching' {
        $script:MissingResponses[$script:ResourceUri].appRoles[0].value = 'User.Read.All'
        $script:MissingResponses[$script:ResourceUri].appId = 'unrelated-api'
        @(Get-ServicePrincipalsWithAppRoles).Count | Should -Be 0
        $script:Coverage.ResourcePermissionDefinitions.State | Should -Be Complete
    }

    It 'makes a null policy unavailable in Full while collecting independent grants' {
        $script:MissingResponses[$script:PolicyUri] = $null
        Invoke-FullAudit
        $script:Coverage.TenantAuthorizationPolicy.State | Should -Be Unavailable
        (Get-MissingSummaryRow ConsentRisk).CoverageState | Should -Be Partial
        $script:MissingExports.ConsentRisk.Count | Should -Be 0
        $script:MissingExports.UserConsentGrants.Count | Should -Be 2
        Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Uri -eq $script:GrantsUri }
    }

    It 'reviews missing policy subset <Missing> while retaining known settings' -ForEach @(
        @{ Missing = 'defaultUserRolePermissions'; Unknown = @('User consent for apps', 'Users can register apps', 'Users can read other users') }
        @{ Missing = 'permissionGrantPoliciesAssigned'; Unknown = @('User consent for apps') }
        @{ Missing = 'allowedToCreateApps'; Unknown = @('Users can register apps') }
        @{ Missing = 'allowedToReadOtherUsers'; Unknown = @('Users can read other users') }
    ) {
        if ($Missing -eq 'defaultUserRolePermissions') { $script:MissingResponses[$script:PolicyUri].Remove($Missing) }
        else { $script:MissingResponses[$script:PolicyUri].defaultUserRolePermissions.Remove($Missing) }
        Invoke-FullAudit
        $script:Coverage.TenantAuthorizationPolicy.State | Should -Be Partial
        (Get-MissingSummaryRow ConsentRisk).CoverageState | Should -Be Partial
        $rows = $script:MissingExports.ConsentRisk
        $rows.Count | Should -Be 3
        foreach ($row in $rows) {
            @($row.PSObject.Properties.Name) | Should -Be @('Setting', 'Value', 'Risk')
            if ($row.Setting -in $Unknown) {
                $row.Value | Should -Be Unknown
                $row.Risk | Should -Match REVIEW
            } else {
                $row.Value | Should -Not -Be Unknown
            }
        }
        $script:MissingExports.UserConsentGrants.Count | Should -Be 2
    }

    It 'does not coerce malformed or null <Field> policy evidence into a known value' -ForEach @(
        @{ Field = 'permissionGrantPoliciesAssigned'; Value = $null; Setting = 'User consent for apps' }
        @{ Field = 'permissionGrantPoliciesAssigned'; Value = 'custom-policy'; Setting = 'User consent for apps' }
        @{ Field = 'allowedToCreateApps'; Value = $null; Setting = 'Users can register apps' }
        @{ Field = 'allowedToCreateApps'; Value = 'false'; Setting = 'Users can register apps' }
        @{ Field = 'allowedToReadOtherUsers'; Value = $null; Setting = 'Users can read other users' }
    ) {
        $script:MissingResponses[$script:PolicyUri].defaultUserRolePermissions[$Field] = $Value
        $row = Invoke-ConsentRiskAssessment | Where-Object Setting -eq $Setting
        $row.Value | Should -Be Unknown
        $row.Risk | Should -Match REVIEW
        $script:Coverage.TenantAuthorizationPolicy.State | Should -Be Partial
    }

    It 'retains legitimate empty assignments and known boolean settings' {
        $rows = @(Invoke-ConsentRiskAssessment)
        $rows.Value | Should -Be @('Disabled', 'No', 'Yes')
        $rows[0].Risk | Should -Match GOOD
        $script:Coverage.TenantAuthorizationPolicy.State | Should -Be Complete
    }

    It 'does not treat a malformed default permissions container as observed settings' {
        $script:MissingResponses[$script:PolicyUri].defaultUserRolePermissions = @($script:MissingResponses[$script:PolicyUri].defaultUserRolePermissions)
        $rows = @(Invoke-ConsentRiskAssessment)
        $rows.Count | Should -Be 3
        @($rows | Where-Object Value -ne Unknown).Count | Should -Be 0
        @($rows | Where-Object Risk -notmatch REVIEW).Count | Should -Be 0
        $script:Coverage.TenantAuthorizationPolicy.State | Should -Be Partial
        $script:MissingExports.UserConsentGrants.Count | Should -Be 2
    }

    It 'retains observed Principal grants after a malformed later page: <Label>' -ForEach @(
        @{ Label = 'null'; Page = $null }
        @{ Label = 'missing value'; Page = @{} }
        @{ Label = 'null value'; Page = @{ value = $null } }
        @{ Label = 'object value'; Page = @{ value = @{ id = 'not-an-array' } } }
        @{ Label = 'string value'; Page = @{ value = 'not-an-array' } }
        @{ Label = 'null array item'; Page = @{ value = @(@{ id = 'untrusted'; consentType = 'Principal' }, $null) } }
        @{ Label = 'string array item'; Page = @{ value = @(@{ id = 'untrusted'; consentType = 'Principal' }, 'invalid') } }
        @{ Label = 'invalid next link'; Page = @{ value = @(); '@odata.nextLink' = 123 } }
        @{ Label = 'invalid next link with items'; Page = @{ value = @(@{ id = 'untrusted'; consentType = 'Principal' }); '@odata.nextLink' = 123 } }
    ) {
        $script:MissingResponses[$script:GrantsUri]['@odata.nextLink'] = $script:NextUri
        $script:MissingResponses[$script:NextUri] = $Page
        $rows = @(Get-UserConsentGrants)
        $rows.id | Should -Be @('grant-one', 'grant-two')
        $script:Coverage.UserConsentGrants.State | Should -Be Partial
        $complete = $true
        @(Get-AllGraphPages -Uri $script:GrantsUri -CoverageSource UserConsentGrants -CollectionComplete ([ref]$complete)).Count | Should -Be 2
        $complete | Should -BeFalse
        { Get-AllGraphPages -Uri $script:GrantsUri } | Should -Throw
        Invoke-FullAudit
        $script:MissingExports.UserConsentGrants.Count | Should -Be 2
        (Get-MissingSummaryRow ConsentRisk).CoverageState | Should -Be Partial
    }

    It 'fails without observed items for malformed first page <Label>' -ForEach @(
        @{ Label = 'null'; Page = $null }
        @{ Label = 'missing value'; Page = @{} }
        @{ Label = 'null value'; Page = @{ value = $null } }
        @{ Label = 'object value'; Page = @{ value = [pscustomobject]@{ id = 'not-an-array' } } }
        @{ Label = 'string value'; Page = @{ value = 'not-an-array' } }
    ) {
        $script:MissingResponses[$script:GrantsUri] = $Page
        { Get-AllGraphPages -Uri $script:GrantsUri -CoverageSource UserConsentGrants } | Should -Throw
        @(Get-UserConsentGrants).Count | Should -Be 0
        $script:Coverage.UserConsentGrants.State | Should -Be Unavailable
    }

    It 'fails on a malformed later page when the earlier page was empty' {
        $script:MissingResponses[$script:GrantsUri] = @{ value = @(); '@odata.nextLink' = $script:NextUri }
        $script:MissingResponses[$script:NextUri] = $null
        { Get-AllGraphPages -Uri $script:GrantsUri -CoverageSource UserConsentGrants } | Should -Throw
    }

    It 'accepts Hashtable and PSCustomObject pages with real empty arrays' {
        $script:MissingResponses[$script:GrantsUri] = [pscustomobject]@{ value = $script:MissingResponses[$script:GrantsUri].value; '@odata.nextLink' = $script:NextUri }
        $script:MissingResponses[$script:NextUri] = [pscustomobject]@{ value = @() }
        $complete = $false
        @(Get-AllGraphPages -Uri $script:GrantsUri -CoverageSource UserConsentGrants -CollectionComplete ([ref]$complete)).Count | Should -Be 2
        $complete | Should -BeTrue
    }

    It 'preserves unresolved client names and grant tuples in Full for <Label>' -ForEach @(
        @{ Label = 'null response'; Response = $null }
        @{ Label = 'missing name'; Response = @{ id = 'client' } }
        @{ Label = 'null name'; Response = @{ displayName = $null } }
        @{ Label = 'empty name'; Response = @{ displayName = '' } }
        @{ Label = 'malformed name'; Response = @{ displayName = @('invalid') } }
    ) {
        $script:MissingResponses[$script:ClientUri] = $Response
        Invoke-FullAudit
        $rows = $script:MissingExports.UserConsentGrants
        $rows.Count | Should -Be 2
        $rows.GrantId | Should -Be @('grant-one', 'grant-two')
        $rows.ResourceSPId | Should -Be @('resource', 'other-resource')
        $rows.ConsentPrincipalId | Should -Be @('user-one', 'user-two')
        $rows.ConsentedScopes | Should -Be @('Mail.Read', 'Files.Read')
        @($rows | Where-Object AppName -ne '[unresolved]').Count | Should -Be 0
        $script:Coverage.UserConsentClientResolution.State | Should -Be Partial
        (Get-MissingSummaryRow ConsentRisk).CoverageState | Should -Be Partial
        Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Uri -eq $script:ClientUri }
    }
}