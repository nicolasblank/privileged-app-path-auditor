BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'Invoke-PrivilegedAudit.ps1')

    function Reset-IsolationCollections {
        $script:CachedDangerousApps = $null
        $script:CachedRoleAssignments = $null
        $script:CachedRoleDefinitions = $null
        $script:CachedServicePrincipals = $null
        $script:CachedResourceServicePrincipals = @{}
    }

    function Get-IsolationSummary {
        param([string]$Section)
        $script:isolationExports.FullAuditSummary | Where-Object Section -eq $Section
    }
}

Describe 'P2 Full mode isolation through real collectors' {
    BeforeEach {
        Reset-AuditCoverage
        Reset-IsolationCollections
        $script:AuditConfig = $script:DefaultAuditConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        $script:DangerousPermissions = $script:DefaultDangerousPermissions
        $script:PrivilegedRoles = $script:DefaultPrivilegedRoles
        $script:AttackPathDefs = @()
        $script:ConnectedTenantId = 'synthetic-home'
        $script:MicrosoftAppIds = [System.Collections.Generic.HashSet[string]]::new()
        $script:isolationFailure = 'sp-a'
        $script:isolationFailureKind = 'InvalidDates'
        $script:isolationExports = @{}
        $script:isolationRequests = [System.Collections.Generic.List[object]]::new()
        $script:isolationSPs = @('a', 'b' | ForEach-Object {
            [pscustomobject]@{
                id = "sp-$_"; appId = "app-$_"; displayName = "Synthetic $_"
                appOwnerOrganizationId = 'synthetic-home'; servicePrincipalType = 'Application'; accountEnabled = $true
            }
        })
        Set-CoverageState -Source MicrosoftFirstPartyAppCatalog -State Complete
        Mock Get-Date { [datetime]'2026-09-09T12:00:00Z' }
        Mock Write-Host {}
        Mock Write-Banner {}
        Mock Write-SectionDivider {}
        Mock Write-Recommendation {}
        Mock Write-Reference {}
        Mock Export-AuditCsv { param($Name, $Data); $script:isolationExports[$Name] = @($Data) }
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Method -ne 'GET') { throw 'Only synthetic GET requests are allowed' }
            if ($Uri -match '/servicePrincipals\?') { return @{ value = $script:isolationSPs } }
            if ($Uri -match '/servicePrincipals/sp-([ab])/appRoleAssignments') {
                return @{ value = @(if ($Matches[1] -eq 'a') {
                    @{ appRoleId = 'permission-id'; resourceId = 'graph-sp'; resourceDisplayName = 'Microsoft Graph' }
                }) }
            }
            if ($Uri -match '/servicePrincipals/graph-sp\?') {
                return @{ id = 'graph-sp'; appId = $script:MicrosoftGraphAppId; appRoles = @(@{ id = 'permission-id'; value = 'Application.ReadWrite.All' }) }
            }
            if ($Uri -match '/roleDefinitions$') {
                return @{ value = @(@{
                    id = 'sensitive-role'; displayName = 'Synthetic sensitive role'; isBuiltIn = $true
                    templateId = 'e8611ab8-c189-46e8-94e1-60213ab1f814'; isEnabled = $true; isPrivileged = $true
                    rolePermissions = @()
                }) }
            }
            if ($Uri -match '/roleAssignments\?') {
                return @{ value = @(@{
                    roleDefinitionId = 'sensitive-role'; principalId = 'sp-b'; directoryScopeId = '/'; appScopeId = $null
                    principal = @{ '@odata.type' = '#microsoft.graph.servicePrincipal'; displayName = 'Synthetic b'; appId = 'app-b' }
                }) }
            }
            if ($Uri -match '/(oauth2PermissionGrants|users)\?') { return @{ value = @() } }
            if ($Uri -match '/applications\?') {
                $appId = if ($Uri -match 'app-b') { 'app-b' } else { 'app-a' }
                return @{ value = @(@{
                    id = "object-$appId"; appId = $appId; signInAudience = 'AzureADMyOrg'
                    servicePrincipalLockConfiguration = $null; passwordCredentials = @(); keyCredentials = @()
                }) }
            }
            if ($Uri -match '/federatedIdentityCredentials') { return @{ value = @() } }
            if ($Uri -match '/owners\?') {
                return @{ value = @(@{ id = 'synthetic-owner'; displayName = 'Synthetic owner'; userPrincipalName = 'owner@example.test' }) }
            }
            if ($Uri -match '/servicePrincipals/(sp-[ab])\?') {
                $spId = $Matches[1]
                $mode = (Get-PSCallStack | Where-Object Command -in @('Invoke-AttackPathAnalysis', 'Invoke-ShadowAdminDetection', 'Invoke-StalePrivilegeDetection', 'Invoke-CredentialHygieneAudit') | Select-Object -First 1).Command
                $script:isolationRequests.Add([pscustomobject]@{ Mode = $mode; SPId = $spId })
                if ($spId -eq $script:isolationFailure -and $script:isolationFailureKind -eq 'RequestFailure') { throw "Synthetic credential request failure for $spId" }
                return @{ id = $spId; keyCredentials = @(); passwordCredentials = @(@{
                    keyId = "key-$spId"; displayName = 'Synthetic credential'
                    startDateTime = if ($spId -eq $script:isolationFailure) { 'bad-date' } else { '2026-09-01T00:00:00Z' }
                    endDateTime = '2026-10-01T00:00:00Z'
                }) }
            }
            if ($Uri -match '/reports/servicePrincipalSignInActivities') {
                return @{ value = @(@{ appId = 'app-a'; lastSignInActivity = @{ lastSignInDateTime = '2026-09-09T00:00:00Z' } }) }
            }
            if ($Uri -match '/policies/authorizationPolicy') {
                return @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @() }; allowEmailVerifiedUsersToJoinOrganization = $false }
            }
            throw "Unexpected synthetic URI: $Uri"
        }
    }

    It 'isolates permission-only A credential failure from role-only B in Full ShadowAdmins' {
        $standalone = @(Invoke-ShadowAdminDetection)
        $standalone.Count | Should -Be 1
        Test-AuditCoverageComplete | Should -BeTrue
        $script:isolationRequests.Clear()
        Reset-AuditCoverage
        Reset-IsolationCollections
        Set-CoverageState -Source MicrosoftFirstPartyAppCatalog -State Complete

        Invoke-FullAudit

        @($script:isolationRequests | Where-Object Mode -eq Invoke-AttackPathAnalysis | Select-Object -ExpandProperty SPId -Unique | Sort-Object) | Should -Be @('sp-a', 'sp-b')
        @($script:isolationRequests | Where-Object Mode -eq Invoke-ShadowAdminDetection | Select-Object -ExpandProperty SPId -Unique) | Should -Be @('sp-b')
        $script:isolationExports.ShadowAdmins.Count | Should -Be $standalone.Count
        $script:Coverage.ServicePrincipalCredentials.State | Should -Be Partial
        ($script:Coverage.ServicePrincipalCredentials.Details -join '; ') | Should -Match 'sp-a'
        (Get-IsolationSummary DataCoverage).CoverageState | Should -Be Partial
        (Get-IsolationSummary AttackPaths).CoverageState | Should -Be Partial
        (Get-IsolationSummary StalePrivilege).CoverageState | Should -Be Partial
        (Get-IsolationSummary CredentialHygiene).CoverageState | Should -Be Partial
        $shadow = Get-IsolationSummary ShadowAdmins
        $shadow.CoverageState | Should -Be Complete
        $shadow.CoverageDetail | Should -Match 'ServicePrincipalCredentials: Complete'
        $shadow.CoverageDetail | Should -Not -Match 'sp-a|bad-date'
    }

    It 'isolates role-only B <FailureKind> from permission-only A in Full <Section>' -ForEach @(
        foreach ($section in @('StalePrivilege', 'CredentialHygiene')) {
            @{ Section = $section; FailureKind = 'InvalidDates' }
            @{ Section = $section; FailureKind = 'RequestFailure' }
        }
    ) {
        $script:isolationFailure = 'sp-b'
        $script:isolationFailureKind = $FailureKind
        Invoke-FullAudit

        foreach ($mode in @('Invoke-StalePrivilegeDetection', 'Invoke-CredentialHygieneAudit')) {
            @($script:isolationRequests | Where-Object Mode -eq $mode | Select-Object -ExpandProperty SPId -Unique) | Should -Be @('sp-a')
        }
        $script:Coverage.ServicePrincipalCredentials.State | Should -Be Partial
        ($script:Coverage.ServicePrincipalCredentials.Details -join '; ') | Should -Match 'sp-b'
        (Get-IsolationSummary DataCoverage).CoverageState | Should -Be Partial
        (Get-IsolationSummary AttackPaths).CoverageState | Should -Be Partial
        (Get-IsolationSummary ShadowAdmins).CoverageState | Should -Be Partial
        $row = Get-IsolationSummary $Section
        $row.CoverageState | Should -Be Complete
        $row.CoverageDetail | Should -Match 'ServicePrincipalCredentials: Complete'
        $row.CoverageDetail | Should -Not -Match 'sp-b|bad-date'
        $script:StalePrivilegeDataAvailable | Should -BeTrue
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match 'No stale high-privilege apps found' -and $ForegroundColor -eq 'Green' }
    }

    It 'does not retain a mode capture after Full returns or across repeated Full calls' {
        Invoke-FullAudit
        $script:ModeCoverageCapture | Should -BeNullOrEmpty
        Test-AuditCoverageComplete -Sources ServicePrincipalCredentials | Should -BeFalse
        $script:isolationFailure = 'sp-b'
        $script:isolationRequests.Clear()
        Invoke-FullAudit
        $script:ModeCoverageCapture | Should -BeNullOrEmpty
        (Get-IsolationSummary CredentialHygiene).CoverageState | Should -Be Complete
        (Get-IsolationSummary ShadowAdmins).CoverageState | Should -Be Partial
        (Get-IsolationSummary DataCoverage).CoverageState | Should -Be Partial
        $details = $script:Coverage.ServicePrincipalCredentials.Details -join '; '
        $details | Should -Match 'sp-a'
        $details | Should -Match 'sp-b'
        Test-AuditCoverageComplete -Sources ServicePrincipalCredentials | Should -BeFalse
    }

    It 'restores capture when a mode throws without discarding its failures' {
        Mock Invoke-ShadowAdminDetection {
            Set-CoverageState -Source ServicePrincipalCredentials -State Partial -Detail 'synthetic throw detail'
            throw 'synthetic mode failure'
        }
        { Invoke-FullAudit } | Should -Throw '*synthetic mode failure*'
        $script:ModeCoverageCapture | Should -BeNullOrEmpty
        Test-AuditCoverageComplete -Sources ServicePrincipalCredentials | Should -BeFalse
        ($script:Coverage.ServicePrincipalCredentials.Details -join '; ') | Should -Match 'sp-a.*synthetic throw detail'
        Set-CoverageState -Source ServicePrincipalCredentials -State Complete
        $script:Coverage.ServicePrincipalCredentials.State | Should -Be Partial
    }

    It 'does not import earlier credential failures when stale skips credential queries' {
        Mock Invoke-MgGraphRequest { throw 'Synthetic sign-in failure' } -ParameterFilter { $Uri -match '/reports/servicePrincipalSignInActivities' }
        Invoke-FullAudit
        @($script:isolationRequests | Where-Object Mode -eq Invoke-StalePrivilegeDetection).Count | Should -Be 0
        $stale = Get-IsolationSummary StalePrivilege
        $stale.CoverageState | Should -Be Partial
        $stale.CoverageDetail | Should -Match 'ServicePrincipalSignInActivity: Unavailable'
        $stale.CoverageDetail | Should -Not -Match 'ServicePrincipalCredentials|sp-a'
        (Get-IsolationSummary AttackPaths).CoverageState | Should -Be Partial
        (Get-IsolationSummary CredentialHygiene).CoverageState | Should -Be Partial
        (Get-IsolationSummary DataCoverage).CoverageState | Should -Be Partial
        $script:Coverage.ServicePrincipalCredentials.State | Should -Be Partial
    }

    It 'retains failures in cached core evidence for every mode that reuses it' {
        $script:isolationFailure = $null
        $null = Get-PrivilegedRoleAssignments
        Set-CoverageState -Source RoleDefinitions -State Partial -Detail 'Synthetic cached role gap'
        Invoke-FullAudit
        foreach ($section in @('RoleAudit', 'AttackPaths', 'ShadowAdmins')) {
            (Get-IsolationSummary $section).CoverageState | Should -Be Partial
            (Get-IsolationSummary $section).CoverageDetail | Should -Match 'Synthetic cached role gap'
        }
        foreach ($section in @('PermissionAudit', 'StalePrivilege', 'CredentialHygiene')) {
            (Get-IsolationSummary $section).CoverageState | Should -Be Complete
        }
        (Get-IsolationSummary DataCoverage).CoverageState | Should -Be Partial
        Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Uri -match '/roleDefinitions$' }
    }

    It 'restores an outer capture after <Outcome> and keeps local and global ledgers monotonic' -ForEach @(
        @{ Outcome = 'return' }; @{ Outcome = 'throw' }
    ) {
        $outer = [ordered]@{}
        $local = [ordered]@{}
        $script:ModeCoverageCapture = $outer
        try {
            Set-CoverageState -Source ServicePrincipalCredentials -State Partial -Detail 'earlier target failure'
            $action = {
                Set-CoverageState -Source ServicePrincipalCredentials -State Complete
                Test-AuditCoverageComplete -Sources ServicePrincipalCredentials | Should -BeTrue
                Test-AuditCoverageComplete | Should -BeFalse
                Set-CoverageState -Source ServicePrincipalCredentials -State Partial -Detail 'local target failure'
                Set-CoverageState -Source ServicePrincipalCredentials -State Complete
                Test-AuditCoverageComplete -Sources ServicePrincipalCredentials | Should -BeFalse
                if ($Outcome -eq 'throw') { throw 'Synthetic captured failure' }
            }
            if ($Outcome -eq 'throw') {
                { Invoke-WithModeCoverage -Coverage $local -Action $action } | Should -Throw '*Synthetic captured failure*'
            } else {
                Invoke-WithModeCoverage -Coverage $local -Action $action
            }
            [object]::ReferenceEquals($script:ModeCoverageCapture, $outer) | Should -BeTrue
            $local.ServicePrincipalCredentials.State | Should -Be Partial
            ($local.ServicePrincipalCredentials.Details -join '; ') | Should -Be 'local target failure'
            ($outer.ServicePrincipalCredentials.Details -join '; ') | Should -Be 'earlier target failure'
            ($script:Coverage.ServicePrincipalCredentials.Details -join '; ') | Should -Be 'earlier target failure; local target failure'
        } finally {
            $script:ModeCoverageCapture = $null
        }
    }
}