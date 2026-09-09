BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'Invoke-PrivilegedAudit.ps1')

    function Set-SummaryModeSources {
        param([string]$Mode)
        foreach ($source in $script:summarySources[$Mode]) {
            if ($source -in $script:summaryMissing) { continue }
            $state = if ($script:summaryStates.ContainsKey($source)) { $script:summaryStates[$source] } else { 'Complete' }
            Set-CoverageState -Source $source -State $state -Detail "Synthetic $source evidence"
        }
    }

    function Get-SummaryModeRow {
        param([string]$Mode)
        $script:summaryExports.FullAuditSummary | Where-Object Section -eq $Mode
    }
}

Describe 'P2 coverage-aware Full summaries' {
    BeforeEach {
        Reset-AuditCoverage
        $script:AuditConfig = $script:DefaultAuditConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        $script:DangerousPermissions = @(@{ name = 'Synthetic delegated'; type = 'Delegated' })
        $script:summaryExports = @{}
        $script:summaryMissing = @()
        $script:summaryStates = @{}
        $script:summarySources = @{
            PermissionAudit = @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions', 'DelegatedPermissionGrants')
            RoleAudit = @('RoleDefinitions', 'ActiveRoleAssignments', 'RoleGroupMemberships', 'Users')
            AttackPaths = @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions', 'RoleDefinitions', 'ActiveRoleAssignments', 'RoleGroupMemberships')
            ShadowAdmins = @('RoleDefinitions', 'ActiveRoleAssignments', 'RoleGroupMemberships')
            StalePrivilege = @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions')
            ConsentRisk = @('TenantAuthorizationPolicy', 'UserConsentGrants')
            CredentialHygiene = @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions', 'DelegatedPermissionGrants')
        }
        $script:summaryPerms = @()
        $script:summaryRoles = [pscustomobject]@{ PrivilegedUsers = @{}; NonPrivilegedUsers = @(); SPRoles = @(); CoverageComplete = $true }
        $script:summaryAttacks = @()
        $script:summaryShadows = @()
        $script:summaryStale = @()
        $script:summaryConsent = @()
        $script:summaryCredentials = @()
        $script:StalePrivilegeDataAvailable = $true
        $script:StalePrivilegeStatus = 'Complete'
        Mock Write-Host {}
        Mock Write-Banner {}
        Mock Write-AuditCoverageSummary {}
        Mock Export-AuditCsv { param($Name, $Data); $script:summaryExports[$Name] = @($Data) }
        Mock Invoke-PermissionAudit { Set-SummaryModeSources PermissionAudit; $script:summaryPerms }
        Mock Invoke-RoleAudit { Set-SummaryModeSources RoleAudit; $script:summaryRoles }
        Mock Invoke-AttackPathAnalysis { Set-SummaryModeSources AttackPaths; $script:summaryAttacks }
        Mock Invoke-ShadowAdminDetection { Set-SummaryModeSources ShadowAdmins; $script:summaryShadows }
        Mock Invoke-StalePrivilegeDetection { Set-SummaryModeSources StalePrivilege; $script:summaryStale }
        Mock Invoke-ConsentRiskAssessment { Set-SummaryModeSources ConsentRisk; $script:summaryConsent }
        Mock Invoke-CredentialHygieneAudit { Set-SummaryModeSources CredentialHygiene; $script:summaryCredentials }
        Mock Invoke-MgGraphRequest { throw 'Network is forbidden in summary tests' }
    }

    It 'reports complete observed-empty <Mode> without requiring skipped candidate lookups' -ForEach @(
        @{ Mode = 'PermissionAudit' }; @{ Mode = 'RoleAudit' }; @{ Mode = 'AttackPaths' }
        @{ Mode = 'ShadowAdmins' }; @{ Mode = 'StalePrivilege' }; @{ Mode = 'ConsentRisk' }; @{ Mode = 'CredentialHygiene' }
    ) {
        Invoke-FullAudit
        $row = Get-SummaryModeRow $Mode
        $row.CoverageState | Should -Be Complete
        $row.CoverageDetail | Should -Not -Match 'Owners|Credentials|Locks|SignIn|ClientResolution'
        $row.Finding | Should -Not -Match 'Incomplete|Unavailable|lower bound'
    }

    It 'qualifies <Mode> zero counts when required <Source> is <State>' -ForEach @(
        foreach ($pair in @(
            @{ Mode = 'PermissionAudit'; Source = 'ServicePrincipals' }
            @{ Mode = 'PermissionAudit'; Source = 'ApplicationPermissionGrants' }
            @{ Mode = 'PermissionAudit'; Source = 'ResourcePermissionDefinitions' }
            @{ Mode = 'PermissionAudit'; Source = 'DelegatedPermissionGrants' }
            @{ Mode = 'RoleAudit'; Source = 'Users' }
            @{ Mode = 'RoleAudit'; Source = 'RoleDefinitions' }
            @{ Mode = 'RoleAudit'; Source = 'ActiveRoleAssignments' }
            @{ Mode = 'RoleAudit'; Source = 'RoleGroupMemberships' }
            @{ Mode = 'AttackPaths'; Source = 'ApplicationPermissionGrants' }
            @{ Mode = 'AttackPaths'; Source = 'ActiveRoleAssignments' }
            @{ Mode = 'ShadowAdmins'; Source = 'RoleGroupMemberships' }
            @{ Mode = 'StalePrivilege'; Source = 'ResourcePermissionDefinitions' }
            @{ Mode = 'ConsentRisk'; Source = 'TenantAuthorizationPolicy' }
            @{ Mode = 'ConsentRisk'; Source = 'UserConsentGrants' }
            @{ Mode = 'CredentialHygiene'; Source = 'DelegatedPermissionGrants' }
        )) {
            foreach ($state in @('Partial', 'Unavailable', 'Missing')) { $pair + @{ State = $state } }
        }
    ) {
        if ($State -eq 'Missing') { $script:summaryMissing = @($Source) } else { $script:summaryStates[$Source] = $State }
        Invoke-FullAudit
        $row = Get-SummaryModeRow $Mode
        $row.CoverageState | Should -Be Partial
        $row.CoverageDetail | Should -Match $Source
        $row.CoverageDetail | Should -Match $State
        $row.Finding | Should -Match 'Incomplete.*observed'
        $label = @{ PermissionAudit = 'Permission Audit'; RoleAudit = 'Role Audit'; AttackPaths = 'Attack Paths'; ShadowAdmins = 'Shadow Admins'; StalePrivilege = 'Stale Privilege'; ConsentRisk = 'Consent Risk'; CredentialHygiene = 'Credential Hygiene' }[$Mode]
        Should -Invoke Write-Host -Times 0 -Exactly -ParameterFilter { "$Object" -match "^  ${label}:" -and $ForegroundColor -eq 'Green' }
    }

    It 'reports unavailable when no required evidence or observations exist' {
        $script:summaryMissing = @($script:summarySources.Values | ForEach-Object { $_ } | Select-Object -Unique)
        Invoke-FullAudit
        foreach ($mode in $script:summarySources.Keys) {
            (Get-SummaryModeRow $mode).CoverageState | Should -Be Unavailable
            (Get-SummaryModeRow $mode).Finding | Should -Match 'Unavailable.*observed'
        }
        (Get-SummaryModeRow DataCoverage).CoverageState | Should -Be Unavailable
    }

    It 'ignores unrelated and later failures in PermissionAudit and RoleAudit' {
        $script:summarySources.StalePrivilege += 'ServicePrincipalSignInActivity'
        $script:summarySources.CredentialHygiene += 'ApplicationCredentials'
        $script:summaryStates.ServicePrincipalSignInActivity = 'Unavailable'
        $script:summaryStates.ApplicationCredentials = 'Partial'
        Invoke-FullAudit
        foreach ($mode in @('PermissionAudit', 'RoleAudit', 'AttackPaths')) {
            (Get-SummaryModeRow $mode).CoverageState | Should -Be Complete
        }
    }

    It 'does not require deliberately disabled delegated or user-consent inventory' {
        $script:DangerousPermissions = @()
        $script:AuditConfig.consentRisk.flagUserConsentedApps = $false
        $script:summaryMissing = @('DelegatedPermissionGrants', 'UserConsentGrants')
        Invoke-FullAudit
        foreach ($mode in @('PermissionAudit', 'CredentialHygiene', 'ConsentRisk')) {
            (Get-SummaryModeRow $mode).CoverageState | Should -Be Complete
        }
    }

    It 'does not taint application-only modes with delegated inventory failure' {
        $script:summaryStates.DelegatedPermissionGrants = 'Unavailable'
        Invoke-FullAudit
        foreach ($mode in @('AttackPaths', 'ShadowAdmins', 'StalePrivilege', 'RoleAudit')) {
            (Get-SummaryModeRow $mode).CoverageState | Should -Be Complete
        }
    }

    It 'includes initialized catalog failure only where classification affects the mode' {
        Set-CoverageState -Source MicrosoftFirstPartyAppCatalog -State Unavailable -Detail 'Synthetic catalog unavailable'
        Invoke-FullAudit
        foreach ($mode in @('PermissionAudit', 'AttackPaths', 'StalePrivilege', 'CredentialHygiene')) {
            (Get-SummaryModeRow $mode).CoverageState | Should -Be Partial
            (Get-SummaryModeRow $mode).CoverageDetail | Should -Match MicrosoftFirstPartyAppCatalog
        }
        foreach ($mode in @('RoleAudit', 'ShadowAdmins', 'ConsentRisk')) { (Get-SummaryModeRow $mode).CoverageState | Should -Be Complete }
    }

    It 'respects disabled first-party filtering for permission inventory but retains owner classification coverage' {
        $script:AuditConfig.filters.excludeFirstPartyMicrosoftApps = $false
        $script:summaryPerms = @([pscustomobject]@{ AppId = 'synthetic-app'; AppTenantType = 'HomeTenant'; PermissionType = 'Application' })
        Set-CoverageState -Source MicrosoftFirstPartyAppCatalog -State Partial -Detail 'Synthetic catalog partial'
        Invoke-FullAudit
        (Get-SummaryModeRow PermissionAudit).CoverageState | Should -Be Complete
        foreach ($mode in @('AttackPaths', 'StalePrivilege', 'CredentialHygiene')) { (Get-SummaryModeRow $mode).CoverageState | Should -Be Partial }
    }

    It 'includes applicable recorded optional <Source> in <Mode>' -ForEach @(
        @{ Mode = 'AttackPaths'; Source = 'ApplicationOwners' }
        @{ Mode = 'AttackPaths'; Source = 'ServicePrincipalOwners' }
        @{ Mode = 'AttackPaths'; Source = 'ServicePrincipalCredentials' }
        @{ Mode = 'AttackPaths'; Source = 'AppInstanceLocks' }
        @{ Mode = 'ShadowAdmins'; Source = 'ServicePrincipalOwners' }
        @{ Mode = 'ShadowAdmins'; Source = 'ServicePrincipalCredentials' }
        @{ Mode = 'StalePrivilege'; Source = 'ServicePrincipalSignInActivity' }
        @{ Mode = 'StalePrivilege'; Source = 'ApplicationCredentials' }
        @{ Mode = 'StalePrivilege'; Source = 'FederatedIdentityCredentials' }
        @{ Mode = 'StalePrivilege'; Source = 'ServicePrincipalCredentials' }
        @{ Mode = 'ConsentRisk'; Source = 'UserConsentClientResolution' }
        @{ Mode = 'CredentialHygiene'; Source = 'ApplicationCredentials' }
        @{ Mode = 'CredentialHygiene'; Source = 'FederatedIdentityCredentials' }
        @{ Mode = 'CredentialHygiene'; Source = 'ServicePrincipalCredentials' }
        @{ Mode = 'CredentialHygiene'; Source = 'AppInstanceLocks' }
    ) {
        $script:summaryPerms = @([pscustomobject]@{ AppId = 'synthetic-app'; AppTenantType = 'HomeTenant'; PermissionType = 'Application' })
        $script:summaryRoles.SPRoles = @([pscustomobject]@{ PrincipalId = 'synthetic-sp'; IsSensitiveTarget = $true })
        $script:summarySources[$Mode] += $Source
        $script:summaryStates[$Source] = 'Partial'
        Invoke-FullAudit
        (Get-SummaryModeRow $Mode).CoverageState | Should -Be Partial
        (Get-SummaryModeRow $Mode).CoverageDetail | Should -Match $Source
    }

    It 'keeps observed lower bounds and direct potential mitigated classifications under missing evidence' {
        $script:summaryMissing = @($script:summarySources.Values | ForEach-Object { $_ } | Select-Object -Unique)
        $script:summaryPerms = @([pscustomobject]@{ AppId = 'synthetic-app'; PermissionType = 'Application' })
        $script:summaryAttacks = @('Direct', 'PotentialRoleUnknown', 'PotentialLockUnknown', 'MitigatedByAppInstanceLock' | ForEach-Object { [pscustomobject]@{ Exploitability = $_ } })
        $script:summaryConsent = @([pscustomobject]@{ Risk = 'HIGH' })
        $script:summaryCredentials = @([pscustomobject]@{ CredType = 'Secret'; SPDirectCreds = 1; CredentialEvidence = 'Partial'; RiskLevel = 'HIGH; REVIEW' })
        Invoke-FullAudit
        (Get-SummaryModeRow PermissionAudit).Count | Should -Be 1
        (Get-SummaryModeRow AttackPaths).Count | Should -Be '1 direct, 2 potential'
        (Get-SummaryModeRow AttackPaths).Finding | Should -Match '1 blocked by app instance lock'
        (Get-SummaryModeRow ConsentRisk).Count | Should -Be 1
        (Get-SummaryModeRow CredentialHygiene).Count | Should -Be '1 secrets, 1 SP-creds'
        foreach ($mode in @('PermissionAudit', 'AttackPaths', 'ConsentRisk', 'CredentialHygiene')) {
            (Get-SummaryModeRow $mode).CoverageState | Should -Be Partial
            (Get-SummaryModeRow $mode).Finding | Should -Match 'observed.*lower bounds'
        }
        foreach ($row in @($script:summaryExports.FullAuditSummary | Where-Object Section -Like 'Action*')) {
            $row.CoverageState | Should -BeNullOrEmpty
            $row.CoverageDetail | Should -BeNullOrEmpty
        }
    }

    It 'shows consent review findings without changing the legacy critical Count' {
        $script:summaryConsent = @([pscustomobject]@{ Risk = 'REVIEW'; Value = 'Custom policy: synthetic' })
        Invoke-FullAudit
        $row = Get-SummaryModeRow ConsentRisk
        $row.Count | Should -Be 0
        $row.CoverageState | Should -Be Complete
        $row.Finding | Should -Match '1.*review'
        Should -Invoke Write-Host -Times 0 -Exactly -ParameterFilter { "$Object" -match '^  Consent Risk:' -and $ForegroundColor -eq 'Green' }
    }

    It 'requires credential review from row evidence even without source failure and secret counts' {
        $script:summaryCredentials = @([pscustomobject]@{ CredType = 'Unknown'; SPDirectCreds = 'Unknown'; CredentialEvidence = 'NotLocallyObservable'; RiskLevel = 'REVIEW' })
        Invoke-FullAudit
        $row = Get-SummaryModeRow CredentialHygiene
        $row.Count | Should -Be '0 secrets, 0 SP-creds'
        $row.CoverageState | Should -Be Partial
        $row.CoverageDetail | Should -Match 'CredentialEvidence.*NotLocallyObservable'
        $row.Finding | Should -Match '1.*review'
        Should -Invoke Write-Host -Times 0 -Exactly -ParameterFilter { "$Object" -match '^  Credential Hygiene:' -and $ForegroundColor -eq 'Green' }
    }

    It 'preserves stale availability reason and distinct observed apps' {
        $script:summaryStale = @([pscustomobject]@{ AppId = 'same-app' }, [pscustomobject]@{ AppId = 'same-app' })
        $script:StalePrivilegeDataAvailable = $false
        $script:StalePrivilegeStatus = 'Credential coverage is incomplete'
        Invoke-FullAudit
        $row = Get-SummaryModeRow StalePrivilege
        $row.Count | Should -Be 1
        $row.CoverageState | Should -Be Partial
        $row.CoverageDetail | Should -Match 'Credential coverage is incomplete'
        $row.Finding | Should -Match 'Incomplete \(credential evidence\).*1 dormant.*observed'
    }

    It 'preserves the P1 not-evaluated stale reason' {
        $script:StalePrivilegeDataAvailable = $false
        $script:StalePrivilegeStatus = 'Not evaluated (sign-in activity unavailable)'
        Invoke-FullAudit
        $row = Get-SummaryModeRow StalePrivilege
        $row.CoverageState | Should -Be Partial
        $row.Finding | Should -Match 'Not evaluated \(sign-in activity unavailable\)'
        $row.CoverageDetail | Should -Match 'sign-in activity unavailable'
    }
}