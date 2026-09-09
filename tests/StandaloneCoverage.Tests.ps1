BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'Invoke-PrivilegedAudit.ps1')
    $script:standaloneCommands = @{ PermissionAudit = 'Invoke-PermissionAudit'; CredentialHygiene = 'Invoke-CredentialHygieneAudit' }
}

Describe 'Standalone permission-source requirements' {
    BeforeEach {
        Reset-AuditCoverage
        $script:CachedDangerousApps = $null
        $script:CachedServicePrincipals = $null
        $script:CachedResourceServicePrincipals = @{}
        $script:AuditConfig = $script:DefaultAuditConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        $script:ConnectedTenantId = 'synthetic-home'
        $script:MicrosoftAppIds = [System.Collections.Generic.HashSet[string]]::new()
        $script:DangerousPermissions = @($script:DefaultDangerousPermissions | Where-Object type -eq Application)
        $script:standaloneFailure = $null
        Mock Write-Host {}
        Mock Export-AuditCsv {}
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Method -ne 'GET') { throw 'Only read-only synthetic requests are allowed' }
            if ($Uri -match '/servicePrincipals\?') {
                if ($script:standaloneFailure -eq 'ServicePrincipals') { throw 'Synthetic inventory unavailable' }
                $sps = @(if ($script:standaloneFailure -in @('ApplicationPermissionGrants', 'ResourcePermissionDefinitions')) {
                    @{ id = 'client'; appId = 'client-app'; displayName = 'Synthetic client'; appOwnerOrganizationId = 'synthetic-home'; accountEnabled = $true }
                })
                return @{ value = $sps }
            }
            if ($Uri -match '/client/appRoleAssignments\?') {
                if ($script:standaloneFailure -eq 'ApplicationPermissionGrants') { throw 'Synthetic grants unavailable' }
                return @{ value = @(@{ id = 'grant'; resourceId = 'resource'; appRoleId = 'role' }) }
            }
            if ($Uri -match '/servicePrincipals/resource\?') { throw 'Synthetic resource definition unavailable' }
            if ($Uri -match '/oauth2PermissionGrants\?') {
                if ($script:standaloneFailure -eq 'DelegatedPermissionGrants') { throw 'Synthetic delegated grants unavailable' }
                return @{ value = @() }
            }
            throw "Unexpected synthetic URI: $Uri"
        }
    }

    It 'reports a complete empty <Mode> result for <Configuration> configuration' -ForEach @(
        foreach ($mode in @('PermissionAudit', 'CredentialHygiene')) {
            foreach ($configuration in @('ApplicationOnly', 'Empty', 'Mixed', 'DelegatedOnly')) {
                @{ Mode = $mode; Configuration = $configuration }
            }
        }
    ) {
        switch ($Configuration) {
            'Empty' { $script:DangerousPermissions = @() }
            'Mixed' { $script:DangerousPermissions = $script:DefaultDangerousPermissions }
            'DelegatedOnly' { $script:DangerousPermissions = @($script:DefaultDangerousPermissions | Where-Object type -eq Delegated) }
        }
        @(& ($script:standaloneCommands[$Mode])).Count | Should -Be 0
        $script:Coverage.ServicePrincipals.State | Should -Be 'Complete'
        $script:Coverage.ApplicationPermissionGrants.State | Should -Be 'Complete'
        $script:Coverage.ResourcePermissionDefinitions.State | Should -Be 'Complete'
        $usesDelegated = $Configuration -in @('Mixed', 'DelegatedOnly')
        $script:Coverage.Contains('DelegatedPermissionGrants') | Should -Be $usesDelegated
        if ($usesDelegated) {
            Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Uri -match '/oauth2PermissionGrants\?' }
        } else {
            Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly -ParameterFilter { $Uri -match '/oauth2PermissionGrants\?' }
        }
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match '^✓ No (configured dangerous permissions|apps with configured dangerous grants) found\.' -and $ForegroundColor -eq 'Green' }
        Should -Invoke Write-Host -Times 0 -Exactly -ParameterFilter { "$Object" -match 'incomplete' }
    }

    It 'preserves the <Failure> warning in standalone <Mode>' -ForEach @(
        foreach ($mode in @('PermissionAudit', 'CredentialHygiene')) {
            foreach ($failure in @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions', 'DelegatedPermissionGrants')) {
                @{ Mode = $mode; Failure = $failure }
            }
        }
    ) {
        if ($Failure -eq 'DelegatedPermissionGrants') { $script:DangerousPermissions = $script:DefaultDangerousPermissions }
        $script:standaloneFailure = $Failure
        @(& ($script:standaloneCommands[$Mode])).Count | Should -Be 0
        $script:Coverage[$Failure].State | Should -BeIn @('Partial', 'Unavailable')
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match 'permission audit is incomplete|credential-hygiene coverage is incomplete' }
        Should -Invoke Write-Host -Times 0 -Exactly -ParameterFilter { "$Object" -match '^✓ No (configured dangerous permissions|apps with configured dangerous grants)' }
    }

    It 'ignores an intentionally unused delegated source failure in <Mode> without deleting it' -ForEach @(
        @{ Mode = 'PermissionAudit' }; @{ Mode = 'CredentialHygiene' }
    ) {
        Set-CoverageState -Source 'DelegatedPermissionGrants' -State Unavailable -Detail 'Earlier unrelated synthetic collection'
        @(& ($script:standaloneCommands[$Mode])).Count | Should -Be 0
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match '^✓ No (configured dangerous permissions|apps with configured dangerous grants) found\.' }
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly -ParameterFilter { $Uri -match '/oauth2PermissionGrants\?' }
        $script:Coverage.DelegatedPermissionGrants.State | Should -Be 'Unavailable'
        Test-AuditCoverageComplete | Should -BeFalse
    }
}
