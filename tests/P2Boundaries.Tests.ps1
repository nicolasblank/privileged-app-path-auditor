BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'Invoke-PrivilegedAudit.ps1')

    function Invoke-MgGraphRequest {
        param($Method, $Uri)
        throw "Unmocked Graph request: $Method $Uri"
    }

    function Reset-P2State {
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
        $script:ExportPath = $null
    }
}

Describe 'P2 resource-specific permission equivalence' {
    BeforeEach {
        Reset-P2State
        Mock Write-Host {}
        Mock Invoke-RestMethod { throw 'No network allowed' }
        $script:p2Permission = 'RoleManagement.ReadWrite.Directory'
        $script:p2Resource = $script:MicrosoftGraphAppId
        $script:p2Scope = '/'
        $script:p2Template = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Method -ne 'GET') { throw 'Only synthetic GET requests are allowed' }
            if ($Uri -match '/roleDefinitions$') {
                return @{ value = @(@{ id = 'actor-role'; templateId = $script:p2Template; displayName = 'Synthetic role'; isBuiltIn = $true; isPrivileged = $true; rolePermissions = @() }) }
            }
            if ($Uri -match '/roleAssignments\?') {
                return @{ value = @(@{ roleDefinitionId = 'actor-role'; principalId = 'operator'; directoryScopeId = $script:p2Scope; appScopeId = $null; principal = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Operator'; userPrincipalName = 'operator@example.test' } }) }
            }
            if ($Uri -match '/servicePrincipals\?') {
                return @{ value = @(@{ id = 'client-sp'; appId = 'client-app'; displayName = 'Synthetic client'; appOwnerOrganizationId = 'home-tenant'; accountEnabled = $true }) }
            }
            if ($Uri -match '/client-sp/appRoleAssignments\?') { return @{ value = @(@{ appRoleId = 'permission-role'; resourceId = 'resource-sp' }) } }
            if ($Uri -match '/servicePrincipals/resource-sp\?') {
                return @{ id = 'resource-sp'; appId = $script:p2Resource; displayName = 'Synthetic resource'; appRoles = @(@{ id = 'permission-role'; value = $script:p2Permission }) }
            }
            if ($Uri -match '/oauth2PermissionGrants\?') { return @{ value = @() } }
            if ($Uri -match '/applications\?') {
                return @{ value = @(@{ id = 'app-object'; appId = 'client-app'; signInAudience = 'AzureADMyOrg'; servicePrincipalLockConfiguration = @{ isEnabled = $false } }) }
            }
            if ($Uri -match '/applications/app-object/owners\?') { return @{ value = @(@{ id = 'operator'; displayName = 'Operator'; userPrincipalName = 'operator@example.test' }) } }
            if ($Uri -match '/servicePrincipals/client-sp\?') { return @{ id = 'client-sp'; passwordCredentials = @(); keyCredentials = @() } }
            throw "Unexpected synthetic URI: $Uri"
        }
    }

    It 'binds <Permission> equivalence for <Role> to explicit Graph identity' -ForEach @(
        @{ Permission = 'RoleManagement.ReadWrite.Directory'; Role = 'PRA'; Template = 'e8611ab8-c189-46e8-94e1-60213ab1f814' }
        @{ Permission = 'Application.ReadWrite.All'; Role = 'ApplicationAdmin'; Template = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' }
        @{ Permission = 'Application.ReadWrite.All'; Role = 'CloudApplicationAdmin'; Template = '158c047a-c907-4556-b7ef-446551a6b5f7' }
        @{ Permission = 'AppRoleAssignment.ReadWrite.All'; Role = 'PRA'; Template = 'e8611ab8-c189-46e8-94e1-60213ab1f814' }
        @{ Permission = 'RoleManagement.ReadWrite.Directory'; Role = 'GA'; Template = '62e90394-69f5-4237-9190-012177145e10' }
        @{ Permission = 'Application.ReadWrite.All'; Role = 'GA'; Template = '62e90394-69f5-4237-9190-012177145e10' }
        @{ Permission = 'AppRoleAssignment.ReadWrite.All'; Role = 'GA'; Template = '62e90394-69f5-4237-9190-012177145e10' }
        @{ Permission = 'Directory.ReadWrite.All'; Role = 'GA'; Template = '62e90394-69f5-4237-9190-012177145e10' }
    ) {
        $assignment = [pscustomobject]@{ PrincipalId = 'operator'; PrincipalType = '#microsoft.graph.user'; RoleTemplateId = $Template; DirectoryScopeId = '/'; AppScopeId = $null }
        Test-UserAlreadyEquivalentToPermission operator $Permission @($assignment) -ResourceAppId $script:MicrosoftGraphAppId | Should -BeTrue
        Test-UserAlreadyEquivalentToPermission operator $Permission @($assignment) -ResourceAppId '11111111-2222-3333-4444-555555555555' | Should -BeFalse
        Test-UserAlreadyEquivalentToPermission operator $Permission @($assignment) | Should -BeFalse
    }

    It 'preserves owner-path delta and unknown scope for <Permission> with <Role>' -ForEach @(
        @{ Permission = 'RoleManagement.ReadWrite.Directory'; Role = 'PRA'; Template = 'e8611ab8-c189-46e8-94e1-60213ab1f814' }
        @{ Permission = 'Application.ReadWrite.All'; Role = 'ApplicationAdmin'; Template = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' }
        @{ Permission = 'Application.ReadWrite.All'; Role = 'CloudApplicationAdmin'; Template = '158c047a-c907-4556-b7ef-446551a6b5f7' }
        @{ Permission = 'AppRoleAssignment.ReadWrite.All'; Role = 'PRA'; Template = 'e8611ab8-c189-46e8-94e1-60213ab1f814' }
        @{ Permission = 'RoleManagement.ReadWrite.Directory'; Role = 'GA'; Template = '62e90394-69f5-4237-9190-012177145e10' }
        @{ Permission = 'Application.ReadWrite.All'; Role = 'GA'; Template = '62e90394-69f5-4237-9190-012177145e10' }
        @{ Permission = 'AppRoleAssignment.ReadWrite.All'; Role = 'GA'; Template = '62e90394-69f5-4237-9190-012177145e10' }
    ) {
        $script:p2Permission = $Permission
        $script:p2Template = $Template
        foreach ($boundary in @(
            @{ Resource = $script:MicrosoftGraphAppId; Scope = '/'; Expected = 'Equivalent' }
            @{ Resource = $script:MicrosoftGraphAppId; Scope = $null; Expected = 'PotentialRoleUnknown' }
            @{ Resource = $script:MicrosoftGraphAppId; Scope = '/unknown/scope'; Expected = 'PotentialRoleUnknown' }
            @{ Resource = '11111111-2222-3333-4444-555555555555'; Scope = '/'; Expected = 'Direct' }
        )) {
            Reset-P2State
            $script:p2Resource = $boundary.Resource
            $script:p2Scope = $boundary.Scope
            if ($script:p2Resource -ne $script:MicrosoftGraphAppId) {
                $script:DangerousPermissions += @{ name = $Permission; type = 'Application'; resourceAppId = $script:p2Resource; risk = 'Critical'; reason = 'Synthetic custom API capability' }
            }
            $paths = @(Invoke-AttackPathAnalysis)
            if ($boundary.Expected -eq 'Equivalent') { $paths.Count | Should -Be 0 } else {
                $paths.Count | Should -Be 1
                $paths[0].PathId | Should -Be 'APP_OWNER_ESCALATION'
                $paths[0].Exploitability | Should -Be $boundary.Expected
                if ($boundary.Expected -eq 'PotentialRoleUnknown') { $paths[0].EvidenceDetail | Should -Match 'scope' }
            }
        }
        Should -Invoke Invoke-MgGraphRequest -Times 4 -Exactly -ParameterFilter { $Uri -match '/roleDefinitions$' }
    }
}

Describe 'P2 PermissionAudit mixed CSV schema' {
    BeforeEach {
        Reset-P2State
        $script:DangerousPermissions += @{ name = 'RoleManagement.ReadWrite.Directory'; type = 'Delegated'; resourceAppId = $script:MicrosoftGraphAppId; risk = 'Critical'; reason = 'Synthetic delegated grant' }
        $ExportPath = Join-Path $TestDrive 'exports'
        Mock Write-Host {}
        Mock Invoke-RestMethod { throw 'No network allowed' }
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Method -ne 'GET') { throw 'Only synthetic GET requests are allowed' }
            if ($Uri -match '/servicePrincipals\?') {
                return @{ value = @(@{ id = 'client-sp'; appId = 'client-app'; displayName = 'Synthetic client'; appOwnerOrganizationId = 'home-tenant'; accountEnabled = $true }) }
            }
            if ($Uri -match '/client-sp/appRoleAssignments\?') { return @{ value = @(@{ appRoleId = 'permission-role'; resourceId = 'resource-sp' }) } }
            if ($Uri -match '/servicePrincipals/resource-sp\?') {
                return @{ id = 'resource-sp'; appId = $script:MicrosoftGraphAppId; displayName = 'Microsoft Graph'; appRoles = @(@{ id = 'permission-role'; value = 'RoleManagement.ReadWrite.Directory' }) }
            }
            if ($Uri -match '/oauth2PermissionGrants\?') {
                return @{ value = @(
                    @{ clientId = 'client-sp'; resourceId = 'resource-sp'; consentType = 'Principal'; principalId = 'synthetic-user'; scope = 'RoleManagement.ReadWrite.Directory' }
                    @{ clientId = 'client-sp'; resourceId = 'resource-sp'; consentType = 'AllPrincipals'; principalId = $null; scope = 'RoleManagement.ReadWrite.Directory' }
                ) }
            }
            throw "Unexpected synthetic URI: $Uri"
        }
    }

    It 'emits identical ordered application and delegated properties' {
        $rows = @(Invoke-PermissionAudit)
        $rows.Count | Should -Be 3
        @($rows[0].PSObject.Properties.Name) | Should -Be @($rows[1].PSObject.Properties.Name)
        @($rows[0].PSObject.Properties.Name) | Should -Contain 'ConsentPrincipalId'
        $rows[0].ConsentPrincipalId | Should -BeNullOrEmpty
        $rows[1].ConsentPrincipalId | Should -Be 'synthetic-user'
    }

    It 'retains principal identity through real export with <First> rows first' -ForEach @(
        @{ First = 'Application' }
        @{ First = 'Delegated' }
    ) {
        $rows = @(Invoke-PermissionAudit)
        $rows.Count | Should -Be 3
        if ($First -eq 'Delegated') {
            $orderedRows = @($rows | Where-Object PermissionType -eq Delegated) + @($rows | Where-Object PermissionType -eq Application)
            Export-AuditCsv -Name PermissionAudit -Data $orderedRows
        }
        $imported = @(Import-Csv (Join-Path $ExportPath 'PermissionAudit.csv'))
        $imported.Count | Should -Be 3
        $imported[0].PermissionType | Should -Be $First
        @($imported[0].PSObject.Properties.Name) | Should -Contain 'ConsentPrincipalId'
        ($imported | Where-Object ConsentType -eq Principal).ConsentPrincipalId | Should -Be 'synthetic-user'
        ($imported | Where-Object PermissionType -eq Application).ConsentPrincipalId | Should -BeNullOrEmpty
        ($imported | Where-Object ConsentType -eq AllPrincipals).ConsentPrincipalId | Should -BeNullOrEmpty
        Should -Invoke Invoke-MgGraphRequest -Times 4 -Exactly
    }
}

Describe 'P2 Microsoft catalog cache validation' {
    BeforeEach {
        Reset-P2State
        $script:p2CatalogPath = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $script:p2CatalogPath | Out-Null
        $script:p2CacheFile = Join-Path $script:p2CatalogPath 'MicrosoftApps.json'
        Mock Invoke-RestMethod { throw 'Synthetic offline download failure' }
        Mock Invoke-MgGraphRequest { throw 'No tenant access allowed' }
    }

    It 'uses valid <Shape> cache offline: fresh Complete, expired Partial' -ForEach @(
        @{ Shape = 'singleton'; Json = '{"AppId":"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"}'; Count = 1 }
        @{ Shape = 'array'; Json = '[{"AppId":"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"},{"AppId":"11111111-2222-3333-4444-555555555555"}]'; Count = 2 }
    ) {
        Set-Content -LiteralPath $script:p2CacheFile -Value $Json
        $fresh = @(Update-MicrosoftAppsLookup -CatalogConfigPath $script:p2CatalogPath)
        $fresh.Count | Should -Be $Count
        $fresh | Should -Contain 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        $script:Coverage.MicrosoftFirstPartyAppCatalog.State | Should -Be 'Complete'
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        (Get-Item $script:p2CacheFile).LastWriteTime = (Get-Date).AddHours(-25)
        Reset-AuditCoverage
        $expired = @(Update-MicrosoftAppsLookup -CatalogConfigPath $script:p2CatalogPath)
        $expired.Count | Should -Be $Count
        $expired | Should -Be $fresh
        $script:Coverage.MicrosoftFirstPartyAppCatalog.State | Should -Be 'Partial'
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly
    }

    It 'rejects invalid <Shape> fresh and expired caches without retaining IDs' -ForEach @(
        @{ Shape = 'empty array'; Json = '[]' }
        @{ Shape = 'null'; Json = 'null' }
        @{ Shape = 'empty text'; Json = '' }
        @{ Shape = 'malformed JSON'; Json = '{' }
        @{ Shape = 'empty singleton'; Json = '{}' }
        @{ Shape = 'invalid singleton ID'; Json = '{"AppId":"not-a-guid"}' }
        @{ Shape = 'invalid array ID'; Json = '[{"AppId":"not-a-guid"}]' }
        @{ Shape = 'cached GUID suffix'; Json = '{"AppId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee-debris"}' }
        @{ Shape = 'numeric ID'; Json = '{"AppId":123}' }
        @{ Shape = 'array-valued ID'; Json = '{"AppId":["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"]}' }
        @{ Shape = 'object-valued ID'; Json = '{"AppId":{"value":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}' }
        @{ Shape = 'nested array'; Json = '[[{"AppId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]]' }
        @{ Shape = 'string singleton'; Json = '"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"' }
        @{ Shape = 'mixed valid and invalid'; Json = '[{"AppId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},{"AppId":"invalid"}]' }
        @{ Shape = 'mixed valid and missing'; Json = '[{"AppId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},{}]' }
        @{ Shape = 'mixed valid and null'; Json = '[{"AppId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},null]' }
    ) {
        Set-Content -LiteralPath $script:p2CacheFile -Value $Json
        foreach ($age in @(0, 25)) {
            Reset-AuditCoverage
            (Get-Item $script:p2CacheFile).LastWriteTime = (Get-Date).AddHours(-$age)
            @(Update-MicrosoftAppsLookup -CatalogConfigPath $script:p2CatalogPath).Count | Should -Be 0
            $script:Coverage.MicrosoftFirstPartyAppCatalog.State | Should -Be 'Unavailable'
        }
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter { $Method -eq 'Get' }
    }

    It 'replaces an invalid expired cache with a valid downloaded <Shape>' -ForEach @(
        @{ Shape = 'singleton'; Json = '{"AppId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}'; Count = 1 }
        @{ Shape = 'array'; Json = '[{"AppId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},{"AppId":"11111111-2222-3333-4444-555555555555"}]'; Count = 2 }
    ) {
        Set-Content -LiteralPath $script:p2CacheFile -Value '[{"AppId":"invalid"}]'
        (Get-Item $script:p2CacheFile).LastWriteTime = (Get-Date).AddHours(-25)
        $script:p2Download = ConvertFrom-Json -InputObject $Json -NoEnumerate
        Mock Invoke-RestMethod { return ,$script:p2Download }
        $result = @(Update-MicrosoftAppsLookup -CatalogConfigPath $script:p2CatalogPath)
        $result.Count | Should -Be $Count
        $result | Should -Not -Contain 'invalid'
        $script:Coverage.MicrosoftFirstPartyAppCatalog.State | Should -Be 'Complete'
        Test-Path "$script:p2CacheFile.tmp" | Should -BeFalse
        Reset-AuditCoverage
        @(Update-MicrosoftAppsLookup -CatalogConfigPath $script:p2CatalogPath) | Should -Be $result
        $script:Coverage.MicrosoftFirstPartyAppCatalog.State | Should -Be 'Complete'
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly
    }

    It 'does not replace usable stale cache with invalid downloaded <Shape>' -ForEach @(
        @{ Shape = 'empty array'; Json = '[]' }
        @{ Shape = 'null'; Json = 'null' }
        @{ Shape = 'invalid singleton'; Json = '{"AppId":"invalid"}' }
        @{ Shape = 'invalid array'; Json = '[{"AppId":"invalid"}]' }
        @{ Shape = 'array-valued ID'; Json = '{"AppId":["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"]}' }
        @{ Shape = 'nested array'; Json = '[[{"AppId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]]' }
        @{ Shape = 'mixed array'; Json = '[{"AppId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},{"AppId":"invalid"}]' }
    ) {
        Set-Content -LiteralPath $script:p2CacheFile -Value '{"AppId":"11111111-2222-3333-4444-555555555555"}'
        $original = Get-Content -LiteralPath $script:p2CacheFile -Raw
        (Get-Item $script:p2CacheFile).LastWriteTime = (Get-Date).AddHours(-25)
        $script:p2Download = ConvertFrom-Json -InputObject $Json -NoEnumerate
        Mock Invoke-RestMethod { return ,$script:p2Download }
        @(Update-MicrosoftAppsLookup -CatalogConfigPath $script:p2CatalogPath) | Should -Be @('11111111-2222-3333-4444-555555555555')
        $script:Coverage.MicrosoftFirstPartyAppCatalog.State | Should -Be 'Partial'
        Get-Content -LiteralPath $script:p2CacheFile -Raw | Should -BeExactly $original
        Test-Path "$script:p2CacheFile.tmp" | Should -BeFalse
    }
}