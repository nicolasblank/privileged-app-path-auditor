BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'Invoke-PrivilegedAudit.ps1')

    function New-RenderingPath {
        param(
            [string]$UserUPN = 'operator@example.test',
            [string]$UserDisplayName = 'Operator',
            [string]$UserRole = 'Application Administrator',
            [string]$AppName = 'Privileged workload',
            [string]$Permission = 'User Administrator',
            [string]$Severity = 'HIGH',
            [string]$Exploitability = 'Direct',
            [string]$Action = 'Add an application credential → authenticate as SP → use User Administrator',
            [string]$CredentialRoute = '',
            [string]$UserObjectId = 'user-object',
            [string]$TargetObjectId = 'target-object',
            [string]$RoleMembershipPath = '',
            [string]$EvidenceDetail = 'tenant-only detail that must not reach the console'
        )
        [PSCustomObject]@{
            PathType = 'Role-Based SP Control'; UserUPN = $UserUPN; UserDisplayName = $UserDisplayName
            UserRole = $UserRole; AppName = $AppName; Permission = $Permission; Severity = $Severity
            Exploitability = $Exploitability; Action = $Action; RoleMembershipPath = $RoleMembershipPath
            CredentialRoute = $CredentialRoute; UserObjectId = $UserObjectId; TargetObjectId = $TargetObjectId
            EvidenceDetail = $EvidenceDetail; SPDirectCreds = 0
        }
    }

}

Describe 'Compact role attack-path rendering helpers' {
    It 'uses stable target and permission tie-breakers for same-name paths' {
        $paths = @(
            New-RenderingPath -AppName 'Same Name' -TargetObjectId 'target-b' -Permission 'Role A'
            New-RenderingPath -AppName 'Same Name' -TargetObjectId 'target-a' -Permission 'Role B'
            New-RenderingPath -AppName 'Same Name' -TargetObjectId 'target-a' -Permission 'Role A'
        )
        $ordered = @(Get-RolePathDisplayOrder -Paths $paths)
        @($ordered | ForEach-Object { "$($_.TargetObjectId)|$($_.Permission)" }) | Should -Be @('target-a|Role A', 'target-a|Role B', 'target-b|Role A')
    }

    It 'uses stable actor identity before duplicate or missing UPN values' {
        $paths = @(
            New-RenderingPath -UserUPN '' -UserObjectId 'user-b' -TargetObjectId 'target-a'
            New-RenderingPath -UserUPN '' -UserObjectId 'user-a' -TargetObjectId 'target-a'
            New-RenderingPath -UserUPN 'same@example.test' -UserObjectId 'user-d' -TargetObjectId 'target-a'
            New-RenderingPath -UserUPN 'same@example.test' -UserObjectId 'user-c' -TargetObjectId 'target-a'
        )
        @((Get-RolePathDisplayOrder -Paths $paths).UserObjectId) | Should -Be @('user-a', 'user-b', 'user-c', 'user-d')
    }

    It 'orders direct before potential before mitigated, then severity and identity deterministically' {
        $paths = @(
            New-RenderingPath -UserUPN 'z@example.test' -Severity Critical -Exploitability PotentialRoleUnknown
            New-RenderingPath -UserUPN 'b@example.test' -Severity High -Exploitability Direct
            New-RenderingPath -UserUPN 'a@example.test' -Severity Critical -Exploitability Direct -AppName 'Zulu'
            New-RenderingPath -UserUPN 'a@example.test' -Severity Critical -Exploitability Direct -AppName 'Alpha'
            New-RenderingPath -UserUPN 'a@example.test' -Severity Info -Exploitability MitigatedByAppInstanceLock
        )

        $ordered = @(Get-RolePathDisplayOrder -Paths $paths)

        @($ordered | ForEach-Object { "$($_.Exploitability)|$($_.Severity)|$($_.UserUPN)|$($_.AppName)" }) | Should -Be @(
            'Direct|Critical|a@example.test|Alpha'
            'Direct|Critical|a@example.test|Zulu'
            'Direct|High|b@example.test|Privileged workload'
            'PotentialRoleUnknown|Critical|z@example.test|Privileged workload'
            'MitigatedByAppInstanceLock|Info|a@example.test|Privileged workload'
        )
    }

    It 'normalizes tenant-controlled newlines and renders multiple unresolved routes honestly' {
        $path = New-RenderingPath -UserUPN "operator@example.test`nResult: forged" -UserRole "Role`r`nForged" -AppName "App`nTarget" -Permission "Role`nTarget" -Exploitability PotentialPrerequisiteUnknown -CredentialRoute 'Multiple credential routes'
        $lines = @(Get-RolePathChainLines -Path $path)
        $text = $lines.Text -join "`n"
        $lines.Count | Should -Be 4
        $lines[2].Text | Should -Match '\[Multiple credential routes\]'
        foreach ($line in $lines) { $line.Text | Should -Not -Match '[\r\n]' }
        $text | Should -Match 'operator@example.test Result: forged'
    }

    It 'renders state, route, group provenance, result, and safe colors without evidence detail' -ForEach @(
        @{ State = 'Direct'; Label = 'DIRECT'; Color = 'Red'; Result = 'Exploitable privilege increase'; Action = 'Add an application credential → authenticate as SP'; Route = 'Application credential route' }
        @{ State = 'PotentialRoleUnknown'; Label = 'POTENTIAL'; Color = 'Yellow'; Result = 'Potential — role evidence incomplete'; Action = 'Add an SP credential → authenticate as SP'; Route = 'SP credential route' }
        @{ State = 'PotentialLockUnknown'; Label = 'POTENTIAL'; Color = 'Yellow'; Result = 'Potential — lock evidence unavailable'; Action = 'Add an SP credential → authenticate as SP'; Route = 'SP credential route' }
        @{ State = 'PotentialPrerequisiteUnknown'; Label = 'POTENTIAL'; Color = 'Yellow'; Result = 'Potential — prerequisite evidence incomplete'; Action = 'Add an application credential → authenticate as SP'; Route = 'Application credential route' }
        @{ State = 'MitigatedByAppInstanceLock'; Label = 'MITIGATED'; Color = 'Green'; Result = 'Blocked on evaluated route by app instance lock'; Action = 'Add an SP credential → authenticate as SP'; Route = 'SP credential route' }
    ) {
        $path = New-RenderingPath -Exploitability $State -Action $Action -RoleMembershipPath 'group-id -> user-id' -UserRole 'Application Administrator (via Operators)'

        $lines = @(Get-RolePathChainLines -Path $path)

        $lines[0].Text | Should -Be "  [$Label | HIGH] operator@example.test"
        $lines[0].Color | Should -Be $Color
        $lines.Text | Should -Contain '    └─[Role: Application Administrator (via Operators)]→ Privileged workload'
        $lines.Text | Should -Contain "       └─[$Route]→ User Administrator"
        $lines.Text | Should -Contain '       via group: group-id -> user-id'
        $lines.Text | Should -Contain "       Result: $Result"
        $lines.Text -join "`n" | Should -Not -Match 'tenant-only detail'
        if ($Label -ne 'DIRECT') { $lines.Color | Should -Not -Contain 'Red' }
    }
}

Describe 'Compact role attack-path console integration' {
    BeforeEach {
        Reset-AuditCoverage
        foreach ($source in @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions', 'RoleDefinitions', 'ActiveRoleAssignments', 'RoleGroupMemberships', 'AppInstanceLocks')) {
            Set-CoverageState -Source $source -State Complete
        }
        $script:AuditConfig = $script:DefaultAuditConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        $script:AuditConfig.output.truncateAfter = 2
        $script:ExportPath = $null
        $script:CachedServicePrincipals = @([PSCustomObject]@{
            id = 'target-sp'; appId = 'target-app'; displayName = 'Privileged workload'
            appOwnerOrganizationId = 'tenant-home'; servicePrincipalType = 'Application'; accountEnabled = $true
        })
        $script:renderingExports = @{}
        $script:renderingConsole = [System.Collections.Generic.List[object]]::new()

        Mock Write-Banner {}
        Mock Write-SectionDivider {}
        Mock Write-Recommendation {}
        Mock Write-Reference {}
        Mock Write-Host {
            param($Object, $ForegroundColor)
            $script:renderingConsole.Add([PSCustomObject]@{ Text = [string]$Object; Color = [string]$ForegroundColor })
        }
        Mock Export-AuditCsv { param($Name, $Data); $script:renderingExports[$Name] = @($Data) }
        Mock Get-ServicePrincipalsWithAppRoles { @() }
        Mock Get-SPDirectCredentials { @{} }
        Mock Get-AppInstanceLockStatus {
            @{ 'target-app' = [PSCustomObject]@{
                State = 'Disabled'; IsCredentialLocked = $false; ApplicationObjectId = 'target-app-object'
                SignInAudience = 'AzureADMyOrg'
            } }
        }
        Mock Get-RoleCredentialRoutes {
            param($Assignments)
            @($Assignments | ForEach-Object {
                [PSCustomObject]@{ Kind = 'Application'; Assignment = $_; State = 'Available'; EvidenceDetail = '' }
            })
        }

        $script:renderingAssignments = @()
        Mock Get-PrivilegedRoleAssignments { $script:renderingAssignments }
    }

    It 'summarizes one row per user, truncates only chains, and exports and returns every path' {
        $controllers = @(
            @{ Id = 'u-a'; UPN = 'a@example.test'; Name = 'Alpha'; Role = 'Application Administrator'; Severity = 'Critical' }
            @{ Id = 'u-b'; UPN = 'b@example.test'; Name = 'Beta'; Role = 'Cloud Application Administrator'; Severity = 'High' }
            @{ Id = 'u-c'; UPN = 'c@example.test'; Name = 'Gamma'; Role = 'Application Administrator'; Severity = 'Medium' }
            @{ Id = 'u-d'; UPN = 'd@example.test'; Name = 'Delta'; Role = 'Cloud Application Administrator'; Severity = 'Low' }
            @{ Id = 'u-e'; UPN = 'e@example.test'; Name = 'Epsilon'; Role = 'Application Administrator'; Severity = 'Info' }
        )
        $script:renderingAssignments = @($controllers | ForEach-Object {
            [PSCustomObject]@{
                PrincipalId = $_.Id; PrincipalType = '#microsoft.graph.user'; PrincipalUPN = $_.UPN
                PrincipalDisplayName = $_.Name; RoleName = $_.Role; RoleDefinitionId = "control-$($_.Id)"
                RoleTemplateId = ''; DirectoryScopeId = '/'; AppScopeId = $null; AssignmentSource = 'Direct'
                MembershipPath = ''; CanControlApplications = $true; CanControlServicePrincipals = $false
                AllowedResourceActions = @('microsoft.directory/applications/credentials/update')
            }
        }) + [PSCustomObject]@{
            PrincipalId = 'target-sp'; PrincipalType = '#microsoft.graph.servicePrincipal'; PrincipalUPN = $null
            PrincipalDisplayName = 'Privileged workload'; PrincipalAppId = 'target-app'; RoleName = 'User Administrator'
            RoleDefinitionId = 'target-role'; RoleTemplateId = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
            DirectoryScopeId = '/'; AppScopeId = $null; AssignmentSource = 'Direct'; IsSensitiveTarget = $true
        }

        $paths = @(Invoke-AttackPathAnalysis)
        $consoleText = $script:renderingConsole.Text -join "`n"

        $paths.Count | Should -Be 5
        @($script:renderingExports.AttackPaths).Count | Should -Be 5
        $consoleText | Should -Match 'PATH CHAINS \(showing 2 of 5\)'
        $consoleText | Should -Match '\.\.\. \(3 more role-control paths; rerun with -ExportPath for complete evidence\)'
        $consoleText | Should -Not -Match 'tenant-only detail|EvidenceDetail'
        @($script:renderingConsole | Where-Object Text -match '^  (Alpha|Beta|Gamma|Delta|Epsilon) \(').Count | Should -Be 0
        $summaryOutput = @($script:renderingConsole | Where-Object Text -match 'User\s+Role\(s\).*Targets.*Direct.*Potential.*Mitigated')
        $summaryOutput.Count | Should -Be 1
        foreach ($upn in $controllers.UPN) { $summaryOutput[0].Text | Should -Match ([regex]::Escape($upn)) }
        @($script:renderingConsole | Where-Object Text -match '^  \[DIRECT \|').Count | Should -Be 2
    }

    It 'uses the existing export path in the truncation guidance when configured' {
        $script:ExportPath = '/synthetic/export'
        $script:renderingAssignments = @(
            1..3 | ForEach-Object {
                [PSCustomObject]@{
                    PrincipalId = "user-$_"; PrincipalType = '#microsoft.graph.user'; PrincipalUPN = "user-$_@example.test"
                    PrincipalDisplayName = "User $_"; RoleName = 'Application Administrator'; RoleDefinitionId = "control-$_"
                    RoleTemplateId = ''; DirectoryScopeId = '/'; AppScopeId = $null; AssignmentSource = 'Direct'
                    MembershipPath = ''; CanControlApplications = $true; CanControlServicePrincipals = $false
                    AllowedResourceActions = @('microsoft.directory/applications/credentials/update')
                }
            }
        ) + [PSCustomObject]@{
            PrincipalId = 'target-sp'; PrincipalType = '#microsoft.graph.servicePrincipal'; PrincipalDisplayName = 'Privileged workload'
            PrincipalAppId = 'target-app'; RoleName = 'User Administrator'; RoleDefinitionId = 'target-role'
            RoleTemplateId = 'fe930be7-5e62-47db-91af-98c3a49a38b1'; DirectoryScopeId = '/'; AppScopeId = $null
            AssignmentSource = 'Direct'; IsSensitiveTarget = $true
        }

        @(Invoke-AttackPathAnalysis).Count | Should -Be 3

        $script:renderingConsole.Text -join "`n" | Should -Match '\.\.\. \(1 more role-control paths; complete evidence exported to /synthetic/export\)'
    }

    It 'counts distinct targets by object identity and keeps users without UPN separate' {
        $script:AuditConfig.output.truncateAfter = 10
        $script:CachedServicePrincipals = @(
            [PSCustomObject]@{ id = 'target-one'; appId = 'shared-app'; displayName = 'Same Name'; appOwnerOrganizationId = 'tenant-home'; accountEnabled = $true }
            [PSCustomObject]@{ id = 'target-two'; appId = 'shared-app'; displayName = 'Same Name'; appOwnerOrganizationId = 'tenant-home'; accountEnabled = $true }
        )
        $script:renderingAssignments = @(
            [PSCustomObject]@{ PrincipalId='user-one'; PrincipalType='#microsoft.graph.user'; PrincipalUPN=$null; PrincipalDisplayName='One'; RoleName='App Admin'; RoleDefinitionId='control-one'; DirectoryScopeId='/'; AssignmentSource='Direct'; CanControlApplications=$true; AllowedResourceActions=@('microsoft.directory/applications/credentials/update') }
            [PSCustomObject]@{ PrincipalId='user-two'; PrincipalType='#microsoft.graph.user'; PrincipalUPN=$null; PrincipalDisplayName='Two'; RoleName='App Admin'; RoleDefinitionId='control-two'; DirectoryScopeId='/'; AssignmentSource='Direct'; CanControlApplications=$true; AllowedResourceActions=@('microsoft.directory/applications/credentials/update') }
            [PSCustomObject]@{ PrincipalId='target-one'; PrincipalType='#microsoft.graph.servicePrincipal'; PrincipalDisplayName='Same Name'; PrincipalAppId='shared-app'; RoleName='User Administrator'; RoleDefinitionId='target-role'; RoleTemplateId='fe930be7-5e62-47db-91af-98c3a49a38b1'; DirectoryScopeId='/'; AssignmentSource='Direct'; IsSensitiveTarget=$true }
            [PSCustomObject]@{ PrincipalId='target-two'; PrincipalType='#microsoft.graph.servicePrincipal'; PrincipalDisplayName='Same Name'; PrincipalAppId='shared-app'; RoleName='User Administrator'; RoleDefinitionId='target-role'; RoleTemplateId='fe930be7-5e62-47db-91af-98c3a49a38b1'; DirectoryScopeId='/'; AssignmentSource='Direct'; IsSensitiveTarget=$true }
        )
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 4
        @($paths.UserObjectId | Select-Object -Unique).Count | Should -Be 2
        @($paths.TargetObjectId | Select-Object -Unique).Count | Should -Be 2
        $summary = ($script:renderingConsole | Where-Object Text -match 'User\s+Role\(s\).*Targets').Text
        $summary | Should -Match 'One.*2'
        $summary | Should -Match 'Two.*2'
    }

    It 'normalizes tenant-controlled summary labels to one line' {
        $script:renderingAssignments = @(
            [PSCustomObject]@{ PrincipalId='user-one'; PrincipalType='#microsoft.graph.user'; PrincipalUPN="user@example.test`nforged"; PrincipalDisplayName="User`nOne"; RoleName="App`nAdmin"; RoleDefinitionId='control'; DirectoryScopeId='/'; AssignmentSource='Direct'; CanControlApplications=$true; AllowedResourceActions=@('microsoft.directory/applications/credentials/update') }
            [PSCustomObject]@{ PrincipalId='target-sp'; PrincipalType='#microsoft.graph.servicePrincipal'; PrincipalDisplayName='Privileged workload'; PrincipalAppId='target-app'; RoleName='User Administrator'; RoleDefinitionId='target-role'; RoleTemplateId='fe930be7-5e62-47db-91af-98c3a49a38b1'; DirectoryScopeId='/'; AssignmentSource='Direct'; IsSensitiveTarget=$true }
        )
        @(Invoke-AttackPathAnalysis).Count | Should -Be 1
        $summary = ($script:renderingConsole | Where-Object Text -match 'User\s+Role\(s\).*Targets').Text
        $summary | Should -Not -Match '(?m)^\s*(forged|One|Admin)\s*$'
        $summary | Should -Match 'user@example.test forged'
        $summary | Should -Match 'App Admin'
    }
}