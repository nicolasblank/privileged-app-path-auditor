BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'Invoke-PrivilegedAudit.ps1')

    function New-RoleGroupDefinition {
        param(
            [string]$Id = 'rd-pra',
            [string]$TemplateId = 'e8611ab8-c189-46e8-94e1-60213ab1f814',
            [string]$Name = 'Privileged Role Administrator',
            [string[]]$Actions = @()
        )
        [PSCustomObject]@{
            id = $Id; templateId = $TemplateId; displayName = $Name
            isBuiltIn = [bool]$TemplateId; isEnabled = $true; isPrivileged = [bool]$TemplateId
            rolePermissions = @([PSCustomObject]@{ allowedResourceActions = $Actions })
        }
    }

    function New-RoleGroupAssignment {
        param(
            [string]$Id = 'assignment-group',
            [string]$RoleDefinitionId = 'rd-pra',
            [string]$PrincipalId = 'group-1',
            [string]$PrincipalType = 'group',
            [string]$DirectoryScopeId = '/',
            [string]$AppScopeId = $null
        )
        [PSCustomObject]@{
            id = $Id; roleDefinitionId = $RoleDefinitionId; principalId = $PrincipalId
            directoryScopeId = $DirectoryScopeId; appScopeId = $AppScopeId
            principal = [PSCustomObject]@{
                '@odata.type' = "#microsoft.graph.$PrincipalType"
                displayName = if ($PrincipalType -eq 'group') { "Group $PrincipalId" } else { "User $PrincipalId" }
                userPrincipalName = if ($PrincipalType -eq 'user') { "$PrincipalId@example.test" } else { $null }
                appId = $null
            }
        }
    }

    function Reset-RoleGroupState {
        Reset-AuditCoverage
        $script:CachedDangerousApps = $null
        $script:CachedRoleAssignments = $null
        $script:CachedRoleDefinitions = $null
        $script:CachedServicePrincipals = @()
        $script:CachedResourceServicePrincipals = @{}
        $script:DangerousPermissions = @($script:DefaultDangerousPermissions | ForEach-Object { @{} + $_ })
        $script:PrivilegedRoles = @($script:DefaultPrivilegedRoles | ForEach-Object { @{} + $_ })
        $script:AuditConfig = $script:DefaultAuditConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        $script:ConnectedTenantId = 'tenant-home'
        $script:MicrosoftAppIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $script:roleGroupDefinitions = @((New-RoleGroupDefinition))
        $script:roleGroupAssignments = @()
        $script:roleGroupPages = @{}
        $script:roleGroupFailures = @{}
        $script:roleGroupCalls = [System.Collections.Generic.List[string]]::new()
        $script:capturedExports = @{}
        $script:ExportPath = $null
    }
}

Describe 'Role-assigned group transitive user collection' {
    BeforeEach {
        Reset-RoleGroupState
        Mock Write-Host {}
        Mock Invoke-RestMethod { throw 'No network allowed' }
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Method -ne 'GET') { throw 'Only synthetic GET requests are allowed' }
            if ($Uri -match '/roleDefinitions$') { return @{ value = $script:roleGroupDefinitions } }
            if ($Uri -match '/roleAssignments\?') { return @{ value = $script:roleGroupAssignments } }
            if ($Uri -match '/groups/([^/]+)/transitiveMembers/microsoft\.graph\.user\?') {
                $groupId = $Matches[1]
                $script:roleGroupCalls.Add($groupId)
                if ($script:roleGroupFailures.ContainsKey($groupId)) { throw $script:roleGroupFailures[$groupId] }
                return $script:roleGroupPages[$groupId]
            }
            if ($Uri -match '^https://synthetic\.test/groups/([^/]+)/page/2$') {
                $groupId = $Matches[1]
                $script:roleGroupCalls.Add("$groupId-page-2")
                if ($script:roleGroupFailures.ContainsKey("$groupId-page-2")) { throw $script:roleGroupFailures["$groupId-page-2"] }
                return $script:roleGroupPages["$groupId-page-2"]
            }
            throw "Unexpected synthetic URI: $Uri"
        }
    }

    It 'does not query groups and reports complete coverage when no group is assigned' {
        $script:roleGroupAssignments = @((New-RoleGroupAssignment -Id assignment-user -PrincipalId user-direct -PrincipalType user))
        $rows = @(Get-PrivilegedRoleAssignments)
        $rows.Count | Should -Be 1
        $rows[0].AssignmentSource | Should -Be Direct
        $rows[0].RoleAssignmentId | Should -Be assignment-user
        $script:Coverage.RoleGroupMemberships.State | Should -Be Complete
        $script:roleGroupCalls.Count | Should -Be 0
    }

    It 'keeps an empty successfully expanded group and reports complete coverage' {
        $script:roleGroupAssignments = @((New-RoleGroupAssignment))
        $script:roleGroupPages['group-1'] = @{ value = @() }
        $rows = @(Get-PrivilegedRoleAssignments)
        $rows.Count | Should -Be 1
        $rows[0].AssignmentSource | Should -Be RoleAssignedGroup
        $rows[0].MembershipPath | Should -Be group-1
        $script:Coverage.RoleGroupMemberships.State | Should -Be Complete
    }

    It 'retains transitive users observed before a later page failure and marks partial coverage' {
        $script:roleGroupAssignments = @((New-RoleGroupAssignment))
        $script:roleGroupPages['group-1'] = @{
            value = @(@{ id = 'user-nested'; displayName = 'Nested User'; userPrincipalName = 'nested@example.test' })
            '@odata.nextLink' = 'https://synthetic.test/groups/group-1/page/2'
        }
        $script:roleGroupFailures['group-1-page-2'] = 'synthetic later page failure'
        $rows = @(Get-PrivilegedRoleAssignments)
        $rows.Count | Should -Be 2
        $member = $rows | Where-Object AssignmentSource -eq RoleAssignedGroupMember
        $member.PrincipalId | Should -Be user-nested
        $member.SourceGroupId | Should -Be group-1
        $member.MembershipPath | Should -Be 'group-1 -> user-nested'
        $script:Coverage.RoleGroupMemberships.State | Should -Be Partial
    }

    It 'collects all users from a successful multi-page expansion' {
        $script:roleGroupAssignments = @((New-RoleGroupAssignment))
        $script:roleGroupPages['group-1'] = @{
            value = @(@{ id = 'user-1'; displayName = 'User One'; userPrincipalName = 'one@example.test' })
            '@odata.nextLink' = 'https://synthetic.test/groups/group-1/page/2'
        }
        $script:roleGroupPages['group-1-page-2'] = @{ value = @(@{ id = 'user-2'; displayName = 'User Two'; userPrincipalName = 'two@example.test' }) }
        $rows = @(Get-PrivilegedRoleAssignments)
        @($rows | Where-Object AssignmentSource -eq RoleAssignedGroupMember).PrincipalId | Should -Be @('user-1', 'user-2')
        $script:Coverage.RoleGroupMemberships.State | Should -Be Complete
    }

    It 'keeps successful groups when a different first page fails and marks partial coverage' {
        $script:roleGroupAssignments = @(
            (New-RoleGroupAssignment -Id assignment-one -PrincipalId group-1)
            (New-RoleGroupAssignment -Id assignment-two -PrincipalId group-2)
        )
        $script:roleGroupPages['group-1'] = @{ value = @(@{ id = 'user-1'; displayName = 'User One'; userPrincipalName = 'one@example.test' }) }
        $script:roleGroupFailures['group-2'] = 'synthetic first page failure'
        $rows = @(Get-PrivilegedRoleAssignments)
        @($rows | Where-Object AssignmentSource -eq RoleAssignedGroup).Count | Should -Be 2
        @($rows | Where-Object AssignmentSource -eq RoleAssignedGroupMember).PrincipalId | Should -Be @('user-1')
        $script:Coverage.RoleGroupMemberships.State | Should -Be Partial
    }

    It 'marks malformed member identity partial without creating an effective row' {
        $script:roleGroupAssignments = @((New-RoleGroupAssignment))
        $script:roleGroupPages['group-1'] = @{ value = @(@{ displayName = 'Missing ID'; userPrincipalName = 'missing@example.test' }) }
        $rows = @(Get-PrivilegedRoleAssignments)
        $rows.Count | Should -Be 1
        $script:Coverage.RoleGroupMemberships.State | Should -Be Partial
    }

    It 'marks unresolved assignment principal metadata partial instead of treating the principal as non-privileged' {
        $script:roleGroupAssignments = @([PSCustomObject]@{
            id = 'assignment-unresolved'; roleDefinitionId = 'rd-pra'; principalId = 'user-unresolved'
            directoryScopeId = '/'; appScopeId = $null; principal = $null
        })
        $rows = @(Get-PrivilegedRoleAssignments)
        $rows.Count | Should -Be 1
        $rows[0].PrincipalType | Should -BeNullOrEmpty
        $script:Coverage.RoleGroupMemberships.State | Should -Be Partial
        $script:Coverage.RoleGroupMemberships.Details -join '; ' | Should -Match 'principal type'
    }

    It 'queries each assigned group once and preserves distinct assignment IDs' {
        $script:roleGroupAssignments = @(
            (New-RoleGroupAssignment -Id duplicate-one)
            (New-RoleGroupAssignment -Id duplicate-two)
        )
        $script:roleGroupPages['group-1'] = @{ value = @(@{ id = 'user-1'; displayName = 'User One'; userPrincipalName = 'one@example.test' }) }
        $rows = @(Get-PrivilegedRoleAssignments)
        $script:roleGroupCalls | Should -Be @('group-1')
        $members = @($rows | Where-Object AssignmentSource -eq RoleAssignedGroupMember)
        $members.Count | Should -Be 2
        $members.SourceAssignmentId | Should -Be @('duplicate-one', 'duplicate-two')
    }

    It 'deduplicates repeated copies of the same assignment ID' {
        $script:roleGroupAssignments = @(
            (New-RoleGroupAssignment -Id repeated-assignment)
            (New-RoleGroupAssignment -Id repeated-assignment)
        )
        $script:roleGroupPages['group-1'] = @{ value = @(@{ id = 'user-1'; displayName = 'User One'; userPrincipalName = 'one@example.test' }) }
        $rows = @(Get-PrivilegedRoleAssignments)
        $script:roleGroupCalls | Should -Be @('group-1')
        @($rows | Where-Object AssignmentSource -eq RoleAssignedGroup).Count | Should -Be 1
        @($rows | Where-Object AssignmentSource -eq RoleAssignedGroupMember).Count | Should -Be 1
    }

    It 'retains separate direct and group-derived evidence for the same user and role' {
        $script:roleGroupAssignments = @(
            (New-RoleGroupAssignment -Id assignment-direct -PrincipalId user-1 -PrincipalType user)
            (New-RoleGroupAssignment)
        )
        $script:roleGroupPages['group-1'] = @{ value = @(@{ id = 'user-1'; displayName = 'User One'; userPrincipalName = 'one@example.test' }) }
        $rows = @(Get-PrivilegedRoleAssignments)
        @($rows | Where-Object PrincipalId -eq user-1).Count | Should -Be 2
        @($rows | Where-Object PrincipalId -eq user-1).AssignmentSource | Should -Contain Direct
        @($rows | Where-Object PrincipalId -eq user-1).AssignmentSource | Should -Contain RoleAssignedGroupMember
        Test-UserAlreadyEquivalentToPermission user-1 AppRoleAssignment.ReadWrite.All $rows -ResourceAppId $script:MicrosoftGraphAppId | Should -BeTrue
    }
}

Describe 'Role-assigned group downstream semantics' {
    BeforeEach {
        Reset-RoleGroupState
        Mock Write-Host {}
        Mock Write-Banner {}
        Mock Write-SectionDivider {}
        Mock Write-Recommendation {}
        Mock Write-Reference {}
        Mock Invoke-RestMethod { throw 'No network allowed' }
        Mock Export-AuditCsv {
            param($Name, $Data)
            $script:capturedExports[$Name] = @($Data)
        }
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Method -ne 'GET') { throw 'Only synthetic GET requests are allowed' }
            if ($Uri -match '/roleDefinitions$') { return @{ value = $script:roleGroupDefinitions } }
            if ($Uri -match '/roleAssignments\?') { return @{ value = $script:roleGroupAssignments } }
            if ($Uri -match '/groups/([^/]+)/transitiveMembers/microsoft\.graph\.user\?') {
                $groupId = $Matches[1]
                $script:roleGroupCalls.Add($groupId)
                if ($script:roleGroupFailures.ContainsKey($groupId)) { throw $script:roleGroupFailures[$groupId] }
                return $script:roleGroupPages[$groupId]
            }
            throw "Unexpected synthetic URI: $Uri"
        }
        Mock Get-SPDirectCredentials { @{} }
        Mock Get-AllUsers {
            Set-CoverageState -Source Users -State Complete
            @(
                [PSCustomObject]@{ id = 'user-member'; displayName = 'Member'; userPrincipalName = 'member@example.test' }
                [PSCustomObject]@{ id = 'user-other'; displayName = 'Other'; userPrincipalName = 'other@example.test' }
            )
        }
    }

    It 'classifies expanded users once and exports both raw groups and membership chains' {
        $script:roleGroupAssignments = @(
            (New-RoleGroupAssignment -Id direct-pra -PrincipalId user-member -PrincipalType user)
            (New-RoleGroupAssignment -Id group-pra)
        )
        $script:roleGroupPages['group-1'] = @{ value = @(@{ id = 'user-member'; displayName = 'Member'; userPrincipalName = 'member@example.test' }) }
        $result = Invoke-RoleAudit
        $result.PrivilegedUsers.Keys | Should -Contain user-member
        @($result.PrivilegedUsers['user-member'].Roles) | Should -Be @('Privileged Role Administrator')
        @($result.NonPrivilegedUsers).id | Should -Be @('user-other')
        $script:capturedExports['RoleAssignedGroups'].Count | Should -Be 1
        $script:capturedExports['RoleGroupMembers'].Count | Should -Be 1
        $script:capturedExports['RoleGroupMembers'][0].MembershipPath | Should -Be 'group-1 -> user-member'
    }

    It 'uses a group-derived PRA assignment as current permission equivalence' {
        $script:roleGroupAssignments = @((New-RoleGroupAssignment))
        $script:roleGroupPages['group-1'] = @{ value = @(@{ id = 'user-member'; displayName = 'Member'; userPrincipalName = 'member@example.test' }) }
        $dangerous = [PSCustomObject]@{
            SPId = 'client-sp'; SPDisplayName = 'Client'; AppId = 'client-app'; AppTenantType = 'HomeTenant'
            ResourceAppId = $script:MicrosoftGraphAppId; Permission = 'AppRoleAssignment.ReadWrite.All'
            PermissionType = 'Application'; Risk = 'Critical'; Reason = 'Synthetic'; AttackAction = 'grant permissions'; AccountEnabled = $true
        }
        Mock Get-ServicePrincipalsWithAppRoles { @($dangerous) }
        Mock Get-ApplicationOwners { @{ 'client-app' = [PSCustomObject]@{ Status = 'Complete'; AppObjectId = 'app-object'; Owners = @([PSCustomObject]@{ id = 'user-member'; displayName = 'Member'; userPrincipalName = 'member@example.test' }) } } }
        Mock Get-AppInstanceLockStatus { @{ 'client-app' = [PSCustomObject]@{ State = 'Disabled'; IsCredentialLocked = $false; ApplicationObjectId = 'app-object'; SignInAudience = 'AzureADMyOrg' } } }
        $script:CachedServicePrincipals = @([PSCustomObject]@{ id = 'client-sp'; appId = 'client-app'; accountEnabled = $true; appOwnerOrganizationId = 'tenant-home' })
        @(Invoke-AttackPathAnalysis | Where-Object PathId -eq APP_OWNER_ESCALATION).Count | Should -Be 0
    }

    It 'does not suppress an owner path with a scoped group-derived PRA assignment' {
        $script:roleGroupAssignments = @((New-RoleGroupAssignment -DirectoryScopeId '/administrativeUnits/au-1'))
        $script:roleGroupPages['group-1'] = @{ value = @(@{ id = 'user-member'; displayName = 'Member'; userPrincipalName = 'member@example.test' }) }
        $dangerous = [PSCustomObject]@{
            SPId = 'client-sp'; SPDisplayName = 'Client'; AppId = 'client-app'; AppTenantType = 'HomeTenant'
            ResourceAppId = $script:MicrosoftGraphAppId; Permission = 'AppRoleAssignment.ReadWrite.All'
            PermissionType = 'Application'; Risk = 'Critical'; Reason = 'Synthetic'; AttackAction = 'grant permissions'; AccountEnabled = $true
        }
        Mock Get-ServicePrincipalsWithAppRoles { @($dangerous) }
        Mock Get-ApplicationOwners { @{ 'client-app' = [PSCustomObject]@{ Status = 'Complete'; AppObjectId = 'app-object'; Owners = @([PSCustomObject]@{ id = 'user-member'; displayName = 'Member'; userPrincipalName = 'member@example.test' }) } } }
        Mock Get-AppInstanceLockStatus { @{ 'client-app' = [PSCustomObject]@{ State = 'Disabled'; IsCredentialLocked = $false; ApplicationObjectId = 'app-object'; SignInAudience = 'AzureADMyOrg' } } }
        $script:CachedServicePrincipals = @([PSCustomObject]@{ id = 'client-sp'; appId = 'client-app'; accountEnabled = $true; appOwnerOrganizationId = 'tenant-home' })
        $paths = @(Invoke-AttackPathAnalysis | Where-Object PathId -eq APP_OWNER_ESCALATION)
        $paths.Count | Should -Be 1
        $paths[0].Exploitability | Should -Be Direct
    }

    It 'creates one role-control path with source-group provenance when expansion is complete' {
        $script:roleGroupDefinitions = @(
            (New-RoleGroupDefinition -Id rd-control -TemplateId $null -Name 'Application Control' -Actions @('microsoft.directory/servicePrincipals/credentials/update'))
            (New-RoleGroupDefinition -Id rd-target -TemplateId '62e90394-69f5-4237-9190-012177145e10' -Name 'Global Administrator')
        )
        $script:roleGroupAssignments = @(
            (New-RoleGroupAssignment -Id group-control -RoleDefinitionId rd-control)
            (New-RoleGroupAssignment -Id sp-target -RoleDefinitionId rd-target -PrincipalId target-sp -PrincipalType servicePrincipal)
        )
        $script:roleGroupPages['group-1'] = @{ value = @(@{ id = 'user-member'; displayName = 'Member'; userPrincipalName = 'member@example.test' }) }
        Mock Get-ServicePrincipalsWithAppRoles { @() }
        Mock Get-AppInstanceLockStatus { @{ 'target-app' = [PSCustomObject]@{ State = 'Disabled'; IsCredentialLocked = $false; ApplicationObjectId = 'target-app-object'; SignInAudience = 'AzureADMyOrg' } } }
        $script:CachedServicePrincipals = @([PSCustomObject]@{ id = 'target-sp'; appId = 'target-app'; displayName = 'Target'; accountEnabled = $true; appOwnerOrganizationId = 'tenant-home'; servicePrincipalType = 'Application' })
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 1
        $paths[0].Exploitability | Should -Be Direct
        $paths[0].RoleAssignmentSource | Should -Be RoleAssignedGroupMember
        $paths[0].RoleMembershipPath | Should -Be 'group-1 -> user-member'
    }

    It 'makes an observed group-derived role path potential when another group expansion fails' {
        $script:roleGroupDefinitions = @(
            (New-RoleGroupDefinition -Id rd-control -TemplateId $null -Name 'Application Control' -Actions @('microsoft.directory/servicePrincipals/credentials/update'))
            (New-RoleGroupDefinition -Id rd-target -TemplateId '62e90394-69f5-4237-9190-012177145e10' -Name 'Global Administrator')
        )
        $script:roleGroupAssignments = @(
            (New-RoleGroupAssignment -Id group-control -RoleDefinitionId rd-control)
            (New-RoleGroupAssignment -Id group-failed -RoleDefinitionId rd-control -PrincipalId group-2)
            (New-RoleGroupAssignment -Id sp-target -RoleDefinitionId rd-target -PrincipalId target-sp -PrincipalType servicePrincipal)
        )
        $script:roleGroupPages['group-1'] = @{ value = @(@{ id = 'user-member'; displayName = 'Member'; userPrincipalName = 'member@example.test' }) }
        $script:roleGroupFailures['group-2'] = 'synthetic denied group'
        Mock Get-ServicePrincipalsWithAppRoles { @() }
        Mock Get-AppInstanceLockStatus { @{ 'target-app' = [PSCustomObject]@{ State = 'Disabled'; IsCredentialLocked = $false; ApplicationObjectId = 'target-app-object'; SignInAudience = 'AzureADMyOrg' } } }
        $script:CachedServicePrincipals = @([PSCustomObject]@{ id = 'target-sp'; appId = 'target-app'; displayName = 'Target'; accountEnabled = $true; appOwnerOrganizationId = 'tenant-home'; servicePrincipalType = 'Application' })
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 1
        $paths[0].Exploitability | Should -Be PotentialRoleUnknown
    }

    It 'deduplicates a controller with direct and group-derived authority into one path' {
        $script:roleGroupDefinitions = @(
            (New-RoleGroupDefinition -Id rd-control -TemplateId $null -Name 'Application Control' -Actions @('microsoft.directory/servicePrincipals/credentials/update'))
            (New-RoleGroupDefinition -Id rd-target -TemplateId '62e90394-69f5-4237-9190-012177145e10' -Name 'Global Administrator')
        )
        $script:roleGroupAssignments = @(
            (New-RoleGroupAssignment -Id direct-control -RoleDefinitionId rd-control -PrincipalId user-member -PrincipalType user)
            (New-RoleGroupAssignment -Id group-control -RoleDefinitionId rd-control)
            (New-RoleGroupAssignment -Id sp-target -RoleDefinitionId rd-target -PrincipalId target-sp -PrincipalType servicePrincipal)
        )
        $script:roleGroupPages['group-1'] = @{ value = @(@{ id = 'user-member'; displayName = 'Member'; userPrincipalName = 'member@example.test' }) }
        Mock Get-ServicePrincipalsWithAppRoles { @() }
        Mock Get-AppInstanceLockStatus { @{ 'target-app' = [PSCustomObject]@{ State = 'Disabled'; IsCredentialLocked = $false; ApplicationObjectId = 'target-app-object'; SignInAudience = 'AzureADMyOrg' } } }
        $script:CachedServicePrincipals = @([PSCustomObject]@{ id = 'target-sp'; appId = 'target-app'; displayName = 'Target'; accountEnabled = $true; appOwnerOrganizationId = 'tenant-home'; servicePrincipalType = 'Application' })
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 1
        $paths[0].RoleAssignmentSource | Should -Match 'Direct'
        $paths[0].RoleAssignmentSource | Should -Match 'RoleAssignedGroupMember'
        $paths[0].RoleMembershipPath | Should -Match 'group-1 -> user-member'
    }
}