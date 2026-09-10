BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'Invoke-PrivilegedAudit.ps1')

    function Invoke-MgGraphRequest {
        param($Method, $Uri)
        throw "Unmocked Graph request: $Method $Uri"
    }

    function New-ValidityCredential {
        param($Start = '2026-09-01T00:00:00Z', $End = '2026-10-01T00:00:00Z')
        @{ keyId = 'synthetic-key'; displayName = 'Synthetic credential'; startDateTime = $Start; endDateTime = $End }
    }

    function New-ValidityGrant {
        param([string]$AppId = 'app-one', [string]$Permission = 'Application.ReadWrite.All')
        [pscustomobject]@{
            AppId = $AppId; SPId = "sp-$AppId"; SPDisplayName = 'Same display name'
            AppTenantType = 'HomeTenant'; PermissionType = 'Application'; Permission = $Permission
            ResourceAppId = $script:MicrosoftGraphAppId
        }
    }
}

Describe 'P2 credential validity through real collectors and consumers' {
    BeforeEach {
        Reset-AuditCoverage
        $script:AuditConfig = $script:DefaultAuditConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        $script:validityApp = @{ id = 'app-object'; passwordCredentials = @(); keyCredentials = @() }
        $script:validitySP = @{ id = 'sp-app-one'; passwordCredentials = @(); keyCredentials = @() }
        $script:validityFICs = @()
        $script:validityGrants = @(New-ValidityGrant)
        $script:validityPartial = $false
        $script:validityExports = @{}
        $script:validityRoles = @()
        $script:CachedServicePrincipals = @(@{ id = 'sp-app-one'; appId = 'app-one'; accountEnabled = $true })
        Mock Get-Date { [datetime]'2026-09-09T12:00:00Z' }
        Mock Write-Host {}
        Mock Write-Banner {}
        Mock Write-Reference {}
        Mock Write-Recommendation {}
        Mock Write-AuditCoverageSummary {}
        Mock Export-AuditCsv { param($Name, $Data); $script:validityExports[$Name] = @($Data) }
        Mock Get-ServicePrincipalsWithAppRoles {
            foreach ($source in @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions')) {
                Set-CoverageState -Source $source -State Complete
            }
            if ($script:validityPartial) { Set-CoverageState -Source ApplicationPermissionGrants -State Partial -Detail 'Synthetic incomplete grants' }
            $script:validityGrants
        }
        Mock Get-PrivilegedRoleAssignments {
            foreach ($source in @('RoleDefinitions', 'ActiveRoleAssignments', 'RoleGroupMemberships')) { Set-CoverageState -Source $source -State Complete }
            $script:validityRoles
        }
        Mock Get-ApplicationOwners {
            @{ 'app-one' = [pscustomobject]@{ Status = 'Complete'; AppObjectId = 'app-object'; Owners = @(@{ id = 'owner'; displayName = 'Synthetic owner'; userPrincipalName = 'owner@example.test' }) } }
        }
        Mock Get-ServicePrincipalOwners {
            @{ 'sp-app-one' = @(@{ id = 'owner'; displayName = 'Synthetic owner'; userPrincipalName = 'owner@example.test' }) }
        }
        Mock Get-AppInstanceLockStatus { @{} }
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Method -ne 'GET') { throw 'Only synthetic GET requests are allowed' }
            if ($Uri -match '/applications\?') { return @{ value = @($script:validityApp) } }
            if ($Uri -match '/applications/app-object/federatedIdentityCredentials') { return @{ value = $script:validityFICs } }
            if ($Uri -match '/servicePrincipals/[^/?]+\?') { return $script:validitySP }
            if ($Uri -match '/reports/servicePrincipalSignInActivities') {
                return @{ value = @($script:validityGrants | ForEach-Object {
                    @{ appId = $_.AppId; lastSignInActivity = @{ lastSignInDateTime = '2025-01-01T00:00:00Z' } }
                }) }
            }
            throw "Unexpected synthetic URI: $Uri"
        }
    }

    It 'classifies <Surface> <Property> with <Case> dates as <Validity>' -ForEach @(
        foreach ($surface in @('App', 'SP')) {
            foreach ($property in @('passwordCredentials', 'keyCredentials')) {
                foreach ($case in @(
                    @{ Case = 'current'; Start = '2026-09-01T00:00:00Z'; End = '2026-10-01T00:00:00Z'; Validity = 'Current'; Current = $true; Expired = $false }
                    @{ Case = 'start exactly now'; Start = '2026-09-09T12:00:00Z'; End = '2026-10-01T00:00:00Z'; Validity = 'Current'; Current = $true; Expired = $false }
                    @{ Case = 'end exactly now'; Start = '2026-09-01T00:00:00Z'; End = '2026-09-09T12:00:00Z'; Validity = 'Expired'; Current = $false; Expired = $true }
                    @{ Case = 'future'; Start = '2026-09-10T00:00:00Z'; End = '2026-10-01T00:00:00Z'; Validity = 'Future'; Current = $false; Expired = $false }
                    @{ Case = 'expired'; Start = '2026-09-01T00:00:00Z'; End = '2026-09-02T00:00:00Z'; Validity = 'Expired'; Current = $false; Expired = $true }
                    @{ Case = 'offset start equal now'; Start = '2026-09-09T14:00:00+02:00'; End = '2026-09-09T08:01:00-04:00'; Validity = 'Current'; Current = $true; Expired = $false }
                    @{ Case = 'offset end equal now'; Start = '2026-09-01T00:00:00Z'; End = '2026-09-09T08:00:00-04:00'; Validity = 'Expired'; Current = $false; Expired = $true }
                    @{ Case = 'offset future'; Start = '2026-09-09T08:01:00-04:00'; End = '2026-10-01T00:00:00Z'; Validity = 'Future'; Current = $false; Expired = $false }
                    @{ Case = 'missing start'; Start = $null; End = '2026-10-01T00:00:00Z'; Validity = 'Unknown'; Current = $false; Expired = $false }
                    @{ Case = 'missing end'; Start = '2026-09-01T00:00:00Z'; End = $null; Validity = 'Unknown'; Current = $false; Expired = $null }
                    @{ Case = 'malformed start'; Start = 'not-a-date'; End = '2026-10-01T00:00:00Z'; Validity = 'Unknown'; Current = $false; Expired = $false }
                    @{ Case = 'malformed end'; Start = '2026-09-01T00:00:00Z'; End = 'not-a-date'; Validity = 'Unknown'; Current = $false; Expired = $null }
                    @{ Case = 'inverted'; Start = '2026-10-01T00:00:00Z'; End = '2026-09-01T00:00:00Z'; Validity = 'Unknown'; Current = $false; Expired = $true }
                    @{ Case = 'empty interval'; Start = '2026-09-09T12:00:00Z'; End = '2026-09-09T12:00:00Z'; Validity = 'Unknown'; Current = $false; Expired = $true }
                    @{ Case = 'typed offsets'; Start = [datetimeoffset]'2026-09-09T14:00:00+02:00'; End = [datetimeoffset]'2026-09-09T08:01:00-04:00'; Validity = 'Current'; Current = $true; Expired = $false }
                    @{ Case = 'time-only values'; Start = '00:00'; End = '23:59'; Validity = 'Unknown'; Current = $false; Expired = $null }
                    @{ Case = 'date-only values'; Start = '2026-09-01'; End = '2026-10-01'; Validity = 'Unknown'; Current = $false; Expired = $null }
                    @{ Case = 'missing timezone'; Start = '2026-09-01T00:00:00'; End = '2026-10-01T00:00:00'; Validity = 'Unknown'; Current = $false; Expired = $null }
                )) { $case + @{ Surface = $surface; Property = $property } }
            }
        }
    ) {
        $evidence = @{}
        if ($Surface -eq 'App') {
            $script:validityApp[$Property] = @(New-ValidityCredential -Start $Start -End $End)
            $credentials = (Get-AppCredentials -AppIds app-one -EvidenceStatus $evidence)['app-one']
            $source = 'ApplicationCredentials'; $objectId = 'app-one'
        } else {
            $script:validitySP[$Property] = @(New-ValidityCredential -Start $Start -End $End)
            $credentials = (Get-SPDirectCredentials -SPIds sp-app-one -EvidenceStatus $evidence)['sp-app-one']
            $source = 'ServicePrincipalCredentials'; $objectId = 'sp-app-one'
        }
        @($credentials).Count | Should -Be 1
        $credentials[0].Validity | Should -Be $Validity
        $credentials[0].IsCurrentlyValid | Should -Be $Current
        $credentials[0].Expired | Should -Be $Expired
        $expectedEvidence = if ($Validity -eq 'Unknown') { 'Partial' } else { 'Complete' }
        $evidence[$objectId] | Should -Be $expectedEvidence
        $script:Coverage[$source].State | Should -Be $expectedEvidence
    }

    It 'excludes <Surface> <Property> <Case> credentials from stale without changing known-date coverage' -ForEach @(
        foreach ($surface in @('App', 'SP')) {
            foreach ($property in @('passwordCredentials', 'keyCredentials')) {
                @{ Surface = $surface; Property = $property; Case = 'future'; Start = '2026-09-10T00:00:00Z'; End = '2026-10-01T00:00:00Z' }
                @{ Surface = $surface; Property = $property; Case = 'expired'; Start = '2026-09-01T00:00:00Z'; End = '2026-09-09T12:00:00Z' }
            }
        }
    ) {
        $response = if ($Surface -eq 'App') { $script:validityApp } else { $script:validitySP }
        $response[$Property] = @(New-ValidityCredential -Start $Start -End $End)
        @(Invoke-StalePrivilegeDetection).Count | Should -Be 0
        $script:StalePrivilegeDataAvailable | Should -BeTrue
    }

    It 'never emits clean stale for <Surface> <Case> validity and retains a separate current credential' -ForEach @(
        foreach ($surface in @('App', 'SP')) {
            @{ Surface = $surface; Case = 'missing start'; Start = $null; End = '2026-10-01T00:00:00Z' }
            @{ Surface = $surface; Case = 'missing end'; Start = '2026-09-01T00:00:00Z'; End = $null }
            @{ Surface = $surface; Case = 'malformed start'; Start = 'invalid'; End = '2026-10-01T00:00:00Z' }
            @{ Surface = $surface; Case = 'malformed end'; Start = '2026-09-01T00:00:00Z'; End = 'invalid' }
            @{ Surface = $surface; Case = 'inverted'; Start = '2026-10-01T00:00:00Z'; End = '2026-09-01T00:00:00Z' }
        }
    ) {
        $response = if ($Surface -eq 'App') { $script:validityApp } else { $script:validitySP }
        $response.passwordCredentials = @(New-ValidityCredential -Start $Start -End $End)
        @(Invoke-StalePrivilegeDetection).Count | Should -Be 0
        $script:StalePrivilegeDataAvailable | Should -BeFalse
        $script:StalePrivilegeStatus | Should -Be 'Credential coverage is incomplete'
        Should -Invoke Write-Host -Times 0 -Exactly -ParameterFilter { "$Object" -match 'No stale high-privilege apps found' }
        $response.keyCredentials = @(New-ValidityCredential)
        $rows = @(Invoke-StalePrivilegeDetection)
        $rows.Count | Should -Be 1
        $rows[0].ValidCredCount | Should -Be 1
        $rows[0].CredentialType | Should -Match 'Certificate'
        $script:StalePrivilegeDataAvailable | Should -BeFalse
    }

    It 'preserves timeless FIC treatment explicitly without inventing dates' {
        $script:validityFICs = @(@{ id = 'fic-one'; name = 'Synthetic federation' })
        $evidence = @{}
        $credential = (Get-AppCredentials -AppIds app-one -EvidenceStatus $evidence)['app-one'][0]
        $credential.Validity | Should -Be 'Timeless'
        $credential.IsCurrentlyValid | Should -BeTrue
        $credential.Expired | Should -BeFalse
        $credential.StartDateTime | Should -BeNullOrEmpty
        $credential.EndDateTime | Should -BeNullOrEmpty
        $evidence['app-one'] | Should -Be 'Complete'
        $row = @(Invoke-StalePrivilegeDetection)[0]
        $row.CredentialType | Should -Be 'Federated'
        $row.CredentialExpires | Should -Be 'N/A'
        $row.ValidCredCount | Should -Be 1
    }

    It 'formats a current typed-offset credential expiry without aborting stale analysis' {
        $script:validityApp.keyCredentials = @(New-ValidityCredential -Start ([datetimeoffset]'2026-09-01T00:00:00Z') -End ([datetimeoffset]'2026-10-01T23:00:00-02:00'))
        $row = @(Invoke-StalePrivilegeDetection)[0]
        $row.ValidCredCount | Should -Be 1
        $row.CredentialExpires | Should -Be '2026-10-02'
        $script:StalePrivilegeDataAvailable | Should -BeTrue
    }

    It 'does not invent dates from time-only credential metadata or call stale analysis clean' {
        $script:validityApp.passwordCredentials = @(New-ValidityCredential -Start '00:00' -End '23:59')
        @(Invoke-StalePrivilegeDetection).Count | Should -Be 0
        $script:StalePrivilegeDataAvailable | Should -BeFalse
        $script:Coverage.ApplicationCredentials.State | Should -Be 'Partial'
        Should -Invoke Write-Host -Times 0 -Exactly -ParameterFilter { "$Object" -match 'No stale high-privilege apps found' }
    }

    It 'uses current SP credentials consistently in AttackPath, ShadowAdmins and Hygiene for <Property>' -ForEach @(
        @{ Property = 'passwordCredentials' }; @{ Property = 'keyCredentials' }
    ) {
        $script:validitySP[$Property] = @(
            (New-ValidityCredential)
            (New-ValidityCredential -Start '2026-09-10T00:00:00Z')
            (New-ValidityCredential -End '2026-09-09T12:00:00Z')
            (New-ValidityCredential -Start $null)
        )
        $paths = @(Invoke-AttackPathAnalysis)
        $paths.Count | Should -Be 1
        $paths[0].SPDirectCreds | Should -Be 1
        $script:validityRoles = @([pscustomobject]@{
            PrincipalId = 'sp-app-one'; PrincipalType = '#microsoft.graph.servicePrincipal'; IsSensitiveTarget = $true
            RoleName = 'Synthetic sensitive role'; PrincipalDisplayName = 'Synthetic SP'; DirectoryScopeId = '/'
        })
        $shadows = @(Invoke-ShadowAdminDetection)
        $shadows.Count | Should -Be 1
        $shadows[0].SPDirectCreds | Should -Be 1
        $hygiene = @(Invoke-CredentialHygieneAudit)[0]
        $hygiene.CredCount | Should -Be 4
        $hygiene.ExpiredCount | Should -Be 1
        $hygiene.SPDirectCreds | Should -Be 1
        $hygiene.CredentialEvidence | Should -Be 'Partial'
        $hygiene.RiskLevel | Should -Match 'REVIEW.*lower.bound'
    }

    It 'uses current-only <Property> counts in the <Branch> AttackPath branch' -ForEach @(
        @{ Branch = 'role-control'; Property = 'passwordCredentials' }
        @{ Branch = 'role-control'; Property = 'keyCredentials' }
        @{ Branch = 'unowned'; Property = 'passwordCredentials' }
        @{ Branch = 'unowned'; Property = 'keyCredentials' }
    ) {
        $script:validitySP[$Property] = @(
            (New-ValidityCredential)
            (New-ValidityCredential -Start '2026-09-10T00:00:00Z')
            (New-ValidityCredential -End '2026-09-09T12:00:00Z')
            (New-ValidityCredential -Start $null)
        )
        if ($Branch -eq 'unowned') {
            Mock Get-ApplicationOwners {
                @{ 'app-one' = [pscustomobject]@{ Status = 'Complete'; AppObjectId = 'app-object'; Owners = @() } }
            }
            $null = Invoke-AttackPathAnalysis
            $rows = $script:validityExports.UnownedPrivilegedApps
        } else {
            $script:validityGrants = @()
            $script:validityRoles = @(
                [pscustomobject]@{
                    PrincipalId = 'sp-app-one'; PrincipalAppId = 'app-one'; PrincipalType = '#microsoft.graph.servicePrincipal'
                    IsSensitiveTarget = $true; RoleDefinitionId = 'target'; RoleName = 'Synthetic target'; DirectoryScopeId = '/'
                }
                [pscustomobject]@{
                    PrincipalId = 'operator'; PrincipalType = '#microsoft.graph.user'; CanControlServicePrincipals = $true
                    RoleDefinitionId = 'controller'; RoleName = 'Synthetic controller'; DirectoryScopeId = '/'
                }
            )
            $rows = @(Invoke-AttackPathAnalysis)
            $rows[0].PathId | Should -Be 'ROLE_BASED_SP_CONTROL'
        }
        $rows.Count | Should -Be 1
        $rows[0].SPDirectCreds | Should -Be 1
        $script:Coverage.ServicePrincipalCredentials.State | Should -Be 'Partial'
    }

    It 'supports an explicit clock independently of the collector clock' {
        $credential = New-ValidityCredential -Start '2026-09-09T13:00:00Z'
        (Resolve-CredentialValidity -InputObject $credential -Now ([datetimeoffset]'2026-09-09T12:00:00Z')).Validity | Should -Be 'Future'
        (Resolve-CredentialValidity -InputObject $credential -Now ([datetimeoffset]'2026-09-09T13:00:00Z')).Validity | Should -Be 'Current'
        (Resolve-CredentialValidity -InputObject $credential -Now ([datetimeoffset]'2026-10-01T00:00:00Z')).Validity | Should -Be 'Expired'
    }

    It 'keeps future and expired SP inventory but no active SP credentials' {
        $script:validitySP.passwordCredentials = @(
            (New-ValidityCredential -Start '2026-09-10T00:00:00Z')
            (New-ValidityCredential -End '2026-09-09T12:00:00Z')
        )
        $row = @(Invoke-CredentialHygieneAudit)[0]
        $row.CredCount | Should -Be 2
        $row.ExpiredCount | Should -Be 1
        $row.SPDirectCreds | Should -Be 0
        $row.CredentialEvidence | Should -Be 'Complete'
        $row.RiskLevel | Should -Not -Match 'SP-level credentials'
    }

    It 'reports unknown active SP count when only missing date evidence is observed' {
        $script:validitySP.keyCredentials = @(New-ValidityCredential -End $null)
        $row = @(Invoke-CredentialHygieneAudit)[0]
        $row.CredCount | Should -Be 1
        $row.SPDirectCreds | Should -Be 'Unknown'
        $row.CredentialEvidence | Should -Be 'Partial'
        $row.RiskLevel | Should -Match 'REVIEW'
        $row.RiskLevel | Should -Not -Match 'GOOD|no credentials'
    }

    It 'isolates unknown dates to the affected object while source coverage stays partial' {
        Mock Invoke-MgGraphRequest {
            @{ value = @(@{ id = 'app-object'; passwordCredentials = @((New-ValidityCredential -Start $null)); keyCredentials = @() }) }
        } -ParameterFilter { $Uri -match "appId eq 'unknown-app'" }
        $evidence = @{}
        $null = Get-AppCredentials -AppIds unknown-app, app-one -EvidenceStatus $evidence
        $evidence['unknown-app'] | Should -Be 'Partial'
        $evidence['app-one'] | Should -Be 'Complete'
        $script:Coverage.ApplicationCredentials.State | Should -Be 'Partial'
    }

    It 'counts <Apps> distinct stale AppIds for console, Full summary and actions with partial=<Partial>' -ForEach @(
        @{ Apps = 1; Partial = $false }; @{ Apps = 2; Partial = $false }
        @{ Apps = 1; Partial = $true }; @{ Apps = 2; Partial = $true }
    ) {
        $script:validityGrants += New-ValidityGrant -Permission 'RoleManagement.ReadWrite.Directory'
        if ($Apps -eq 2) { $script:validityGrants += New-ValidityGrant -AppId app-two }
        $script:validityPartial = $Partial
        $script:validityApp.keyCredentials = @(New-ValidityCredential)
        Mock Invoke-PermissionAudit { @() }
        Mock Invoke-RoleAudit { [pscustomobject]@{ PrivilegedUsers = @{}; NonPrivilegedUsers = @(); SPRoles = @(); CoverageComplete = $true } }
        Mock Invoke-AttackPathAnalysis { @() }
        Mock Invoke-ShadowAdminDetection { @() }
        Mock Invoke-ConsentRiskAssessment { @() }
        Mock Invoke-CredentialHygieneAudit { @() }
        Invoke-FullAudit
        $script:validityExports.StalePrivilege.Count | Should -Be ($Apps + 1)
        @($script:validityExports.StalePrivilege | Select-Object -ExpandProperty AppId -Unique).Count | Should -Be $Apps
        @($script:validityExports.StalePrivilege | Select-Object -ExpandProperty AppName -Unique).Count | Should -Be 1
        $summary = $script:validityExports.FullAuditSummary | Where-Object Section -eq StalePrivilege
        $summary.Count | Should -Be $Apps
        $summary.Finding | Should -Match "$Apps dormant high-privilege apps"
        $action = $script:validityExports.FullAuditSummary | Where-Object Finding -Like 'Disable/delete*'
        $action.Finding | Should -Be "Disable/delete $Apps dormant apps with dangerous permissions and valid credentials"
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -eq "Found $Apps stale high-privilege app(s):" }
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match "Stale Privilege:.*$Apps dormant high-privilege apps" }
        if ($Partial) {
            $summary.Finding | Should -Be "Incomplete (permission evidence); $Apps dormant high-privilege apps observed"
            $script:StalePrivilegeDataAvailable | Should -BeFalse
            Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match 'observed lower bounds' }
        } else { $script:StalePrivilegeDataAvailable | Should -BeTrue }
    }
}