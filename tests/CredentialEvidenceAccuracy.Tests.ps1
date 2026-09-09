BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'Invoke-PrivilegedAudit.ps1')

    function New-CredentialEvidenceGrant {
        param([string]$AppId = 'home-app', [string]$SPId = 'home-sp', [string]$TenantType = 'HomeTenant')
        [PSCustomObject]@{
            AppId = $AppId; SPId = $SPId; SPDisplayName = $AppId
            AppTenantType = $TenantType; PermissionType = 'Application'
            Permission = 'Application.ReadWrite.All'
        }
    }
}

Describe 'Credential evidence accuracy' {
    BeforeEach {
        Reset-AuditCoverage
        $script:AuditConfig = $script:DefaultAuditConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        $script:credentialAppResponse = @{
            id = 'home-object'; appId = 'home-app'; passwordCredentials = @(); keyCredentials = @()
        }
        $script:credentialSPResponse = @{ id = 'home-sp'; passwordCredentials = @(); keyCredentials = @() }
        $script:credentialFICResponse = @()
        $script:credentialAppFails = $false
        $script:credentialSPFails = $false
        $script:credentialFICFails = $false
        $script:credentialFICPaging = $null
        $script:credentialSignInFails = $false
        $script:credentialGrants = @(New-CredentialEvidenceGrant)
        $script:syntheticCertificate = @{
            keyId = 'certificate-1'; displayName = 'Synthetic certificate'
            startDateTime = (Get-Date).AddDays(-10).ToString('o')
            endDateTime = (Get-Date).AddDays(30).ToString('o')
        }
        Mock Write-Host {}
        Mock Write-Banner {}
        Mock Write-Reference {}
        Mock Write-Recommendation {}
        Mock Export-AuditCsv {}
        Mock Get-ServicePrincipalsWithAppRoles {
            foreach ($source in @('ServicePrincipals', 'ApplicationPermissionGrants', 'ResourcePermissionDefinitions')) {
                Set-CoverageState -Source $source -State Complete
            }
            return $script:credentialGrants
        }
        Mock Get-AppInstanceLockStatus { return @{} }
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Method -ne 'GET') { throw 'Only GET is allowed' }
            if ($Uri -match '/applications\?') {
                if ($script:credentialAppFails) { throw 'Synthetic application read denied' }
                return @{ value = @($script:credentialAppResponse | Where-Object { $_ }) }
            }
            if ($Uri -match '/applications/[^/]+/federatedIdentityCredentials') {
                if ($script:credentialFICFails) { throw 'Synthetic FIC read denied' }
                $page = @{ value = @($script:credentialFICResponse) }
                if ($script:credentialFICPaging) { $page['@odata.nextLink'] = 'https://graph.microsoft.com/v1.0/fic-page-two' }
                return $page
            }
            if ($Uri -match '/fic-page-two$') {
                if ($script:credentialFICPaging -eq 'Failure') { throw 'Synthetic later FIC page denied' }
                return @{ value = @(@{ id = 'fic-two'; name = 'Second synthetic federation' }) }
            }
            if ($Uri -match '/servicePrincipals/[^/?]+\?') {
                if ($script:credentialSPFails) { throw 'Synthetic SP read denied' }
                return $script:credentialSPResponse
            }
            if ($Uri -match '/reports/servicePrincipalSignInActivities') {
                if ($script:credentialSignInFails) { throw 'Synthetic sign-in read denied' }
                return @{ value = @() }
            }
            throw "Unexpected synthetic URI: $Uri"
        }
    }

    It 'keeps successful empty helper values as arrays with Complete companion status' {
        $appEvidence = @{}
        $spEvidence = @{}
        $appMap = Get-AppCredentials -AppIds 'home-app' -EvidenceStatus $appEvidence
        $spMap = Get-SPDirectCredentials -SPIds 'home-sp' -EvidenceStatus $spEvidence
        ($appMap['home-app'] -is [array]) | Should -BeTrue
        ($spMap['home-sp'] -is [array]) | Should -BeTrue
        $appMap['home-app'].Count | Should -Be 0
        $spMap['home-sp'].Count | Should -Be 0
        $appEvidence['home-app'] | Should -Be 'Complete'
        $spEvidence['home-sp'] | Should -Be 'Complete'
    }

    It 'marks failed application and SP helper reads Unavailable' {
        $script:credentialAppFails = $true
        $script:credentialSPFails = $true
        $appEvidence = @{}
        $spEvidence = @{}
        $appMap = Get-AppCredentials -AppIds 'home-app' -EvidenceStatus $appEvidence
        $spMap = Get-SPDirectCredentials -SPIds 'home-sp' -EvidenceStatus $spEvidence
        $appMap.ContainsKey('home-app') | Should -BeFalse
        $spMap.ContainsKey('home-sp') | Should -BeFalse
        $appEvidence['home-app'] | Should -Be 'Unavailable'
        $spEvidence['home-sp'] | Should -Be 'Unavailable'
    }

    It 'does not call a missing local application or SP response Complete-empty' {
        $script:credentialAppResponse = $null
        $script:credentialSPResponse = $null
        $appEvidence = @{}
        $spEvidence = @{}
        $null = Get-AppCredentials -AppIds 'home-app' -EvidenceStatus $appEvidence
        $spMap = Get-SPDirectCredentials -SPIds 'home-sp' -EvidenceStatus $spEvidence
        $appEvidence['home-app'] | Should -Be 'Unavailable'
        $spEvidence['home-sp'] | Should -Be 'Unavailable'
        $spMap.ContainsKey('home-sp') | Should -BeFalse
    }

    It 'preserves observed application credentials when FIC enumeration fails' {
        $script:credentialAppResponse.keyCredentials = @($script:syntheticCertificate)
        $script:credentialFICFails = $true
        $evidence = @{}
        $result = Get-AppCredentials -AppIds 'home-app' -EvidenceStatus $evidence
        $result['home-app'].Count | Should -Be 1
        $result['home-app'][0].Type | Should -Be 'Certificate'
        $evidence['home-app'] | Should -Be 'Partial'
    }

    It 'retains observed federated credentials after a later page fails with per-call Partial status' {
        $script:credentialFICResponse = @(@{ id = 'fic-one'; name = 'First synthetic federation' })
        $script:credentialFICPaging = 'Failure'
        $evidence = @{}
        $result = Get-AppCredentials -AppIds 'home-app' -EvidenceStatus $evidence
        $result['home-app'].Count | Should -Be 1
        $result['home-app'][0].Type | Should -Be 'Federated'
        $result['home-app'][0].KeyId | Should -Be 'fic-one'
        $evidence['home-app'] | Should -Be 'Partial'
        $script:Coverage.FederatedIdentityCredentials.State | Should -Be 'Partial'

        $script:credentialFICPaging = 'Success'
        $result = Get-AppCredentials -AppIds 'home-app' -EvidenceStatus $evidence
        $result['home-app'].Count | Should -Be 2
        $evidence['home-app'] | Should -Be 'Complete'
        $script:Coverage.FederatedIdentityCredentials.State | Should -Be 'Partial'
    }

    It 'retains stale evidence from a federated credential on a successful earlier page' {
        $script:credentialFICResponse = @(@{ id = 'fic-one'; name = 'First synthetic federation' })
        $script:credentialFICPaging = 'Failure'
        $result = @(Invoke-StalePrivilegeDetection)
        $result.Count | Should -Be 1
        $result[0].CredentialType | Should -Be 'Federated'
        $script:StalePrivilegeDataAvailable | Should -BeFalse
        $script:StalePrivilegeStatus | Should -Match 'Credential'
    }

    It 'collects successful FIC pages without weakening complete evidence' {
        $script:credentialFICResponse = @(@{ id = 'fic-one'; name = 'First synthetic federation' })
        $script:credentialFICPaging = 'Success'
        $evidence = @{}
        $result = Get-AppCredentials -AppIds 'home-app' -EvidenceStatus $evidence
        $result['home-app'].Count | Should -Be 2
        $evidence['home-app'] | Should -Be 'Complete'
        $script:Coverage.FederatedIdentityCredentials.State | Should -Be 'Complete'
    }

    It 'treats omitted credential properties as incomplete while retaining observed credentials' {
        $script:credentialAppResponse.Remove('passwordCredentials')
        $script:credentialAppResponse.keyCredentials = @($script:syntheticCertificate)
        $script:credentialSPResponse.Remove('passwordCredentials')
        $script:credentialSPResponse.keyCredentials = @($script:syntheticCertificate)
        $appEvidence = @{}
        $spEvidence = @{}
        (Get-AppCredentials -AppIds 'home-app' -EvidenceStatus $appEvidence)['home-app'].Count | Should -Be 1
        (Get-SPDirectCredentials -SPIds 'home-sp' -EvidenceStatus $spEvidence)['home-sp'].Count | Should -Be 1
        $appEvidence['home-app'] | Should -Be 'Partial'
        $spEvidence['home-sp'] | Should -Be 'Partial'
    }

    It 'reports Unknown rather than None or zero for <Failure> with no observed credentials' -ForEach @(
        @{ Failure = 'application'; Expected = 'Partial' }
        @{ Failure = 'SP'; Expected = 'Partial' }
        @{ Failure = 'FIC'; Expected = 'Partial' }
        @{ Failure = 'both'; Expected = 'Unavailable' }
        @{ Failure = 'missing application'; Expected = 'Partial' }
    ) {
        param($Failure, $Expected)
        $script:credentialAppFails = $Failure -in @('application', 'both')
        $script:credentialSPFails = $Failure -in @('SP', 'both')
        $script:credentialFICFails = $Failure -eq 'FIC'
        if ($Failure -eq 'missing application') { $script:credentialAppResponse = $null }
        $result = @(Invoke-CredentialHygieneAudit)
        $result.Count | Should -Be 1
        $result[0].CredentialEvidence | Should -Be $Expected
        $result[0].CredType | Should -Be 'Unknown'
        $result[0].CredCount | Should -Be 'Unknown'
        $result[0].ExpiredCount | Should -Be 'Unknown'
        $result[0].RiskLevel | Should -Match 'REVIEW'
        $result[0].RiskLevel | Should -Not -Match 'GOOD|INFO|no credentials'
        if ($script:credentialSPFails) { $result[0].SPDirectCreds | Should -Be 'Unknown' }
    }

    It 'keeps successfully enumerated empty credentials informational' {
        $result = @(Invoke-CredentialHygieneAudit)[0]
        $result.CredentialEvidence | Should -Be 'Complete'
        $result.CredType | Should -Be 'None'
        $result.CredCount | Should -Be 0
        $result.RiskLevel | Should -Match 'INFO.*no credentials'
    }

    It 'keeps a fully observed preferred credential GOOD with its exact count' {
        $script:credentialAppResponse.keyCredentials = @($script:syntheticCertificate)
        $result = @(Invoke-CredentialHygieneAudit)[0]
        $result.CredentialEvidence | Should -Be 'Complete'
        $result.CredType | Should -Be 'Certificate'
        $result.CredCount | Should -Be 1
        $result.RiskLevel | Should -Match 'GOOD'
    }

    It 'reports observed preferred credentials as a lower bound requiring review when FIC is unknown' {
        $script:credentialAppResponse.keyCredentials = @($script:syntheticCertificate)
        $script:credentialFICFails = $true
        $result = @(Invoke-CredentialHygieneAudit)[0]
        $result.CredentialEvidence | Should -Be 'Partial'
        $result.CredType | Should -Be 'Certificate'
        $result.CredCount | Should -Be 1
        $result.RiskLevel | Should -Match 'REVIEW.*lower.bound'
        $result.RiskLevel | Should -Not -Match 'GOOD'
    }

    It 'never queries an external publisher registration or calls it credential-free' {
        $script:credentialGrants = @(New-CredentialEvidenceGrant -TenantType ThirdParty)
        $result = @(Invoke-CredentialHygieneAudit)[0]
        $result.CredentialEvidence | Should -Be 'NotLocallyObservable'
        $result.CredType | Should -Be 'Unknown'
        $result.CredCount | Should -Be 'Unknown'
        $result.RiskLevel | Should -Match 'REVIEW'
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly -ParameterFilter { $Uri -match '/applications' }
    }

    It 'retains observed SP risk and lower-bound counts with unknown publisher credentials' {
        $script:credentialGrants = @(New-CredentialEvidenceGrant -TenantType ThirdParty)
        $script:credentialSPResponse.passwordCredentials = @($script:syntheticCertificate)
        $result = @(Invoke-CredentialHygieneAudit)[0]
        $result.CredentialEvidence | Should -Be 'NotLocallyObservable'
        $result.CredType | Should -Be 'SP-Secret'
        $result.CredCount | Should -Be 1
        $result.SPDirectCreds | Should -Be 1
        $result.RiskLevel | Should -Match 'CRITICAL'
        $result.RiskLevel | Should -Match 'REVIEW.*lower.bound'
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly -ParameterFilter { $Uri -match '/applications' }
    }

    It 'isolates credential evidence per app instead of tainting every row with a failed read' {
        $script:credentialGrants += New-CredentialEvidenceGrant -AppId 'failed-app' -SPId 'failed-sp'
        Mock Invoke-MgGraphRequest { throw 'Synthetic single app denied' } -ParameterFilter { $Uri -match "appId eq 'failed-app'" }
        $result = @(Invoke-CredentialHygieneAudit)
        ($result | Where-Object AppId -eq 'home-app').CredentialEvidence | Should -Be 'Complete'
        ($result | Where-Object AppId -eq 'home-app').CredCount | Should -Be 0
        ($result | Where-Object AppId -eq 'failed-app').CredentialEvidence | Should -Be 'Partial'
        ($result | Where-Object AppId -eq 'failed-app').CredCount | Should -Be 'Unknown'
    }

    It 'does not carry credential evidence from a previous mode invocation' {
        $script:credentialFICFails = $true
        @(Invoke-CredentialHygieneAudit)[0].CredentialEvidence | Should -Be 'Partial'
        $script:credentialFICFails = $false
        @(Invoke-CredentialHygieneAudit)[0].CredentialEvidence | Should -Be 'Complete'
    }

    It 'does not emit a clean stale result for <Failure>' -ForEach @(
        @{ Failure = 'application' }; @{ Failure = 'SP' }; @{ Failure = 'FIC' }; @{ Failure = 'third-party' }
    ) {
        param($Failure)
        $script:credentialAppFails = $Failure -eq 'application'
        $script:credentialSPFails = $Failure -eq 'SP'
        $script:credentialFICFails = $Failure -eq 'FIC'
        if ($Failure -eq 'third-party') { $script:credentialGrants = @(New-CredentialEvidenceGrant -TenantType ThirdParty) }
        @(Invoke-StalePrivilegeDetection).Count | Should -Be 0
        $script:StalePrivilegeDataAvailable | Should -BeFalse
        $script:StalePrivilegeStatus | Should -Match 'credential.*incomplete'
        $script:StalePrivilegeStatus | Should -Not -Match 'sign-in activity unavailable'
        Should -Invoke Write-Host -Times 0 -Exactly -ParameterFilter { "$Object" -match 'No stale high-privilege apps found' }
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match 'credential coverage is incomplete' }
    }

    It 'allows a clean stale result after successful empty credential enumeration' {
        @(Invoke-StalePrivilegeDetection).Count | Should -Be 0
        $script:StalePrivilegeDataAvailable | Should -BeTrue
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match 'No stale high-privilege apps found' }
    }

    It 'retains proven stale findings even when additional FIC evidence is unavailable' {
        $script:credentialAppResponse.keyCredentials = @($script:syntheticCertificate)
        $script:credentialFICFails = $true
        $result = @(Invoke-StalePrivilegeDetection)
        $result.Count | Should -Be 1
        $result[0].ValidCredCount | Should -Be 1
        $result[0].CredentialType | Should -Be 'Certificate'
        $script:StalePrivilegeDataAvailable | Should -BeFalse
        $script:StalePrivilegeStatus | Should -Match 'credential.*incomplete'
    }

    It 'resets stale availability and its reason between calls' {
        $script:credentialAppFails = $true
        $null = Invoke-StalePrivilegeDetection
        $script:StalePrivilegeDataAvailable | Should -BeFalse
        $script:credentialAppFails = $false
        $null = Invoke-StalePrivilegeDetection
        $script:StalePrivilegeDataAvailable | Should -BeTrue
        $script:StalePrivilegeStatus | Should -Be 'Complete'
    }

    It 'keeps the distinct sign-in-unavailable reason' {
        $script:credentialSignInFails = $true
        @(Invoke-StalePrivilegeDetection).Count | Should -Be 0
        $script:StalePrivilegeDataAvailable | Should -BeFalse
        $script:StalePrivilegeStatus | Should -Be 'Not evaluated (sign-in activity unavailable)'
    }

    It 'reports the correct Full stale reason for <Scenario> without counting unknown SP credentials' -ForEach @(
        @{ Scenario = 'credential failure'; ExpectedStale = 'Incomplete \(credential evidence\); 0 dormant high-privilege apps observed' }
        @{ Scenario = 'sign-in failure'; ExpectedStale = 'Not evaluated \(sign-in activity unavailable\)' }
        @{ Scenario = 'successful empty'; ExpectedStale = '0 dormant high-privilege apps' }
    ) {
        param($Scenario, $ExpectedStale)
        Mock Invoke-PermissionAudit { return @() }
        Mock Invoke-RoleAudit {
            return @{ CoverageComplete = $true; PrivilegedUsers = @(); NonPrivilegedUsers = @(); SPRoles = @() }
        }
        Mock Invoke-AttackPathAnalysis { return @() }
        Mock Invoke-ShadowAdminDetection { return @() }
        Mock Invoke-ConsentRiskAssessment { return @() }
        $script:credentialSPFails = $Scenario -eq 'credential failure'
        $script:credentialSignInFails = $Scenario -eq 'sign-in failure'

        $null = Invoke-FullAudit

        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match "Stale Privilege:\s+$ExpectedStale$" }
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match 'Credential Hygiene:.*0 with SP-level credentials$' }
    }
}