BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..' 'Invoke-PrivilegedAudit.ps1'
    $tokens = $null
    $parseErrors = $null
    $scriptAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $scriptPath,
        [ref]$tokens,
        [ref]$parseErrors
    )

    foreach ($functionName in @('Get-SPSignInActivity', 'Invoke-StalePrivilegeDetection')) {
        $functionAst = $scriptAst.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $functionName
        }, $true)

        if (-not $functionAst) {
            throw "Function '$functionName' was not found in $scriptPath."
        }

        . ([scriptblock]::Create($functionAst.Extent.Text))
    }

    function Get-AllGraphPages { }
    function Write-Banner { }
    function Get-ServicePrincipalsWithAppRoles { }
    function Get-AppCredentials { }
}

Describe 'Invoke-PrivilegedAudit.ps1 syntax' {
    It 'parses without errors' {
        $parseErrors | Should -BeNullOrEmpty
    }
}

Describe 'Get-SPSignInActivity' {
    It 'queries the Microsoft Graph beta endpoint' {
        Mock Get-AllGraphPages {
            param($Uri)
            $Uri | Should -Be 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities?$top=999'
            return @([PSCustomObject]@{ appId = 'app-1' })
        }

        $result = Get-SPSignInActivity

        $result.ContainsKey('app-1') | Should -BeTrue
        Should -Invoke Get-AllGraphPages -Times 1 -Exactly
    }

    It 'returns null when sign-in activity is unavailable' {
        Mock Get-AllGraphPages { throw 'Graph activity query failed' }

        $result = Get-SPSignInActivity

        $result | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-StalePrivilegeDetection' {
    It 'skips stale classification when sign-in activity is unavailable' {
        Mock Write-Banner { }
        Mock Get-ServicePrincipalsWithAppRoles {
            return @([PSCustomObject]@{
                AppId = 'app-1'
                SPDisplayName = 'Privileged app'
            })
        }
        Mock Get-SPSignInActivity { return $null }
        Mock Get-AppCredentials { throw 'Credential lookup must not run' }

        $result = @(Invoke-StalePrivilegeDetection)

        $result.Count | Should -Be 0
        $script:StalePrivilegeDataAvailable | Should -BeFalse
        Should -Invoke Get-AppCredentials -Times 0 -Exactly
    }
}
