BeforeAll {
    $script:repoRoot = Split-Path $PSScriptRoot -Parent
    $script:scanner = Join-Path $script:repoRoot 'tools/Test-RepositoryDataSafety.ps1'
    $script:pwsh = (Get-Process -Id $PID).Path

    function New-SafetyRepository {
        $path = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $path | Out-Null
        & git -C $path init -q
        & git -C $path config user.name 'Synthetic Tester'
        & git -C $path config user.email 'tester@example.test'
        Set-Content (Join-Path $path 'safe.ps1') "'user@example.test'; '11111111-2222-3333-4444-555555555555'"
        & git -C $path add safe.ps1
        & git -C $path commit -qm initial
        return $path
    }

    function Invoke-SafetyScanner {
        param([string]$Repository, [string]$Mode, [string[]]$PushUpdates, [string]$RemoteName)
        $arguments = @('-NoLogo', '-NoProfile', '-File', $script:scanner, '-Repository', $Repository, '-Mode', $Mode)
        if ($PushUpdates) {
            foreach ($update in $PushUpdates) { $arguments += @('-PushUpdates', $update) }
        }
        if ($RemoteName) { $arguments += @('-RemoteName', $RemoteName) }
        $output = & $script:pwsh @arguments 2>&1 | Out-String
        [PSCustomObject]@{ ExitCode = $LASTEXITCODE; Output = $output }
    }
}

Describe 'Repository data safety path and staged-blob policy' {
    It 'allows ordinary synthetic source with test identities and GUIDs' {
        $repo = New-SafetyRepository
        (Invoke-SafetyScanner $repo TrackedTree).ExitCode | Should -Be 0
    }

    It 'bounds inspection without rejecting a large safe blob' {
        $repo = New-SafetyRepository
        [IO.File]::WriteAllText((Join-Path $repo 'large.txt'), ('safe content' * 100000))
        & git -C $repo add large.txt
        (Invoke-SafetyScanner $repo Staged).ExitCode | Should -Be 0
    }

    It 'blocks force-added prohibited path <Path>' -ForEach @(
        @{ Path = 'audit-results/report.txt' }
        @{ Path = 'nested/AUDIT-RESULTS-OLD/report.txt' }
        @{ Path = 'Full-results/report.txt' }
        @{ Path = 'some/tmp/report.txt' }
        @{ Path = 'config/MicrosoftApps.json' }
        @{ Path = 'testResults.xml' }
        @{ Path = 'logs/run.log' }
        @{ Path = 'private.code-workspace' }
        @{ Path = 'config/local-customer.json' }
        @{ Path = 'config/nested/local-customer.json' }
    ) {
        $repo = New-SafetyRepository
        $target = Join-Path $repo $Path
        New-Item -ItemType Directory -Path (Split-Path $target) -Force | Out-Null
        Set-Content $target 'synthetic data'
        & git -C $repo add -f -- $Path
        $result = Invoke-SafetyScanner $repo Staged
        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'PROHIBITED_PATH'
        $result.Output | Should -Match ([regex]::Escape($Path))
        $result.Output | Should -Not -Match 'synthetic data'
    }

    It 'blocks every tracked CSV regardless of directory' {
        $repo = New-SafetyRepository
        New-Item (Join-Path $repo 'fixtures') -ItemType Directory | Out-Null
        Set-Content (Join-Path $repo 'fixtures/sample.csv') 'One,Two'
        & git -C $repo add fixtures/sample.csv
        $result = Invoke-SafetyScanner $repo Staged
        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'TRACKED_CSV'
    }

    It 'blocks a root file named exactly .csv' {
        $repo = New-SafetyRepository
        Set-Content (Join-Path $repo '.csv') 'One,Two'
        & git -C $repo add .csv
        $result = Invoke-SafetyScanner $repo Staged
        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'TRACKED_CSV'
    }

    It 'blocks a tracked CSV whose filename contains a newline' {
        $repo = New-SafetyRepository
        $name = "report`n.csv"
        Set-Content (Join-Path $repo $name) 'One,Two'
        & git -C $repo add -- $name
        $result = Invoke-SafetyScanner $repo Staged
        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'TRACKED_CSV'
    }

    It 'escapes terminal control characters in violation paths' {
        $repo = New-SafetyRepository
        $name = "report$([char]27)[2J.csv"
        [IO.File]::WriteAllText((Join-Path $repo $name), 'One,Two')
        & git -C $repo add -- $name
        $result = Invoke-SafetyScanner $repo Staged
        $result.ExitCode | Should -Be 1
        $result.Output | Should -Not -Match ([regex]::Escape([string][char]27))
        $result.Output | Should -Match '\\u001B'
    }

    It 'blocks an audit export renamed to text without printing its row contents' {
        $repo = New-SafetyRepository
        Set-Content (Join-Path $repo 'notes.txt') 'PathNumber,PathType,UserUPN,AppName,AppId,Permission'
        Add-Content (Join-Path $repo 'notes.txt') '1,attack,sensitive@example.test,Private App,id,Permission'
        & git -C $repo add notes.txt
        $result = Invoke-SafetyScanner $repo Staged
        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'AUDIT_EXPORT_HEADER'
        $result.Output | Should -Not -Match 'sensitive@example.test|Private App'
    }

    It 'blocks renamed current export schema <Schema>' -ForEach @(
        @{ Schema = 'Summary'; Header = 'Category,Count,Description' }
        @{ Schema = 'UnknownOwnerApps'; Header = 'DisplayName,AppId,ObjectId,Type,Enabled,EntraPortalUrl' }
        @{ Schema = 'FullAuditSummary'; Header = 'Section,Finding,Count,CoverageState,CoverageDetail' }
        @{ Schema = 'ShadowAdmins'; Header = 'UserDisplayName,UserUPN,SPDisplayName,SPId,SPRole,SPDirectCreds,ExistingRoles,Risk,Remediation,UserEntraUrl,SPEntraUrl' }
        @{ Schema = 'UnownedPrivilegedApps'; Header = 'AppName,AppId,Permissions,SPDirectCreds,AppInstanceLock,AppTenantType,EntraUrl' }
    ) {
        $repo = New-SafetyRepository
        Set-Content (Join-Path $repo 'renamed.txt') $Header
        & git -C $repo add renamed.txt
        $result = Invoke-SafetyScanner $repo Staged
        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'AUDIT_EXPORT_HEADER'
    }

    It 'scans the staged blob rather than an unstaged working-tree replacement' {
        $repo = New-SafetyRepository
        Set-Content (Join-Path $repo 'notes.txt') 'safe text'
        & git -C $repo add notes.txt
        Set-Content (Join-Path $repo 'notes.txt') 'PathNumber,PathType,UserUPN,AppName,AppId,Permission'
        (Invoke-SafetyScanner $repo Staged).ExitCode | Should -Be 0
    }
}

Describe 'Repository data safety history and push policy' {
    It 'passes the current tree but fails history after prohibited data is added and deleted' {
        $repo = New-SafetyRepository
        New-Item (Join-Path $repo 'Full-results') -ItemType Directory | Out-Null
        Set-Content (Join-Path $repo 'Full-results/report.txt') 'private'
        & git -C $repo add -f Full-results/report.txt
        & git -C $repo commit -qm add-output
        & git -C $repo rm -q Full-results/report.txt
        & git -C $repo commit -qm delete-output
        (Invoke-SafetyScanner $repo TrackedTree).ExitCode | Should -Be 0
        (Invoke-SafetyScanner $repo History).ExitCode | Should -Be 1
    }

    It 'blocks prohibited content introduced by a pre-push commit range' {
        $repo = New-SafetyRepository
        $old = (& git -C $repo rev-parse HEAD).Trim()
        Set-Content (Join-Path $repo 'leak.csv') 'One,Two'
        & git -C $repo add leak.csv
        & git -C $repo commit -qm add-output
        $new = (& git -C $repo rev-parse HEAD).Trim()
        $update = "refs/heads/main $new refs/heads/main $old"
        (Invoke-SafetyScanner $repo PrePush @($update)).ExitCode | Should -Be 1
    }

    It 'does not let a stale remote-tracking ref suppress a new-branch scan' {
        $repo = New-SafetyRepository
        Set-Content (Join-Path $repo 'leak.csv') 'One,Two'
        & git -C $repo add leak.csv
        & git -C $repo commit -qm add-output
        $new = (& git -C $repo rev-parse HEAD).Trim()
        & git -C $repo update-ref refs/remotes/origin/stale $new
        $update = "refs/heads/topic $new refs/heads/topic 0000000000000000000000000000000000000000"
        (Invoke-SafetyScanner $repo PrePush @($update) origin).ExitCode | Should -Be 1
    }

    It 'blocks an audit export blob targeted directly by an annotated tag' {
        $repo = New-SafetyRepository
        Set-Content (Join-Path $repo 'renamed.txt') 'Category,Count,Description'
        $blob = (& git -C $repo hash-object -w renamed.txt).Trim()
        & git -C $repo tag -a confidential-export $blob -m 'synthetic blob tag'
        $tag = (& git -C $repo rev-parse refs/tags/confidential-export).Trim()
        $update = "refs/tags/confidential-export $tag refs/tags/confidential-export 0000000000000000000000000000000000000000"
        (Invoke-SafetyScanner $repo PrePush @($update)).ExitCode | Should -Be 1
        (Invoke-SafetyScanner $repo History).ExitCode | Should -Be 1
    }

    It 'blocks a prohibited path in a tree targeted directly by an annotated tag' {
        $repo = New-SafetyRepository
        New-Item (Join-Path $repo 'audit-results') -ItemType Directory | Out-Null
        Set-Content (Join-Path $repo 'audit-results/report.txt') 'synthetic'
        & git -C $repo add -f audit-results/report.txt
        $tree = (& git -C $repo write-tree).Trim()
        & git -C $repo reset -q HEAD -- audit-results/report.txt
        & git -C $repo tag -a confidential-tree $tree -m 'synthetic tree tag'
        $tag = (& git -C $repo rev-parse refs/tags/confidential-tree).Trim()
        $update = "refs/tags/confidential-tree $tag refs/tags/confidential-tree 0000000000000000000000000000000000000000"
        (Invoke-SafetyScanner $repo PrePush @($update)).ExitCode | Should -Be 1
        (Invoke-SafetyScanner $repo History).ExitCode | Should -Be 1
    }

    It 'blocks a committed gitlink under a prohibited path' {
        $repo = New-SafetyRepository
        $commit = (& git -C $repo rev-parse HEAD).Trim()
        & git -C $repo update-index --add --cacheinfo "160000,$commit,audit-results/leak"
        & git -C $repo commit -qm add-gitlink
        (Invoke-SafetyScanner $repo TrackedTree).ExitCode | Should -Be 1
        (Invoke-SafetyScanner $repo History).ExitCode | Should -Be 1
    }
}

Describe 'Repository safety hook and workflow contracts' {
    It 'ships strict hook launchers and full-history CI checks' {
        $preCommit = Get-Content (Join-Path $script:repoRoot '.githooks/pre-commit') -Raw
        $prePush = Get-Content (Join-Path $script:repoRoot '.githooks/pre-push') -Raw
        $workflow = Get-Content (Join-Path $script:repoRoot '.github/workflows/test.yml') -Raw
        $preCommit | Should -Match 'Test-RepositoryDataSafety\.ps1.*Staged'
        $prePush | Should -Match 'Test-RepositoryDataSafety\.ps1.*PrePush'
        "$preCommit`n$prePush" | Should -Not -Match '(?i)skip|bypass|allowlist'
        $workflow | Should -Match 'fetch-depth:\s*0'
        $workflow | Should -Match 'Run repository data safety checks'
        $workflow | Should -Match 'Mode TrackedTree'
        $workflow | Should -Match 'Mode History'
    }

    It 'blocks a force-added output through the actual pre-commit hook' {
        $repo = New-SafetyRepository
        & git -C $repo config core.hooksPath (Join-Path $script:repoRoot '.githooks')
        New-Item (Join-Path $repo 'audit-results') -ItemType Directory | Out-Null
        Set-Content (Join-Path $repo 'audit-results/report.txt') 'private'
        & git -C $repo add -f audit-results/report.txt
        & git -C $repo commit -m blocked 2>$null
        $LASTEXITCODE | Should -Not -Be 0
    }
}