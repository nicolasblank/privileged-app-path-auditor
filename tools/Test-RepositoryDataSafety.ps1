[CmdletBinding()]
param(
    [Parameter()][ValidateSet('Staged', 'PrePush', 'TrackedTree', 'History')][string]$Mode = 'TrackedTree',
    [Parameter()][string]$Repository = '.',
    [Parameter()][string]$RemoteName,
    [Parameter()][string]$RemoteUrl,
    [Parameter()][string[]]$PushUpdates
)

$ErrorActionPreference = 'Stop'

function Invoke-GitText {
    param([string]$WorkingDirectory, [string[]]$Arguments, [switch]$AllowFailure)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = 'git'
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { [void]$start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    [void]$process.Start()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0 -and -not $AllowFailure) {
        throw "Git command failed ($($Arguments -join ' ')): $($stderr.Trim())"
    }
    [PSCustomObject]@{ ExitCode = $process.ExitCode; Output = $stdout; Error = $stderr }
}

function Invoke-GitBytes {
    param([string]$WorkingDirectory, [string[]]$Arguments)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = 'git'
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { [void]$start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    [void]$process.Start()
    $memory = [IO.MemoryStream]::new()
    $process.StandardOutput.BaseStream.CopyTo($memory)
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "Git command failed ($($Arguments -join ' ')): $($stderr.Trim())"
    }
    return $memory.ToArray()
}

function ConvertFrom-NulDelimitedGitOutput {
    param([byte[]]$Bytes)
    $records = [Collections.Generic.List[string]]::new()
    $start = 0
    for ($index = 0; $index -lt $Bytes.Count; $index++) {
        if ($Bytes[$index] -ne 0) { continue }
        $records.Add([Text.Encoding]::UTF8.GetString($Bytes, $start, $index - $start))
        $start = $index + 1
    }
    if ($start -ne $Bytes.Count) { throw 'Git returned a non-terminated path record' }
    return @($records)
}

function Get-GitBlobPrefix {
    param([string]$WorkingDirectory, [string]$Specification)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = 'git'
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    [void]$start.ArgumentList.Add('cat-file')
    [void]$start.ArgumentList.Add('blob')
    [void]$start.ArgumentList.Add($Specification)
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    [void]$process.Start()
    $buffer = [byte[]]::new(65536)
    $count = 0
    while ($count -lt $buffer.Length) {
        $read = $process.StandardOutput.BaseStream.Read($buffer, $count, $buffer.Length - $count)
        if ($read -eq 0) { break }
        $count += $read
    }
    $truncated = $count -eq $buffer.Length -and -not $process.HasExited
    if ($truncated) { $process.Kill() }
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0 -and -not $truncated) { throw "Unable to read Git blob ${Specification}: $($stderr.Trim())" }
    if ($count -eq 0) { return [byte[]]::new(0) }
    return $buffer[0..($count - 1)]
}

function Get-NormalizedRepositoryPath {
    param([string]$Path)
    $normalized = $Path.Replace('\', '/')
    while ($normalized.StartsWith('./', [StringComparison]::Ordinal)) { $normalized = $normalized.Substring(2) }
    if (-not $normalized -or $normalized.StartsWith('/') -or $normalized -match '(^|/)\.\.(/|$)') {
        throw "Malformed repository path: $Path"
    }
    return $normalized
}

function Get-PathRule {
    param([string]$Path)
    $normalized = Get-NormalizedRepositoryPath $Path
    $lower = $normalized.ToLowerInvariant()
    $components = $lower.Split('/')
    if (@($components | Where-Object { $_ -in @('audit-results', 'audit-results-old', 'full-results', 'tmp') }).Count) { return 'PROHIBITED_PATH' }
    if ($lower -eq 'config/microsoftapps.json') { return 'PROHIBITED_PATH' }
    if ([IO.Path]::GetFileName($lower) -eq 'testresults.xml') { return 'PROHIBITED_PATH' }
    if ($lower.EndsWith('.log') -or $lower.EndsWith('.code-workspace')) { return 'PROHIBITED_PATH' }
    if ($lower -match '^config/(?:.*/)?local-[^/]+\.json$') { return 'PROHIBITED_PATH' }
    if ($lower.EndsWith('.csv')) { return 'TRACKED_CSV' }
    return $null
}

function Get-FirstCsvFields {
    param([string]$Text)
    $fields = [Collections.Generic.List[string]]::new()
    $builder = [Text.StringBuilder]::new()
    $quoted = $false
    for ($index = 0; $index -lt $Text.Length; $index++) {
        $character = $Text[$index]
        if ($character -eq '"') {
            if ($quoted -and $index + 1 -lt $Text.Length -and $Text[$index + 1] -eq '"') {
                [void]$builder.Append('"')
                $index++
            } else { $quoted = -not $quoted }
            continue
        }
        if (-not $quoted -and $character -eq ',') {
            $fields.Add($builder.ToString())
            [void]$builder.Clear()
            continue
        }
        if (-not $quoted -and ($character -eq "`r" -or $character -eq "`n")) { break }
        [void]$builder.Append($character)
    }
    $fields.Add($builder.ToString())
    return @($fields)
}

function Test-AuditExportHeader {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Count -eq 0) { return $false }
    $sample = $Bytes[0..([Math]::Min($Bytes.Count - 1, 65535))]
    if ($sample -contains 0) { return $false }
    $text = [Text.Encoding]::UTF8.GetString($sample).TrimStart([char]0xFEFF)
    $fields = @(Get-FirstCsvFields $text)
    if ($fields.Count -lt 2) { return $false }
    $header = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($field in $fields) { [void]$header.Add($field.Trim()) }
    $signatures = @(
        @('PathNumber', 'PathType', 'UserUPN', 'AppName', 'AppId', 'Permission'),
        @('Exploitability', 'EvidenceDetail', 'PathId', 'AppId'),
        @('SPId', 'SPDisplayName', 'AppId', 'Permission', 'PermissionType'),
        @('DisplayName', 'UPN', 'Roles', 'HasPrivilegedRole'),
        @('LastSignIn', 'CredentialType', 'CredentialExpires', 'ValidCredCount'),
        @('CredType', 'CredCount', 'ExpiredCount', 'RiskLevel'),
        @('Source', 'State', 'Detail'),
        @('Setting', 'Value', 'Risk'),
        @('GrantId', 'ClientSPId', 'ResourceSPId', 'ConsentPrincipalId'),
        @('GroupId', 'GroupName', 'UserId', 'RoleDefinitionId', 'MembershipPath'),
        @('GroupName', 'GroupId', 'Role', 'DirectoryScopeId', 'RoleAssignmentId'),
        @('Category', 'Count', 'Description'),
        @('DisplayName', 'AppId', 'ObjectId', 'Type', 'Enabled', 'EntraPortalUrl'),
        @('Section', 'Finding', 'Count', 'CoverageState', 'CoverageDetail'),
        @('UserDisplayName', 'UserUPN', 'SPDisplayName', 'SPId', 'SPRole', 'SPDirectCreds', 'ExistingRoles', 'Risk', 'Remediation', 'UserEntraUrl', 'SPEntraUrl'),
        @('AppName', 'AppId', 'Permissions', 'SPDirectCreds', 'AppInstanceLock', 'AppTenantType', 'EntraUrl')
    )
    foreach ($signature in $signatures) {
        if (@($signature | Where-Object { -not $header.Contains($_) }).Count -eq 0) { return $true }
    }
    return $false
}

function Get-TreeEntries {
    param([string]$WorkingDirectory, [string]$Treeish)
    $records = ConvertFrom-NulDelimitedGitOutput (Invoke-GitBytes $WorkingDirectory @('ls-tree', '-r', '-z', '--full-tree', $Treeish))
    foreach ($record in $records) {
        if ($record -match '^\d+\s+(blob|commit)\s+([0-9a-f]+)\t([\s\S]+)$') {
            [PSCustomObject]@{ ObjectType = $Matches[1]; Oid = $Matches[2]; Path = $Matches[3]; Context = $Treeish; Specification = $Matches[2] }
        }
    }
}

function Get-IndexEntries {
    param([string]$WorkingDirectory)
    $records = ConvertFrom-NulDelimitedGitOutput (Invoke-GitBytes $WorkingDirectory @('ls-files', '--stage', '-z'))
    foreach ($record in $records) {
        if ($record -match '^(\d+)\s+([0-9a-f]+)\s+0\t([\s\S]+)$') {
            $objectType = if ($Matches[1] -eq '160000') { 'commit' } else { 'blob' }
            [PSCustomObject]@{ ObjectType = $objectType; Oid = $Matches[2]; Path = $Matches[3]; Context = 'index'; Specification = $Matches[2] }
        }
    }
}

function Get-ReachableBlobEntries {
    param([string]$WorkingDirectory, [string]$Tip, [string]$Context)
    $objectIds = (Invoke-GitText $WorkingDirectory @('rev-list', '--objects', '--no-object-names', $Tip)).Output -split "`n" | Where-Object { $_ }
    foreach ($objectId in $objectIds) {
        $type = (Invoke-GitText $WorkingDirectory @('cat-file', '-t', $objectId)).Output.Trim()
        if ($type -eq 'blob') {
            [PSCustomObject]@{ ObjectType = 'blob'; Oid = $objectId; Path = "<object:$objectId>"; Context = $Context; Specification = $objectId; ContentOnly = $true }
        }
    }
}

function Get-TipTreeEntries {
    param([string]$WorkingDirectory, [string]$Tip)
    $tree = Invoke-GitText $WorkingDirectory @('rev-parse', "$Tip^{tree}") -AllowFailure
    if ($tree.ExitCode -ne 0) { return @() }
    return @(Get-TreeEntries $WorkingDirectory $tree.Output.Trim())
}

function ConvertTo-SafeDiagnosticPath {
    param([string]$Path)
    $builder = [Text.StringBuilder]::new()
    foreach ($character in $Path.ToCharArray()) {
        if ([char]::IsControl($character)) {
            [void]$builder.Append(('\u{0:X4}' -f [int]$character))
        } else {
            [void]$builder.Append($character)
        }
    }
    return $builder.ToString()
}

function Invoke-RepositoryDataSafetyScan {
    param(
        [ValidateSet('Staged', 'PrePush', 'TrackedTree', 'History')][string]$ScanMode,
        [string]$RepositoryPath,
        [string]$PushRemoteName,
        [string[]]$Updates
    )

    $root = (Invoke-GitText $RepositoryPath @('rev-parse', '--show-toplevel')).Output.Trim()
    $entries = [Collections.Generic.List[object]]::new()
    if ($ScanMode -eq 'Staged') {
        foreach ($entry in @(Get-IndexEntries $root)) { $entries.Add($entry) }
    } elseif ($ScanMode -eq 'TrackedTree') {
        foreach ($entry in @(Get-TreeEntries $root 'HEAD')) { $entries.Add($entry) }
    } else {
        $commits = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $tips = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        if ($ScanMode -eq 'History') {
            foreach ($commit in @((Invoke-GitText $root @('rev-list', '--all')).Output -split "`n" | Where-Object { $_ })) { [void]$commits.Add($commit) }
            foreach ($tip in @((Invoke-GitText $root @('for-each-ref', '--format=%(objectname)')).Output -split "`n" | Where-Object { $_ })) { [void]$tips.Add($tip) }
        } else {
            $lines = if ($Updates) { $Updates } else { @([Console]::In.ReadToEnd() -split "`n" | Where-Object { $_ }) }
            foreach ($line in $lines) {
                $parts = @($line -split '\s+')
                if ($parts.Count -ne 4) { throw "Malformed pre-push update line" }
                $localSha = $parts[1]; $remoteSha = $parts[3]
                if ($localSha -match '^0+$') { continue }
                [void]$tips.Add($localSha)
                $arguments = @('rev-list', $localSha)
                foreach ($commit in @((Invoke-GitText $root $arguments).Output -split "`n" | Where-Object { $_ })) { [void]$commits.Add($commit) }
            }
        }
        foreach ($commit in $commits) { foreach ($entry in @(Get-TreeEntries $root $commit)) { $entries.Add($entry) } }
        foreach ($tip in $tips) {
            foreach ($entry in @(Get-TipTreeEntries $root $tip)) { $entries.Add($entry) }
            foreach ($entry in @(Get-ReachableBlobEntries $root $tip $tip)) { $entries.Add($entry) }
        }
    }

    $violations = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $entries) {
        $path = Get-NormalizedRepositoryPath $entry.Path
        $key = "$($entry.Oid)|$path"
        if (-not $seen.Add($key)) { continue }
        $rule = if ($entry.ContentOnly) { $null } else { Get-PathRule $path }
        if ($rule) {
            $violations.Add([PSCustomObject]@{ Mode = $ScanMode; Context = $entry.Context; Path = $path; Rule = $rule })
            continue
        }
        if ($entry.ObjectType -ne 'blob') { continue }
        $bytes = Get-GitBlobPrefix $root $entry.Specification
        if (Test-AuditExportHeader $bytes) {
            $violations.Add([PSCustomObject]@{ Mode = $ScanMode; Context = $entry.Context; Path = $path; Rule = 'AUDIT_EXPORT_HEADER' })
        }
    }
    foreach ($violation in $violations) {
        $safePath = ConvertTo-SafeDiagnosticPath $violation.Path
        [Console]::Error.WriteLine("DATA_SAFETY [$($violation.Rule)] mode=$($violation.Mode) context=$($violation.Context) path=$safePath")
    }
    return [PSCustomObject]@{ ExitCode = if ($violations.Count) { 1 } else { 0 }; ViolationCount = $violations.Count; Violations = @($violations) }
}

if ($MyInvocation.InvocationName -eq '.') { return }

try {
    $result = Invoke-RepositoryDataSafetyScan -ScanMode $Mode -RepositoryPath $Repository -PushRemoteName $RemoteName -Updates $PushUpdates
    exit $result.ExitCode
} catch {
    [Console]::Error.WriteLine("DATA_SAFETY [OPERATIONAL_ERROR] mode=$Mode path=<repository>")
    exit 2
}