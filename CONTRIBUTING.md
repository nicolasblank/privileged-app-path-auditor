# Contributing

Contributions are welcome when they improve the accuracy, explainability, safety, or operational usefulness of Entra application privilege-path analysis.

## Before proposing a feature

Describe the principal-to-privilege question the feature would answer. A useful proposal includes:

- A realistic control relationship or evidence gap
- Why the current analysis cannot answer it
- Relevant Microsoft documentation or a reproducible synthetic example
- The expected finding, privilege delta, and coverage behavior

Generic inventory, presentation, MCP, or integration work should have a concrete user workflow before it expands the project.

## Development setup

Clone the repository as shown in the [README](README.md#run-your-first-audit), enter its root, and open PowerShell 7 (`pwsh`). Production behavior is primarily implemented in `Invoke-PrivilegedAudit.ps1`; regression suites are under `tests/`.

Use Pester 5.7.1 or later:

```powershell
# Run these commands from the repository root.
Install-Module Pester -MinimumVersion 5.7.1 -Scope CurrentUser
Invoke-Pester -Path ./tests -CI -Output Detailed
```

A successful full run reports `Tests Failed: 0`. Pester discovers all `tests/*.Tests.ps1` files. Run a focused file during development, then run the full suite before submitting:

```powershell
Invoke-Pester -Path ./tests/RoleGroupExpansion.Tests.ps1 -CI -Output Detailed
```

The test suite uses synthetic fixtures, mocked Graph requests, and Pester's isolated `TestDrive` paths. It must not authenticate, require a live tenant, or read local audit exports. An unexpected Graph request should fail the test rather than reach the network. CI runs the full suite on Windows, Linux, and macOS.

## Repository data-safety checks

Enable the versioned hooks once in every clone:

```powershell
git config --local core.hooksPath .githooks
git config --local --get core.hooksPath
```

VS Code invokes normal Git commits and pushes, so it honors `core.hooksPath`. Cloning a repository does not install hooks automatically; CI is the authoritative backstop when local setup is missing.

Run the same strict checks directly:

```powershell
./tools/Test-RepositoryDataSafety.ps1 -Mode TrackedTree
./tools/Test-RepositoryDataSafety.ps1 -Mode History
```

Exit `0` means clean, `1` means a policy violation, and `2` means the scanner could not complete safely. The policy has no allowlist or bypass: tracked CSV files, audit-output/cache paths, and files whose first CSV record matches an audit-export schema are rejected.

`.gitignore` is convenience, not enforcement. It can be bypassed with force-add, does not protect already tracked files, and cannot remove a file from earlier commits. The pre-commit hook scans staged Git blobs; pre-push scans the complete history and reachable blobs of every pushed tip, including files added and deleted before the push; CI scans HEAD and full fetched history.

The focused files are organized by behavioral boundary rather than product mode. Choose the narrowest matching suite, then run the full suite before submitting:

| Concern | Test suite(s) |
|---|---|
| Repository, configuration, Graph safety, and broad mode contracts | `Invoke-PrivilegedAudit.Tests.ps1`, `PathConfigurationContract.Tests.ps1` |
| Core privilege-path decisions and reviewed edge cases | `CorePathAccuracy.Tests.ps1`, `P1FollowUp.Tests.ps1`, `P2Boundaries.Tests.ps1` |
| Console path presentation | `AttackPathRendering.Tests.ps1` |
| Role-assigned group evidence | `RoleGroupExpansion.Tests.ps1` |
| Pagination and malformed/missing Graph evidence | `PaginationAccuracy.Tests.ps1`, `P2MissingEvidence.Tests.ps1` |
| Credential evidence and validity | `CredentialEvidenceAccuracy.Tests.ps1`, `P2CredentialValidity.Tests.ps1` |
| Consent policy and delegated-grant evidence | `P2Consent.Tests.ps1` |
| Standalone and Full-mode coverage summaries | `StandaloneCoverage.Tests.ps1`, `P2Summary.Tests.ps1`, `P2ModeIsolation.Tests.ps1` |

`P1` and `P2` are historical accuracy-review labels, not severity or priority levels. Add a case to the narrowest existing suite when practical; create a new suite only for a distinct public or evidence contract. The project does not currently define stable Pester tags for narrower filtering, so a focused file is the supported quick-iteration unit.

## Correctness requirements

- Keep Graph access read-only. New direct Graph requests must use `GET` and new scopes must be read-only.
- Missing or failed evidence must become partial or unavailable coverage, not an empty trusted result.
- Preserve application versus service-principal, local versus third-party, and application versus delegated boundaries.
- Test privilege delta; do not infer exploitability from a role display name or owner relationship alone.
- Apply assignment scope and mitigations only to the route they actually affect.
- Use synthetic tenant identifiers and data in tests and examples.

## Changing public behavior

Modes, parameters, CSV filenames and columns, path IDs, exploitability states, coverage meanings, and configuration semantics are public contracts.

When changing one:

1. Add or update a regression test.
2. Update the relevant documentation.
3. Update configuration and JSON Schema together when applicable.
4. Update the version consistently in the script and checked-in configuration.
5. Add a changelog entry explaining how an operator's result can change.

## Testing guidance

Prefer a small fixture that proves the semantic boundary. Include negative cases, such as:

- Same permission name on the wrong resource API
- Delegated grant excluded from an application-only path
- Custom role with the relevant action
- Scoped role assignment that does not reach the target
- Existing privilege equivalent to the target
- Missing role, owner, lock, activity, or catalogue evidence

Do not run live-tenant collection in automated tests or commit captured tenant output.

When fixing a defect, demonstrate it with a failing synthetic regression first. Prefer asserting the public conclusion and coverage state through the real helper or mode, not only repeating an internal Boolean calculation. Include the important clean or negative boundary so the fix cannot simply classify every candidate as risky.

## Pull requests

Keep a pull request focused. Explain:

- The incorrect or missing conclusion
- The evidence model before and after the change
- Tests performed
- Any public output or compatibility impact

Before submitting, run the full Pester suite and both repository safety modes, check documentation links, inspect `git diff`, and ensure no audit output, cache, tokens, or tenant-specific data is staged.
