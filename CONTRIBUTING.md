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

Use PowerShell 7 and Pester 5.7.1 or later:

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

The focused files are organized by behavioral boundary rather than product mode. For example, `PaginationAccuracy.Tests.ps1` covers partial collection semantics, while `CorePathAccuracy.Tests.ps1` and `P1FollowUp.Tests.ps1` cover cross-mode path decisions. Add a case to the narrowest existing suite when practical; create a new suite only for a distinct contract.

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

Before submitting, run the full Pester suite, check documentation links, inspect `git diff`, and ensure no audit output, cache, tokens, or tenant-specific data is staged.
