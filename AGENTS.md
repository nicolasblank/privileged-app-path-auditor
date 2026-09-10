# Repository guidance for coding agents

## Scope

This is a PowerShell 7, read-only Microsoft Entra privilege-path auditor. The core question is whether control of an application or service principal gives a principal additional privilege and whether the Graph evidence is sufficient to support that conclusion.

Key files:

- `Invoke-PrivilegedAudit.ps1` — implementation and embedded defaults
- `tests/Invoke-PrivilegedAudit.Tests.ps1` — mocked semantic regression suite
- `config/` and `config/schema/` — checked-in overrides and JSON Schemas
- `README.md`, `ROADMAP.md`, `CHANGELOG.md`, and `docs/` — public behavior and operator guidance

No MCP server or external connector is required to build, test, or review the project.

## Safety and correctness invariants

- Keep tenant access read-only. Required Graph scopes must remain read-only and direct Graph requests must use `GET`.
- Never turn failed, missing, or unobservable evidence into a clean result. Use complete, partial, or unavailable coverage.
- Preserve application registration versus service principal semantics.
- Preserve home-tenant versus third-party semantics; do not infer access to an external publisher's application object.
- Preserve application versus delegated grant semantics and bind permissions to the correct resource API.
- Determine privilege delta from current evidence; an owner relationship or sensitive-role label alone does not prove escalation.
- Apply role scope and app instance locks only to the route they actually affect.
- Live tenant runs require explicit user direction. Confirm the displayed tenant and account and treat all output as confidential.
- Do not copy raw tenant output into GitHub, prompts, MCP tools, or other external systems. Use synthetic fixtures or redact it first.
- Repository data-safety scans are mandatory. Never weaken, bypass, or allowlist audit-output path, CSV, export-header, staged-blob, pre-push-range, or full-history checks.

## Public contract

Treat these as compatibility-sensitive:

- Modes and parameters
- CSV filenames and columns
- Path IDs and finding meanings
- Exploitability and coverage states
- Configuration keys, defaults, replacement behavior, and schemas

When changing a public contract, update tests, README or the relevant document, configuration/schema if applicable, and `CHANGELOG.md`. Keep the script and checked-in configuration version in sync.

## Development

- Support PowerShell 7 on Windows, Linux, and macOS.
- Run `Invoke-Pester -Path ./tests -CI -Output Detailed`.
- Automated tests must use mocks and synthetic data; do not require tenant access or network access.
- Prefer a focused regression fixture that proves both the positive path and the important negative boundary.
- Keep embedded defaults, checked-in configuration, schema, tests, and documentation aligned.

## Before finishing

- Run the full Pester suite.
- Inspect the diff for unintended public-output changes.
- Check local Markdown links and version consistency.
- Ensure no audit exports, catalogue cache, credentials, tokens, or tenant-specific evidence are staged.
- Run `tools/Test-RepositoryDataSafety.ps1` in `TrackedTree` and `History` modes before release.

Keep this file short. Add a rule only for a critical invariant or a failure that has recurred; put tutorials and general guidance in `CONTRIBUTING.md` or `docs/`.
