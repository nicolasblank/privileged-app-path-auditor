# Privileged App Path Auditor Roadmap

This project stays deliberately narrow: it determines who can turn control of an Entra application or service principal into **additional privilege**, shows the path, and states whether the collected evidence is sufficient to trust that conclusion.

The roadmap is a statement of priorities, not delivery dates. Microsoft Entra changes, real tenant evidence, and user reports can change the order.

## Product boundaries

The project will remain:

- Read-only and usable without additional collector, database, or hosted infrastructure
- Focused on Entra application and service-principal privilege paths
- Based on privilege delta and explainable evidence rather than generic inventory counts
- Explicit about incomplete and unavailable evidence
- Small enough for an engineer to run and understand directly

Permission inventory, credential hygiene, consent posture, and stale-application checks remain supporting context. The project will not compete as a broad Microsoft 365 posture suite or general attack-graph platform.

## Current: v0.6.0 — Correct path analysis

v0.6 changes the finding engine while preserving the familiar command-line workflow.

- Evaluate current built-in and custom Entra roles from their live permitted actions
- Account for current Microsoft role classification, with a dated fallback when preview evidence is unavailable
- Calculate whether a reachable permission or role increases the principal's existing privilege
- Separate application control from service-principal control
- Separate application permissions from delegated grants and bind grants to their resource API
- Separate local application registrations from third-party service principals
- Apply role-assignment scope and app instance lock evidence to the relevant path
- Classify paths as direct, potential, or mitigated and report complete, partial, or unavailable data coverage
- Avoid treating failed queries, missing activity, or unresolved local objects as clean evidence
- Remove the unexplained aggregate risk score while preserving factual counts and remediation actions
- Maintain regression coverage on Windows, Linux, and macOS

## Next: v0.7.0 — Complete and stabilize the evidence

The next release closes known evidence gaps and makes every finding suitable for repeatable machine use.

- Expand active role-assigned groups to effective transitive user members and retain assigned-group provenance (completed in v0.6); consider intermediate nesting evidence only if Graph evidence permits it
- Include active and eligible/PIM assignments where Microsoft Graph evidence permits
- Preserve assignment and administrative scope in each relevant finding
- Introduce stable finding identifiers
- Define and test a versioned JSON evidence contract
- Record proof, reason, remediation, exploitability, and coverage on each finding
- Expand fixtures for custom roles, unusual scopes, locks, third-party apps, and incomplete Graph responses
- Improve retry, throttling, caching, and large-tenant performance without weakening evidence semantics

PIM and group coverage are valuable here because they complete the lightweight audit's evidence, not because they are unique categories of security tooling.

## Then: v0.8.0 — Show what changed

After finding identifiers and JSON are stable, make repeat scans operationally useful.

- Compare an audit with a trusted baseline
- Report new, changed, unchanged, and resolved findings
- Add automation-friendly exit codes
- Support failure policies such as “new direct privilege-increasing paths”
- Document unattended authentication and scheduled assessment patterns
- Produce compact machine-readable evidence for CI and operational review

## Validate before adding

The following will be considered only when a concrete user workflow demonstrates value:

- Agent identity and workload identity paths not already explained by the current model
- An MCP adapter over the stable, versioned finding contract
- SIEM, ticketing, or governance integrations
- Portable HTML evidence reports
- Remediation ownership and status tracking

An integration or presentation layer is not a roadmap goal on its own.

## Not planned

- Automatic remediation
- A hosted administration console
- A large interactive graph interface
- Broad Microsoft 365 posture assessment
- Generic permission, secret, or consent inventory as the product's primary purpose

## Proposing roadmap work

[Open an issue](https://github.com/nicolasblank/privileged-app-path-auditor/issues/new) with:

- The principal-to-privilege question the change would answer
- Why the current evidence model cannot answer it
- A realistic example or Microsoft documentation
- The expected finding and coverage behavior

Do not include tenant secrets, tokens, credentials, or private organizational data in public issues.
