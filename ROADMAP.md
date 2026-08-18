# Privileged App Path Auditor Roadmap

This roadmap describes the intended direction of Privileged App Path Auditor. It is a statement of priorities, not a commitment to specific delivery dates.

Feedback, Microsoft Entra platform changes, how much time I have and real-world findings may change the order of planned work, but feedback is critical. Please keep it coming.

## Current release

The current stable release is **v0.5.1**.

It adds service principal credential visibility, role-based service principal control detection, application instance lock reporting, unowned privileged application detection, and safer handling of unavailable service principal sign-in activity.

## Project priorities

The project will remain:

- Read-only by default
- Focused on Entra application and service principal attack paths
- Transparent about missing or incomplete evidence
- Usable without deploying additional infrastructure
- Evidence-driven rather than dependent on unexplained risk scores

Getting the existing findings right comes before adding more checks.

## Next: v0.5.2 — Fixes to Existing Checks

This release will fix incorrect or unclear behavior in the current checks.

Planned work includes:

- Account for current Microsoft Entra role definitions and 2026 role changes
- Distinguish sensitive target roles, application-control roles, and a principal's existing privileges
- Improve application instance lock interpretation
- Improve built-in and custom user consent policy interpretation
- Keep delegated and application permissions separate
- Bind dangerous permissions to the correct resource API
- Distinguish third-party service principals from local application registrations
- Report incomplete or unavailable evidence instead of silently treating it as clean
- Add regression tests for corrected behavior
- Add automated testing on Windows, Linux, and macOS
- Correct or remove configuration options that do not currently affect behavior

## Planned: v0.6.0 — Findings and Role Handling

This release will make findings more consistent and improve how application control and Entra roles are evaluated.

Planned work includes:

- Stable finding identifiers
- A versioned JSON finding format
- Explicit exploitability, confidence, severity, and data coverage fields
- Capability-based analysis of built-in and custom Entra roles
- Direct, group-derived, scoped, active, and eligible/PIM role assignments
- Clear separation of application registrations, service principals, third-party applications, and agent identities
- Better retry, throttling, caching, and performance behavior
- A larger fixture-based test corpus
- Removal or redesign of the overall risk score

## Planned: v0.7.0 — Baselines and Change Tracking

This release will make repeat scans useful by showing what changed since a previous run.

Planned work includes:

- Baseline reports
- New, existing, resolved, and changed findings
- Automation-friendly exit codes
- Failure conditions such as newly detected critical paths
- Scheduled assessment examples
- Optional unattended authentication
- Additional machine-readable reporting formats

## Later: v0.8.0 — Reports and Integrations

Possible later work includes:

- Portable static HTML evidence reports
- Application management policy effectiveness
- Workload identity protection context
- Remediation ownership and status tracking
- Integrations requested by users and contributors

These will be considered after the finding format and core checks are stable.

## Not currently planned

The following are deliberately outside the immediate roadmap:

- Automatic remediation
- A hosted administration console
- A large interactive graph interface
- Broad Microsoft 365 posture assessment unrelated to application paths

The project intends to remain a focused, read-only application attack path auditor.

## Feedback and contributions

Roadmap feedback is welcome. Please [open a GitHub issue](https://github.com/nicolasblank/privileged-app-path-auditor/issues/new) describing:

- The problem or attack path
- Why it matters
- An example or supporting Microsoft documentation
- The expected auditor behavior

Security-sensitive reports should not include tenant secrets, tokens, credentials, or private organizational data.
