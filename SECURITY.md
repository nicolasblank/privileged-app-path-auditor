# Security policy

Privileged App Path Auditor processes sensitive identity-security evidence. Please report vulnerabilities responsibly and keep tenant data out of public issues.

## Supported version

Security fixes are applied to the latest released version. Reproduce against the current default branch where it is safe to do so.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature for this repository when available. If it is unavailable, contact the repository owner privately through the contact method on the owner's GitHub profile before sharing technical details.

Include only the minimum information needed to reproduce the problem:

- Tool and PowerShell version
- A synthetic or redacted input shape
- Expected and observed behavior
- Security impact
- Suggested mitigation, if known

Do not send access tokens, client secrets, certificates, tenant secrets, raw exports, full user lists, or unredacted production identifiers.

## Repository data handling

Audit exports are confidential even when they contain no credentials. They can identify users, applications, role assignments, permissions, and attack relationships.

Do not rely on `.gitignore` alone: it does not protect force-added or already tracked files, renamed exports, or sensitive files present only in older commits. This repository includes a strict Git-object scanner, versioned pre-commit/pre-push hooks, and full-history CI checks. See [Contributing](CONTRIBUTING.md#repository-data-safety-checks) for setup and commands.

If tenant evidence enters Git history, deleting it in a later commit is insufficient. Stop pushes, remove the data from every affected ref, coordinate clone cleanup, and contact the hosting provider to remove cached objects and pull-request references.

## Public issues

Use public issues for non-sensitive bugs and feature proposals. Redact tenant IDs, object IDs, user principal names, application names, and Graph responses unless they are synthetic.

## Operational handling

- Verify the connected account and tenant before running an audit.
- Store exports in an access-controlled location.
- Review output before sending it to an AI provider, MCP server, SIEM, ticketing system, or other third party.
- Remove temporary reports when the investigation and retention requirement are complete.
- Never grant a write-capable Entra role solely to run this read-only tool.

## Project security boundary

The tool requests delegated read-only Graph scopes and its direct Graph calls use `GET`. It does not remediate tenant configuration. A change that introduces a write scope, non-GET Graph call, unattended credential, external upload, or automatic remediation is a security-boundary change and requires explicit design review and documentation.
