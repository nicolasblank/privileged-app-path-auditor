# Privileged App Path Auditor

> **Version 0.6.0** · [Roadmap](ROADMAP.md) · [Changelog](CHANGELOG.md)

A read-only PowerShell auditor that answers a narrow question:

> **Who can gain additional privilege through an Entra application, exactly how, and is the available Microsoft Graph evidence sufficient to trust that conclusion?**

The tool evaluates application ownership, service-principal control, high-impact permissions, Entra role capabilities, the principal's existing privilege, app instance locks, and data coverage. It reports the path and its evidence instead of treating every privileged application or owner relationship as an exploitable escalation.

`AttackPath` is the core analysis. The other modes provide the permission, role, credential, consent, and activity context needed to investigate and reduce those paths.

## Run your first audit

You need PowerShell 7 and the Microsoft Graph PowerShell SDK:

```powershell
Install-Module Microsoft.Graph.Applications -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
```

Clone the repository and run the focused path analysis:

```powershell
git clone https://github.com/nicolasblank/privileged-app-path-auditor.git
cd privileged-app-path-auditor
./Invoke-PrivilegedAudit.ps1 -Mode AttackPath
```

Or run every audit mode:

```powershell
./Invoke-PrivilegedAudit.ps1 -Mode Full
```

The script opens an interactive Microsoft Graph sign-in when needed. Before continuing, verify that the displayed account and tenant are the ones you intend to audit.

To save CSV evidence, explicitly provide an export directory:

```powershell
./Invoke-PrivilegedAudit.ps1 -Mode Full -ExportPath ./audit-results
```

Without `-ExportPath`, findings are printed to the console and no reports are created. The only operational file the tool may write by default is `config/MicrosoftApps.json`, a 24-hour local cache used to classify Microsoft first-party applications.

## What makes a path meaningful

The auditor does more than join an owner to a permission:

1. It separates application permissions from delegated permissions. Only application permissions enter the credential-takeover path.
2. It binds each configured permission to its resource API, preventing a same-named permission on another API from matching accidentally.
3. It distinguishes a local application registration from its service principal and from a third-party service principal.
4. It reads current built-in and custom role definitions, distinguishes application authentication settings from credential-write authority, and checks single-tenant-only action restrictions.
5. It compares the reachable privilege with the principal's existing privilege and supported assignment scopes. A narrower assignment is not equivalent to tenant-wide authority; unknown scope leaves the delta uncertain.
6. It checks application-registration and service-principal object scopes separately, resolves required local objects, checks target account state, and applies lock evidence to the relevant route.
7. It records incomplete or unavailable Graph evidence. A zero count is not called clean when required evidence is missing.

These semantics are explained in [How the analysis works](docs/HOW-IT-WORKS.md).

## Reading an attack-path result

The `Exploitability` field describes what the collected evidence supports:

| Value | Meaning |
|---|---|
| `Direct` | The evaluated control route, enabled target account, and privilege increase are supported by the collected evidence. |
| `PotentialRoleUnknown` | Incomplete role evidence may hide equivalent privilege or an alternative control route; unresolved equivalence scope also prevents a firm conclusion. |
| `PotentialPrerequisiteUnknown` | A required local object, control scope, audience, or enabled target account is not established. |
| `PotentialLockUnknown` | Role control reaches a service principal, but the relevant lock state cannot be observed. |
| `MitigatedByAppInstanceLock` | Role and prerequisite evidence is complete, and all evaluated credential routes are blocked by the observed app instance lock. |

`DataCoverage.csv` and the console coverage summary show which sources were complete, partial, or unavailable. Always interpret finding counts together with that coverage.

`EvidenceDetail` explains missing prerequisites and scope evidence on attack-path rows. A proven application route can bypass a locked SP route. A blocked observed route does not establish full mitigation when role evidence could conceal another route. Unsupported control scopes remain uncertain, not silently excluded. The auditor does not assume it can re-enable a disabled target.

Credential hygiene reports `CredentialEvidence` per application. `Unknown` is not zero: numeric counts with incomplete evidence are observed lower bounds. A failed query or an unobservable publisher registration is not a credential-free application.

`FullAuditSummary.csv` qualifies each mode with `CoverageState` and `CoverageDetail`; unrelated failures do not taint a mode's own evidence, while run-wide coverage retains every failure. Credential validity uses both start and end timestamps, and stale summary counts are distinct applications rather than permission rows.

See [Investigating findings](docs/INVESTIGATING-FINDINGS.md) for a practical triage workflow.

## Modes

| Mode | Purpose |
|---|---|
| `AttackPath` | Maps privilege-increasing application-owner and role-control paths. This is the primary mode. |
| `PermissionAudit` | Reports configured high-impact application and delegated grants, kept separate. |
| `RoleAudit` | Reports active sensitive-role assignments and role-assigned groups. |
| `ShadowAdmins` | Finds owners of service principals that hold sensitive directory roles. |
| `StalePrivilege` | Finds high-impact applications with valid credentials and no recent sign-in evidence. |
| `ConsentRisk` | Reviews tenant consent policy and single-user delegated grants without inferring who approved consent. |
| `CredentialHygiene` | Reviews credential types, expiry, SP-level credentials, and app instance lock state. |
| `Full` | Runs all modes and produces a factual summary of counts, coverage, and recommended actions. |

The supporting modes are useful context; they are not substitutes for the privilege-delta analysis in `AttackPath`.

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Mode` | `Full` | One of the modes listed above. |
| `-ExportPath` | None | Directory for CSV reports. Created only when there is data to export. |
| `-InactiveDays` | `90` | Inactivity threshold for `StalePrivilege`. |
| `-ConfigPath` | `./config` | Configuration directory. Built-in defaults are used when it is absent. |

Examples:

```powershell
# Focus on privilege-increasing paths and save evidence
./Invoke-PrivilegedAudit.ps1 -Mode AttackPath -ExportPath ./audit-results

# Use a 60-day inactivity threshold
./Invoke-PrivilegedAudit.ps1 -Mode StalePrivilege -InactiveDays 60

# Use a separate configuration directory
./Invoke-PrivilegedAudit.ps1 -Mode Full -ConfigPath ./my-config
```

## Access and safety

The script requests these delegated Microsoft Graph scopes:

```text
Application.Read.All
Directory.Read.All
RoleManagement.Read.Directory
AuditLog.Read.All
Policy.Read.All
```

They are read-only. The script's direct Microsoft Graph requests use `GET`; it does not remediate or modify the tenant.

Use an account with enough read access to collect the required evidence. Global Reader is the simplest read-only choice for a full audit. Directory Reader plus Security Reader, or an appropriate custom read-only role, may also work depending on tenant policy. Do not assign Global Administrator merely to run this tool.

Tenant findings can contain identities, application names, object IDs, permissions, and security relationships. Treat console output and exported files as confidential. Review and redact evidence before attaching it to a public issue or passing it to another external system.

## What changed in v0.6

v0.6 changes how findings are calculated, not how the auditor is run. Results may differ materially from v0.5 because the conclusions now use:

- Live role definitions and permitted actions, including custom roles and current Microsoft classification
- Permission-specific privilege delta rather than a generic privileged/non-privileged label
- Correct application, service-principal, third-party, grant-type, and resource-API boundaries
- Role-assignment scope and correctly interpreted app instance locks
- Explicit direct, potential, mitigated, partial, and unavailable states
- Safer fallback behavior for role definitions, consent policy, sign-in activity, and the Microsoft app catalogue
- Retention of observed inventory, grant, role, and federated-credential pages after later-page failures, with partial coverage instead of discarded findings
- Resource-bound privilege equivalence, lossless single-user grant exports, mixed-policy review, validated catalogue caches, and coverage-aware Full summaries

The previous aggregate 0–20 risk score has been removed. `Full` mode retains the underlying finding counts, evidence coverage, and prioritized actions so the operator can see why action is recommended.

See [CHANGELOG.md](CHANGELOG.md) for the complete release history.

## Exports

Exports are opt-in and use one CSV per relevant mode. Important files include:

- `AttackPaths.csv` — the principal, controlled object, target permission or role, exploitability, result, remediation, and Entra links
- `PermissionAudit.csv` — high-impact application and delegated grants
- `RoleAudit.csv` and `RoleAssignedGroups.csv` — observed active role evidence
- `DataCoverage.csv` — completeness and failure detail for every queried evidence source
- `FullAuditSummary.csv` — factual mode counts, coverage, and top actions; no aggregate risk score

See [Output reference](docs/OUTPUTS.md) for the complete file list and interpretation rules.

## Known limits

- Authentication is interactive delegated authentication; unattended application authentication is not implemented.
- `StalePrivilege` uses the beta `servicePrincipalSignInActivities` endpoint. If it is unavailable, stale detection is skipped rather than inferred from missing data.
- Microsoft's role `isPrivileged` classification is obtained from Graph beta when available. Fallback configuration is used with partial coverage when it is not.
- v0.6 reports active role assignments. PIM-eligible assignments and transitive members of role-assigned groups are not expanded.
- Tenant-wide and object-specific scopes are evaluated separately for application and SP credential routes. Role equivalence recognizes supported same-scope and tenant-wide coverage, not arbitrary administrative-scope containment.
- A mitigated result applies to the specific credential route evaluated; it is not a general statement that the application is safe.
- Lock enforcement across home and consumer tenants remains a service-validation question; these fixes do not change that assumption or perform live exploitation tests.
- All current permission-equivalence mappings require the Microsoft Graph resource ID and supported role scope. They do not infer equivalent authority for custom APIs or arbitrary custom consent roles.
- Credential dates establish the observed validity window, not authentication capability. SAML credential purpose and the sign-in report's existing `Never` label remain separate validation questions.

These gaps drive the next roadmap work and are reported in coverage rather than hidden. See [ROADMAP.md](ROADMAP.md).

## Documentation

- [How the analysis works](docs/HOW-IT-WORKS.md)
- [Investigating findings](docs/INVESTIGATING-FINDINGS.md)
- [Output reference](docs/OUTPUTS.md)
- [Configuration](docs/CONFIGURATION.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Development

The regression suite uses Pester 5.7.1 or later:

```powershell
Invoke-Pester -Path ./tests -CI -Output Detailed
```

CI runs the same suite on Windows, Linux, and macOS. Tenant access is not required for the tests; Graph behavior is mocked.

## License

GPL-3.0. See [LICENSE](LICENSE).

## Acknowledgements

[merill/microsoft-info](https://github.com/merill/microsoft-info) provides the MIT-licensed Microsoft first-party application catalogue used for classification. The catalogue is downloaded when available and cached locally for 24 hours.

The application and service-principal path analysis also builds on public identity-security research, including [Azure privilege escalation via service-principal abuse](https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5).
