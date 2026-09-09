# Output reference

Findings are printed to the console. CSV files are created only when `-ExportPath` is supplied and a report has data to write.

```powershell
./Invoke-PrivilegedAudit.ps1 -Mode Full -ExportPath ./audit-results
```

Treat the export directory as confidential tenant security evidence.

## Files

| File | Produced by | Contents |
|---|---|---|
| `Summary.csv` | Modes that collect service principals | Counts for Microsoft first-party, home-tenant, third-party, unknown-owner, and scanned service principals. |
| `UnknownOwnerApps.csv` | Modes that collect service principals | Service principals without a resolved owner organization and a direct Entra link for investigation. |
| `PermissionAudit.csv` | `PermissionAudit`, `Full` | Configured high-impact application and delegated grants, their resource API, effect, and exploitability context. |
| `RoleAudit.csv` | `RoleAudit`, `Full` | Users observed with sensitive-role assignments and users confirmed without them when role evidence is complete. |
| `RoleAssignedGroups.csv` | `RoleAudit`, `Full` | Raw active assignments to groups, including role, scope, and role-assignment ID. |
| `RoleGroupMembers.csv` | `RoleAudit`, `Full` | Effective transitive user role evidence derived from assigned groups, including source group, role, scope, source assignment ID, and membership provenance. |
| `AttackPaths.csv` | `AttackPath`, `Full` | Privilege-increasing owner and role-control paths, potential paths, and lock-mitigated routes. |
| `UnownedPrivilegedApps.csv` | `AttackPath`, `Full` | Confirmed local applications with configured high-impact application permissions and no owners. |
| `ShadowAdmins.csv` | `ShadowAdmins`, `Full` | Owners of service principals with sensitive directory roles, including direct SP credential counts. |
| `StalePrivilege.csv` | `StalePrivilege`, `Full` | Inactive high-impact applications with valid credentials. Not written when sign-in evidence is unavailable. |
| `ConsentRisk.csv` | `ConsentRisk`, `Full` | Tenant consent-policy observations and recommended action. |
| `UserConsentGrants.csv` | `ConsentRisk`, `Full` | Each observed single-user delegated grant when configured; beneficiary identity is retained, but approver identity is not inferred. |
| `CredentialHygiene.csv` | `CredentialHygiene`, `Full` | Credential types, counts, expiry, direct SP credentials, and app instance lock state. |
| `DataCoverage.csv` | Any mode | Complete, partial, or unavailable state and detail for each queried source. |
| `FullAuditSummary.csv` | `Full` | Per-mode factual counts, coverage, and up to five recommended actions. It does not contain an aggregate risk score. |

Files with no rows are not created.

## Attack path fields

Important `AttackPaths.csv` columns include:

| Field | Interpretation |
|---|---|
| `PathNumber` | Display sequence for this run; not a stable finding ID. |
| `PathId` | Path category, such as `APP_OWNER_ESCALATION` or `ROLE_BASED_SP_CONTROL`. |
| `PathType` | Human-readable path category. |
| `Severity` | Impact of the reachable permission or directory role, not a probability score. |
| `UserDisplayName`, `UserUPN` | Principal that holds the observed control relationship. |
| `UserRole` | Existing role evidence used for the privilege-delta decision. |
| `AppName`, `AppId` | Target application identity. |
| `Permission`, `PermissionType` | Reachable permission or directory role and its category. |
| `Exploitability` | `Direct`, a `Potential*` state, or `MitigatedByAppInstanceLock`. |
| `EvidenceDetail` | Additive explanation of missing prerequisite, role, scope, and alternative-route evidence; present on both path types. |
| `RoleAssignmentSource` | `Direct`, `RoleAssignedGroupMember`, or both for a role-control actor; blank for owner paths. |
| `RoleMembershipPath` | Semicolon-separated `assigned-group ID -> effective-user ID` provenance for group-derived role control; blank when not applicable. |
| `Action` | The evaluated control-to-privilege chain. |
| `Result` | The specific impact supported by the target privilege. |
| `SPDirectCreds` | Count of observed SP credentials whose complete start/end interval includes the audit time. |
| `AppInstanceLock` | Observed lock interpretation or unavailable/not-applicable state. |
| `Remediation` | Path-specific actions from configuration. |
| `UserEntraUrl`, `AppEntraUrl` | Direct investigation links. |

Column availability can vary by path type. Stable cross-version finding IDs and a versioned JSON contract are planned for v0.7.

## Exploitability

| Value | Use |
|---|---|
| `Direct` | The collected evidence supports an available control route, an enabled target account, and a privilege increase. |
| `Conditional` | A delegated grant depends on a signed-in user; used in permission evidence, not the application-only takeover path. |
| `PotentialRoleUnknown` | Incomplete role collection may hide equivalent privilege or an alternative control route; missing/unsupported equivalence scope also prevents a firm conclusion. |
| `PotentialPrerequisiteUnknown` | Required application identity, control scope, restricted-action audience, or enabled-account evidence is missing or not satisfied. |
| `PotentialLockUnknown` | The service-principal route is otherwise visible, but lock evidence is unavailable. |
| `MitigatedByAppInstanceLock` | Role and prerequisite evidence is complete and the observed lock blocks all evaluated OAuth credential routes. |

Potential and mitigated rows are retained because they identify an evidence gap or an important control. They should not be counted as confirmed direct paths.

`RoleMembershipPath` records effective assignment provenance, not every nested group hop. `RoleGroupMembers.csv` is the evidence table for group-derived roles. Distinct source role-assignment IDs remain distinct rows; identical repeated records are suppressed. If any relevant group expansion is partial, role-dependent path conclusions remain potential even when some memberships were observed.

Role uncertainty takes precedence over unmet prerequisites; both take precedence over mitigation. Only then can all evaluated routes being blocked establish mitigation. Remaining unknown lock evidence takes precedence over `Direct`. Unsupported control-scope syntax is uncertainty, not exclusion. A proven alternative route can remove route-specific uncertainty, but not missing role or account evidence. Consult `EvidenceDetail` for all reasons; the state is not a list of every gap.

A potential row can therefore retain `AppInstanceLock = OAuthCredentialChangesLocked` and a blocked-route explanation without being classified as mitigated. It keeps the target-impact severity rather than `INFO`. The P1 follow-up changes these classifications, not column names or exploitability-state names.

## Credential count contract

`CredentialHygiene.csv` adds `CredentialEvidence`:

| Value | Interpretation |
|---|---|
| `Complete` | Required local application, FIC, and SP credential collections completed. |
| `Partial` | Some credential evidence is available, but at least one required collection/property is incomplete. |
| `Unavailable` | Required credential evidence could not be collected. |
| `NotLocallyObservable` | Publisher application credentials cannot be inspected locally; SP evidence was collected. |

`CredType`, `CredCount`, and `ExpiredCount` use the literal `Unknown` when no credentials were observed and total evidence is incomplete. `SPDirectCreds` independently uses `Unknown` when its relevant count cannot be established. Numeric values remain observed lower bounds when the row's evidence is incomplete. Only complete empty evidence produces `None`, zero total credentials, and `INFO (no credentials)`.

Consumers must no longer assume all hygiene count cells are integers. These changes apply to credential-hygiene rows; attack-path and shadow credential counts remain numeric observed counts and must be read with source coverage, not as proof of absence. Their meaning now requires current validity (`start <= now < end`), not merely an unexpired end date.

Hygiene `CredCount` remains total observed credential inventory, including future/expired entries. `ExpiredCount` counts entries whose readable end timestamp is at or before audit time; unknown intervals require review even if the end timestamp is readable. Missing, incomplete, or malformed timestamps cannot establish current validity. FICs retain their existing timeless treatment.

`StalePrivilege.csv` retains its columns and one row per dangerous permission. `ValidCredCount` counts current credentials; `CredentialExpires` is the chosen observed credential's UTC date. Console and Full stale application counts use distinct `AppId` (including when applications share display names), not evidence-row count. Findings/counts can be lower bounds under partial coverage. Sign-in unavailability still prevents stale findings.

## Permission and consent export contracts

`PermissionAudit.csv` uses the same ordered columns for application and delegated rows. `ConsentPrincipalId` is empty for application grants and contains the beneficiary ID for single-user delegated grants; it is empty for all-principal grants. It is retained when grant types are mixed, regardless of row order.

`UserConsentGrants.csv` is now **one row per observed grant**, not one aggregated row per client:

| Column | Meaning |
|---|---|
| `GrantId` | Graph delegated grant ID. |
| `ClientSPId` | Client service-principal object ID. |
| `ResourceSPId` | Resource service-principal object ID for this grant. |
| `ConsentPrincipalId` | Beneficiary user ID, not the person who approved consent. |
| `ConsentType` | `Principal` for the single-user grants selected by this inventory. |
| `ConsentedScopes` | Original scope string, kept with its resource and beneficiary. |
| `AppName` | Resolved client name or `[unresolved]`. |

Migration: `ResourceSPIds` is replaced by singular `ResourceSPId`; `ConsentingUsers` is removed because the grant does not identify the approver. Consumers previously grouping by client must now group explicitly while preserving grant tuples. Missing client names do not remove rows. Read coverage when collection is partial; "each observed grant" does not promise an exhaustive list after failures.

## Full summary coverage contract

`FullAuditSummary.csv` retains `Section`, `Finding`, and `Count`, adding `CoverageState` and `CoverageDetail` to mode rows and the aggregate coverage row. Action rows leave the new fields blank.

- `Complete`: required and applicable evidence for that mode is complete.
- `Partial`: some evidence exists, but a required source or relevant observation is incomplete.
- `Unavailable`: no usable evidence is available to establish the required assessment.

`Count` remains the observed count, including zero; it must be interpreted with coverage. Incomplete `Finding` text explicitly qualifies counts as observations/lower bounds. Review-only consent and credential findings remain visible without being called clean. A mode uses its own queried target evidence and reused core inventories. Unqueried optional sources do not inherit another mode's failures. Run-wide `DataCoverage.csv` retains every source failure even when a later mode's own evidence is Complete.

## Data coverage

`DataCoverage.csv` has three fields:

- `Source` — the Graph evidence source or local classification dependency.
- `State` — `Complete`, `Partial`, or `Unavailable`.
- `Detail` — object-specific failure, fallback, or known expansion gap.

Coverage is mode-dependent. For example, a `PermissionAudit` does not need sign-in activity, while `StalePrivilege` does. Review the coverage sources relevant to the selected mode.

## Entra links

Reports that identify an application, service principal, or user contain an Entra admin center URL where the entity was resolved. Links accelerate investigation but do not replace verification of the connected tenant or the relationship shown in the row.

## Console truncation

Console lists can be truncated according to `output.truncateAfter` and `output.maxUsersInRoleAuditList`. CSV exports retain the complete collected rows. Coverage failures are not hidden by truncation.
