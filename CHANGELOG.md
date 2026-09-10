# Changelog

Notable changes to Privileged App Path Auditor are recorded here. The project follows semantic versioning while the public finding contract is still being stabilized.

## [0.6.1] - Unreleased

### Fixed

- Make mocked regression suites independent of an installed Microsoft Graph SDK so synthetic tests run consistently on Windows, Linux, and macOS.

## [0.6.0] - 2026-09-10

v0.6 changes how findings are calculated, not how the auditor is run. Results can differ materially from v0.5 because the engine now tests whether a control relationship produces additional privilege and records the evidence needed to support that conclusion.

### Changed

- Add strict repository data-safety enforcement over Git objects: staged content, complete pushed-tip history, non-commit ref targets, the tracked tree, and full reachable history. Versioned hooks protect VS Code Git operations once enabled, and CI provides the authoritative full-history gate.
- Replace the unbounded role-control target table with a one-row-per-user triage summary and prioritized compact path chains. Console detail respects `output.truncateAfter`; returned and exported findings remain complete.
- Count users and target SPs by stable object identity, add deterministic chain ordering, identify ambiguous candidates as `Multiple credential routes`, and normalize tenant-controlled labels to single-line console text.
- Read current Entra role definitions at runtime, including Microsoft `isPrivileged` classification and permitted actions for built-in and custom roles.
- Resolve legacy role definitions individually when the collection endpoint omits them.
- Add a dated fallback for relevant 2026 role additions and classification changes when preview classification is unavailable.
- Evaluate permission-specific privilege delta instead of suppressing every owner who already has any sensitive role.
- Separate application-object control from service-principal control and respect target scope.
- Bind dangerous permissions to grant type and resource API.
- Keep delegated grants out of application-credential takeover paths and report them as conditional exposure.
- Limit owner and unowned-app analysis to local application registrations while retaining third-party service principals in permission reporting.
- Interpret app instance lock Boolean fields and distinguish locked, disabled, partially configured, unavailable, and not-applicable states.
- Recognize prefixed built-in consent assignments and report custom consent policies for review.
- Report data coverage as complete, partial, or unavailable; missing evidence no longer becomes a clean result.
- Remove the unexplained aggregate risk score from `Full` mode and `FullAuditSummary.csv`.
- Simplify the README and move detailed operational guidance into focused documentation.

### Fixed

- Expand active role-assigned groups to effective transitive user assignments with inherited role/scope evidence and source-group provenance. Retain raw group assignments, successful groups, and users observed before later-page failures; keep incomplete groups partial.
- Prevent false negative role classification when expanded assignment principal metadata is missing or unsupported. Preserve distinct source role-assignment IDs while suppressing repeated copies of the same assignment record.
- Keep role-group provenance columns stable in mixed `AttackPaths.csv` exports.
- Share conditional permission-coverage requirements across standalone PermissionAudit, standalone CredentialHygiene, and Full. Application-only and intentionally empty configurations no longer report missing delegated coverage; genuine required-source failures still warn.
- Clarify the attack-path catalogue's existing runtime limits: three IDs provide specific overrides, and unused metadata does not configure detectors, output labels, or references. No new catalogue functionality is enabled.
- Correct checked-in audit descriptions to distinguish currently valid direct-SP credentials from inactive inventory, and single-user consent beneficiaries from approval actors.
- Require Microsoft Graph resource identity for all built-in permission-equivalence mappings, including the Global Administrator shortcut. Preserve the reviewed scope and uncertainty behavior.
- Qualify Full summaries by each mode's required/applicable evidence; preserve per-mode target isolation and monotonic run-wide failures. Unknown sources and review-only findings no longer appear as clean green zeros.
- Handle additive mixed consent policies without calling them low-risk-only, retain per-grant client/resource/beneficiary identity without inferring an approver, and collect grants even when policy retrieval fails.
- Retain delegated principal identity in mixed PermissionAudit CSVs through a consistent row schema.
- Require complete timezone-qualified credential start/end timestamps with `start <= now < end`, preserve future versus expired distinctions, keep unknown intervals partial, and format typed-offset expiry dates in UTC. Preserve timeless FIC treatment without asserting authentication capability.
- Count distinct application IDs in stale-privilege console and Full summaries/actions while retaining permission-level CSV evidence rows.
- Validate fresh and expired catalogue cache shapes and GUIDs; reject invalid caches as a whole, preserve valid expired fallback, and retain existing download encoding recovery.
- Reject malformed collection pages, unresolved permission resources, absent policy settings, and missing client names as incomplete evidence. Retain earlier valid pages where the caller opts in.
- Evaluate incomplete role/scope evidence and unmet prerequisites before full lock mitigation. Keep observed block evidence on potential rows without downgrading target impact to `INFO`.
- Retain unsupported directory/app-specific credential-control scopes as uncertain routes while preserving exclusions for known object/type mismatches and administrative-unit credential scopes.
- Add Microsoft Graph-specific `AppRoleAssignment.ReadWrite.All` equivalence for the modeled permission-grant capability of confirmed tenant-wide PRA/Global Administrator assignments, using role template IDs rather than display names. Unknown scopes remain potential; same-named custom-resource permissions do not match this new rule.
- Correct application credential-capability matching: authentication-settings-only actions no longer imply credential writes; `applications.myOrganization` authority requires a single-tenant audience.
- Evaluate application-registration and SP scopes against their respective object IDs. Require observed local identity rather than inferring it from publisher tenancy.
- Compare supported role-assignment scopes when suppressing equivalent privilege in AttackPath and ShadowAdmins. Unknown scope retains uncertainty; narrower assignments do not suppress broader targets.
- Apply role completeness, candidate-specific scope uncertainty, and enabled-target prerequisites consistently to owner and role-control paths. Preserve independent application/SP route alternatives; do not infer target re-enablement.
- Distinguish failed, partial, and externally unobservable credentials from confirmed empty collections. Retain observed credential risks and prevent false-clean stale results.
- Retain observed inventory, grant, role, and FIC pages after later pagination failures with partial coverage. Keep strict failure behavior for other collectors that rely on complete lists.
- Include incomplete upstream permission evidence in final AttackPath/StalePrivilege no-findings checks and report distinct stale incompleteness reasons.
- Preserve the Microsoft first-party app catalogue when a recoverable encoding issue affects one entry.
- Apply configured disabled-app, credential-risk, expiry, multiple-credential, output-limit, and consent settings.
- Avoid reporting missing local application objects as confirmed unowned applications.
- Skip stale-app conclusions when service-principal sign-in activity is unavailable.

### Testing

- Add disposable-repository regression tests for force-added output paths, arbitrary CSVs, hostile filenames, renamed export schemas, staged-index isolation, add-then-delete history, pushed tips, non-commit tag targets, hook execution, and CI wiring.
- Add rendering regressions for state/severity ordering, stable identity counts, multiple-route presentation, group provenance, console-only truncation, single-line safety, and unchanged returned/exported path counts.
- Add test-first role-group expansion fixtures for empty, nested, paginated, failed, malformed, duplicate, direct-plus-group, permission-equivalence, role-control, RoleAudit, coverage, and mixed-CSV behavior.
- Add standalone grant-type/coverage regressions and sentinel configuration-contract tests, including owner severity fallback, target-role severity precedence, unowned console-only recommendations, descriptive-only IDs, and the checked-in description wording.
- Add test-first suites for resource/cache/export boundaries, consent, credential dates/counts, Full summaries, missing responses, and mode isolation. Use synthetic Graph responses, TestDrive-only caches/exports, and injected clocks; no tenant access is required.
- Replace the regression that incorrectly expected full mitigation with incomplete role evidence. Add end-to-end Graph-collector fixtures for partial role pages, role groups, unsupported scopes, retained lock evidence, and resource-specific equivalence boundaries.
- Add test-first core path, credential evidence, and pagination suites covering positive, negative, incomplete-evidence, alternative-route, and real-collector pagination fixtures.
- Add regression fixtures for privilege delta, role capabilities, permission semantics, application locks, partial evidence, Graph paging, caching, and fallback behavior.
- Run Pester on Windows, Linux, and macOS in CI.
- Enforce the read-only Graph contract, version consistency, configuration schemas, and local documentation links.

### Output contract changes

- `AttackPaths.csv`: add `PotentialPrerequisiteUnknown` exploitability and an `EvidenceDetail` column on both path types; `PotentialRoleUnknown` also covers unresolved equivalence scopes.
- `CredentialHygiene.csv`: add `CredentialEvidence` (`Complete`, `Partial`, `Unavailable`, `NotLocallyObservable`). Unknown counts are the literal `Unknown`, not zero; observed numeric counts under incomplete evidence are lower bounds.
- `PermissionAudit.csv`: consistently include `ConsentPrincipalId`, empty for application grants.
- `UserConsentGrants.csv`: change from per-client aggregates to per-grant rows (`GrantId`, `ClientSPId`, `ResourceSPId`, `ConsentPrincipalId`, `ConsentType`, `ConsentedScopes`, `AppName`). Replace plural `ResourceSPIds`; remove misleading `ConsentingUsers`.
- `FullAuditSummary.csv`: add `CoverageState` and `CoverageDetail`; `Count` remains observed counts, and stale counts are distinct app IDs. Action-row coverage fields are blank.
- `RoleAssignedGroups.csv`: retain raw group assignments with scope and role-assignment ID. Add `RoleGroupMembers.csv` for effective transitive users and source-group provenance. Add `RoleAssignmentSource` and `RoleMembershipPath` to role-control attack paths, with blank columns retained on owner paths for a stable CSV schema.
- Active SP counters and `StalePrivilege.ValidCredCount` now require a current complete interval; hygiene total inventory still includes future/expired records. Stale expiry dates are formatted in UTC.
- Retain existing modes, parameters, filenames, path IDs, configuration keys, and version `0.6.0` while this release is unreleased. Existing CSV consumers must handle the new state/column and nonnumeric unknown hygiene counts.
- This release does not resolve live lock-enforcement questions, PIM-eligible assignments, hidden-membership access, intermediate nested-group reconstruction, re-enablement paths, arbitrary custom-resource/custom-role equivalence, sign-in `Never` semantics, or SAML credential purpose. No JSON contract was added.

## [0.5.1] - 2026-07-19

- Query `servicePrincipalSignInActivities` from Microsoft Graph beta, where the property is available.
- Skip stale detection when activity data is unavailable rather than reporting false stale findings.
- Avoid producing `StalePrivilege.csv` when the required activity evidence is unavailable.

## [0.5.0]

- Add role-based service-principal control detection.
- Add visibility of credentials stored directly on service principals.
- Add application instance property lock reporting.
- Add unowned privileged application detection.

Earlier history is available in the repository's Git tags and commit history.
