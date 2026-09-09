# Investigating findings

Use this workflow to turn an audit result into a defensible remediation decision.

## Start with coverage

1. Confirm the account and tenant shown at connection time.
2. Read the console `DATA COVERAGE` section or open `DataCoverage.csv`.
3. Identify `Partial` or `Unavailable` sources that affect the mode you are reviewing.
4. Treat zero findings as meaningful only when the required evidence sources are complete.
5. In Full mode, read each summary row's `CoverageState` and `CoverageDetail`. Different target sets can have different completeness; a Complete row does not erase failures in run-wide `DataCoverage.csv`.

Do not publish raw tenant evidence in a public issue. Exports can contain names, user principal names, object IDs, permissions, and security relationships.

## Attack paths

For each row in `AttackPaths.csv`, establish:

- **Who:** `UserDisplayName`, `UserUPN`, and the direct role evidence shown in `UserRole`.
- **What is controlled:** `AppName`, `AppId`, and `PathType`.
- **What becomes reachable:** `Permission`, `PermissionType`, `Result`, and `Severity`.
- **How:** `Action` describes the credential or control chain.
- **How certain:** `Exploitability`, `EvidenceDetail`, and the relevant rows in `DataCoverage.csv`.
- **What reduces the path:** `AppInstanceLock` and the recommended remediation.

### Application owner escalation

1. Open `AppEntraUrl` and verify that the application is local and still required.
2. Confirm the reported user remains an owner and determine why ownership is needed.
3. Review the reported application permission on the enterprise application.
4. Compare the permission's effect with the user's current role and job requirement.
5. Check recent owner, credential, and consent changes in Entra audit logs.
6. Prefer removing unnecessary ownership or reducing the permission. Changing credential type alone does not remove an owner's ability to add another credential.
7. If the result is `PotentialRoleUnknown`, complete the missing role evidence before calling the path exploitable or dismissing it.
8. For `PotentialPrerequisiteUnknown`, verify the application object, control scope, and target SP's enabled state. A disabled account is not assumed re-enableable by this path.

### Role control of a privileged service principal

Start with the user summary table to prioritize administrators who reach the most targets and to separate direct, potential, and mitigated counts. Then use each compact chain to identify the exact role and target requiring action. The chain section is console-limited; use `AttackPaths.csv` for complete evidence and filtering.

1. Verify the user's role definition and assignment scope against the correct object ID: application registration for app authority, SP for SP authority.
2. Inspect the role's allowed resource actions; authentication-settings access alone is not application credential authority. Check `signInAudience` for single-tenant-only actions.
3. Open the target service principal and confirm its directory-role assignment.
4. Review `AppInstanceLock` together with `Exploitability`. A blocked observed SP route can still be `PotentialRoleUnknown` when incomplete roles may hide another route. Do not treat it as fully mitigated or informational until role and prerequisite evidence supports that conclusion.
5. Review direct service-principal credentials, because they are separate from credentials shown on the app registration.
6. Reduce or scope the application-control role, remove unnecessary target privilege, and use eligible assignment with appropriate approval where possible.
7. Compare existing and reachable role scopes. An AU-scoped assignment does not establish tenant-wide equivalence. Read all `EvidenceDetail` reasons; a proven alternative route and an uncertain alternative have different effects on the conclusion.
8. Investigate unsupported directory/app-specific control scopes as unknown applicability, not proof that the role cannot reach the target. Known unrelated-object scopes remain excluded.
9. When `RoleAssignmentSource` includes `RoleAssignedGroupMember`, use `RoleMembershipPath` and `RoleGroupMembers.csv` to verify the assigned group, source role assignment, user, role, and scope. The path shows effective membership, not intermediate nested groups.
10. For `Multiple credential routes`, inspect `EvidenceDetail`: more than one application/SP route contributed and no single uncertain route fully explains the candidate.

### Unowned high-impact application

An unowned application is an accountability and lifecycle finding, not automatically an escalation path.

1. Confirm `ApplicationOwners` coverage is complete for the app.
2. Identify the system or team responsible for the workload.
3. Verify whether the grant and credentials are still required.
4. Assign accountable owners or remove the obsolete application and consent through the organization's change process.

## Shadow administrators

`ShadowAdmins.csv` shows a service principal with a sensitive directory role and its observed owner.

1. Confirm the service principal still needs the role and that the role's scope is appropriate.
2. Verify whether the owner can manage credentials for the applicable object.
3. Review SP-level credentials and their complete validity intervals; active counts exclude future or unknown intervals. Credential purpose still needs investigation, not an assumption that every SP certificate is an injected client credential.
4. Review role assignment, owner, and credential-change audit events.
5. Remove unnecessary ownership or role assignment rather than relying only on credential rotation.

## Role-assigned groups

`RoleAssignedGroups.csv` is the raw assignment evidence. `RoleGroupMembers.csv` lists effective user members returned by the transitive-members endpoint.

1. Verify the source group remains intentionally role-assignable and the role assignment's scope is correct.
2. Confirm the effective user is still a transitive member. The recorded path is `assigned group -> user`; investigate intermediate groups separately if needed.
3. Treat duplicate source assignment IDs, unexpected multiple groups, and tenant-wide group-derived administration as high-value review points.
4. If `RoleGroupMemberships` is partial, do not classify absent users as non-privileged. Check access to hidden membership and any failed group IDs in `DataCoverage.csv`.
5. Prefer reducing group membership or assignment scope through normal change control; this auditor does not remediate.

## Permission findings

`PermissionAudit.csv` intentionally includes two different categories:

- `Application` grants allow the workload identity to act without a signed-in user.
- `Delegated` grants require user interaction and inherit the signed-in user's effective permissions.

Verify the `ResourceAppId` and resource name as well as the permission name. A same-named permission from another API is not interchangeable.

Permission inventory is supporting evidence. A dangerous grant alone does not prove a principal can take it over.

## Stale privilege

`StalePrivilege` is evaluated only when service-principal sign-in activity is available.

1. Confirm inventory, application-grant, resource-definition, `ServicePrincipalSignInActivity`, and credential coverage. Partial collections make observed findings/counts lower bounds, not a clean scan.
2. Check whether the workload uses another identity, cloud, or telemetry source not represented by this activity.
3. Verify application owners and business purpose.
4. Disable first when feasible, monitor impact, then remove obsolete grants and credentials through the normal change process.

An unavailable activity source produces no stale findings; it must not be interpreted as “never used.”

Stale application totals count distinct app IDs; multiple permission rows can describe one app. Confirm `start <= now < end` for the observed password/key credentials. Missing or malformed timestamps leave evidence partial. The existing `Never` label is not proof of lifetime non-use, and date validity alone is not proof that a credential can authenticate.

## Credential hygiene

Read `CredentialEvidence` before interpreting counts. `Unknown` is not zero, and a publisher registration that is not locally observable is not credential-free. Numeric counts on incomplete rows are observed lower bounds; resolve the missing source before accepting a preferred-credential or no-credential conclusion.

Prioritize:

1. Direct service-principal credentials that are not expected.
2. Expired credentials that can be removed.
3. Unexplained multiple credentials.
4. Long-lived client secrets on high-impact applications.
5. Lock states that leave the service-principal credential route open where a lock is supported.

Prefer managed identities or workload identity federation where the workload supports them. Certificates improve secret handling but do not make an excessive permission safe.

## Consent findings

1. Confirm the tenant's effective user-consent policy.
2. Treat mixed/custom consent policy assignments as requiring review. One low-risk policy does not restrict permissions allowed by another assigned policy.
3. Review single-user delegated grants by `GrantId`, client, resource, scopes, and `ConsentPrincipalId`. The principal is the beneficiary, not evidence of who approved consent. Policy retrieval failure does not suppress the independent grant inventory.
4. Consider verified-publisher restrictions and an admin consent workflow based on the organization's operating model.

## Close the finding with evidence

Record:

- The principal, application or service principal, and reachable privilege
- Whether the path was direct, potential, or mitigated
- Any incomplete evidence that remains
- The control relationship or permission changed
- The date and owner of the remediation decision
- A follow-up audit showing the path is resolved or explaining why it remains accepted

Stable finding IDs and baseline comparison are planned for v0.7 and v0.8. Until then, retain the relevant export rows and object IDs with the change record.
