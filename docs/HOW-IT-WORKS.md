# How the analysis works

Privileged App Path Auditor is built around one decision: does a principal's control of an Entra application or service principal let that principal reach privilege they do not already have?

The answer is assembled from Microsoft Graph evidence. Read each conclusion alongside its source coverage and, for attack paths, `EvidenceDetail`. Empty results from incomplete sources do not establish absence.

## Evidence flow

1. Connect with delegated, read-only Graph scopes and record the connected tenant.
2. Collect service principals and classify them as Microsoft first-party, home tenant, third-party, or unknown owner.
3. Resolve application and delegated grants against the resource service principal's permission definitions.
4. Read current directory role definitions, assignments, permitted actions, sensitivity, and scope.
5. Collect application owners, service-principal owners, credential metadata, locks, sign-in activity, and consent policy as required by the selected mode.
6. Build candidate control relationships.
7. Remove relationships that do not produce a privilege increase or do not apply to the target scope.
8. Classify the remaining path from the available lock, role, and ownership evidence.
9. Report findings together with evidence coverage and remediation.

## The main path types

### Application owner to application permission

A local application owner may be able to add a credential to the application registration, authenticate as its service principal, and use the application's granted **application** permissions.

The path is reported only when:

- A local application registration was resolved.
- Its owner evidence was collected successfully.
- The target grant is an application permission configured as high impact for the correct resource API.
- No confirmed equivalent tenant-wide assignment rules out the privilege increase.

`Direct` additionally requires complete role evidence, supported scope evidence for potentially equivalent assignments, and an observed enabled target SP. Missing prerequisites leave a potential path rather than a firm escalation. The application object ID must be resolved; home-tenant classification alone is not proof.

Delegated permissions require a signed-in user and are reported by `PermissionAudit` as conditional exposure. They are not treated as application-only credential takeover.

### Role capability to privileged service principal

A built-in or custom Entra role can permit changes to application objects, service principals, or their credentials. The auditor evaluates `allowedResourceActions` instead of assuming that only specifically named administrator roles can create the path.

Application-object and service-principal actions are evaluated separately. Application credential actions must apply tenant-wide or to the resolved **application-registration object ID**; SP actions use the **service-principal object ID**. These IDs are not interchangeable. Missing scope is not treated as tenant-wide authority. Unknown directory-scope syntax and unsupported app-specific scopes retain a potential route; they are not proof of non-applicability. Known unrelated objects, wrong object types, and administrative-unit scopes remain excluded from these credential routes. The reachable directory role's tier supplies the path severity.

For application objects, `credentials/update` and `allProperties/update` support credential changes; `authentication/update` alone does not. The `applications.myOrganization` subtype requires `signInAudience = AzureADMyOrg`. A local multitenant registration does not qualify; missing audience leaves restricted authority uncertain. SP-action semantics are evaluated independently, not inferred from application-action names.

App instance lock evidence is then applied to the service-principal credential route:

- `Direct` when a supported route is available, the target SP is observed enabled, and role/scope evidence supports the privilege increase.
- `PotentialRoleUnknown` when role collection or candidate-specific equivalence scope is incomplete, including when missing role evidence might conceal an alternative control route.
- `PotentialPrerequisiteUnknown` when a required local object, control scope, restricted-action audience, or enabled account is not established.
- `PotentialLockUnknown` when the lock cannot be observed for the relevant application.
- `MitigatedByAppInstanceLock` when role and prerequisite evidence is complete and the observed lock blocks all evaluated credential routes.

A proven application credential route can remain available despite a locked or unobservable SP route. Conversely, an uncertain application route prevents classifying the combined candidate as fully mitigated. Blocked observed routes do not establish full mitigation when incomplete role evidence could hide another route. The lock observation remains in `AppInstanceLock` and `EvidenceDetail`, but the candidate remains potential and keeps its target-impact severity rather than being downgraded to `INFO`. Even complete mitigation within this model is not proof that every other route to the object is safe.

When several uncertainties coexist, the classification order is: role/delta uncertainty, unmet prerequisites, all evaluated routes blocked, unknown lock, then direct. A proven alternative can satisfy a route-specific prerequisite, but cannot repair missing role or account evidence. `EvidenceDetail` retains the individual reasons, including uncertainty on an alternative route even when another route is proven. Disabled targets remain potential; re-enablement is not modelled. Lock enforcement across tenant relationships has not been established by the mocked tests and is unchanged by this accuracy pass.

### Service-principal owner to directory role

`ShadowAdmins` cross-references service-principal owners with sensitive directory roles assigned to the service principal. It also collects credentials stored directly on the service principal, which are distinct from application-registration credentials.

This is supporting relationship evidence. The main `AttackPath` analysis adds capability, scope, lock, and privilege-delta semantics where applicable.

## Privilege delta

The same control relationship can have different meaning for different principals:

- A Global Administrator reaching another Global Administrator-equivalent target has no privilege increase for this model.
- A reader reaching `Directory.ReadWrite.All` has a material privilege increase even though the reader already holds a Microsoft-classified sensitive role.
- A principal already assigned the exact target directory role at the same supported scope, or tenant-wide, is not reported as escalating to that same scoped role.
- An AU-scoped assignment does not suppress a path to the tenant-wide role. Arbitrary scope containment is not inferred.
- Missing or unsupported scope on a potentially equivalent assignment leaves the candidate `PotentialRoleUnknown`, not suppressed and not direct.
- If role evidence is incomplete, otherwise valid owner and role-control paths become `PotentialRoleUnknown` rather than direct or clean.

This avoids the two common shortcuts of treating every owner as non-privileged or treating every existing administrator assignment as equivalent to every target privilege.

For the modeled application-permission-grant effect of **Microsoft Graph** `AppRoleAssignment.ReadWrite.All`, a confirmed tenant-wide Privileged Role Administrator or Global Administrator assignment already provides that authority. The rule uses the resolved built-in role template ID and supported assignment scope, not the role's display name. It requires resource app ID `00000003-0000-0000-c000-000000000000`; a missing resource ID or a same-named custom API permission does not match. Scoped assignments do not establish tenant-wide equivalence, and unknown potentially equivalent scopes keep the owner path potential. An unresolved role definition cannot justify suppression.

This is a documented built-in capability mapping for the permission-grant effect reported by this tool, not proof that every operation available through that permission has identical semantics. All current permission-equivalence mappings, including the Global Administrator shortcut, require the resolved Microsoft Graph resource ID. Missing resource identity or same-named custom API permissions never inherit these mappings. Custom API equivalence and arbitrary custom consent-role capabilities are not inferred.

## Current and custom roles

The tool reads role definitions at runtime:

- Microsoft `isPrivileged` classification identifies current sensitive targets when the beta evidence is available.
- `allowedResourceActions` identifies roles that can change application or service-principal credentials, including custom roles.
- The assignment's `directoryScopeId` is applied to the target.
- The configured built-in template IDs provide an explicit fallback when preview classification is unavailable.

Active role assignments to groups are expanded with the read-only Microsoft Graph transitive-user endpoint. The original group assignment remains evidence, and each effective user receives a derived assignment with the same role definition, assignment scope, and source assignment ID. This lets privilege-delta checks account for a user's current group-derived authority and lets group-derived credential-control roles create path candidates.

The provenance is deliberately limited to `assigned group ID -> effective user ID`. The endpoint returns transitive user leaves but not each intermediate nested group, so `MembershipPath` is not a reconstructed nesting chain. Each distinct Graph role-assignment ID is retained. Duplicate copies of the same assignment ID are suppressed, while the same user reached through different groups, roles, or scopes remains separate evidence.

Group expansion is complete only when every relevant assigned group returns usable user identities across all pages. A failed or malformed group response makes `RoleGroupMemberships` partial while retaining other groups and users observed before a later-page failure. Missing or unsupported principal type on an active role assignment also prevents negative role classification. Empty successful groups remain complete. Groups with hidden membership can require `Member.Read.Hidden`; that permission is not requested by v0.6, so a Graph denial remains explicit partial coverage.

The v0.6 fallback includes relevant role additions and classification changes known in 2026, but live definitions remain authoritative. When the live classification cannot be collected, `RoleDefinitions` coverage is partial.

## Object and permission boundaries

The auditor keeps these concepts separate:

| Boundary | Why it matters |
|---|---|
| Application registration vs service principal | Owners, credentials, actions, and locks do not apply identically to both objects. |
| Home-tenant vs third-party service principal | A tenant can govern consent to a third-party application but cannot inspect or manage its external application registration. |
| Application vs delegated grant | Application permissions work as the workload; delegated permissions require a signed-in user. |
| Permission name vs resource API | Identical permission names on different APIs do not necessarily represent the same capability. |
| Active assignment vs group/PIM evidence | v0.6 expands active role-assigned groups to transitive user leaves, but does not include eligible/PIM assignments or reconstruct intermediate nested groups. |

## Coverage model

Each evidence source has one of three states:

| State | Meaning |
|---|---|
| `Complete` | The source was collected for the scope needed by the analysis. An empty result can be meaningful. |
| `Partial` | Some evidence was collected, but at least one relevant object, expansion, or fallback is incomplete. |
| `Unavailable` | The source could not be collected and conclusions that require it cannot be trusted as complete. |

Run-wide coverage only moves from stronger to weaker. A later successful item cannot erase an earlier failure from the same evidence source. In Full mode, each mode also captures its own queried evidence, so an unrelated application's credential failure in AttackPath does not make a successful ShadowAdmins collection incomplete. Reused core inventories keep their original coverage. Mode-local collection never upgrades or discards the run-wide record.

Examples:

- Failure of the top-level service-principal query makes `ServicePrincipals` unavailable.
- A failed grant query for one client makes application-permission coverage partial while retaining other collected findings.
- Failure to retrieve sign-in activity makes stale detection unavailable and stops credential lookup for that mode.
- A failed, partial, malformed, or access-limited role-group expansion makes role-group membership coverage partial while retaining observed users and raw group assignments.

Inventory, application/delegated grants, user-consent grants, role definitions/assignments, and federated credentials retain successfully collected pages if a later page fails. Their source becomes `Partial`, and later successes cannot restore aggregate completeness. A failed first page, or failure before any items were observed, still uses the collector's failure state. Role and permission findings observed before a failure remain usable evidence, not proof of a complete scan.

Null or malformed pages are failures, not empty collections. The same retention rule applies to malformed later pages. Unresolved resource SPs or grant definitions degrade permission-definition coverage instead of silently yielding a clean permission scan.

Owner, application-object, sign-in activity, and user-list pagination remain strict: a page failure rejects that collection and records incomplete/unavailable evidence rather than using a partial list to infer absence. `AttackPath` and `StalePrivilege` final no-findings messages also check upstream inventory and grant coverage.

`DataCoverage.csv` is therefore part of the result, not diagnostic noise.

## Credential evidence

Application and SP credential helpers retain their per-object array-map return shape, with an optional per-call evidence-status companion. Successful empty arrays mean confirmed absence; failed or omitted properties do not. FIC failure leaves application credentials partial, retaining any observed secrets, certificates, and earlier FIC pages. Per-call status is separate from monotonic run-wide coverage, so one failed application does not taint another application's row.

`CredentialHygiene` adds `CredentialEvidence` (`Complete`, `Partial`, `Unavailable`, or `NotLocallyObservable`). When nothing was observed but collection is incomplete, type/count fields use `Unknown` and the row requires review. Observed numeric counts are lower bounds when evidence is incomplete; known risks are retained. External publisher credentials are not queried or presumed absent.

Password and key credentials are current only when `startDateTime <= now < endDateTime`. Complete timezone-qualified timestamps are compared as UTC instants; abbreviated dates/times, missing timezones, missing values, malformed dates, and inverted or empty intervals give unknown validity and partial credential evidence. Future credentials are not expired, but do not count as currently valid. End-time equality means expired. FICs retain the existing timeless treatment because they do not expose this interval; this is not proof of issuer or authentication capability.

`StalePrivilege` and active SP credential counters use that current-validity criterion. Hygiene total inventory counts retain future and expired credentials. Stale expiry dates are formatted in UTC. Stale CSV evidence remains one row per dangerous permission, but displayed app totals, Full counts, and remediation totals use distinct `AppId`, not display names.

`StalePrivilege` retains findings supported by observed current credentials while reporting incomplete permission/credential coverage. It cannot declare a clean result when those sources are incomplete. A failed sign-in collection still skips the mode. The report's existing `Never` label and aggregate activity semantics are unchanged and still require separate validation; SAML credential purpose is likewise not established by date checks.

## Consent evidence

Permission-grant policies are additive. The low-risk policy is described as low-risk-only only when it is the sole effective assigned policy. Mixed low-risk/custom policies remain `REVIEW`, with all effective policy IDs retained. The legacy broad policy still indicates broad user-consentable permissions when combined with others; it does not grant users administrator-only consent authority. Unknown policy settings produce `Unknown`/`REVIEW`, not `Disabled` or `GOOD`.

Authorization-policy collection and single-user delegated grant collection are independent. A policy failure leaves its coverage unavailable but does not suppress the configured grant inventory. `UserConsentGrants.csv` retains each observed grant's ID, client, resource, beneficiary principal, consent type, and original scope string. `consentType = Principal` identifies a single-user authorization, not its approver: the exporter makes no user-versus-admin approval claim. A missing client display name leaves `[unresolved]` and partial resolution coverage without discarding the grant. Console truncation never truncates exported evidence.

## Classification and the local catalogue

Every service principal is classified using `appOwnerOrganizationId` and, when available, the [merill/microsoft-info](https://github.com/merill/microsoft-info) Microsoft application catalogue.

| Classification | Interpretation |
|---|---|
| Microsoft first-party | Known Microsoft-owned application; excluded by default from the high-impact grant scan. |
| Home tenant | Backed by an application registration in the connected tenant; owner and application-object remediation can be evaluated. |
| Third party | Registered in another tenant; consent and local service-principal state are actionable, but its external application object is not. |
| Unknown owner | Owner organization is absent and the app is not in the catalogue; manual classification is needed. |

The downloaded catalogue is validated and cached in `config/MicrosoftApps.json` for 24 hours. Cache loading validates nonempty object/array contents and canonical GUID app IDs regardless of file age. Invalid caches are rejected as a whole; valid IDs from a partly invalid cache are not retained. A valid fresh cache requires no download; a valid expired cache remains usable with partial coverage if refresh fails. A fresh invalid cache is rejected rather than automatically refreshed; normal expiry or removal of that invalid cache permits a later download. Existing upstream leading-GUID encoding recovery and atomic cache replacement are preserved. If no validated catalogue is available, classification falls back to owner-organization evidence with unavailable catalogue coverage.

## Full mode

`Full` runs each focused mode and then reports factual counts, data coverage, and up to five remediation actions. It deliberately does not compress unlike findings into an aggregate risk score.

Each Full summary row includes `CoverageState` and `CoverageDetail`. Complete empty evidence is distinct from zero observations under partial/unavailable evidence. Required sources depend on the mode and configuration: for example, no delegated-grant source is required when no delegated permissions are configured, and disabled single-user consent inventory is not treated as a failed query. Optional target-specific sources are considered when the mode actually queries them. A sign-in failure does not taint PermissionAudit, and a credential failure for a different target set does not taint ShadowAdmins.

Incomplete rows retain observed counts as lower bounds with visible qualifiers, not green clean verdicts. Consent/custom-policy and credential-review findings remain reviewable even when high/critical or secret counts are zero. `DataCoverage.csv` still contains the monotonic run-wide source record: a Complete mode is not a Complete run. See [Output reference](OUTPUTS.md) for the CSV migration details.

## Semantic references

- [Application registration permissions](https://learn.microsoft.com/entra/identity/role-based-access-control/custom-available-permissions)
- [Application-registration scope for role assignments](https://learn.microsoft.com/entra/identity/role-based-access-control/manage-roles-portal#assign-roles-with-app-registration-scope)
- [Roles permitted to grant tenant-wide admin consent](https://learn.microsoft.com/entra/identity/enterprise-apps/grant-admin-consent#prerequisites)
- [Additive consent-policy evaluation](https://learn.microsoft.com/entra/identity/enterprise-apps/manage-app-consent-policies#multiple-policies-or-authorization-mechanisms-to-grant-consent)
- [Delegated grant identity and beneficiary semantics](https://learn.microsoft.com/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0)
