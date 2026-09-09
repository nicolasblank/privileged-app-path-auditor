# Troubleshooting

## PowerShell reports a parser or syntax error

Use PowerShell 7 or later:

```powershell
$PSVersionTable.PSVersion
```

Windows PowerShell 5.1 is not supported.

## A Microsoft Graph module is missing

Install the required SDK modules in the current user's scope:

```powershell
Install-Module Microsoft.Graph.Applications -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
```

Restart PowerShell if an older module version is already loaded.

## The script reconnects to Graph

An existing Graph context is reused only when it contains all required delegated scopes. The script reconnects when one or more scopes are absent.

Check the context:

```powershell
Get-MgContext | Select-Object Account, TenantId, Scopes
```

Verify the account and tenant before accepting the audit result.

## Access is denied or coverage is partial

Graph consent and the signed-in user's Entra role are separate requirements. A scope can be present while the account still lacks directory access to the requested evidence.

Review the affected `Source` and `Detail` in the coverage summary. Global Reader is the simplest read-only role for a full audit. Do not assign a write-capable role solely to make the audit run.

## No findings were returned

First determine whether the relevant evidence is complete:

- A complete source with zero matching rows can support a clean result for that source.
- A partial or unavailable source cannot.
- The selected mode may not query evidence required by another mode.

Run `Full` with `-ExportPath` when you need the broadest coverage record.

## `StalePrivilege` was skipped

The mode depends on the beta `servicePrincipalSignInActivities` endpoint. Availability can depend on Graph behavior, licensing, cloud, permission, and retained activity.

If collection fails, the tool skips stale classification. It does not interpret missing activity as “never used.” Review the coverage detail and corroborate activity through an authoritative tenant log source.

## Role-definition coverage is partial

The auditor attempts to read Microsoft `isPrivileged` classification from Graph beta. If beta collection fails, it falls back to v1 definitions and the configured built-in role policy. The observed permitted actions are retained where possible, but sensitive-role classification is marked partial.

Do not remove that warning merely because the fallback produced familiar role names.

## Role-assigned group expansion is partial

v0.6 expands role-assigned groups to effective transitive user members using `GET /groups/{id}/transitiveMembers/microsoft.graph.user`. `Directory.Read.All`, already requested by the auditor, is sufficient for ordinary group membership reads.

Review `DataCoverage.csv` for the affected group ID and Graph error. Earlier pages and other successful groups are retained, but absent users cannot be treated as confirmed non-members while coverage is partial. Hidden-membership groups can require `Member.Read.Hidden`, which v0.6 does not request. Do not add broader permission merely to produce a clean report without first confirming that hidden membership is the actual requirement.

`RoleGroupMembers.csv` records the assigned group, effective user, role, scope, source assignment ID, and `group -> user` provenance. It does not reconstruct intermediate nested groups.

## App instance lock is unavailable or not applicable

Lock configuration is read from the local application object. It can be:

- Unavailable when the application query failed.
- Not applicable when the publisher's application object is outside the connected tenant.
- Not configured or disabled for a local app.
- Enabled but not protecting the OAuth credential property used by the path.
- Protecting OAuth credential changes.

Do not call an unobservable publisher lock disabled. Do not treat a protected credential route as proof that every control path is blocked.

## Microsoft first-party catalogue download failed

The tool uses `config/MicrosoftApps.json` for a 24-hour cache. When neither download nor valid cache is available, classification falls back to `appOwnerOrganizationId` and coverage records the limitation.

If a stale or corrupt cache is suspected, move it out of the repository and rerun when network access is available. The file is ignored by Git and can be regenerated.

## CSV files were not created

CSV output is opt-in:

```powershell
./Invoke-PrivilegedAudit.ps1 -Mode Full -ExportPath ./audit-results
```

A report with no rows is not written. Inspect console output and `DataCoverage.csv` before deciding that the absence of a file means no issue exists.

## Console output is truncated

Only display is truncated. Supply `-ExportPath` to retain all collected rows in CSV. Adjust `output.truncateAfter` or `output.maxUsersInRoleAuditList` in a custom configuration if necessary.

## Reporting a reproducible problem

Include:

- Tool version and PowerShell version
- Mode and non-sensitive parameters
- Coverage source and state
- A redacted error message or synthetic object shape
- Expected versus observed behavior

Never include access tokens, credentials, tenant secrets, raw user lists, or unredacted private application evidence in a public issue. See [SECURITY.md](../SECURITY.md) for sensitive reports.
