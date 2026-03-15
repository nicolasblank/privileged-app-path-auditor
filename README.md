# Privileged App Path Auditor

> **Version 0.4.0**

A PowerShell tool that maps privilege escalation attack paths through Entra ID application ownership. If a regular user owns an app registration that has `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, or another Global Admin-equivalent permission, that user can add a secret to the app, authenticate as it, and **silently become a Global Administrator** — no alerts, no approval, no MFA. This tool finds every one of those paths in your tenant.

It also detects shadow admins, stale high-privilege apps, credential hygiene issues, and consent policy weaknesses — all in a single script with zero cost and no dependencies beyond the Microsoft Graph PowerShell SDK.

> **No files are created unless you ask for them.** By default the script prints findings to the console only — no CSVs, no exports, no files written anywhere. To generate CSV reports, explicitly pass the `-ExportPath` parameter:
> ```powershell
> .\Invoke-PrivilegedAudit.ps1 -Mode Full -ExportPath ./audit-results
> ```
> Without `-ExportPath`, nothing is written to disk.

## Why This Exists

Application identities are one of the largest and least governed attack surfaces in Microsoft Entra ID. A typical enterprise tenant has hundreds of app registrations, many with powerful permissions granted during initial setup and never reviewed. The problem isn't the permissions themselves — it's **who can use them**.

### The Attack Path

In Entra ID, any user listed as an **owner** of an app registration can:

1. Add a new client secret or certificate to the app
2. Use that credential to authenticate as the app's service principal
3. Inherit every application permission the app has been granted

If the app holds `RoleManagement.ReadWrite.Directory`, the user can now assign themselves — or anyone — the Global Administrator role. If it holds `AppRoleAssignment.ReadWrite.All`, the user can grant the app any permission, including the ones it didn't originally have. The entire chain requires no admin privileges, generates no approval workflow, and (without Conditional Access for workload identities) triggers no MFA challenge.

This is not a theoretical risk. It is a documented attack technique that works in every Entra ID tenant where app ownership and app permissions are not actively governed.

### What's Missing Today

Existing free tools either list permissions without context or require expensive licenses (E5, P2) to surface risk. None of them answer the critical question:

> **"Can a regular user in my tenant escalate to Global Administrator through an app they own?"**

This tool answers that question — and several others — by mapping the actual end-to-end attack paths, not just listing permissions. It cross-references app owners, app permissions, service principal role assignments, sign-in activity, and credential metadata to produce actionable findings with direct Entra portal links for immediate investigation.

## What It Finds

| Mode | What It Detects |
|---|---|
| `PermissionAudit` | App registrations and service principals with Global Admin-equivalent permissions |
| `RoleAudit` | Users who hold privileged directory roles vs. those who don't |
| `AttackPath` | End-to-end paths from unprivileged user → app ownership → privilege escalation |
| `ShadowAdmins` | Users who own service principals that hold privileged directory roles |
| `StalePrivilege` | Dormant high-privilege apps with valid credentials and no recent sign-ins |
| `ConsentRisk` | Tenant consent policy configuration weaknesses |
| `CredentialHygiene` | High-privilege apps using secrets instead of certificates or managed identities |
| `Full` | Runs all of the above |

## Prerequisites

- **PowerShell 7+** — if you only have Windows PowerShell 5.1 (the blue one), install PowerShell 7 from [https://aka.ms/powershell](https://aka.ms/powershell). On macOS/Linux: `brew install powershell` or see the [install docs](https://learn.microsoft.com/powershell/scripting/install/installing-powershell).
- **Microsoft Graph PowerShell SDK** modules:
  - `Microsoft.Graph.Applications`
  - `Microsoft.Graph.Identity.DirectoryManagement`
  - `Microsoft.Graph.Identity.SignIns`

Install them if needed:

```powershell
Install-Module Microsoft.Graph.Applications -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
```

- **Entra ID account** with one of these roles:
  - Global Reader (recommended — least privilege for full read access)
  - Application Administrator
  - Directory Reader + Security Reader

### Required Graph Scopes

The script connects with these delegated scopes:

```
Application.Read.All
Directory.Read.All
RoleManagement.Read.Directory
AuditLog.Read.All
Policy.Read.All
```

All read-only. The tool never modifies your tenant.

## Usage

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Mode` | String | *(required)* | Audit mode to run — see table below |
| `-ExportPath` | String | *(none)* | Directory for CSV export. Created if it doesn't exist |
| `-InactiveDays` | Int | `90` | Days of inactivity before an app is flagged as stale |
| `-ConfigPath` | String | `./config` | Path to config directory. Falls back to built-in defaults if missing |

### Modes

| Mode | What It Does | Typical Runtime |
|---|---|---|
| `PermissionAudit` | Flags apps with GA-equivalent application permissions | ~2 min |
| `RoleAudit` | Lists users in/out of privileged directory roles | ~3 sec |
| `AttackPath` | Maps user → app owner → privilege escalation chains | ~2 min |
| `ShadowAdmins` | Finds users who own SPs that hold privileged roles | ~3 sec |
| `StalePrivilege` | Dormant high-privilege apps with valid credentials | ~2 min |
| `ConsentRisk` | Evaluates tenant consent policy and user-consented apps | ~40 sec |
| `CredentialHygiene` | Audits credential type/count for high-privilege apps | ~2 min |
| `Full` | Runs all modes sequentially | ~9 min |

> **Note:** Typical runtimes were measured against a real Entra ID tenant with ~1,300 service principals. Your results will vary depending on tenant size and network latency.

### Getting the Tool

**Option A — Download ZIP (no Git required)**

1. Go to [github.com/nicolasblank/privileged-app-path-auditor](https://github.com/nicolasblank/privileged-app-path-auditor)
2. Click the green **Code** button → **Download ZIP**
3. Extract the ZIP to a folder on your machine (e.g. `C:\Tools\privileged-app-path-auditor`)
4. Open PowerShell 7 and `cd` into that folder

**Option B — Git clone**

```powershell
git clone https://github.com/nicolasblank/privileged-app-path-auditor.git
cd privileged-app-path-auditor
```

### Running the Audit

```powershell
# Run the full audit — the best first run
.\Invoke-PrivilegedAudit.ps1 -Mode Full

# Run a single focused audit
.\Invoke-PrivilegedAudit.ps1 -Mode AttackPath
```

The script will call `Connect-MgGraph` automatically if you are not already connected. A browser window will open for interactive sign-in — sign in with a Global Reader (or equivalent) account in the tenant you want to audit.

### Exporting Results

```powershell
# Export all modes to CSV files
.\Invoke-PrivilegedAudit.ps1 -Mode Full -ExportPath ./audit-results
```

One CSV per mode is created in the export directory:

| File | Source Mode | Entra Links |
|---|---|---|
| `Summary.csv` | SP classification (all modes that scan SPs) | — |
| `UnknownOwnerApps.csv` | SPs with no owner org | App link |
| `PermissionAudit.csv` | PermissionAudit | App link |
| `RoleAudit.csv` | RoleAudit | User link |
| `AttackPaths.csv` | AttackPath | App + User links |
| `ShadowAdmins.csv` | ShadowAdmins | SP + User links |
| `StalePrivilege.csv` | StalePrivilege | App link |
| `ConsentRisk.csv` | ConsentRisk | — |
| `CredentialHygiene.csv` | CredentialHygiene | App link |
| `FullAuditSummary.csv` | Full (overall results, risk score, top actions) | — |

`Summary.csv` contains the service principal classification breakdown (total, Microsoft first-party, home tenant, third-party, unknown owner, and how many were scanned). It is written by any mode that queries service principals.

`FullAuditSummary.csv` is only produced by `Full` mode. It contains one row per mode with the finding count, the overall risk level and score, and the top remediation actions — useful for dashboards, trend tracking, or forwarding to a SIEM.

### Entra Admin Center Links

Every CSV that reports on a specific app or user includes an `EntraPortalUrl` column (or `AppEntraUrl` / `UserEntraUrl` where both entities appear). These are direct deep-links into the Microsoft Entra admin center — open them in a browser to jump straight to the entity's management blade without searching.

#### URL Patterns

| Entity | URL format | Opens |
|---|---|---|
| Service Principal / App | `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/{id}/appId/{appId}` | Enterprise app Overview blade |
| User | `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/UserDetailsMenuBlade/~/Profile/userId/{id}` | User profile blade |

#### Which CSVs Include Links

| CSV | Column(s) | Entity linked |
|---|---|---|
| `UnknownOwnerApps.csv` | `EntraPortalUrl` | Enterprise application |
| `PermissionAudit.csv` | `EntraPortalUrl` | Enterprise application with dangerous permissions |
| `RoleAudit.csv` | `EntraPortalUrl` | User with directory role assignment |
| `AttackPaths.csv` | `AppEntraUrl`, `UserEntraUrl` | The privileged app and the non-admin user who owns it |
| `ShadowAdmins.csv` | `SPEntraUrl`, `UserEntraUrl` | The role-bearing service principal and its owner |
| `StalePrivilege.csv` | `EntraPortalUrl` | Enterprise application with stale privilege |
| `CredentialHygiene.csv` | `EntraPortalUrl` | Enterprise application with credential issues |

`ConsentRisk.csv`, `Summary.csv`, and `FullAuditSummary.csv` report tenant-level settings or aggregate counts and do not link to individual entities.

#### How to Use the Links

1. **Open the CSV** in Excel, Google Sheets, or any viewer that renders clickable hyperlinks
2. **Click an `EntraPortalUrl`** — it opens the entity directly in the Entra admin center (you must be signed in with an admin account)
3. **Investigate** using the blades relevant to the finding type:

| Finding type | What to check in Entra |
|---|---|
| Dangerous permission | **Permissions** tab — review and remove unnecessary API permissions |
| Privileged role holder | **Assigned roles** tab — verify the role is intended; consider PIM eligible assignment instead of permanent |
| Attack path (app) | **Owners** tab — remove non-admin owners from privileged apps; **Permissions** tab — reduce scope |
| Attack path (user) | **Owned applications** — review all apps the user can control |
| Shadow admin | **Owned applications** — the user can reset credentials on a role-bearing SP; remove ownership or the SP role |
| Stale privilege | **Sign-in logs** tab — confirm inactivity; **Properties** — disable the app if unused |
| Credential hygiene | **Certificates & secrets** — rotate expired credentials or remove unused ones |
| Unknown owner app | **Overview** — check publisher and sign-in activity; **Owners** — assign an owner or flag for removal |

#### Tips

- **Bookmark the export** — Entra URLs are deterministic and stable. They will continue to work as long as the entity exists in your tenant.
- **Bulk triage** — sort the CSV by `Risk` or `RiskLevel`, then work through the Entra links from critical to info.
- **Delegate investigation** — share the CSV with a colleague who has Entra admin access. The links let them jump directly to each finding without needing to search.

### Investigating Unknown Owner Apps

When the audit reports unknown owner apps, each one is exported to `UnknownOwnerApps.csv` with a clickable `EntraPortalUrl` column. For each app:

1. **Open the Entra portal link** — check the Overview blade for publisher, sign-in activity, and assigned users
2. **Check Owners** — if no owners are listed, the app may be orphaned. Assign an owner or flag for removal
3. **Check Permissions** — review the API permissions tab. Unknown-origin apps with `Directory.ReadWrite.All` or `RoleManagement.ReadWrite.Directory` are high priority
4. **Check Sign-in logs** — if the app has never signed in and has no users assigned, consider disabling it
5. **Decide**: keep (assign an owner), disable (`Update-MgServicePrincipal -AccountEnabled:$false`), or delete

Unknown owner apps are **not** filtered from scanning — they are checked for dangerous permissions alongside home tenant and third-party apps.

### Investigating Attack Paths

Attack path findings are the highest-severity output of the tool. Each row in `AttackPaths.csv` represents a confirmed, exploitable privilege escalation chain: a non-admin user who owns an app that has a Global Admin-equivalent permission.

#### Understanding the Finding

Every attack path has three components:

| Component | CSV Column | What It Means |
|---|---|---|
| **The user** | `UserUPN`, `UserDisplayName` | A regular user with no privileged Entra ID roles. They are an owner of the app registration, which means they can modify its credentials. |
| **The app** | `AppName`, `AppId` | An app registration whose service principal has been granted a dangerous application permission (e.g. `RoleManagement.ReadWrite.Directory`). |
| **The escalation** | `Permission`, `Action`, `Result` | What the user can do: add a secret, authenticate as the app, and exploit the permission to reach Global Admin equivalence. |

The `AppEntraUrl` link opens the enterprise application blade; the `UserEntraUrl` link opens the user's profile.

#### Why This Is Critical

The user does not need any admin role to execute this attack. App owners can add credentials to their apps through the Entra portal, the Azure CLI, or the Microsoft Graph API. Once they have a credential, they authenticate as the service principal — inheriting every application permission the app has been granted. If that includes `RoleManagement.ReadWrite.Directory`, they can assign themselves Global Administrator. The entire chain can be completed in under a minute with no approval workflow and no MFA (unless Conditional Access for workload identities is configured).

#### Step-by-Step Investigation

For each row in `AttackPaths.csv`:

1. **Open the app link** (`AppEntraUrl`) — go to the **Owners** tab. Confirm the user listed in the finding is still an owner. If they were removed since the last scan, re-run the audit to verify the path is closed.

2. **Evaluate ownership necessity** — does this user need to be an owner of this app? Common legitimate reasons:
   - The user is the developer who built and maintains the app
   - The user is the team lead responsible for the app's lifecycle
   - The ownership was inherited and never cleaned up (most common)

3. **Check the permission** — go to the **Permissions** tab (API permissions). Look at the specific permission listed in the `Permission` column:
   - `RoleManagement.ReadWrite.Directory` — can assign any role to any principal
   - `AppRoleAssignment.ReadWrite.All` — can grant any app permission to any service principal
   - `Application.ReadWrite.All` — can modify credentials on any app in the tenant
   - `Directory.ReadWrite.All` — broad write access to all directory objects
   - `Directory.AccessAsUser.All` — full directory access as the signed-in user (delegated)

4. **Decide on remediation** — there are two ways to break the path, and you should consider both:

   | Option | When to Use | How |
   |---|---|---|
   | **Remove the owner** | The user doesn't need ownership. This is the fastest fix. | Entra portal → Enterprise app → Owners → Remove |
   | **Reduce the permission** | The app doesn't need a GA-equivalent permission. Replace with a least-privilege alternative. | Entra portal → App registration → API permissions → Remove and re-grant with narrower scope |
   | **Both** | Ideal for maximum risk reduction | Remove the owner **and** reduce the permission |

5. **Apply compensating controls** — if neither removal is feasible (e.g. production app with a legitimate owner):
   - Enable **Conditional Access for workload identities** on the service principal to require a compliant network or block token issuance outside trusted locations
   - Configure **app instance lock** to prevent credential changes without admin approval
   - Set up **alerts** on credential additions via Azure Monitor or Microsoft Sentinel

6. **Verify the fix** — re-run the audit in AttackPath mode:
   ```powershell
   .\Invoke-PrivilegedAudit.ps1 -Mode AttackPath
   ```
   The path should no longer appear. If it does, check whether another user is also an owner, or whether the permission was re-granted.

#### Bulk Triage

If the audit finds many attack paths, prioritize by permission severity:

1. `RoleManagement.ReadWrite.Directory` — direct Global Admin escalation (fix first)
2. `AppRoleAssignment.ReadWrite.All` — can self-grant any permission (fix second)
3. `Application.ReadWrite.All` — can pivot to other apps (fix third)
4. `Directory.ReadWrite.All` — broad but less direct escalation (fix fourth)

Sort the CSV by `Permission` and work through each group. Use the `AppEntraUrl` links to jump directly to each app.

### Investigating Shadow Admins

Shadow admin findings identify non-admin users who own service principals that hold privileged Entra ID directory roles. Unlike attack paths (which exploit app permissions), shadow admins exploit **role assignments on service principals**.

#### Understanding the Finding

Each row in `ShadowAdmins.csv` represents a user who can:

1. Reset the credentials of a service principal they own
2. Authenticate as that service principal
3. Inherit the SP's privileged directory role (e.g. Privileged Role Administrator, Global Administrator)

| CSV Column | What It Means |
|---|---|
| `UserUPN` | The non-admin user who owns the SP |
| `SPDisplayName`, `SPId` | The service principal that holds a privileged role |
| `SPRole` | The directory role assigned to the SP |
| `Risk` | The full attack chain description |

#### Step-by-Step Investigation

1. **Open the SP link** (`SPEntraUrl`) — go to **Owners** and confirm the user is listed

2. **Check the SP's role** — go to **Assigned roles** (or check `SPRole` in the CSV). Is this role actually required for the SP's function? Common over-assignments:
   - SP has Global Administrator but only needs Application Administrator
   - SP has Privileged Role Administrator but only needs User Administrator
   - SP has a role from initial setup that was never scoped down

3. **Check the user link** (`UserEntraUrl`) — go to **Owned applications** to see everything this user can control. A user who owns multiple role-bearing SPs is a higher priority.

4. **Remediate**:

   | Option | When to Use |
   |---|---|
   | **Remove user as SP owner** | The user doesn't need to manage this SP |
   | **Remove the SP's role assignment** | The SP doesn't need a privileged role |
   | **Replace permanent with PIM-eligible** | The SP needs the role occasionally — use just-in-time activation instead |
   | **Scope the role** | Use an Administrative Unit to limit the role's blast radius |

5. **Verify** — re-run: `.\Invoke-PrivilegedAudit.ps1 -Mode ShadowAdmins`

### Investigating Stale Privileges

Stale privilege findings flag high-privilege apps that have valid credentials but no recent sign-in activity. These are dormant apps that could be exploited if an attacker obtains their credentials — they are already pre-authorized with dangerous permissions.

#### Understanding the Finding

Each row in `StalePrivilege.csv` represents an app that has all three risk factors simultaneously:

| CSV Column | What It Means |
|---|---|
| `AppName`, `AppId` | The dormant app |
| `Permission` | The dangerous permission the app holds |
| `LastSignIn` | How long since the app last authenticated (or "Never") |
| `CredentialType` | Whether the app uses a Secret or Certificate |
| `CredentialExpires` | When the valid credential expires |
| `ValidCredCount` | Number of non-expired credentials (multiple credentials increase risk) |

An app that has never signed in, holds `RoleManagement.ReadWrite.Directory`, and has a valid secret is a critical finding — it is a fully loaded weapon that no one is using.

#### Step-by-Step Investigation

1. **Open the app link** (`EntraPortalUrl`) — check the **Overview** for the app's description, publisher, and assigned users

2. **Determine if the app is still needed**:
   - Check **Sign-in logs** — is there any activity at all, or was it active years ago?
   - Check **Users and groups** — are users or groups assigned to this app?
   - Ask the app's owner (if one exists) — is this app part of an active workflow, seasonal process, or disaster recovery plan?

3. **Check for credential exposure**:
   - Go to **Certificates & secrets** — how many credentials exist? When were they created?
   - Multiple secrets created at different times may indicate credential sprawl or a compromised rotation process
   - A secret created recently on an otherwise dormant app is a red flag

4. **Remediate based on the situation**:

   | Situation | Action |
   |---|---|
   | App is abandoned / no one claims it | Disable the app: `Update-MgServicePrincipal -ServicePrincipalId <id> -AccountEnabled:$false`, then delete after a bake period |
   | App is needed but the permission is too broad | Remove the dangerous permission and grant a least-privilege alternative |
   | App is needed and the permission is justified | Rotate credentials, remove extras, configure Conditional Access for workload identities, and set up sign-in monitoring |
   | App has never signed in | Almost certainly safe to disable — but verify with the owner first |

5. **Don't just revoke the credential** — removing the secret doesn't fix the root cause. The dangerous permission remains, and a new credential can be added. Either remove the permission or disable the app.

6. **Verify** — re-run: `.\Invoke-PrivilegedAudit.ps1 -Mode StalePrivilege`

### Investigating Credential Hygiene Findings

Credential hygiene findings assess **how** high-privilege apps authenticate, not whether they should have the permission (that's PermissionAudit's job). The risk hierarchy is: secrets are the weakest, certificates are better, and federated credentials / managed identities are best.

#### Understanding the Risk Levels

| Risk Level | Meaning |
|---|---|
| **CRITICAL** | Multiple credentials including secrets — likely credential sprawl |
| **HIGH** | Single secret — extractable, can be leaked in logs/config files |
| **MODERATE** | Certificate only — better, but the permission itself is still dangerous |
| **GOOD** | Federated or managed identity — best practice |
| **INFO** | No credentials at all — the app can't authenticate (may be unused) |

#### Step-by-Step Investigation

1. **Open the app link** (`EntraPortalUrl`) — go to **Certificates & secrets**

2. **Assess the credential situation**:
   - **Multiple credentials** (`CredCount > 1`) — why does this app have more than one? Common causes: failed rotation (old secret not deleted), multiple environments sharing one app registration, or credential compromise where a new secret was added without revoking the old one
   - **Expired credentials** (`ExpiredCount > 0`) — these should be removed. They can't be used for authentication but they clutter the app and may indicate poor lifecycle management
   - **Secrets on a high-privilege app** — secrets are strings that can be copied, pasted into emails, committed to source control, or logged in CI/CD output. Unlike certificates, they don't require a private key

3. **Plan the migration**:

   | Current State | Target State | How |
   |---|---|---|
   | Secret | Certificate | Generate a certificate, upload the public key to the app registration, update the app's code to use certificate-based auth, then delete the secret |
   | Secret | Managed Identity | If the app runs on Azure (App Service, Functions, VMs, AKS), switch to a system-assigned or user-assigned managed identity — no credentials to manage at all |
   | Secret | Federated credential | For GitHub Actions, Kubernetes, or other OIDC-capable platforms, configure workload identity federation |
   | Multiple secrets | Single certificate | Consolidate to one certificate, update all consumers, delete all secrets |

4. **Remove expired credentials** — even though they can't be used, they add noise. Go to **Certificates & secrets** and delete any with a past expiry date.

5. **Verify** — re-run: `.\Invoke-PrivilegedAudit.ps1 -Mode CredentialHygiene`

### Adjusting Stale Threshold

```powershell
# Flag apps inactive for 30+ days instead of the default 90
.\Invoke-PrivilegedAudit.ps1 -Mode StalePrivilege -InactiveDays 30
```

### Using a Custom Config Directory

```powershell
# Point to a custom config directory
.\Invoke-PrivilegedAudit.ps1 -Mode Full -ConfigPath /path/to/custom-config

# If the path doesn't exist, built-in defaults are used (no error)
.\Invoke-PrivilegedAudit.ps1 -Mode Full -ConfigPath /nonexistent
```

### Recommended Workflow

1. **First run** — `Full` mode with export to get a baseline:
   ```powershell
   .\Invoke-PrivilegedAudit.ps1 -Mode Full -ExportPath ./audit-results
   ```
2. **Triage** — focus on `AttackPath` and `ShadowAdmins` results first (highest risk)
3. **Remediate** — remove dangerous owners, revoke unused permissions, delete stale apps
4. **Re-run** individual modes after remediation to verify fixes:
   ```powershell
   .\Invoke-PrivilegedAudit.ps1 -Mode AttackPath
   ```

## Example Output

### PermissionAudit

Finds apps with permissions that grant Global Admin equivalence.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  PERMISSION AUDIT -- Apps with Global Admin-Equivalent Permissions           ║
╚══════════════════════════════════════════════════════════════════════════════╝

Found 4 app(s) with dangerous permissions:

App Name                    App ID                                Permission                              Type
--------                    ------                                ----------                              ----
Legacy Migration Tool       a1b2c3d4-e5f6-7890-abcd-ef1234567890  RoleManagement.ReadWrite.Directory      Application
HR Sync Service             b2c3d4e5-f6a7-8901-bcde-f12345678901  AppRoleAssignment.ReadWrite.All          Application
Dev Automation App          c3d4e5f6-a7b8-9012-cdef-123456789012  Application.ReadWrite.All                Application
Old Reporting Dashboard     d4e5f6a7-b8c9-0123-defa-234567890123  Directory.ReadWrite.All                  Application

⚠  These permissions allow an app to assign roles, modify any application,
   or write to the directory — effectively equivalent to Global Administrator.

Reference: https://learn.microsoft.com/graph/permissions-overview#best-practices-for-using-microsoft-graph-permissions
```

### RoleAudit

Lists users in privileged roles and those not in any privileged role.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  ROLE AUDIT -- Privileged Role Membership                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

USERS IN PRIVILEGED ROLES (7 users):

User                          UPN                             Role(s)
----                          ---                             -------
Alice Admin                   alice@contoso.com               Global Administrator
Bob Breakglass                bob-bg@contoso.com              Global Administrator
Carol Security                carol@contoso.com               Security Administrator, Conditional Access Administrator
Dave Helpdesk                 dave@contoso.com                Helpdesk Administrator
Eve Apps                      eve@contoso.com                 Application Administrator
Frank Exchange                frank@contoso.com               Exchange Administrator
Grace Identity                grace@contoso.com               Privileged Role Administrator

USERS NOT IN ANY PRIVILEGED ROLE (243 users):

User                          UPN
----                          ---
John Doe                      john.doe@contoso.com
Jane Smith                    jane.smith@contoso.com
... (241 more)

Reference: https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference
```

### AttackPath

Maps end-to-end privilege escalation paths through app ownership.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  ATTACK PATH ANALYSIS -- User -> App Owner -> Privilege Escalation           ║
╚══════════════════════════════════════════════════════════════════════════════╝

Found 2 attack path(s):

───────────────────────────────────────────────────────────────────────────────
⚠  PATH 1: App Owner Escalation (CRITICAL)
───────────────────────────────────────────────────────────────────────────────

  ┌─────────────────────────────────────────────────────────────────────────┐
  │  john.doe@contoso.com
  │  Role: None (regular user)
  │                          ↓ owns
  │  App: "Legacy Migration Tool" (a1b2c3d4-e5f6-7890-abcd-ef1234567890)
  │  Permission: RoleManagement.ReadWrite.Directory (Application)
  │                          ↓ can exploit
  │  Action: Add secret → authenticate as app → assign any role
  │  Result: GLOBAL ADMIN EQUIVALENT ACCESS
  └─────────────────────────────────────────────────────────────────────────┘

  Remediation:
    • Remove john.doe@contoso.com as owner of this app
    • OR replace RoleManagement.ReadWrite.Directory with a least-privilege permission
    • OR require Conditional Access for workload identities on this service principal

───────────────────────────────────────────────────────────────────────────────
⚠  PATH 2: App Owner Escalation (CRITICAL)
───────────────────────────────────────────────────────────────────────────────

  ┌─────────────────────────────────────────────────────────────────────────┐
  │  jane.smith@contoso.com
  │  Role: None (regular user)
  │                          ↓ owns
  │  App: "HR Sync Service" (b2c3d4e5-f6a7-8901-bcde-f12345678901)
  │  Permission: AppRoleAssignment.ReadWrite.All (Application)
  │                          ↓ can exploit
  │  Action: Add secret → authenticate as app → grant itself any permission
  │  Result: GLOBAL ADMIN EQUIVALENT ACCESS
  └─────────────────────────────────────────────────────────────────────────┘

  Remediation:
    • Remove jane.smith@contoso.com as owner of this app
    • OR replace AppRoleAssignment.ReadWrite.All with a scoped permission
    • OR move this app to use a Managed Identity instead

Reference: https://learn.microsoft.com/entra/identity/role-based-access-control/security-planning#protect-against-consent-grant-attacks
```

### ShadowAdmins

Finds users who own service principals that hold privileged directory roles.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  SHADOW ADMIN DETECTION -- SP Owners with Indirect Privilege                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

Found 1 shadow admin path(s):

  User:              mike.intern@contoso.com (No privileged roles)
  Owns SP:           "Automation Service" (SP ID: e5f6a7b8-c9d0-1234-efab-567890123456)
  SP Has Role:       Privileged Role Administrator
  Risk:              User can reset SP credentials → activate as SP → assign any role
  Remediation:       Remove user as SP owner or remove the SP's role assignment

Reference: https://learn.microsoft.com/entra/identity/role-based-access-control/privileged-roles-permissions
```

### StalePrivilege

Flags high-privilege apps that haven't signed in recently but still have valid credentials.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  STALE PRIVILEGE -- Dormant High-Privilege Apps with Valid Credentials       ║
╚══════════════════════════════════════════════════════════════════════════════╝

Found 3 stale high-privilege app(s):

App Name                 Dangerous Permission                  Last Sign-In    Credential Type  Credential Expires
--------                 --------------------                  ------------    ---------------  ------------------
Old Reporting Dashboard  Directory.ReadWrite.All                187 days ago    Secret           2026-09-15
Decom Phase2 Sync        RoleManagement.ReadWrite.Directory     Never           Certificate      2027-01-10
Test Automation          Application.ReadWrite.All              312 days ago    Secret           2026-12-01

⚠  These apps have dangerous permissions, valid credentials, and no recent activity.
   They are prime targets for credential theft and privilege escalation.

  Remediation:
    • Disable or delete the app if no longer needed
    • Remove the dangerous permissions
    • Rotate and then revoke the credentials

Reference: https://learn.microsoft.com/entra/identity/enterprise-apps/manage-application-permissions
```

### ConsentRisk

Assesses the tenant's consent policy configuration.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  CONSENT RISK -- Tenant Consent Policy Assessment                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

Setting                                    Value                    Risk
-------                                    -----                    ----
User consent for apps                      Allowed                  ⚠  HIGH
User consent scope                         All permissions          ⚠  CRITICAL
Admin consent workflow enabled             No                       ⚠  HIGH
Block risky consent                        Not configured           ⚠  HIGH
Users can add gallery apps                 Yes                      ⚠  MEDIUM
Users can register apps                    Yes                      ⓘ  LOW

APPS WITH USER-CONSENTED (NOT ADMIN-CONSENTED) PERMISSIONS (12 apps):

App Name                 Consented Scopes                               Consented By
--------                 ----------------                               ------------
Sketchy AI Tool          Mail.Read, Files.ReadWrite.All, User.Read       john.doe@contoso.com
Random Survey App        User.Read, profile, email, openid               5 users
...

  Remediation:
    • Set user consent to "Do not allow user consent" or "Allow for verified publishers only"
    • Enable admin consent workflow so users can request access
    • Review and revoke suspicious user-consented permissions above

Reference: https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent
```

### CredentialHygiene

Evaluates credential practices for high-privilege apps.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  CREDENTIAL HYGIENE -- Credential Risk for High-Privilege Apps               ║
╚══════════════════════════════════════════════════════════════════════════════╝

Found 4 high-privilege apps. Credential breakdown:

App Name                 Permission                         Cred Type    Count  Expiry           Risk
--------                 ----------                         ---------    -----  ------           ----
Legacy Migration Tool    RoleManagement.ReadWrite.Directory  Secret       3      1 expired,      ⚠  CRITICAL
                                                                                 2 active            (multiple active secrets)
HR Sync Service          AppRoleAssignment.ReadWrite.All     Secret       1      2026-06-15      ⚠  HIGH
                                                                                                     (secret, not cert)
Dev Automation App       Application.ReadWrite.All           Certificate  1      2027-03-01      ✓  MODERATE
                                                                                                     (cert is better, but
                                                                                                      permission is dangerous)
Infra Pipeline           Directory.ReadWrite.All             Federated    1      N/A             ✓  GOOD
                                                                                                     (federated/managed identity)

SUMMARY:
  Apps using secrets:              2  ← migrate to certificates or managed identities
  Apps using certificates:         1  ← review permission scope
  Apps using federated/managed:    1  ← best practice ✓
  Total expired credentials:       1  ← remove to reduce attack surface
  Apps with multiple credentials:  1  ← investigate, may indicate credential sprawl

Reference: https://learn.microsoft.com/entra/identity/enterprise-apps/certificate-management
```

### Full Mode

Runs all modes sequentially and produces a summary:

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  FULL AUDIT SUMMARY                                                          ║
╚══════════════════════════════════════════════════════════════════════════════╝

  Permission Audit:      4 apps with GA-equivalent permissions
  Role Audit:            7 users in privileged roles, 243 not
  Attack Paths:          2 critical escalation paths found
  Shadow Admins:         1 shadow admin detected
  Stale Privilege:       3 dormant high-privilege apps
  Consent Risk:          4 HIGH/CRITICAL consent policy issues
  Credential Hygiene:    2 high-privilege apps using secrets

  OVERALL RISK:          ██████████░░░░░░░░░░  HIGH

  Top 3 Actions:
    1. Remove non-admin owners from apps with dangerous permissions (2 paths)
    2. Disable user consent or restrict to verified publishers
    3. Disable/delete 3 dormant apps with dangerous permissions and valid credentials

  Full results exported to: ./audit-results/
```

## Dangerous Permissions Reference

These application permissions are flagged as Global Admin-equivalent because they allow an app to escalate its own or others' privileges:

| Permission | Why It's Dangerous |
|---|---|
| `RoleManagement.ReadWrite.Directory` | Can assign any Entra ID role, including Global Administrator |
| `AppRoleAssignment.ReadWrite.All` | Can grant itself or any app any permission |
| `Application.ReadWrite.All` | Can modify any app's credentials and impersonate it |
| `Directory.ReadWrite.All` | Near-full write access to all directory objects |
| `Directory.AccessAsUser.All` | Highest privileged delegated permission — full directory access as the user |

Source: [Microsoft Graph permissions overview — Best practices](https://learn.microsoft.com/graph/permissions-overview#best-practices-for-using-microsoft-graph-permissions)

## Privileged Roles Checked

The following Entra ID built-in roles are classified as privileged (marked with the Privileged label by Microsoft):

| Role | Template ID |
|---|---|
| Global Administrator | `62e90394-69f5-4237-9190-012177145e10` |
| Privileged Role Administrator | `e8611ab8-c189-46e8-94e1-60213ab1f814` |
| Privileged Authentication Administrator | `7be44c8a-adaf-4e2a-84d6-ab2649e08a13` |
| Global Reader | `f2ef992c-3afb-46b9-b7cf-a126ee74c451` |
| Security Administrator | `194ae4cb-b126-40b2-bd5b-6091b380977d` |
| Conditional Access Administrator | `b1be1c3e-b65d-4f19-8427-f6fa0d97feb9` |
| Exchange Administrator | `29232cdf-9323-42fd-ade2-1d097af3e4de` |
| SharePoint Administrator | `f28a1f50-f6e7-4571-818b-6a12f2af6b6c` |
| User Administrator | `fe930be7-5e62-47db-91af-98c3a49a38b1` |
| Application Administrator | `9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3` |
| Cloud Application Administrator | `158c047a-c907-4556-b7ef-446551a6b5f7` |
| Authentication Administrator | `c4e39bd9-1100-46d3-8c65-fb160da0071f` |
| Helpdesk Administrator | `729827e3-9c14-49f7-bb1b-9608f156bbb8` |
| Intune Administrator | `3a2c62db-5318-420d-8d74-23affee5d9d5` |

Source: [Microsoft Entra built-in roles](https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference)

## How It Works

1. Connects to Microsoft Graph using interactive delegated authentication (`Connect-MgGraph`)
2. Queries service principals, app role assignments, directory role assignments, sign-in activity, consent grants, and authorization policies using read-only Graph API calls
3. Classifies all service principals and displays a summary before scanning:

```
  Service Principal Summary:
    Total:                    1298
    Microsoft first-party:    1014
    Home tenant:              91
    Third-party (cross-tenant):179
    Unknown owner:            14

  Scanning 284 non-Microsoft SPs for dangerous permissions...
```

| Category | Description |
|---|---|
| **Microsoft first-party** | Apps owned by Microsoft — identified using the [merill/microsoft-info](https://github.com/merill/microsoft-info) database (4,000+ known app IDs, refreshed daily) and `appOwnerOrganizationId`. All are cross-tenant by nature but are a known quantity. |
| **Home tenant** | Apps your organization registered in Entra ID |
| **Third-party (cross-tenant)** | Apps from non-Microsoft external vendors (SaaS products you've consented to). These are typically the highest-risk category — they originate from another organization's tenant and have been granted permissions in yours. |
| **Unknown owner** | No `appOwnerOrganizationId` and not in the Microsoft lookup. May be legacy apps, managed identities with incomplete metadata, or apps from deleted tenants. These are exported to `UnknownOwnerApps.csv` with direct Entra portal links for investigation. |

4. Cross-references the data to map relationships (user → owns app → app has permission → escalation path)
5. Outputs findings to the console with actionable remediation guidance
6. Optionally exports results to CSV files for reporting

## Limitations

- **Read-only** — this tool never modifies your tenant
- **Delegated auth only** — requires an interactive sign-in (no support for app-only auth to avoid creating yet another privileged app)
- **Sign-in log retention** — Entra ID retains sign-in logs for 7 days (free) or 30 days (P1/P2). StalePrivilege accuracy depends on your log retention
- **PIM eligible assignments** — detecting PIM-eligible (not active) role assignments requires Entra ID P2. The tool will report active assignments regardless of license and attempt PIM queries where available

## Configuration

The tool works out of the box with zero configuration. All dangerous permissions, privileged roles, and settings are hardcoded as defaults. To customize, add or edit JSON files in the `config/` directory — they override the defaults.

### Config Files

| File | Purpose |
|---|---|
| `config/dangerous-permissions.json` | Permissions flagged as GA-equivalent |
| `config/privileged-roles.json` | Entra ID built-in roles classified as privileged |
| `config/audit-config.json` | Thresholds, filters, and output settings |
| `config/attack-paths.json` | Attack path definitions and remediation guidance |

### Customizing Permissions

Add or remove permissions in `config/dangerous-permissions.json`:

```json
{
  "permissions": [
    {
      "name": "RoleManagement.ReadWrite.Directory",
      "type": "Application",
      "risk": "Critical",
      "reason": "Can assign any Entra ID role to any principal"
    }
  ]
}
```

### Customizing Roles

Add custom or tenant-specific roles in `config/privileged-roles.json`:

```json
{
  "roles": [
    {
      "name": "Global Administrator",
      "templateId": "62e90394-69f5-4237-9190-012177145e10",
      "tier": "Critical"
    }
  ]
}
```

### Audit Settings

Override thresholds in `config/audit-config.json`:

```json
{
  "stalePrivilege": { "inactiveDays": 60 },
  "filters": {
    "excludeFirstPartyMicrosoftApps": true,
    "excludeAppIds": ["app-id-to-skip"]
  }
}
```

### How Defaults + Overrides Work

1. The script has hardcoded defaults for all permissions, roles, and settings
2. If a config JSON file exists, its values **replace** the defaults entirely
3. CLI parameters (e.g., `-InactiveDays 60`) override config file values
4. If no `config/` directory exists, the script still runs with full functionality
5. Use `config/local-*.json` files for machine-specific overrides (gitignored)

## License

**GPL-3.0** — See [LICENSE](LICENSE) for full text.

This project is intentionally licensed under GPL-3.0 rather than a permissive license like MIT. The existing tooling in this space is dominated by paid commercial products (Defender for Cloud Apps requiring E5 Security, Access Reviews requiring Entra ID P2). GPL-3.0 ensures that:

- The tool **stays free and open** — anyone can use, modify, and distribute it
- Anyone who builds on this work **must also open-source their changes** under GPL-3.0
- No one can fork this into a **closed-source paid product** and sell it back to the community that needs it most
- Security tooling for identity governance should be **accessible to every organization**, not just those with enterprise budgets

If you're a vendor and want to integrate this into a commercial product, reach out to discuss licensing.

## Acknowledgements

- **[merill/microsoft-info](https://github.com/merill/microsoft-info)** (MIT) — Provides the daily-updated database of 4,000+ Microsoft first-party application IDs used to filter out Microsoft-owned apps. The list is auto-downloaded and cached locally for 24 hours.

## References

- [Microsoft Graph permissions overview](https://learn.microsoft.com/graph/permissions-overview)
- [Microsoft Entra built-in roles](https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference)
- [Privileged roles and permissions in Entra ID](https://learn.microsoft.com/entra/identity/role-based-access-control/privileged-roles-permissions)
- [Review permissions granted to enterprise applications](https://learn.microsoft.com/entra/identity/enterprise-apps/manage-application-permissions)
- [Grant and revoke API permissions](https://learn.microsoft.com/powershell/microsoftgraph/how-to-grant-revoke-api-permissions)
- [Configure user consent settings](https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent)
