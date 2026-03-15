# Privileged App Path Auditor

A PowerShell tool that identifies privilege escalation paths through Entra ID app registrations, maps shadow admin relationships, and audits privileged role membership — all in a single script with zero cost and no dependencies beyond the Microsoft Graph PowerShell SDK.

## Why This Exists

Application identities are one of the largest and least governed attack surfaces in Microsoft Entra ID. Existing free tools either list permissions without context or require expensive licenses (E5, P2) to surface risk. None of them answer the critical question:

> **"Can a regular user in my tenant escalate to Global Administrator through an app they own?"**

This tool answers that question — and several others — by mapping the actual attack paths, not just listing permissions.

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

- **PowerShell 7+**
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
RoleManagement.Directory.Read.All
AuditLog.Read.All
Policy.Read.All
```

All read-only. The tool never modifies your tenant.

## Usage

```powershell
# Run the full audit (all modes)
.\Invoke-PrivilegedAudit.ps1 -Mode Full

# Run a specific mode
.\Invoke-PrivilegedAudit.ps1 -Mode AttackPath

# Export results to CSV files in a folder
.\Invoke-PrivilegedAudit.ps1 -Mode Full -ExportPath ./audit-results

# Specify how many days of inactivity counts as "stale" (default: 90)
.\Invoke-PrivilegedAudit.ps1 -Mode StalePrivilege -InactiveDays 60
```

## Example Output

### PermissionAudit

Finds apps with permissions that grant Global Admin equivalence.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  PERMISSION AUDIT — Apps with Global Admin-Equivalent Permissions          ║
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
║  ROLE AUDIT — Privileged Role Membership                                   ║
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
║  ATTACK PATH ANALYSIS — User → App Owner → Privilege Escalation            ║
╚══════════════════════════════════════════════════════════════════════════════╝

Found 2 attack path(s):

───────────────────────────────────────────────────────────────────────────────
⚠  PATH 1: App Owner Escalation (CRITICAL)
───────────────────────────────────────────────────────────────────────────────

  ┌─────────────────────────────────────────────────────────────────────────┐
  │  john.doe@contoso.com                                                  │
  │  Role: None (regular user)                                             │
  │                          ↓ owns                                        │
  │  App: "Legacy Migration Tool" (a1b2c3d4-e5f6-7890-abcd-ef1234567890)  │
  │  Permission: RoleManagement.ReadWrite.Directory (Application)          │
  │                          ↓ can exploit                                 │
  │  Action: Add secret → authenticate as app → assign any role            │
  │  Result: GLOBAL ADMIN EQUIVALENT ACCESS                                │
  └─────────────────────────────────────────────────────────────────────────┘

  Remediation:
    • Remove john.doe@contoso.com as owner of this app
    • OR replace RoleManagement.ReadWrite.Directory with a least-privilege permission
    • OR require Conditional Access for workload identities on this service principal

───────────────────────────────────────────────────────────────────────────────
⚠  PATH 2: App Owner Escalation (CRITICAL)
───────────────────────────────────────────────────────────────────────────────

  ┌─────────────────────────────────────────────────────────────────────────┐
  │  jane.smith@contoso.com                                                │
  │  Role: None (regular user)                                             │
  │                          ↓ owns                                        │
  │  App: "HR Sync Service" (b2c3d4e5-f6a7-8901-bcde-f12345678901)        │
  │  Permission: AppRoleAssignment.ReadWrite.All (Application)             │
  │                          ↓ can exploit                                 │
  │  Action: Add secret → authenticate as app → grant itself any permission│
  │  Result: GLOBAL ADMIN EQUIVALENT ACCESS                                │
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
║  SHADOW ADMIN DETECTION — SP Owners with Indirect Privilege                ║
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
║  STALE PRIVILEGE — Dormant High-Privilege Apps with Valid Credentials       ║
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
║  CONSENT RISK — Tenant Consent Policy Assessment                           ║
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
║  CREDENTIAL HYGIENE — Credential Risk for High-Privilege Apps              ║
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
║  FULL AUDIT SUMMARY                                                        ║
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
3. Cross-references the data to map relationships (user → owns app → app has permission → escalation path)
4. Outputs findings to the console with actionable remediation guidance
5. Optionally exports results to CSV files for reporting

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

## References

- [Microsoft Graph permissions overview](https://learn.microsoft.com/graph/permissions-overview)
- [Microsoft Entra built-in roles](https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference)
- [Privileged roles and permissions in Entra ID](https://learn.microsoft.com/entra/identity/role-based-access-control/privileged-roles-permissions)
- [Review permissions granted to enterprise applications](https://learn.microsoft.com/entra/identity/enterprise-apps/manage-application-permissions)
- [Grant and revoke API permissions](https://learn.microsoft.com/powershell/microsoftgraph/how-to-grant-revoke-api-permissions)
- [Configure user consent settings](https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent)
