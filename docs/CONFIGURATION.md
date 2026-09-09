# Configuration

The auditor can run without configuration files using defaults embedded in the script. Checked-in JSON files provide overrides and descriptive catalogue metadata; metadata does not define executable detection logic.

## Files

| File | Purpose |
|---|---|
| `config/dangerous-permissions.json` | High-impact permissions, grant type, resource API, impact, and attack action. |
| `config/privileged-roles.json` | Explicit built-in sensitive-role targets and fallback policy. |
| `config/audit-config.json` | Activity threshold, filters, consent behavior, credential rules, and output limits. |
| `config/attack-paths.json` | Descriptive path catalogue with limited remediation and owner-severity overrides; see [Path definitions](#path-definitions). |

Every checked-in configuration file references a JSON Schema in `config/schema/`. The test suite validates the files against those schemas.

## Override behavior

1. Embedded defaults are loaded first.
2. A matching JSON file in `-ConfigPath` replaces or overrides its configured section.
3. `-InactiveDays` overrides the configured inactivity threshold when supplied.
4. If `-ConfigPath` does not exist, embedded defaults remain active.

Permission, role, and path arrays replace their embedded arrays when present; they are not merged item by item. Keep every definition you still need in a custom file.

Use a separate, untracked directory for tenant-specific configuration:

```powershell
./Invoke-PrivilegedAudit.ps1 -Mode Full -ConfigPath ../privileged-audit-config
```

Do not add tenant IDs, internal application names, or sensitive investigation notes to a public configuration file.

## Dangerous permissions

Definitions must include both grant type and resource API:

```json
{
  "$schema": "/absolute/or/relative/path/to/dangerous-permissions.schema.json",
  "version": "0.6.0",
  "permissions": [
    {
      "name": "RoleManagement.ReadWrite.Directory",
      "type": "Application",
      "resourceAppId": "00000003-0000-0000-c000-000000000000",
      "resourceName": "Microsoft Graph",
      "risk": "Critical",
      "reason": "Can assign any Entra ID role to any principal",
      "attackAction": "assign a privileged directory role to a controlled principal"
    }
  ]
}
```

`type` is `Application` or `Delegated`. Delegated definitions are reported as conditional exposure and do not enter the application-credential takeover path.

The `risk` field expresses the impact of that reachable capability. It is not combined into an aggregate tenant risk score.

## Privileged-role fallback

The primary role evidence comes from live tenant role definitions. Custom roles are discovered from their allowed resource actions and do not need to be copied into `privileged-roles.json`.

The file supplies stable built-in template IDs when preview classification is unavailable and lets the project retain explicit sensitive targets:

```json
{
  "roles": [
    {
      "name": "Global Administrator",
      "templateId": "62e90394-69f5-4237-9190-012177145e10",
      "tier": "Critical",
      "reason": "Full access to Entra ID and connected services"
    }
  ]
}
```

Use a template ID rather than a display name as the stable identity. Runtime role capabilities remain authoritative when they are available.

## Audit behavior

`audit-config.json` supports:

```json
{
  "stalePrivilege": {
    "inactiveDays": 60
  },
  "filters": {
    "excludeDisabledApps": true,
    "excludeFirstPartyMicrosoftApps": true,
    "excludeAppIds": []
  },
  "consentRisk": {
    "flagUserConsentedApps": true
  },
  "credentialHygiene": {
    "preferredCredentialTypes": ["Certificate", "Federated"],
    "riskyCredentialTypes": ["Secret", "SP-Secret", "SP-Certificate"],
    "flagMultipleCredentials": true,
    "flagExpiredCredentials": true
  },
  "output": {
    "maxUsersInRoleAuditList": 500,
    "truncateAfter": 50
  }
}
```

`excludeFirstPartyMicrosoftApps` uses both known Microsoft owner organizations and the cached Microsoft application catalogue. If the catalogue is unavailable, coverage records the reduced classification evidence.

`excludeAppIds` is appropriate for a documented local exception, but exclusion removes evidence from the scan. Maintain an external approval record explaining every excluded app and review it regularly.

`consentRisk.flagUserConsentedApps` keeps its existing key for compatibility. It controls the single-user (`Principal`) delegated-grant inventory, not an assertion that a user rather than an administrator approved consent. The inventory runs independently of authorization-policy retrieval. Setting it to `false` skips that inventory and removes it from Full's required consent sources.

When no delegated permission definitions are configured, delegated grants are intentionally not queried. Standalone `PermissionAudit`, standalone `CredentialHygiene`, and their Full summaries do not require that skipped source. They still require complete service-principal inventory, application-grant, and resource-definition evidence; configured delegated grants must also be complete. An unrelated earlier delegated failure remains in run-wide coverage but does not change an application-only mode's result.

Credential validity is evaluated from complete start/end timestamps. The special critical direct-SP classification requires a currently valid credential. Future and expired credentials remain in inventory and may still trigger configured risky-type or multiple-credential rules. No new configuration switches or policy controls are introduced for these corrections.

## Path definitions

`attack-paths.json` is a descriptive catalogue, **not a configurable detection engine**. `Initialize-Config` retains only `id`, `name`, `severity`, `description`, and `remediation`. It drops `chain`, `detection`, and `references`; changing those catalogue fields does not change queries, control logic, findings, or printed reference URLs.

Only these IDs are looked up by the implementation:

| ID | Runtime fields and effect |
|---|---|
| `APP_OWNER_ESCALATION` | `remediation` supplies the attack-path row's remediation text and console recommendations. `severity` is a fallback only when the permission finding has no `Risk`; permission impact wins when present. If neither supplies severity, the fallback is `High`. |
| `ROLE_BASED_SP_CONTROL` | `remediation` supplies the attack-path row's remediation text and console recommendations. Configured `severity` does not override target-role impact or the `INFO` classification of a confirmed lock-mitigated path. |
| `UNOWNED_PRIVILEGED_APP` | `remediation` supplies console recommendations only. Unowned exports have no configured severity or remediation column. |

For all three, `id` selects the override. Retained `name` and `description` do not replace runtime path labels or result text. References printed by modes are defined in the implementation, not loaded from this catalogue.

The remaining checked-in IDs are descriptive only:

| Catalogue ID | Mode it does **not** configure |
|---|---|
| `SHADOW_ADMIN_SP` | `ShadowAdmins` |
| `CONSENT_GRANT_ATTACK` | `ConsentRisk` |
| `STALE_APP_EXPLOITATION` | `StalePrivilege` |
| `CREDENTIAL_THEFT_SECRET` | `CredentialHygiene` |

Sentinel tests verify these boundaries in [PathConfigurationContract.Tests.ps1](../tests/PathConfigurationContract.Tests.ps1). Adding a new catalogue ID does not add a detector. Removing a definition does not disable detection: owner and role-control paths use their implementation fallbacks, and missing unowned guidance produces no catalogue recommendations. Path-array replacement behavior still applies; this documentation does not wire unused fields or IDs into reports.

Changing a path ID or the meaning of an existing ID is a public-contract change and requires tests and release notes.

## Validate changes

Run the full regression suite after changing configuration or schemas:

```powershell
Invoke-Pester -Path ./tests -CI -Output Detailed
```

Add a synthetic regression test when a configuration change alters which objects match, the meaning of a path, or coverage behavior.
