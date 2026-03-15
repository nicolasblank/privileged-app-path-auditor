/**
 * Remediation script generator.
 * Produces PowerShell (Microsoft.Graph SDK) and HTTP (Graph REST API)
 * commands for each remediation action type.
 *
 * SAFETY: Scripts are generated for copy-paste review — never auto-executed.
 */

import type { RemediationAction, ScriptBlock } from '../types/audit';

let actionCounter = 0;

export function removeOwner(appName: string, appId: string, ownerUpn: string, ownerObjectId: string): RemediationAction {
  actionCounter++;
  const scripts: ScriptBlock[] = [
    {
      language: 'powershell',
      label: 'PowerShell (Microsoft.Graph)',
      code: [
        `# Remove owner "${ownerUpn}" from app "${appName}"`,
        `# ⚠ Verify the app will still have at least one owner after removal`,
        `$app = Get-MgApplication -Filter "appId eq '${appId}'"`,
        `Remove-MgApplicationOwnerByRef -ApplicationId $app.Id -DirectoryObjectId '${ownerObjectId}'`,
      ].join('\n'),
    },
    {
      language: 'http',
      label: 'Graph REST API',
      code: [
        `# Remove owner "${ownerUpn}" from app "${appName}"`,
        `# First: GET /applications?$filter=appId eq '${appId}' → get the object ID`,
        `DELETE https://graph.microsoft.com/v1.0/applications/{objectId}/owners/${ownerObjectId}/$ref`,
        `# Required permission: Application.ReadWrite.All`,
      ].join('\n'),
    },
  ];

  return {
    id: `rem-${actionCounter}`,
    category: 'owner-removal',
    severity: 'warning',
    title: `Remove owner from ${appName}`,
    description: `Remove ${ownerUpn} as owner of "${appName}" to close the privilege escalation path.`,
    appName,
    appId,
    scripts,
  };
}

export function removeAppPermission(appName: string, appId: string, spObjectId: string, permission: string, assignmentId: string): RemediationAction {
  actionCounter++;
  const scripts: ScriptBlock[] = [
    {
      language: 'powershell',
      label: 'PowerShell (Microsoft.Graph)',
      code: [
        `# Remove permission "${permission}" from "${appName}"`,
        `# ⚠ DANGER: This immediately revokes the permission. Verify the app does not need it.`,
        `Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId '${spObjectId}' -AppRoleAssignmentId '${assignmentId}'`,
      ].join('\n'),
    },
    {
      language: 'http',
      label: 'Graph REST API',
      code: [
        `# Remove permission "${permission}" from "${appName}"`,
        `DELETE https://graph.microsoft.com/v1.0/servicePrincipals/${spObjectId}/appRoleAssignments/${assignmentId}`,
        `# Required permission: AppRoleAssignment.ReadWrite.All`,
      ].join('\n'),
    },
  ];

  return {
    id: `rem-${actionCounter}`,
    category: 'permission-removal',
    severity: 'danger',
    title: `Remove ${permission} from ${appName}`,
    description: `Remove the dangerous "${permission}" app role assignment. This takes effect immediately.`,
    appName,
    appId,
    scripts,
  };
}

export function disableApp(appName: string, appId: string, spObjectId: string): RemediationAction {
  actionCounter++;
  const scripts: ScriptBlock[] = [
    {
      language: 'powershell',
      label: 'PowerShell (Microsoft.Graph)',
      code: [
        `# Disable service principal for "${appName}"`,
        `# ⚠ This prevents the app from authenticating. Existing sessions may continue until token expiry.`,
        `Update-MgServicePrincipal -ServicePrincipalId '${spObjectId}' -AccountEnabled:\$false`,
      ].join('\n'),
    },
    {
      language: 'http',
      label: 'Graph REST API',
      code: [
        `# Disable service principal for "${appName}"`,
        `PATCH https://graph.microsoft.com/v1.0/servicePrincipals/${spObjectId}`,
        `Content-Type: application/json`,
        ``,
        `{ "accountEnabled": false }`,
        `# Required permission: Application.ReadWrite.All`,
      ].join('\n'),
    },
  ];

  return {
    id: `rem-${actionCounter}`,
    category: 'app-disable',
    severity: 'danger',
    title: `Disable ${appName}`,
    description: `Disable the service principal to prevent authentication. The app registration remains intact for re-enablement.`,
    appName,
    appId,
    scripts,
  };
}

export function assignOwner(appName: string, appId: string, newOwnerUpn: string, newOwnerObjectId: string): RemediationAction {
  actionCounter++;
  const scripts: ScriptBlock[] = [
    {
      language: 'powershell',
      label: 'PowerShell (Microsoft.Graph)',
      code: [
        `# Assign "${newOwnerUpn}" as owner of "${appName}"`,
        `# ⚠ Only assign ownership to users who should manage this app's credentials and configuration.`,
        `$app = Get-MgApplication -Filter "appId eq '${appId}'"`,
        `$params = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/${newOwnerObjectId}" }`,
        `New-MgApplicationOwnerByRef -ApplicationId $app.Id -BodyParameter $params`,
      ].join('\n'),
    },
    {
      language: 'http',
      label: 'Graph REST API',
      code: [
        `# Assign "${newOwnerUpn}" as owner of "${appName}"`,
        `# First: GET /applications?$filter=appId eq '${appId}' → get the object ID`,
        `POST https://graph.microsoft.com/v1.0/applications/{objectId}/owners/$ref`,
        `Content-Type: application/json`,
        ``,
        `{ "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/${newOwnerObjectId}" }`,
        `# Required permission: Application.ReadWrite.All`,
      ].join('\n'),
    },
  ];

  return {
    id: `rem-${actionCounter}`,
    category: 'owner-assignment',
    severity: 'warning',
    title: `Assign owner to ${appName}`,
    description: `Assign ${newOwnerUpn} as the responsible owner of "${appName}".`,
    appName,
    appId,
    scripts,
  };
}

export function enableAppInstanceLock(appName: string, appId: string): RemediationAction {
  actionCounter++;
  const scripts: ScriptBlock[] = [
    {
      language: 'powershell',
      label: 'PowerShell (Microsoft.Graph)',
      code: [
        `# Enable app instance property lock for "${appName}"`,
        `# This prevents owners from adding credentials directly to the service principal.`,
        `$app = Get-MgApplication -Filter "appId eq '${appId}'"`,
        `$params = @{`,
        `    servicePrincipalLockConfiguration = @{`,
        `        isEnabled = $true`,
        `        allProperties = $true`,
        `    }`,
        `}`,
        `Update-MgApplication -ApplicationId $app.Id -BodyParameter $params`,
      ].join('\n'),
    },
    {
      language: 'http',
      label: 'Graph REST API',
      code: [
        `# Enable app instance property lock for "${appName}"`,
        `# First: GET /applications?$filter=appId eq '${appId}' → get the object ID`,
        `PATCH https://graph.microsoft.com/v1.0/applications/{objectId}`,
        `Content-Type: application/json`,
        ``,
        `{`,
        `  "servicePrincipalLockConfiguration": {`,
        `    "isEnabled": true,`,
        `    "allProperties": true`,
        `  }`,
        `}`,
        `# Required permission: Application.ReadWrite.All`,
      ].join('\n'),
    },
  ];

  return {
    id: `rem-${actionCounter}`,
    category: 'lock-enable',
    severity: 'info',
    title: `Enable instance lock on ${appName}`,
    description: `Prevent SP-level credential injection by enabling the app instance property lock.`,
    appName,
    appId,
    scripts,
  };
}

export function rotateCredentials(appName: string, appId: string, _spObjectId?: string): RemediationAction {
  actionCounter++;
  const scripts: ScriptBlock[] = [
    {
      language: 'powershell',
      label: 'PowerShell (Microsoft.Graph)',
      code: [
        `# Rotate credentials for "${appName}"`,
        `# Step 1: List current credentials`,
        `$app = Get-MgApplication -Filter "appId eq '${appId}'" -Property Id,PasswordCredentials,KeyCredentials`,
        `$app.PasswordCredentials | Format-Table KeyId, DisplayName, EndDateTime`,
        `$app.KeyCredentials | Format-Table KeyId, DisplayName, EndDateTime`,
        ``,
        `# Step 2: Add a new certificate (recommended over secrets)`,
        `# $certPath = "path/to/cert.cer"`,
        `# $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)`,
        `# $keyCredential = @{`,
        `#     type = "AsymmetricX509Cert"`,
        `#     usage = "Verify"`,
        `#     key = [System.Convert]::ToBase64String($cert.RawData)`,
        `# }`,
        `# Update-MgApplication -ApplicationId $app.Id -KeyCredentials @($keyCredential)`,
        ``,
        `# Step 3: Remove old secrets (after verifying new credential works)`,
        `# foreach ($pwd in $app.PasswordCredentials) {`,
        `#     Remove-MgApplicationPassword -ApplicationId $app.Id -KeyId $pwd.KeyId`,
        `# }`,
        ``,
        `# Also check for SP-level credentials (hidden from portal):`,
        `$sp = Get-MgServicePrincipal -Filter "appId eq '${appId}'" -Property Id,PasswordCredentials,KeyCredentials`,
        `if ($sp.PasswordCredentials.Count -gt 0 -or $sp.KeyCredentials.Count -gt 0) {`,
        `    Write-Warning "⚠ SP-level credentials found — these are NOT visible in the portal!"`,
        `    $sp.PasswordCredentials | Format-Table KeyId, DisplayName, EndDateTime`,
        `    # Remove SP-level passwords:`,
        `    # foreach ($pwd in $sp.PasswordCredentials) {`,
        `    #     Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.Id)/removePassword" -Body @{ keyId = $pwd.KeyId }`,
        `    # }`,
        `}`,
      ].join('\n'),
    },
  ];

  return {
    id: `rem-${actionCounter}`,
    category: 'credential-rotation',
    severity: 'warning',
    title: `Rotate credentials for ${appName}`,
    description: `Review and rotate credentials. Migrate from secrets to certificates. Check for hidden SP-level credentials.`,
    appName,
    appId,
    scripts,
  };
}

/** Build bulk remediation script for multiple actions of the same type */
export function buildBulkScript(actions: RemediationAction[], language: 'powershell' | 'http'): string {
  const header = language === 'powershell'
    ? [
        '# ═══════════════════════════════════════════════════════════════',
        '# Bulk Remediation Script — Privileged App Path Auditor',
        `# Generated: ${new Date().toISOString()}`,
        `# Actions: ${actions.length}`,
        '# ⚠ REVIEW EACH ACTION CAREFULLY BEFORE EXECUTING',
        '# ═══════════════════════════════════════════════════════════════',
        '',
        '# Connect to Microsoft Graph with required scopes',
        "Connect-MgGraph -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All'",
        '',
      ].join('\n')
    : [
        '# Bulk Remediation — Graph REST API Calls',
        `# Generated: ${new Date().toISOString()}`,
        `# Actions: ${actions.length}`,
        '',
      ].join('\n');

  const blocks = actions.map((action, i) => {
    const script = action.scripts.find((s) => s.language === language);
    if (!script) return '';
    return [
      `# ── Action ${i + 1}/${actions.length}: ${action.title} ──`,
      script.code,
      '',
    ].join('\n');
  });

  return header + blocks.join('\n');
}
