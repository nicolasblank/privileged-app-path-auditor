/** Typed row shapes matching the PowerShell CSV exports */

export interface AttackPath {
  PathNumber: string;
  PathType: string;
  PathId: string;
  Severity: string;
  UserDisplayName: string;
  UserUPN: string;
  UserRole: string;
  AppName: string;
  AppId: string;
  Permission: string;
  PermissionType: string;
  Action: string;
  Result: string;
  SPDirectCreds: string;
  AppInstanceLock: string;
  Remediation: string;
  UserEntraUrl: string;
  AppEntraUrl: string;
}

export interface CredentialHygiene {
  AppName: string;
  AppId: string;
  Permission: string;
  CredType: string;
  CredCount: string;
  ExpiredCount: string;
  SPDirectCreds: string;
  AppInstanceLock: string;
  RiskLevel: string;
  EntraPortalUrl: string;
}

export interface PermissionAudit {
  SPId: string;
  SPDisplayName: string;
  AppId: string;
  Permission: string;
  PermissionType: string;
  Risk: string;
  Reason: string;
  AccountEnabled: string;
  EntraPortalUrl: string;
}

export interface StalePrivilege {
  AppName: string;
  AppId: string;
  Permission: string;
  LastSignIn: string;
  CredentialType: string;
  CredentialExpires: string;
  ValidCredCount: string;
  EntraPortalUrl: string;
}

export interface UnownedApp {
  AppName: string;
  AppId: string;
  Permissions: string;
  SPDirectCreds: string;
  AppInstanceLock: string;
  EntraUrl: string;
}

export interface RoleAudit {
  DisplayName: string;
  UPN: string;
  Roles: string;
  HasPrivilegedRole: string;
  EntraPortalUrl: string;
}

export interface ConsentRisk {
  Setting: string;
  Value: string;
  Risk: string;
}

export interface AuditSummary {
  Section: string;
  Finding: string;
  Count: string;
}

export interface SPSummary {
  Category: string;
  Count: string;
  Description: string;
}

export interface UnknownOwnerApp {
  DisplayName: string;
  AppId: string;
  ObjectId: string;
  Type: string;
  Enabled: string;
  EntraPortalUrl: string;
}

/** All loaded audit data */
export interface AuditData {
  attackPaths: AttackPath[];
  credentialHygiene: CredentialHygiene[];
  permissionAudit: PermissionAudit[];
  stalePrivilege: StalePrivilege[];
  unownedApps: UnownedApp[];
  roleAudit: RoleAudit[];
  consentRisk: ConsentRisk[];
  summary: AuditSummary[];
  spSummary: SPSummary[];
  unknownOwnerApps: UnknownOwnerApp[];
}

/** Remediation action to be generated as a script */
export interface RemediationAction {
  id: string;
  category: 'owner-removal' | 'permission-removal' | 'credential-rotation' | 'app-disable' | 'owner-assignment' | 'lock-enable';
  severity: 'info' | 'warning' | 'danger';
  title: string;
  description: string;
  appName: string;
  appId: string;
  /** Graph API calls or PowerShell commands to execute */
  scripts: ScriptBlock[];
}

export interface ScriptBlock {
  language: 'powershell' | 'http';
  label: string;
  code: string;
}
