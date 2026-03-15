import { useMemo } from 'react';
import {
  Card,
  Title2,
  Body1,
  MessageBar,
  MessageBarBody,
  MessageBarTitle,
  Badge,
} from '@fluentui/react-components';
import type { AuditData } from '../types/audit';

interface DashboardProps {
  data: AuditData;
  onNavigate: (view: string) => void;
}

interface StatCard {
  label: string;
  value: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  view?: string;
}

export function Dashboard({ data, onNavigate }: DashboardProps) {
  const stats = useMemo<StatCard[]>(() => {
    const criticalPaths = data.attackPaths.filter(
      (p) => p.Severity?.toLowerCase() === 'critical',
    ).length;
    const highPaths = data.attackPaths.filter(
      (p) => p.Severity?.toLowerCase() === 'high',
    ).length;
    const highRiskPerms = data.permissionAudit.filter(
      (p) => p.Risk?.toLowerCase() === 'high' || p.Risk?.toLowerCase() === 'critical',
    ).length;
    const expiredCreds = data.credentialHygiene.filter(
      (c) => parseInt(c.ExpiredCount, 10) > 0,
    ).length;
    const spDirectCreds = data.credentialHygiene.filter(
      (c) => c.SPDirectCreds?.toLowerCase() === 'true' || c.SPDirectCreds?.toLowerCase() === 'yes',
    ).length;
    const unlocked = data.credentialHygiene.filter(
      (c) => c.AppInstanceLock?.toLowerCase() === 'false' || c.AppInstanceLock?.toLowerCase() === 'no',
    ).length;

    return [
      { label: 'Critical Attack Paths', value: criticalPaths, severity: 'critical', view: 'attack-paths' },
      { label: 'High Attack Paths', value: highPaths, severity: 'high', view: 'attack-paths' },
      { label: 'High-Risk Permissions', value: highRiskPerms, severity: 'high', view: 'permissions' },
      { label: 'Apps with Expired Creds', value: expiredCreds, severity: 'medium', view: 'credentials' },
      { label: 'SP-Level Credentials', value: spDirectCreds, severity: 'high', view: 'credentials' },
      { label: 'No Instance Lock', value: unlocked, severity: 'medium', view: 'credentials' },
      { label: 'Stale Privileged Apps', value: data.stalePrivilege.length, severity: 'medium', view: 'stale' },
      { label: 'Unowned Privileged Apps', value: data.unownedApps.length, severity: 'high', view: 'unowned' },
      { label: 'Unique Attack Paths', value: data.attackPaths.length, severity: 'info', view: 'attack-paths' },
      { label: 'Total Role Assignments', value: data.roleAudit.length, severity: 'info', view: 'roles' },
    ];
  }, [data]);

  const criticalCount = stats.filter((s) => s.severity === 'critical' || s.severity === 'high').reduce((a, s) => a + s.value, 0);

  return (
    <div>
      <Title2>Security Dashboard</Title2>

      {criticalCount > 0 && (
        <MessageBar intent="error" style={{ marginTop: 16, marginBottom: 8 }}>
          <MessageBarBody>
            <MessageBarTitle>Action Required</MessageBarTitle>
            {criticalCount} critical/high-severity findings require immediate review.
          </MessageBarBody>
        </MessageBar>
      )}

      <div className="dashboard-grid mt-16">
        {stats.map((stat) => (
          <Card
            key={stat.label}
            className={`stat-card ${stat.severity}`}
            style={{ cursor: stat.view ? 'pointer' : undefined }}
            onClick={() => stat.view && onNavigate(stat.view)}
          >
            <div className="value">{stat.value}</div>
            <div className="label">{stat.label}</div>
          </Card>
        ))}
      </div>

      {/* Audit summary table */}
      {data.summary.length > 0 && (
        <div className="mt-24">
          <Title2>Audit Summary</Title2>
          <table className="data-table mt-8">
            <thead>
              <tr>
                <th>Section</th>
                <th>Finding</th>
                <th style={{ textAlign: 'right' }}>Count</th>
              </tr>
            </thead>
            <tbody>
              {data.summary.map((row, i) => (
                <tr key={i}>
                  <td><strong>{row.Section}</strong></td>
                  <td>{row.Finding}</td>
                  <td style={{ textAlign: 'right' }}>{row.Count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Consent risk */}
      {data.consentRisk.length > 0 && (
        <div className="mt-24">
          <Title2>Tenant Consent Settings</Title2>
          <table className="data-table mt-8">
            <thead>
              <tr>
                <th>Setting</th>
                <th>Value</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {data.consentRisk.map((row, i) => (
                <tr key={i}>
                  <td>{row.Setting}</td>
                  <td><code>{row.Value}</code></td>
                  <td>
                    <Badge
                      appearance="filled"
                      color={row.Risk?.toLowerCase() === 'high' ? 'danger' : row.Risk?.toLowerCase() === 'medium' ? 'warning' : 'success'}
                    >
                      {row.Risk}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* SP Summary */}
      {data.spSummary.length > 0 && (
        <div className="mt-24">
          <Title2>Service Principal Summary</Title2>
          <table className="data-table mt-8">
            <thead>
              <tr>
                <th>Category</th>
                <th style={{ textAlign: 'right' }}>Count</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {data.spSummary.map((row, i) => (
                <tr key={i}>
                  <td><strong>{row.Category}</strong></td>
                  <td style={{ textAlign: 'right' }}>{row.Count}</td>
                  <td>{row.Description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Body1
        style={{ display: 'block', marginTop: 32, color: 'var(--colorNeutralForeground3)' }}
      >
        All data is processed locally in your browser. No information is sent to any server.
      </Body1>
    </div>
  );
}
