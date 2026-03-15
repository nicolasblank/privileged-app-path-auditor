import { useState, useMemo } from 'react';
import { Title2, Button, Badge, ToggleButton } from '@fluentui/react-components';
import { Wand24Regular } from '@fluentui/react-icons';
import type { AttackPath } from '../types/audit';
import { SortableTable, ExportCsvButton } from '../components/SortableTable';
import { RiskBadge } from '../components/RiskBadge';
import { ScriptDialog } from '../components/ScriptDialog';
import { removeOwner, removeAppPermission, enableAppInstanceLock } from '../lib/remediation';
import type { RemediationAction } from '../types/audit';

interface AttackPathsViewProps {
  data: AttackPath[];
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function AttackPathsView({ data }: AttackPathsViewProps) {
  const [filter, setFilter] = useState<string | null>(null);

  const [scriptOpen, setScriptOpen] = useState(false);
  const [scriptActions, setScriptActions] = useState<RemediationAction[]>([]);

  const severities = useMemo(() => {
    const counts = new Map<string, number>();
    data.forEach((row) => {
      const s = (row.Severity ?? 'Unknown').toLowerCase();
      counts.set(s, (counts.get(s) ?? 0) + 1);
    });
    return Array.from(counts.entries())
      .sort((a, b) => (SEVERITY_ORDER[a[0]] ?? 99) - (SEVERITY_ORDER[b[0]] ?? 99));
  }, [data]);

  const filtered = useMemo(
    () => (filter ? data.filter((r) => r.Severity?.toLowerCase() === filter) : data),
    [data, filter],
  );

  const handleBulkRemediate = () => {
    const rows = filtered;
    const actions: RemediationAction[] = [];

    for (const row of rows) {
      if (row.Remediation?.toLowerCase().includes('remove owner')) {
        actions.push(removeOwner(row.AppName, row.AppId, row.UserUPN, ''));
      }
      if (row.Remediation?.toLowerCase().includes('remove permission')) {
        actions.push(removeAppPermission(row.AppName, row.AppId, '', row.Permission, ''));
      }
      if (row.AppInstanceLock?.toLowerCase() === 'false' || row.AppInstanceLock?.toLowerCase() === 'no') {
        actions.push(enableAppInstanceLock(row.AppName, row.AppId));
      }
    }

    if (actions.length > 0) {
      setScriptActions(actions);
      setScriptOpen(true);
    }
  };

  const columns = [
    { key: 'PathNumber' as const, label: '#', minWidth: 40 },
    {
      key: 'Severity' as const,
      label: 'Severity',
      minWidth: 90,
      render: (v: string) => <RiskBadge level={v} />,
    },
    { key: 'PathType' as const, label: 'Path Type', minWidth: 120 },
    { key: 'UserDisplayName' as const, label: 'User', minWidth: 150 },
    { key: 'UserRole' as const, label: 'Role', minWidth: 130 },
    {
      key: 'AppName' as const,
      label: 'Application',
      minWidth: 180,
      isLink: true,
    },
    { key: 'Permission' as const, label: 'Permission', minWidth: 180 },
    {
      key: 'SPDirectCreds' as const,
      label: 'SP Creds',
      minWidth: 80,
      render: (v: string) => <RiskBadge level={v} />,
    },
    {
      key: 'AppInstanceLock' as const,
      label: 'Lock',
      minWidth: 70,
      render: (v: string) => (
        <Badge
          appearance="filled"
          color={v?.toLowerCase() === 'true' || v?.toLowerCase() === 'yes' ? 'success' : 'warning'}
        >
          {v}
        </Badge>
      ),
    },
    { key: 'Remediation' as const, label: 'Remediation', minWidth: 200 },
  ];

  return (
    <div>
      <div className="view-header">
        <Title2>Attack Paths</Title2>
        <div className="flex-row gap-8">
          <Button
            appearance="primary"
            icon={<Wand24Regular />}
            onClick={handleBulkRemediate}
            disabled={filtered.length === 0}
          >
            Generate Fix Script ({filtered.length})
          </Button>
          <ExportCsvButton data={filtered as unknown as Record<string, string>[]} filename="attack-paths-filtered.csv" />
        </div>
      </div>

      <div className="filter-bar">
        <ToggleButton
          checked={filter === null}
          onClick={() => setFilter(null)}
          size="small"
        >
          All ({data.length})
        </ToggleButton>
        {severities.map(([sev, count]) => (
          <ToggleButton
            key={sev}
            checked={filter === sev}
            onClick={() => setFilter(filter === sev ? null : sev)}
            size="small"
          >
            {sev.charAt(0).toUpperCase() + sev.slice(1)} ({count})
          </ToggleButton>
        ))}
      </div>

      <SortableTable
        data={filtered as unknown as Record<string, string>[]}
        columns={columns as any}
        getRowKey={(_, i) => String(i)}
        linkColumn="AppEntraUrl"
      />

      <ScriptDialog actions={scriptActions} open={scriptOpen} onClose={() => setScriptOpen(false)} />
    </div>
  );
}
