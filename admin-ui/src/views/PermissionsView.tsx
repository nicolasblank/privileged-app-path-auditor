import { useState, useMemo } from 'react';
import { Title2, Button, ToggleButton } from '@fluentui/react-components';
import { Wand24Regular } from '@fluentui/react-icons';
import type { PermissionAudit } from '../types/audit';
import { SortableTable, ExportCsvButton } from '../components/SortableTable';
import { RiskBadge } from '../components/RiskBadge';
import { ScriptDialog } from '../components/ScriptDialog';
import { removeAppPermission } from '../lib/remediation';
import type { RemediationAction } from '../types/audit';

interface PermissionsViewProps {
  data: PermissionAudit[];
}

export function PermissionsView({ data }: PermissionsViewProps) {
  const [filter, setFilter] = useState<string | null>(null);
  const [scriptOpen, setScriptOpen] = useState(false);
  const [scriptActions, setScriptActions] = useState<RemediationAction[]>([]);

  const riskLevels = useMemo(() => {
    const counts = new Map<string, number>();
    data.forEach((row) => {
      const r = (row.Risk ?? 'Unknown').toLowerCase();
      counts.set(r, (counts.get(r) ?? 0) + 1);
    });
    return Array.from(counts.entries());
  }, [data]);

  const filtered = useMemo(
    () => (filter ? data.filter((r) => r.Risk?.toLowerCase() === filter) : data),
    [data, filter],
  );

  const handleBulkRemediate = () => {
    const riskFiltered = filtered.filter(
      (r) => r.Risk?.toLowerCase() === 'high' || r.Risk?.toLowerCase() === 'critical',
    );
    const actions: RemediationAction[] = riskFiltered.map((row) =>
      removeAppPermission(row.SPDisplayName, row.AppId, row.SPId, row.Permission, ''),
    );
    if (actions.length > 0) {
      setScriptActions(actions);
      setScriptOpen(true);
    }
  };

  const columns = [
    {
      key: 'SPDisplayName' as const,
      label: 'Service Principal',
      minWidth: 200,
      isLink: true,
    },
    { key: 'Permission' as const, label: 'Permission', minWidth: 200 },
    { key: 'PermissionType' as const, label: 'Type', minWidth: 100 },
    {
      key: 'Risk' as const,
      label: 'Risk',
      minWidth: 80,
      render: (v: string) => <RiskBadge level={v} />,
    },
    { key: 'Reason' as const, label: 'Reason', minWidth: 200 },
    {
      key: 'AccountEnabled' as const,
      label: 'Enabled',
      minWidth: 80,
      render: (v: string) => <RiskBadge level={v} />,
    },
  ];

  return (
    <div>
      <div className="view-header">
        <Title2>Permission Audit</Title2>
        <div className="flex-row gap-8">
          <Button
            appearance="primary"
            icon={<Wand24Regular />}
            onClick={handleBulkRemediate}
            disabled={filtered.filter((r) => r.Risk?.toLowerCase() === 'high' || r.Risk?.toLowerCase() === 'critical').length === 0}
          >
            Remove High-Risk Permissions
          </Button>
          <ExportCsvButton data={filtered as unknown as Record<string, string>[]} filename="permissions-filtered.csv" />
        </div>
      </div>

      <div className="filter-bar">
        <ToggleButton checked={filter === null} onClick={() => setFilter(null)} size="small">
          All ({data.length})
        </ToggleButton>
        {riskLevels.map(([level, count]) => (
          <ToggleButton
            key={level}
            checked={filter === level}
            onClick={() => setFilter(filter === level ? null : level)}
            size="small"
          >
            {level.charAt(0).toUpperCase() + level.slice(1)} ({count})
          </ToggleButton>
        ))}
      </div>

      <SortableTable
        data={filtered as unknown as Record<string, string>[]}
        columns={columns as any}
        getRowKey={(row) => `${(row as any).SPId}-${(row as any).Permission}`}
        linkColumn="EntraPortalUrl"
      />

      <ScriptDialog actions={scriptActions} open={scriptOpen} onClose={() => setScriptOpen(false)} />
    </div>
  );
}
