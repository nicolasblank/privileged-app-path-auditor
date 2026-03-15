import { useState, useMemo } from 'react';
import { Title2, Button, ToggleButton } from '@fluentui/react-components';
import { Wand24Regular } from '@fluentui/react-icons';
import type { CredentialHygiene } from '../types/audit';
import { SortableTable, ExportCsvButton } from '../components/SortableTable';
import { RiskBadge } from '../components/RiskBadge';
import { ScriptDialog } from '../components/ScriptDialog';
import { rotateCredentials, enableAppInstanceLock } from '../lib/remediation';
import type { RemediationAction } from '../types/audit';

interface CredentialHygieneViewProps {
  data: CredentialHygiene[];
}

export function CredentialHygieneView({ data }: CredentialHygieneViewProps) {
  const [filter, setFilter] = useState<string | null>(null);
  const [scriptOpen, setScriptOpen] = useState(false);
  const [scriptActions, setScriptActions] = useState<RemediationAction[]>([]);

  const riskLevels = useMemo(() => {
    const counts = new Map<string, number>();
    data.forEach((row) => {
      const r = (row.RiskLevel ?? 'Unknown').toLowerCase();
      counts.set(r, (counts.get(r) ?? 0) + 1);
    });
    return Array.from(counts.entries());
  }, [data]);

  const filtered = useMemo(
    () => (filter ? data.filter((r) => r.RiskLevel?.toLowerCase() === filter) : data),
    [data, filter],
  );

  const handleBulkRemediate = () => {
    const actions: RemediationAction[] = [];
    for (const row of filtered) {
      actions.push(rotateCredentials(row.AppName, row.AppId, ''));
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
    {
      key: 'AppName' as const,
      label: 'Application',
      minWidth: 200,
      isLink: true,
    },
    { key: 'Permission' as const, label: 'Permission', minWidth: 180 },
    { key: 'CredType' as const, label: 'Cred Type', minWidth: 100 },
    { key: 'CredCount' as const, label: 'Creds', minWidth: 60 },
    { key: 'ExpiredCount' as const, label: 'Expired', minWidth: 70 },
    {
      key: 'SPDirectCreds' as const,
      label: 'SP Creds',
      minWidth: 80,
      render: (v: string) => <RiskBadge level={v} />,
    },
    {
      key: 'AppInstanceLock' as const,
      label: 'Instance Lock',
      minWidth: 100,
      render: (v: string) => <RiskBadge level={v} />,
    },
    {
      key: 'RiskLevel' as const,
      label: 'Risk',
      minWidth: 80,
      render: (v: string) => <RiskBadge level={v} />,
    },
  ];

  return (
    <div>
      <div className="view-header">
        <Title2>Credential Hygiene</Title2>
        <div className="flex-row gap-8">
          <Button
            appearance="primary"
            icon={<Wand24Regular />}
            onClick={handleBulkRemediate}
            disabled={filtered.length === 0}
          >
            Generate Rotation Script ({filtered.length})
          </Button>
          <ExportCsvButton data={filtered as unknown as Record<string, string>[]} filename="credential-hygiene-filtered.csv" />
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
        getRowKey={(row) => (row as any).AppId}
        linkColumn="EntraPortalUrl"
      />

      <ScriptDialog actions={scriptActions} open={scriptOpen} onClose={() => setScriptOpen(false)} />
    </div>
  );
}
