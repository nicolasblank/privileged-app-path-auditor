import { useState } from 'react';
import { Title2, Button } from '@fluentui/react-components';
import { Wand24Regular } from '@fluentui/react-icons';
import type { UnownedApp } from '../types/audit';
import { SortableTable, ExportCsvButton } from '../components/SortableTable';
import { RiskBadge } from '../components/RiskBadge';
import { ScriptDialog } from '../components/ScriptDialog';
import { assignOwner, enableAppInstanceLock } from '../lib/remediation';
import type { RemediationAction } from '../types/audit';

interface UnownedAppsViewProps {
  data: UnownedApp[];
}

export function UnownedAppsView({ data }: UnownedAppsViewProps) {
  const [scriptOpen, setScriptOpen] = useState(false);
  const [scriptActions, setScriptActions] = useState<RemediationAction[]>([]);

  const handleBulkRemediate = () => {
    const actions: RemediationAction[] = [];
    for (const row of data) {
      actions.push(assignOwner(row.AppName, row.AppId, '<TARGET_UPN>', '<TARGET_OBJECT_ID>'));
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
    { key: 'AppId' as const, label: 'App ID', minWidth: 280 },
    { key: 'Permissions' as const, label: 'Permissions', minWidth: 250 },
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
  ];

  return (
    <div>
      <div className="view-header">
        <Title2>Unowned Privileged Apps</Title2>
        <div className="flex-row gap-8">
          <Button
            appearance="primary"
            icon={<Wand24Regular />}
            onClick={handleBulkRemediate}
            disabled={data.length === 0}
          >
            Assign Owners ({data.length})
          </Button>
          <ExportCsvButton data={data as unknown as Record<string, string>[]} filename="unowned-apps.csv" />
        </div>
      </div>

      <SortableTable
        data={data as unknown as Record<string, string>[]}
        columns={columns as any}
        getRowKey={(row) => (row as any).AppId}
        linkColumn="EntraUrl"
      />

      <ScriptDialog actions={scriptActions} open={scriptOpen} onClose={() => setScriptOpen(false)} />
    </div>
  );
}
