import { useState } from 'react';
import { Title2, Button } from '@fluentui/react-components';
import { Wand24Regular } from '@fluentui/react-icons';
import type { StalePrivilege } from '../types/audit';
import { SortableTable, ExportCsvButton } from '../components/SortableTable';
import { RiskBadge } from '../components/RiskBadge';
import { ScriptDialog } from '../components/ScriptDialog';
import { disableApp } from '../lib/remediation';
import type { RemediationAction } from '../types/audit';

interface StalePrivilegeViewProps {
  data: StalePrivilege[];
}

export function StalePrivilegeView({ data }: StalePrivilegeViewProps) {
  const [scriptOpen, setScriptOpen] = useState(false);
  const [scriptActions, setScriptActions] = useState<RemediationAction[]>([]);

  const handleBulkRemediate = () => {
    const actions: RemediationAction[] = [];
    for (const row of data) {
      actions.push(disableApp(row.AppName, row.AppId, ''));
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
    { key: 'Permission' as const, label: 'Permission', minWidth: 200 },
    {
      key: 'LastSignIn' as const,
      label: 'Last Sign-In',
      minWidth: 140,
      render: (v: string) => {
        if (!v || v === 'Never') {
          return <RiskBadge level="Never" />;
        }
        return <>{v}</>;
      },
    },
    { key: 'CredentialType' as const, label: 'Cred Type', minWidth: 100 },
    { key: 'CredentialExpires' as const, label: 'Cred Expires', minWidth: 130 },
    {
      key: 'ValidCredCount' as const,
      label: 'Valid Creds',
      minWidth: 90,
      render: (v: string) => {
        const n = parseInt(v, 10);
        return n > 0 ? <RiskBadge level="Yes" /> : <>{v}</>;
      },
    },
  ];

  return (
    <div>
      <div className="view-header">
        <Title2>Stale Privileged Apps</Title2>
        <div className="flex-row gap-8">
          <Button
            appearance="primary"
            icon={<Wand24Regular />}
            onClick={handleBulkRemediate}
            disabled={data.length === 0}
          >
            Disable All Stale Apps ({data.length})
          </Button>
          <ExportCsvButton data={data as unknown as Record<string, string>[]} filename="stale-privilege.csv" />
        </div>
      </div>

      <SortableTable
        data={data as unknown as Record<string, string>[]}
        columns={columns as any}
        getRowKey={(row) => (row as any).AppId}
        linkColumn="EntraPortalUrl"
      />

      <ScriptDialog actions={scriptActions} open={scriptOpen} onClose={() => setScriptOpen(false)} />
    </div>
  );
}
