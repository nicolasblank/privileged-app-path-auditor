import { Title2 } from '@fluentui/react-components';
import type { RoleAudit } from '../types/audit';
import { SortableTable, ExportCsvButton } from '../components/SortableTable';
import { RiskBadge } from '../components/RiskBadge';

interface RoleAuditViewProps {
  data: RoleAudit[];
}

export function RoleAuditView({ data }: RoleAuditViewProps) {
  const columns = [
    {
      key: 'DisplayName' as const,
      label: 'Display Name',
      minWidth: 200,
      isLink: true,
    },
    { key: 'UPN' as const, label: 'UPN', minWidth: 250 },
    { key: 'Roles' as const, label: 'Roles', minWidth: 300 },
    {
      key: 'HasPrivilegedRole' as const,
      label: 'Privileged',
      minWidth: 90,
      render: (v: string) => <RiskBadge level={v} />,
    },
  ];

  return (
    <div>
      <div className="view-header">
        <Title2>Role Audit</Title2>
        <ExportCsvButton data={data as unknown as Record<string, string>[]} filename="role-audit.csv" />
      </div>

      <SortableTable
        data={data as unknown as Record<string, string>[]}
        columns={columns as any}
        getRowKey={(row) => (row as any).UPN || String(Math.random())}
        linkColumn="EntraPortalUrl"
      />
    </div>
  );
}
