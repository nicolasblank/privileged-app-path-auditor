import {
  Tab,
  TabList,
  CounterBadge,
} from '@fluentui/react-components';
import {
  Home24Regular,
  ShieldError24Regular,
  Key24Regular,
  LockClosed24Regular,
  CalendarClock24Regular,
  PersonQuestionMark24Regular,
  People24Regular,
  Warning24Regular,
} from '@fluentui/react-icons';
import type { AuditData } from '../types/audit';

export type ViewId =
  | 'dashboard'
  | 'attack-paths'
  | 'credentials'
  | 'permissions'
  | 'stale'
  | 'unowned'
  | 'roles'
  | 'consent';

interface NavigationProps {
  current: ViewId;
  onChange: (view: ViewId) => void;
  data: AuditData;
}

const NAV_ITEMS: { id: ViewId; label: string; icon: React.ReactElement; countKey?: keyof AuditData }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: <Home24Regular /> },
  { id: 'attack-paths', label: 'Attack Paths', icon: <ShieldError24Regular />, countKey: 'attackPaths' },
  { id: 'credentials', label: 'Credential Hygiene', icon: <Key24Regular />, countKey: 'credentialHygiene' },
  { id: 'permissions', label: 'Permissions', icon: <LockClosed24Regular />, countKey: 'permissionAudit' },
  { id: 'stale', label: 'Stale Privileges', icon: <CalendarClock24Regular />, countKey: 'stalePrivilege' },
  { id: 'unowned', label: 'Unowned Apps', icon: <PersonQuestionMark24Regular />, countKey: 'unownedApps' },
  { id: 'roles', label: 'Role Audit', icon: <People24Regular />, countKey: 'roleAudit' },
  { id: 'consent', label: 'Consent Risk', icon: <Warning24Regular />, countKey: 'consentRisk' },
];

export function Navigation({ current, onChange, data }: NavigationProps) {
  return (
    <nav className="app-nav">
      <div className="nav-brand">
        <h2>Privileged App<br />Path Auditor</h2>
        <p>Admin Console</p>
      </div>
      <TabList
        vertical
        selectedValue={current}
        onTabSelect={(_, d) => onChange(d.value as ViewId)}
        style={{ padding: '8px 12px' }}
      >
        {NAV_ITEMS.map(({ id, label, icon, countKey }) => {
          const count = countKey ? data[countKey].length : 0;
          return (
            <Tab key={id} value={id} icon={icon}>
              {label}
              {countKey && count > 0 && (
                <CounterBadge
                  count={count}
                  size="small"
                  color="informative"
                  style={{ marginLeft: 8 }}
                />
              )}
            </Tab>
          );
        })}
      </TabList>
    </nav>
  );
}
