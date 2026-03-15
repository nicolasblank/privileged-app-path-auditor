import { useState, useCallback } from 'react';
import {
  Subtitle1,
  Button,
  Tooltip,
} from '@fluentui/react-components';
import { ArrowReset24Regular } from '@fluentui/react-icons';
import './styles.css';
import type { AuditData } from './types/audit';

import { DropZone } from './components/DropZone';
import { Navigation, type ViewId } from './components/Navigation';
import { Dashboard } from './views/Dashboard';
import { AttackPathsView } from './views/AttackPathsView';
import { CredentialHygieneView } from './views/CredentialHygieneView';
import { PermissionsView } from './views/PermissionsView';
import { StalePrivilegeView } from './views/StalePrivilegeView';
import { UnownedAppsView } from './views/UnownedAppsView';
import { RoleAuditView } from './views/RoleAuditView';

function App() {
  const [data, setData] = useState<AuditData | null>(null);
  const [view, setView] = useState<ViewId>('dashboard');

  const handleLoaded = useCallback((loaded: AuditData) => {
    setData(loaded);
    setView('dashboard');
  }, []);

  const handleReset = useCallback(() => {
    setData(null);
    setView('dashboard');
  }, []);

  // Before data is loaded — show the drop zone
  if (!data) {
    return (
      <div style={{ height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
        <DropZone onLoaded={handleLoaded} />
      </div>
    );
  }

  const renderView = () => {
    switch (view) {
      case 'dashboard':
        return <Dashboard data={data} onNavigate={(v) => setView(v as ViewId)} />;
      case 'attack-paths':
        return <AttackPathsView data={data.attackPaths} />;
      case 'credentials':
        return <CredentialHygieneView data={data.credentialHygiene} />;
      case 'permissions':
        return <PermissionsView data={data.permissionAudit} />;
      case 'stale':
        return <StalePrivilegeView data={data.stalePrivilege} />;
      case 'unowned':
        return <UnownedAppsView data={data.unownedApps} />;
      case 'roles':
        return <RoleAuditView data={data.roleAudit} />;
      case 'consent':
        return <Dashboard data={data} onNavigate={(v) => setView(v as ViewId)} />;
      default:
        return <Dashboard data={data} onNavigate={(v) => setView(v as ViewId)} />;
    }
  };

  return (
    <div className="app-shell">
      <Navigation current={view} onChange={setView} data={data} />
      <header className="app-header">
        <Subtitle1>
          {view === 'dashboard' && 'Security Dashboard'}
          {view === 'attack-paths' && 'Attack Paths'}
          {view === 'credentials' && 'Credential Hygiene'}
          {view === 'permissions' && 'Permission Audit'}
          {view === 'stale' && 'Stale Privileges'}
          {view === 'unowned' && 'Unowned Apps'}
          {view === 'roles' && 'Role Audit'}
          {view === 'consent' && 'Consent Risk'}
        </Subtitle1>
        <div className="flex-row gap-8">
          <Tooltip content="Load different audit data" relationship="label">
            <Button
              appearance="subtle"
              icon={<ArrowReset24Regular />}
              onClick={handleReset}
            >
              New Audit
            </Button>
          </Tooltip>
        </div>
      </header>
      <main className="app-main">
        {renderView()}
      </main>
    </div>
  );
}

export default App;
