import { useState, useMemo, useCallback, type ReactNode } from 'react';
import {
  Dialog,
  DialogSurface,
  DialogTitle,
  DialogBody,
  DialogContent,
  DialogActions,
  Button,
  TabList,
  Tab,
  MessageBar,
  MessageBarBody,
  MessageBarTitle,
} from '@fluentui/react-components';
import { Copy24Regular, Dismiss24Regular } from '@fluentui/react-icons';
import type { RemediationAction } from '../types/audit';
import { buildBulkScript } from '../lib/remediation';

interface ScriptDialogProps {
  actions: RemediationAction[];
  open: boolean;
  onClose: () => void;
}

export function ScriptDialog({ actions, open, onClose }: ScriptDialogProps) {
  const [tab, setTab] = useState<'powershell' | 'http'>('powershell');
  const [copied, setCopied] = useState(false);

  const script = useMemo(() => buildBulkScript(actions, tab), [actions, tab]);

  const handleCopy = useCallback(async () => {
    await navigator.clipboard.writeText(script);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [script]);

  const hasDanger = actions.some((a) => a.severity === 'danger');

  return (
    <Dialog open={open} onOpenChange={(_, d) => { if (!d.open) onClose(); }}>
      <DialogSurface style={{ maxWidth: 720, width: '90vw' }}>
        <DialogTitle
          action={<Button appearance="subtle" icon={<Dismiss24Regular />} onClick={onClose} />}
        >
          Generated Remediation Script ({actions.length} action{actions.length !== 1 ? 's' : ''})
        </DialogTitle>
        <DialogBody>
          <DialogContent>
            {hasDanger && (
              <MessageBar intent="error" style={{ marginBottom: 12 }}>
                <MessageBarBody>
                  <MessageBarTitle>Destructive Actions</MessageBarTitle>
                  This script contains actions that immediately revoke permissions or disable applications.
                  Review each action carefully before executing.
                </MessageBarBody>
              </MessageBar>
            )}

            <TabList
              selectedValue={tab}
              onTabSelect={(_, d) => setTab(d.value as 'powershell' | 'http')}
              style={{ marginBottom: 8 }}
            >
              <Tab value="powershell">PowerShell</Tab>
              <Tab value="http">Graph REST API</Tab>
            </TabList>

            <div className="script-block">
              <Button
                className="copy-btn"
                appearance="subtle"
                size="small"
                icon={<Copy24Regular />}
                onClick={handleCopy}
              >
                {copied ? 'Copied!' : 'Copy'}
              </Button>
              <pre>{script}</pre>
            </div>
          </DialogContent>
          <DialogActions>
            <Button appearance="secondary" onClick={onClose}>Close</Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}

/** Convenience wrapper to show a single action */
export function SingleScriptDialog({
  action,
  open,
  onClose,
}: {
  action: RemediationAction | null;
  open: boolean;
  onClose: () => void;
}) {
  if (!action) return null;
  return <ScriptDialog actions={[action]} open={open} onClose={onClose} />;
}

/** Action button that opens the script dialog */
export function RemediateButton({
  children,
  actions,
  appearance = 'subtle',
  icon,
}: {
  children: ReactNode;
  actions: RemediationAction[];
  appearance?: 'primary' | 'subtle' | 'outline';
  icon?: React.ReactElement;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button appearance={appearance} size="small" icon={icon} onClick={() => setOpen(true)}>
        {children}
      </Button>
      <ScriptDialog actions={actions} open={open} onClose={() => setOpen(false)} />
    </>
  );
}
