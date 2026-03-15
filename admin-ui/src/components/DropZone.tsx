import { useRef, useState, useCallback } from 'react';
import { Button, Subtitle1, Body1 } from '@fluentui/react-components';
import { FolderOpen24Regular, ArrowUpload24Regular } from '@fluentui/react-icons';
import type { AuditData } from '../types/audit';
import { loadAuditFolder } from '../lib/csv-loader';

interface DropZoneProps {
  onLoaded: (data: AuditData) => void;
}

export function DropZone({ onLoaded }: DropZoneProps) {
  const [dragover, setDragover] = useState(false);
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleLoad = useCallback(
    async (items: FileList | DataTransferItemList) => {
      setLoading(true);
      try {
        const data = await loadAuditFolder(items);
        onLoaded(data);
      } finally {
        setLoading(false);
      }
    },
    [onLoaded],
  );

  return (
    <div
      className={`drop-zone${dragover ? ' dragover' : ''}`}
      onDragOver={(e) => {
        e.preventDefault();
        setDragover(true);
      }}
      onDragLeave={() => setDragover(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragover(false);
        handleLoad(e.dataTransfer.items);
      }}
      onClick={() => inputRef.current?.click()}
    >
      <FolderOpen24Regular className="icon" />
      <Subtitle1>{loading ? 'Loading…' : 'Drop your audit folder here'}</Subtitle1>
      <Body1>
        Drag the CSV output folder from <code>Invoke-PrivilegedAudit.ps1</code>, or click to browse.
        All data stays in your browser — nothing is uploaded.
      </Body1>
      <Button
        appearance="primary"
        icon={<ArrowUpload24Regular />}
        style={{ marginTop: 24 }}
        disabled={loading}
      >
        Browse files
      </Button>
      <input
        ref={inputRef}
        type="file"
        accept=".csv"
        multiple
        hidden
        onChange={(e) => {
          if (e.target.files) handleLoad(e.target.files);
        }}
      />
    </div>
  );
}
