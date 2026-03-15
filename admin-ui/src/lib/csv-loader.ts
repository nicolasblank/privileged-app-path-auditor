import Papa from 'papaparse';
import type { AuditData } from '../types/audit';

const CSV_FILE_MAP: Record<string, keyof AuditData> = {
  'AttackPaths.csv': 'attackPaths',
  'CredentialHygiene.csv': 'credentialHygiene',
  'PermissionAudit.csv': 'permissionAudit',
  'StalePrivilege.csv': 'stalePrivilege',
  'UnownedPrivilegedApps.csv': 'unownedApps',
  'RoleAudit.csv': 'roleAudit',
  'ConsentRisk.csv': 'consentRisk',
  'FullAuditSummary.csv': 'summary',
  'Summary.csv': 'spSummary',
  'UnknownOwnerApps.csv': 'unknownOwnerApps',
};

function parseCsv<T>(text: string): T[] {
  // Strip UTF-8 BOM if present (PowerShell default)
  const clean = text.replace(/^\uFEFF/, '');
  const result = Papa.parse<T>(clean, {
    header: true,
    skipEmptyLines: true,
    dynamicTyping: false, // keep as strings — we type-cast in the UI
  });
  return result.data;
}

export function emptyAuditData(): AuditData {
  return {
    attackPaths: [],
    credentialHygiene: [],
    permissionAudit: [],
    stalePrivilege: [],
    unownedApps: [],
    roleAudit: [],
    consentRisk: [],
    summary: [],
    spSummary: [],
    unknownOwnerApps: [],
  };
}

/**
 * Load audit CSVs from a dropped folder or file list.
 * Accepts a FileList (from <input>) or a DataTransferItemList (from drag-and-drop).
 */
export async function loadAuditFolder(items: FileList | DataTransferItemList): Promise<AuditData> {
  const data = emptyAuditData();
  const files: File[] = [];

  // Handle DataTransferItemList (drag-and-drop with folder support)
  if ('length' in items && items.length > 0 && 'webkitGetAsEntry' in (items[0] as DataTransferItem)) {
    const entries: FileSystemEntry[] = [];
    for (let i = 0; i < items.length; i++) {
      const entry = (items[i] as DataTransferItem).webkitGetAsEntry();
      if (entry) entries.push(entry);
    }
    // If a single directory was dropped, read its contents
    if (entries.length === 1 && entries[0].isDirectory) {
      const dirFiles = await readDirectory(entries[0] as FileSystemDirectoryEntry);
      files.push(...dirFiles);
    } else {
      // Individual files dropped
      for (const entry of entries) {
        if (entry.isFile) {
          const file = await entryToFile(entry as FileSystemFileEntry);
          files.push(file);
        }
      }
    }
  } else {
    // Plain FileList from <input>
    for (let i = 0; i < items.length; i++) {
      files.push((items as FileList)[i]);
    }
  }

  // Parse each recognized CSV
  await Promise.all(
    files
      .filter((f) => f.name.endsWith('.csv'))
      .map(async (file) => {
        const key = CSV_FILE_MAP[file.name];
        if (!key) return;
        const text = await file.text();
        const rows = parseCsv(text);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (data as any)[key] = rows;
      })
  );

  return data;
}

function readDirectory(dirEntry: FileSystemDirectoryEntry): Promise<File[]> {
  return new Promise((resolve) => {
    const reader = dirEntry.createReader();
    const allFiles: File[] = [];
    const readBatch = () => {
      reader.readEntries(async (entries) => {
        if (entries.length === 0) {
          resolve(allFiles);
          return;
        }
        for (const entry of entries) {
          if (entry.isFile && entry.name.endsWith('.csv')) {
            allFiles.push(await entryToFile(entry as FileSystemFileEntry));
          }
        }
        readBatch(); // directory reader returns in batches
      });
    };
    readBatch();
  });
}

function entryToFile(entry: FileSystemFileEntry): Promise<File> {
  return new Promise((resolve, reject) => {
    entry.file(resolve, reject);
  });
}
