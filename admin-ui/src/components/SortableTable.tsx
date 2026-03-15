import { useState, useMemo, useCallback } from 'react';
import { Input, Button } from '@fluentui/react-components';
import { Search24Regular, ArrowDown24Regular, ArrowUp24Regular } from '@fluentui/react-icons';

interface Column<T> {
  key: keyof T & string;
  label: string;
  minWidth?: number;
  render?: (value: string, row: T) => React.ReactNode;
  /** If true, cell content links to EntraPortalUrl / EntraUrl / AppEntraUrl */
  isLink?: boolean;
}

interface SortableTableProps<T> {
  data: T[];
  columns: Column<T>[];
  getRowKey: (row: T, index: number) => string;
  /** Link column key for Entra portal URLs */
  linkColumn?: keyof T & string;
  onRowClick?: (row: T) => void;
}

export function SortableTable<T extends Record<string, string>>({
  data,
  columns,
  getRowKey,
  linkColumn,
  onRowClick,
}: SortableTableProps<T>) {
  const [sortCol, setSortCol] = useState<string | null>(null);
  const [sortAsc, setSortAsc] = useState(true);
  const [search, setSearch] = useState('');

  const filtered = useMemo(() => {
    if (!search) return data;
    const q = search.toLowerCase();
    return data.filter((row) =>
      columns.some((col) => String(row[col.key]).toLowerCase().includes(q)),
    );
  }, [data, search, columns]);

  const sorted = useMemo(() => {
    if (!sortCol) return filtered;
    return [...filtered].sort((a, b) => {
      const va = String(a[sortCol as keyof T]).toLowerCase();
      const vb = String(b[sortCol as keyof T]).toLowerCase();
      const cmp = va.localeCompare(vb, undefined, { numeric: true });
      return sortAsc ? cmp : -cmp;
    });
  }, [filtered, sortCol, sortAsc]);

  const handleSort = useCallback(
    (col: string) => {
      if (sortCol === col) {
        setSortAsc((p) => !p);
      } else {
        setSortCol(col);
        setSortAsc(true);
      }
    },
    [sortCol],
  );

  return (
    <>
      <div className="view-toolbar mb-16">
        <Input
          placeholder="Search…"
          contentBefore={<Search24Regular />}
          value={search}
          onChange={(_, d) => setSearch(d.value)}
          style={{ width: 280 }}
        />
        <span style={{ color: 'var(--colorNeutralForeground3)', fontSize: 13 }}>
          {sorted.length} of {data.length} items
        </span>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              {columns.map((col) => (
                <th
                  key={col.key}
                  onClick={() => handleSort(col.key)}
                  style={col.minWidth ? { minWidth: col.minWidth } : undefined}
                >
                  {col.label}
                  {sortCol === col.key && (
                    <span className="sort-indicator">
                      {sortAsc ? <ArrowUp24Regular /> : <ArrowDown24Regular />}
                    </span>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map((row, i) => (
              <tr
                key={getRowKey(row, i)}
                onClick={() => onRowClick?.(row)}
                style={onRowClick ? { cursor: 'pointer' } : undefined}
              >
                {columns.map((col) => {
                  const value = String(row[col.key] ?? '');
                  const linkUrl =
                    col.isLink && linkColumn ? String(row[linkColumn]) : undefined;

                  if (col.render) {
                    return <td key={col.key}>{col.render(value, row)}</td>;
                  }

                  if (linkUrl && value) {
                    return (
                      <td key={col.key} className="cell-link">
                        <a
                          href={linkUrl}
                          target="_blank"
                          rel="noreferrer noopener"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {value}
                        </a>
                      </td>
                    );
                  }

                  return (
                    <td key={col.key} className="cell-truncate" title={value}>
                      {value}
                    </td>
                  );
                })}
              </tr>
            ))}
            {sorted.length === 0 && (
              <tr>
                <td
                  colSpan={columns.length}
                  style={{ textAlign: 'center', padding: 32, color: 'var(--colorNeutralForeground3)' }}
                >
                  {data.length === 0 ? 'No data loaded' : 'No items match your search'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

/** Export button: download current view as CSV */
export function ExportCsvButton({ data, filename }: { data: Record<string, string>[]; filename: string }) {
  const handleExport = useCallback(() => {
    if (data.length === 0) return;
    const headers = Object.keys(data[0]);
    const csvContent = [
      headers.join(','),
      ...data.map((row) =>
        headers.map((h) => `"${String(row[h] ?? '').replace(/"/g, '""')}"`).join(','),
      ),
    ].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  }, [data, filename]);

  return (
    <Button appearance="subtle" size="small" onClick={handleExport}>
      Export CSV
    </Button>
  );
}
