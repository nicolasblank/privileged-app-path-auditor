# Admin UI — Development Pattern

> **Reusable pattern:** Vite + React + TypeScript + Fluent UI v9 for premium cross-platform admin interfaces that consume CSV/JSON data. Zero-server, runs in any browser, deployable to Azure Static Web Apps.

---

## Stack

| Layer | Technology | Why |
|---|---|---|
| Bundler | [Vite](https://vite.dev) (react-ts template) | Sub-second HMR, zero-config TypeScript, < 3s production builds |
| UI Framework | [React 18+](https://react.dev) | Component model, hooks, ecosystem |
| Design System | [@fluentui/react-components](https://react.fluentui.dev) (v9) | Microsoft-native look, accessible, themeable |
| Icons | @fluentui/react-icons | Tree-shakeable, matches Fluent UI |
| CSV Parsing | [PapaParse](https://www.papaparse.com) | Streaming, BOM-aware, handles PowerShell UTF-8+BOM output |
| Language | TypeScript (strict) | Type safety across CSV schemas |

## Directory Structure

```
admin-ui/
├── public/                   # Static assets (favicon, etc.)
├── src/
│   ├── components/           # Reusable UI components
│   │   ├── DropZone.tsx      # Drag-and-drop file/folder loader
│   │   ├── Navigation.tsx    # Left nav with TabList + CounterBadge
│   │   ├── RiskBadge.tsx     # Severity/risk level badge
│   │   ├── ScriptDialog.tsx  # Remediation script preview dialog
│   │   └── SortableTable.tsx # Generic sortable/filterable data table
│   ├── lib/                  # Business logic (no UI dependencies)
│   │   ├── csv-loader.ts     # PapaParse CSV loading + folder support
│   │   └── remediation.ts    # Graph API / PowerShell script generator
│   ├── types/
│   │   └── audit.ts          # TypeScript interfaces for all CSV schemas
│   ├── views/                # Feature views (one per data domain)
│   │   ├── Dashboard.tsx
│   │   ├── AttackPathsView.tsx
│   │   ├── CredentialHygieneView.tsx
│   │   ├── PermissionsView.tsx
│   │   ├── StalePrivilegeView.tsx
│   │   ├── UnownedAppsView.tsx
│   │   └── RoleAuditView.tsx
│   ├── App.tsx               # Root component with view routing
│   ├── main.tsx              # Entry point with FluentProvider
│   └── styles.css            # Global CSS (CSS variables from Fluent)
├── index.html
├── package.json
├── tsconfig.json
└── vite.config.ts
```

## Key Patterns

### 1. FluentProvider Wrapping

All components must render inside `<FluentProvider theme={webLightTheme}>`. This is set up in `main.tsx`. The provider injects CSS variables (`--colorBrandForeground1`, `--colorNeutralBackground1`, etc.) used throughout `styles.css`.

### 2. CSS Variables from Fluent UI

Instead of importing Fluent tokens into every component, use CSS variables directly:

```css
.my-element {
  color: var(--colorNeutralForeground1);
  background: var(--colorNeutralBackground2);
  border: 1px solid var(--colorNeutralStroke1);
}
```

This keeps styles in CSS rather than inline JS.

### 3. Typed CSV Schema Pattern

Define a TypeScript interface per CSV file, then aggregate into a single `AuditData` interface:

```typescript
export interface MyDataRow {
  Column1: string;
  Column2: string;
}

export interface AuditData {
  myData: MyDataRow[];
  // ... more arrays
}
```

PapaParse parses with `header: true, dynamicTyping: false` — everything stays as strings for consistency.

### 4. Remediation Script Generation

Scripts are **generated, never auto-executed**. The `lib/remediation.ts` module returns `RemediationAction` objects with `ScriptBlock` arrays containing both PowerShell and Graph REST API versions. The `ScriptDialog` component renders these with copy-to-clipboard.

### 5. SortableTable Component

Generic `<SortableTable<T>>` accepts typed data + column definitions. Supports:
- Full-text search across visible columns
- Click-to-sort with ascending/descending toggle
- Custom cell renderers (badges, links)
- Export-to-CSV for filtered results

### 6. Drop Zone File Loading

The `DropZone` component handles both:
- `<input type="file" multiple>` (file picker)
- Drag-and-drop with folder support via `webkitGetAsEntry()`

Files are matched by name against `CSV_FILE_MAP` in `csv-loader.ts`.

## Commands

```bash
# Development with hot reload
npm run dev

# Production build → dist/
npm run build

# Preview production build locally
npm run preview
```

## Deployment Path: Azure Static Web Apps

The `dist/` output is a static site that can deploy directly to Azure Static Web Apps:

1. `npm run build` → produces `dist/` with `index.html` + JS/CSS bundles
2. Deploy with Azure CLI: `az staticwebapp create --app-location admin-ui --output-location dist`
3. Or connect to GitHub for CI/CD auto-deployment

For authenticated mode (live Graph API calls instead of CSV import):
- Add `@azure/msal-browser` for MSAL authentication
- Configure app registration in Entra ID
- Replace CSV loading with live Graph API calls

## Applying This Pattern to Other Projects

1. `npm create vite@latest my-admin-ui -- --template react-ts`
2. `cd my-admin-ui && npm install @fluentui/react-components @fluentui/react-icons papaparse @types/papaparse`
3. Copy the `src/` structure above
4. Define your data types in `types/`
5. Map your input files in `lib/csv-loader.ts`
6. Build views with `SortableTable` + Fluent UI components
7. Wire views into `App.tsx` with `Navigation` component
