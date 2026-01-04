# Phase 1: UI Implementation

[← README](README.md) | [Architecture](00-architecture.md)

## Goal

Implement the credentials management UI in the dashboard, including tab navigation, import form, credentials table, and revoke functionality. Also clean up the transport/auth setup.

## Prerequisites

- CredentialService RPC working on server
- Existing dashboard at `ui/pages/dashboard.tsx`
- Generated TypeScript clients in `api/gen/proto/es/principal/v1/`

## Success Criteria

- [ ] Transport uses `window.location.origin` instead of hardcoded URL
- [ ] Transport includes `credentials: 'include'` for session cookies
- [ ] Tab navigation between Jobs and Credentials
- [ ] Credentials list displays all credentials
- [ ] Import form submits to ImportCredential RPC
- [ ] Inline success message with IDs and CLI command
- [ ] Revoke button with confirmation
- [ ] Error states for all operations

---

## Step 1: Fix Transport Configuration

The current transport has two issues:
1. Hardcoded URL `https://localhost:8993`
2. Missing `credentials: 'include'` for session cookie support

### 1a. Update createAuthTransport

**File:** `ui/lib/createAuthTransport.ts`

```tsx
import { createConnectTransport } from "@connectrpc/connect-web";
import type { Transport } from "@connectrpc/connect";

/**
 * Create a Connect RPC transport with session cookie support.
 * Uses credentials: 'include' to send session cookie automatically.
 * JWT token is optional - dual auth middleware supports both.
 */
export function createAuthTransport(
  baseUrl: string,
  token: string | null,
): Transport {
  return createConnectTransport({
    baseUrl,
    credentials: "include",  // ADD THIS - sends session cookie
    interceptors: [
      (next) => async (req) => {
        // Inject token if available (optional, session cookie works too)
        if (token) {
          req.header.set("Authorization", `Bearer ${token}`);
        }
        return next(req);
      },
    ],
  });
}
```

### 1b. Fix Hardcoded URL in Dashboard

**File:** `ui/pages/dashboard.tsx`

**Location:** Line 637 in `AppWithToken` component

```tsx
// Before (broken)
const transport = useMemo(
  () => createAuthTransport("https://localhost:8993", token),
  [token],
);

// After (works everywhere)
const transport = useMemo(
  () => createAuthTransport(window.location.origin, token),
  [token],
);
```

### 1c. (Optional) Simplify Token Usage

The JWT token fetch is now optional since the session cookie works. For a minimal change, keep `useToken()` as-is. For a cleaner approach, you could simplify `AppWithToken` to not require a token:

```tsx
// Simplified - no token needed, session cookie is sufficient
function AppWithToken() {
  const user = usePageContext();

  const transport = useMemo(
    () => createAuthTransport(window.location.origin, null),
    [],
  );

  return (
    <TransportProvider transport={transport}>
      <QueryClientProvider client={queryClient}>
        <Dashboard />
      </QueryClientProvider>
    </TransportProvider>
  );
}
```

**Note:** If you remove token usage, you can also delete `ui/lib/token.ts` and `ui/lib/useToken.ts` in a future cleanup.

---

## Step 2: Add Imports

**File:** `ui/pages/dashboard.tsx`

Add at the top with other imports:

```tsx
import {
  listCredentials,
  importCredential,
  revokeCredential,
} from "../../api/gen/proto/es/principal/v1/principal-CredentialService_connectquery";
import { useMutation } from "@connectrpc/connect-query";
import type { Credential } from "../../api/gen/proto/es/principal/v1/principal_pb";
```

---

## Step 3: Add Tab State to Dashboard

**File:** `ui/pages/dashboard.tsx`

In the `Dashboard` component, add tab state:

```tsx
function Dashboard() {
  const { data } = useQuery(listJobs, {});
  const user = usePageContext();
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"jobs" | "credentials">("jobs");  // ADD THIS
```

---

## Step 4: Update Hash Routing

**File:** `ui/pages/dashboard.tsx`

Replace the `handleHashChange` function:

```tsx
useEffect(() => {
  const handleHashChange = () => {
    const hash = window.location.hash;
    if (hash === "#credentials") {
      setActiveTab("credentials");
      setSelectedJobId(null);
    } else if (hash.startsWith("#job-")) {
      setActiveTab("jobs");
      setSelectedJobId(hash.substring(5));
    } else {
      setActiveTab("jobs");
      setSelectedJobId(null);
    }
  };

  handleHashChange();
  window.addEventListener("hashchange", handleHashChange);
  return () => window.removeEventListener("hashchange", handleHashChange);
}, []);
```

---

## Step 5: Add Tab Navigation to Topbar

**File:** `ui/pages/dashboard.tsx`

Update the topbar-left div:

```tsx
<div className="topbar-left">
  <h1 className="topbar-title">airunner</h1>
  <nav className="topbar-tabs">
    <a
      href="#"
      className={activeTab === "jobs" ? "tab-active" : ""}
      onClick={(e) => {
        e.preventDefault();
        window.location.hash = "";
      }}
    >
      Jobs
    </a>
    <a
      href="#credentials"
      className={activeTab === "credentials" ? "tab-active" : ""}
    >
      Credentials
    </a>
  </nav>
</div>
```

---

## Step 6: Create ImportCredentialForm Component

**File:** `ui/pages/dashboard.tsx`

Add before the Dashboard component. Uses `useMutation` from Connect RPC:

```tsx
// Import credential form with inline success message
function ImportCredentialForm({ onSuccess }: { onSuccess: () => void }) {
  const [name, setName] = useState("");
  const [publicKeyPem, setPublicKeyPem] = useState("");
  const [description, setDescription] = useState("");
  const [result, setResult] = useState<{
    principalId: string;
    orgId: string;
    name: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Use Connect RPC mutation
  const mutation = useMutation(importCredential);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setResult(null);

    try {
      const response = await mutation.mutateAsync({
        name,
        publicKeyPem,
        description,
      });

      setResult({
        principalId: response.principalId,
        orgId: response.orgId,
        name: response.name,
      });
      setName("");
      setPublicKeyPem("");
      setDescription("");
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Import failed");
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="import-form">
      <h3>Import Worker Credential</h3>
      <p className="import-subtitle">
        Paste the public key from <code>airunner-cli init</code> output
      </p>

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="cred-name">Name</label>
          <input
            id="cred-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g., production-workers"
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="cred-pubkey">Public Key (PEM)</label>
          <textarea
            id="cred-pubkey"
            value={publicKeyPem}
            onChange={(e) => setPublicKeyPem(e.target.value)}
            placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="cred-desc">Description (optional)</label>
          <input
            id="cred-desc"
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="e.g., Workers for production environment"
          />
        </div>

        <button type="submit" className="btn-primary" disabled={mutation.isPending}>
          {mutation.isPending ? "Importing..." : "Import Credential"}
        </button>
      </form>

      {error && (
        <div className="import-error">
          <p>Error: {error}</p>
        </div>
      )}

      {result && (
        <div className="import-success">
          <p><strong>Credential imported successfully!</strong></p>
          <div className="result-field">
            <span>Principal ID:</span>
            <code>{result.principalId}</code>
            <button
              type="button"
              className="btn-copy"
              onClick={() => copyToClipboard(result.principalId)}
            >
              Copy
            </button>
          </div>
          <div className="result-field">
            <span>Org ID:</span>
            <code>{result.orgId}</code>
            <button
              type="button"
              className="btn-copy"
              onClick={() => copyToClipboard(result.orgId)}
            >
              Copy
            </button>
          </div>
          <div className="result-command">
            <span>Run this command to complete setup:</span>
            <code>
              airunner-cli credentials update {result.name} --org-id {result.orgId} --principal-id {result.principalId}
            </code>
            <button
              type="button"
              className="btn-copy"
              onClick={() =>
                copyToClipboard(
                  `airunner-cli credentials update ${result.name} --org-id ${result.orgId} --principal-id ${result.principalId}`
                )
              }
            >
              Copy
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
```

---

## Step 7: Create CredentialsTable Component

**File:** `ui/pages/dashboard.tsx`

Add after ImportCredentialForm:

```tsx
// Credentials table with revoke functionality
function CredentialsTable({
  credentials,
  currentPrincipalId,
  onRevoke,
}: {
  credentials: Credential[];
  currentPrincipalId: string;
  onRevoke: (principalId: string, name: string) => void;
}) {
  const formatDate = (dateStr: string | undefined): string => {
    if (!dateStr) return "Never";
    try {
      return new Date(dateStr).toLocaleDateString("en-US", {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return "-";
    }
  };

  const truncateFingerprint = (fp: string | undefined): string => {
    if (!fp) return "-";
    return fp.length > 12 ? `${fp.slice(0, 12)}...` : fp;
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const getTypeBadgeClass = (type: string): string => {
    switch (type) {
      case "user":
        return "type-user";
      case "worker":
        return "type-worker";
      case "service":
        return "type-service";
      default:
        return "";
    }
  };

  return (
    <div className="table-wrapper">
      <table className="credentials-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Fingerprint</th>
            <th>Created</th>
            <th>Last Used</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {credentials.map((cred) => (
            <tr key={cred.principalId}>
              <td className="cell-name">{cred.name}</td>
              <td className="cell-type">
                <span className={`type-badge ${getTypeBadgeClass(cred.type)}`}>
                  {cred.type}
                </span>
              </td>
              <td className="cell-fingerprint">
                {cred.fingerprint ? (
                  <code
                    className="fingerprint-code"
                    onClick={() => copyToClipboard(cred.fingerprint)}
                    title="Click to copy"
                  >
                    {truncateFingerprint(cred.fingerprint)}
                  </code>
                ) : (
                  <span className="no-fingerprint">-</span>
                )}
              </td>
              <td className="cell-date">{formatDate(cred.createdAt)}</td>
              <td className="cell-date">{formatDate(cred.lastUsedAt)}</td>
              <td className="cell-actions">
                {cred.type === "worker" && cred.principalId !== currentPrincipalId ? (
                  <button
                    type="button"
                    className="btn-revoke"
                    onClick={() => onRevoke(cred.principalId, cred.name)}
                  >
                    Revoke
                  </button>
                ) : cred.principalId === currentPrincipalId ? (
                  <span className="self-badge">You</span>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

---

## Step 8: Create CredentialsView Component

**File:** `ui/pages/dashboard.tsx`

Add after CredentialsTable. Uses `useQuery` for listing and `useMutation` for revoke:

```tsx
// Main credentials view combining form and table
function CredentialsView() {
  const user = usePageContext();

  // Use Connect RPC query for listing
  const { data, isLoading, error, refetch } = useQuery(listCredentials, {
    principalType: "",
  });

  // Use Connect RPC mutation for revoke
  const revokeMutation = useMutation(revokeCredential);

  const handleRevoke = async (principalId: string, name: string) => {
    if (!confirm(`Revoke credential "${name}"?\n\nThis action cannot be undone. The credential will no longer be able to authenticate.`)) {
      return;
    }

    try {
      await revokeMutation.mutateAsync({ principalId });
      refetch(); // Refresh the list
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to revoke credential");
    }
  };

  const credentials = data?.credentials || [];

  return (
    <div className="credentials-container">
      <ImportCredentialForm onSuccess={() => refetch()} />

      <div className="credentials-section">
        <h2 className="section-title">Credentials</h2>

        {isLoading && (
          <div className="events-loading">
            <div className="spinner"></div>
            <p>Loading credentials...</p>
          </div>
        )}

        {error && (
          <div className="events-error">
            <p>{error instanceof Error ? error.message : "Failed to load credentials"}</p>
            <button type="button" onClick={() => refetch()}>
              Retry
            </button>
          </div>
        )}

        {!isLoading && !error && credentials.length === 0 && (
          <div className="empty-state">
            <p>No credentials yet. Import one using the form above.</p>
          </div>
        )}

        {!isLoading && !error && credentials.length > 0 && (
          <CredentialsTable
            credentials={credentials}
            currentPrincipalId={user?.principal_id || ""}
            onRevoke={handleRevoke}
          />
        )}
      </div>
    </div>
  );
}
```

---

## Step 9: Update Dashboard Conditional Rendering

**File:** `ui/pages/dashboard.tsx`

Replace the conditional rendering in the Dashboard return statement:

```tsx
return (
  <div className="dashboard-container">
    {/* Top Bar */}
    <div className="dashboard-topbar">
      <div className="topbar-left">
        <h1 className="topbar-title">airunner</h1>
        <nav className="topbar-tabs">
          <a
            href="#"
            className={activeTab === "jobs" ? "tab-active" : ""}
            onClick={(e) => {
              e.preventDefault();
              window.location.hash = "";
            }}
          >
            Jobs
          </a>
          <a
            href="#credentials"
            className={activeTab === "credentials" ? "tab-active" : ""}
          >
            Credentials
          </a>
        </nav>
      </div>
      <div className="topbar-right">
        <span className="user-name">{user?.name || "User"}</span>
        <a href="/logout" className="btn-logout">
          Logout
        </a>
      </div>
    </div>

    {/* Conditional content rendering */}
    {selectedJobId ? (
      <JobEventsView jobId={selectedJobId} />
    ) : activeTab === "credentials" ? (
      <CredentialsView />
    ) : (
      <div className="dashboard-content">
        {/* existing jobs content unchanged */}
      </div>
    )}
  </div>
);
```

---

## Step 10: Add CSS Styles

**File:** `ui/pages/dashboard.css`

Add at the end of the file:

```css
/* ========================================
   Tab Navigation
   ======================================== */

.topbar-tabs {
  display: flex;
  gap: 0.5rem;
  margin-left: 2rem;
}

.topbar-tabs a {
  color: var(--nord4);
  text-decoration: none;
  padding: 0.5rem 1rem;
  border-radius: 4px;
  transition: background-color 0.2s, color 0.2s;
}

.topbar-tabs a:hover {
  background: var(--nord2);
  color: var(--nord6);
}

.topbar-tabs a.tab-active {
  background: var(--nord3);
  color: var(--nord6);
}

/* ========================================
   Credentials Container
   ======================================== */

.credentials-container {
  padding: 2rem;
  max-width: 1200px;
  margin: 0 auto;
}

.credentials-section {
  margin-top: 2rem;
}

/* ========================================
   Import Form
   ======================================== */

.import-form {
  background: var(--nord1);
  padding: 1.5rem;
  border-radius: 8px;
}

.import-form h3 {
  margin-top: 0;
  margin-bottom: 0.25rem;
  color: var(--nord6);
}

.import-subtitle {
  color: var(--nord4);
  margin-bottom: 1.5rem;
  font-size: 0.9rem;
}

.import-subtitle code {
  background: var(--nord0);
  padding: 0.125rem 0.375rem;
  border-radius: 3px;
}

.form-group {
  margin-bottom: 1rem;
}

.form-group label {
  display: block;
  margin-bottom: 0.5rem;
  color: var(--nord4);
  font-size: 0.9rem;
}

.form-group input,
.form-group textarea {
  width: 100%;
  padding: 0.625rem;
  background: var(--nord0);
  border: 1px solid var(--nord3);
  border-radius: 4px;
  color: var(--nord6);
  font-size: 0.95rem;
  box-sizing: border-box;
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: var(--nord8);
}

.form-group textarea {
  font-family: "SF Mono", "Fira Code", monospace;
  min-height: 120px;
  resize: vertical;
}

.btn-primary {
  background: var(--nord10);
  color: var(--nord6);
  border: none;
  padding: 0.625rem 1.25rem;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.95rem;
  transition: background-color 0.2s;
}

.btn-primary:hover {
  background: var(--nord9);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

/* ========================================
   Import Success/Error Messages
   ======================================== */

.import-success {
  background: rgba(163, 190, 140, 0.15);
  border: 1px solid var(--nord14);
  color: var(--nord6);
  padding: 1rem;
  border-radius: 4px;
  margin-top: 1rem;
}

.import-success p {
  margin: 0 0 0.75rem 0;
}

.import-success strong {
  color: var(--nord14);
}

.result-field,
.result-command {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
  flex-wrap: wrap;
}

.result-field span,
.result-command span {
  color: var(--nord4);
  min-width: 100px;
}

.result-field code,
.result-command code {
  background: var(--nord0);
  padding: 0.375rem 0.625rem;
  border-radius: 4px;
  font-family: "SF Mono", "Fira Code", monospace;
  font-size: 0.85rem;
  word-break: break-all;
  flex: 1;
}

.result-command {
  flex-direction: column;
  align-items: flex-start;
}

.result-command code {
  width: 100%;
  margin: 0.5rem 0;
}

.btn-copy {
  background: var(--nord3);
  color: var(--nord6);
  border: none;
  padding: 0.25rem 0.5rem;
  border-radius: 3px;
  cursor: pointer;
  font-size: 0.8rem;
  transition: background-color 0.2s;
}

.btn-copy:hover {
  background: var(--nord2);
}

.import-error {
  background: rgba(191, 97, 106, 0.15);
  border: 1px solid var(--nord11);
  color: var(--nord11);
  padding: 1rem;
  border-radius: 4px;
  margin-top: 1rem;
}

.import-error p {
  margin: 0;
}

/* ========================================
   Credentials Table
   ======================================== */

.credentials-table {
  width: 100%;
  border-collapse: collapse;
  background: var(--nord1);
  border-radius: 8px;
  overflow: hidden;
}

.credentials-table th,
.credentials-table td {
  padding: 0.875rem 1rem;
  text-align: left;
  border-bottom: 1px solid var(--nord3);
}

.credentials-table th {
  background: var(--nord2);
  color: var(--nord4);
  font-weight: 500;
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.credentials-table tbody tr:last-child td {
  border-bottom: none;
}

.credentials-table tbody tr:hover {
  background: var(--nord2);
}

.cell-name {
  font-weight: 500;
  color: var(--nord6);
}

.cell-fingerprint .fingerprint-code {
  cursor: pointer;
  padding: 0.25rem 0.5rem;
  background: var(--nord0);
  border-radius: 3px;
  font-size: 0.85rem;
  transition: background-color 0.2s;
}

.cell-fingerprint .fingerprint-code:hover {
  background: var(--nord3);
}

.no-fingerprint {
  color: var(--nord4);
}

.cell-date {
  color: var(--nord4);
  font-size: 0.9rem;
}

.type-badge {
  display: inline-block;
  padding: 0.25rem 0.625rem;
  border-radius: 12px;
  font-size: 0.8rem;
  font-weight: 500;
}

.type-badge.type-user {
  background: rgba(136, 192, 208, 0.2);
  color: var(--nord8);
}

.type-badge.type-worker {
  background: rgba(163, 190, 140, 0.2);
  color: var(--nord14);
}

.type-badge.type-service {
  background: rgba(180, 142, 173, 0.2);
  color: var(--nord15);
}

.btn-revoke {
  background: var(--nord11);
  color: var(--nord6);
  border: none;
  padding: 0.375rem 0.75rem;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85rem;
  transition: background-color 0.2s;
}

.btn-revoke:hover {
  background: #c9545d;
}

.self-badge {
  color: var(--nord4);
  font-size: 0.85rem;
  font-style: italic;
}
```

---

## Verification

After implementing all steps, verify:

1. **Server URL Fix**
   - Open browser dev tools Network tab
   - API calls should go to current origin, not `localhost:8993`

2. **Tab Navigation**
   - Click "Credentials" tab → URL shows `#credentials`
   - Click "Jobs" tab → URL clears hash
   - Browser back/forward buttons work

3. **Credentials List**
   - Shows loading spinner initially
   - Displays all credentials in table
   - Shows empty state if no credentials

4. **Import Form**
   - Validates required fields
   - Shows error on failure
   - Shows success message with IDs
   - Copy buttons work

5. **Revoke**
   - Shows confirmation dialog
   - Removes credential from list on success
   - Cannot revoke own credential (hidden or disabled)

---

[← README](README.md) | [Architecture](00-architecture.md)
