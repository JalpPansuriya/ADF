import { useState } from 'react';
import Dashboard from './pages/Dashboard';

/**
 * Shell: holds the admin key in memory only.
 *
 * Deliberately not persisted to localStorage or sessionStorage. The key can mint
 * root tokens and revoke anything, so leaving it in browser storage would turn any
 * XSS or shared session into full control of the firewall. The cost is retyping it
 * after a reload, which is the right trade for a security console.
 */
export default function App() {
  const [adminKey, setAdminKey] = useState('');

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-4 px-6 py-4">
          <div>
            <h1 className="text-lg font-semibold tracking-tight">
              Agent Delegation Firewall
            </h1>
            <p className="text-xs text-slate-400">
              Capability narrowing &amp; audit for multi-agent pipelines
            </p>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <label htmlFor="admin-key" className="text-xs text-slate-400">
              Admin key
            </label>
            <input
              id="admin-key"
              type="password"
              value={adminKey}
              onChange={(event) => setAdminKey(event.target.value)}
              placeholder="required for approve / deny / revoke"
              autoComplete="off"
              className="w-72 rounded border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-100 placeholder:text-slate-600 focus:border-slate-500 focus:outline-none"
            />
          </div>
        </div>
        {!adminKey && (
          <p className="mx-auto max-w-7xl px-6 pb-3 text-xs text-pending">
            Read-only until an admin key is entered. Kept in memory only, never stored.
          </p>
        )}
      </header>
      <main className="mx-auto max-w-7xl px-6 py-6">
        <Dashboard adminKey={adminKey} />
      </main>
    </div>
  );
}
