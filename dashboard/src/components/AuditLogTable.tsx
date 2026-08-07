import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, type AuditEntry } from '../api/client';
import { Panel } from './DelegationTree';

const ACTIONS = [
  'root_token_minted',
  'token_minted',
  'scope_escalation_denied',
  'depth_limit_exceeded',
  'verify_success',
  'verify_denied',
  'token_revoked',
  'approval_pending',
  'approval_granted',
  'approval_denied',
  'approval_expired',
  'circuit_opened',
  'circuit_reset',
  'anomaly_detected',
];

function decisionClass(decision: string | null): string {
  switch (decision) {
    case 'allow':
      return 'text-allow';
    case 'deny':
      return 'text-deny';
    case 'pending':
      return 'text-pending';
    case 'revoke':
      return 'text-revoked';
    case 'flag':
      return 'text-sky-400';
    default:
      return 'text-slate-400';
  }
}

/**
 * Filterable audit table with a detail drawer.
 *
 * Shows prev_hash/row_hash per row so the chain is inspectable from the UI, not
 * just via the integrity endpoint -- an operator investigating an incident can see
 * how a row is pinned to its predecessor.
 */
export default function AuditLogTable() {
  const [action, setAction] = useState('');
  const [decision, setDecision] = useState('');
  const [selected, setSelected] = useState<AuditEntry | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['audit-log', action, decision],
    queryFn: () =>
      api.auditLog({
        limit: 150,
        action: action || undefined,
        decision: decision || undefined,
      }),
  });

  return (
    <Panel
      title="Audit Log"
      subtitle={data ? `${data.total} event(s) recorded` : undefined}
      actions={
        <div className="flex gap-2">
          <select
            value={action}
            onChange={(event) => setAction(event.target.value)}
            className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs"
          >
            <option value="">all actions</option>
            {ACTIONS.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
          <select
            value={decision}
            onChange={(event) => setDecision(event.target.value)}
            className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs"
          >
            <option value="">all decisions</option>
            <option value="allow">allow</option>
            <option value="deny">deny</option>
            <option value="pending">pending</option>
            <option value="revoke">revoke</option>
            <option value="flag">flag</option>
          </select>
        </div>
      }
    >
      {isLoading && <p className="text-sm text-slate-400">Loading…</p>}
      {error && <p className="text-sm text-deny">{(error as Error).message}</p>}

      {data && (
        <div className="max-h-[420px] overflow-auto rounded border border-slate-800">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-slate-900 text-slate-400">
              <tr>
                <th className="px-3 py-2 font-medium">#</th>
                <th className="px-3 py-2 font-medium">time</th>
                <th className="px-3 py-2 font-medium">action</th>
                <th className="px-3 py-2 font-medium">decision</th>
                <th className="px-3 py-2 font-medium">actor</th>
                <th className="px-3 py-2 font-medium">scopes</th>
                <th className="px-3 py-2 font-medium">reason</th>
              </tr>
            </thead>
            <tbody>
              {data.entries.map((entry) => (
                <tr
                  key={entry.id}
                  onClick={() => setSelected(entry)}
                  className="cursor-pointer border-t border-slate-800 hover:bg-slate-800/40"
                >
                  <td className="px-3 py-1.5 text-slate-500">{entry.id}</td>
                  <td className="px-3 py-1.5 font-mono text-slate-400">
                    {entry.ts.slice(11, 23)}
                  </td>
                  <td className="px-3 py-1.5 text-slate-200">{entry.action}</td>
                  <td className={`px-3 py-1.5 font-medium ${decisionClass(entry.decision)}`}>
                    {entry.decision ?? '—'}
                  </td>
                  <td
                    className="max-w-[150px] truncate px-3 py-1.5 font-mono text-slate-400"
                    title={entry.actor_id ?? ''}
                  >
                    {entry.actor_id ?? '—'}
                  </td>
                  <td className="px-3 py-1.5 text-slate-400">
                    {entry.denied_scopes?.length ? (
                      <span className="text-deny">
                        denied: {entry.denied_scopes.join(', ')}
                      </span>
                    ) : (
                      (entry.scopes ?? []).join(', ') || '—'
                    )}
                  </td>
                  <td
                    className="max-w-[220px] truncate px-3 py-1.5 text-slate-500"
                    title={entry.reason ?? ''}
                  >
                    {entry.reason ?? '—'}
                  </td>
                </tr>
              ))}
              {data.entries.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-3 py-6 text-center text-slate-500">
                    No events match this filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {selected && (
        <div className="mt-4 rounded border border-slate-800 bg-slate-900/60 p-4">
          <div className="mb-3 flex items-center gap-3">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-300">
              Event {selected.id} · {selected.action}
            </h3>
            <button
              type="button"
              onClick={() => setSelected(null)}
              className="ml-auto text-xs text-slate-400 hover:text-slate-200"
            >
              close
            </button>
          </div>
          <pre className="max-h-64 overflow-auto rounded bg-slate-950 p-3 text-[11px] leading-relaxed text-slate-300">
            {JSON.stringify(selected, null, 2)}
          </pre>
          <p className="mt-2 text-[11px] text-slate-500">
            row_hash = sha256(prev_hash + canonical row content). Any edit to this row
            breaks every row after it — verify with the System Health panel.
          </p>
        </div>
      )}
    </Panel>
  );
}
