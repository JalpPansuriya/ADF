import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import { Panel } from './DelegationTree';

/**
 * Human-approval queue for sensitive-scope delegations.
 *
 * Both buttons require the admin key. Approving is what actually *mints* the child
 * token (no token exists while pending), so the copy makes that consequence explicit
 * rather than presenting it as flipping a flag.
 */
export default function ApprovalsQueue({ adminKey }: { adminKey: string }) {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['approvals'],
    queryFn: () => api.approvals(),
  });

  async function decide(approvalId: string, decision: 'approve' | 'deny') {
    if (!adminKey) {
      setMessage('An admin key is required to approve or deny.');
      return;
    }
    setBusy(approvalId);
    setMessage(null);
    try {
      if (decision === 'approve') {
        await api.approve(approvalId, adminKey);
        setMessage(
          'Approved. The child token has now been minted; the requesting agent can collect it.',
        );
      } else {
        await api.deny(approvalId, adminKey);
        setMessage('Denied. No token was minted.');
      }
      await queryClient.invalidateQueries({ queryKey: ['approvals'] });
      await queryClient.invalidateQueries({ queryKey: ['tree'] });
    } catch (exc) {
      setMessage(`Failed: ${(exc as Error).message}`);
    } finally {
      setBusy(null);
    }
  }

  const pending = (data?.approvals ?? []).filter((row) => row.status === 'pending');
  const decided = (data?.approvals ?? []).filter((row) => row.status !== 'pending');

  return (
    <Panel
      title="Approvals Queue"
      subtitle={`${pending.length} awaiting a human`}
    >
      {isLoading && <p className="text-sm text-slate-400">Loading…</p>}
      {error && <p className="text-sm text-deny">{(error as Error).message}</p>}
      {message && <p className="mb-3 text-xs text-pending">{message}</p>}

      {pending.length === 0 && !isLoading && (
        <p className="text-sm text-slate-400">
          Nothing pending. Delegations requesting a sensitive scope appear here and mint
          nothing until approved.
        </p>
      )}

      <ul className="space-y-3">
        {pending.map((row) => (
          <li
            key={row.approval_id}
            className="rounded border border-pending/40 bg-pending/5 p-3 text-xs"
          >
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <span className="font-semibold text-slate-200">{row.child_agent_id}</span>
              <span className="text-slate-400">requests</span>
              {row.requested_scopes.map((scope) => (
                <span
                  key={scope}
                  className={`rounded px-2 py-0.5 ${
                    row.sensitive_scopes.includes(scope)
                      ? 'bg-pending/20 text-pending'
                      : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  {scope}
                </span>
              ))}
              <span className="ml-auto text-slate-500">expires {row.expires_at.slice(11, 19)}</span>
            </div>
            <p className="mb-2 text-slate-500">
              from parent <span className="font-mono">{row.parent_jti.slice(0, 8)}…</span> ·
              sensitive: {row.sensitive_scopes.join(', ')}
            </p>
            <div className="flex gap-2">
              <button
                type="button"
                disabled={busy === row.approval_id || !adminKey}
                onClick={() => decide(row.approval_id, 'approve')}
                className="rounded bg-allow px-3 py-1 font-medium text-white disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
                title={adminKey ? 'Mint the child token' : 'Admin key required'}
              >
                Approve &amp; mint
              </button>
              <button
                type="button"
                disabled={busy === row.approval_id || !adminKey}
                onClick={() => decide(row.approval_id, 'deny')}
                className="rounded bg-deny px-3 py-1 font-medium text-white disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
              >
                Deny
              </button>
            </div>
          </li>
        ))}
      </ul>

      {decided.length > 0 && (
        <details className="mt-4 text-xs text-slate-400">
          <summary className="cursor-pointer text-slate-300">
            {decided.length} decided request(s)
          </summary>
          <ul className="mt-2 space-y-1">
            {decided.map((row) => (
              <li key={row.approval_id} className="flex gap-2 border-t border-slate-800 py-1">
                <span
                  className={
                    row.status === 'approved'
                      ? 'text-allow'
                      : row.status === 'denied'
                        ? 'text-deny'
                        : 'text-revoked'
                  }
                >
                  {row.status}
                </span>
                <span className="text-slate-300">{row.child_agent_id}</span>
                <span className="text-slate-500">{row.requested_scopes.join(', ')}</span>
                {row.approved_by && (
                  <span className="ml-auto text-slate-500">by {row.approved_by}</span>
                )}
              </li>
            ))}
          </ul>
        </details>
      )}
    </Panel>
  );
}
