import { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { api, type IntegrityResponse } from '../api/client';
import { Panel } from './DelegationTree';

interface Sample {
  t: string;
  errorRate: number;
  samples: number;
}

/**
 * Breaker state, error-rate history, rate-limit windows, and an on-demand
 * integrity check.
 *
 * The error-rate series is accumulated client-side from /health polls; the service
 * intentionally keeps no time-series store (that belongs in Prometheus, not in an
 * authorization service's hot path).
 */
export default function SystemHealth({ adminKey }: { adminKey: string }) {
  const queryClient = useQueryClient();
  const [history, setHistory] = useState<Sample[]>([]);
  const [integrity, setIntegrity] = useState<IntegrityResponse | null>(null);
  const [checking, setChecking] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['health'],
    queryFn: api.health,
  });

  useEffect(() => {
    if (!data) return;
    setHistory((previous) =>
      [
        ...previous,
        {
          t: new Date().toLocaleTimeString(),
          errorRate: Number((data.circuit.error_rate * 100).toFixed(1)),
          samples: data.circuit.samples,
        },
      ].slice(-40),
    );
  }, [data]);

  async function checkIntegrity() {
    setChecking(true);
    setMessage(null);
    try {
      setIntegrity(await api.verifyIntegrity());
    } catch (exc) {
      setMessage(`Integrity check failed: ${(exc as Error).message}`);
    } finally {
      setChecking(false);
    }
  }

  async function resetCircuit() {
    if (!adminKey) {
      setMessage('An admin key is required for the break-glass reset.');
      return;
    }
    try {
      const result = await api.resetCircuit(adminKey);
      setMessage(
        result.was_open
          ? 'Circuit breaker closed. Investigate the cause before relying on it.'
          : 'Circuit breaker was already closed.',
      );
      await queryClient.invalidateQueries({ queryKey: ['health'] });
    } catch (exc) {
      setMessage(`Reset failed: ${(exc as Error).message}`);
    }
  }

  if (isLoading) return <Panel title="System Health">Loading…</Panel>;
  if (error)
    return (
      <Panel title="System Health">
        <p className="text-sm text-deny">
          Cannot reach the Checkpoint Service: {(error as Error).message}
        </p>
      </Panel>
    );
  if (!data) return null;

  const windows = Object.entries(data.rate_limits.current_windows);

  return (
    <Panel
      title="System Health"
      subtitle={data.status === 'ok' ? 'operating normally' : 'degraded'}
    >
      {message && <p className="mb-3 text-xs text-pending">{message}</p>}

      <div className="grid gap-4 md:grid-cols-4">
        <Stat
          label="Circuit breaker"
          value={data.circuit.open ? 'OPEN' : 'closed'}
          tone={data.circuit.open ? 'bad' : 'good'}
          note={
            data.circuit.open
              ? (data.circuit.reason ?? '')
              : `threshold ${(data.circuit.threshold * 100).toFixed(0)}% over ${data.circuit.window_seconds}s`
          }
        />
        <Stat
          label="Error rate"
          value={`${(data.circuit.error_rate * 100).toFixed(1)}%`}
          tone={data.circuit.error_rate >= data.circuit.threshold ? 'bad' : 'good'}
          note={`${data.circuit.errors}/${data.circuit.samples} in window`}
        />
        <Stat
          label="Redis cache"
          value={data.redis.available ? 'available' : 'unavailable'}
          tone={data.redis.available ? 'good' : 'warn'}
          note={data.redis.available ? 'O(1) revocation lookups' : 'falling back to Postgres'}
        />
        <Stat
          label="Tokens / revoked"
          value={`${data.counts.tokens} / ${data.counts.revocations}`}
          tone="neutral"
          note={`${data.counts.audit_rows} audit rows`}
        />
      </div>

      {data.circuit.open && (
        <div className="mt-4 rounded border border-deny/50 bg-deny/10 p-3 text-xs">
          <p className="mb-2 text-deny">
            The breaker is open: /verify is refusing all tokens and /delegate is
            blocked. There is no automatic recovery — that is deliberate, so the
            incident cannot be silently masked.
          </p>
          <button
            type="button"
            onClick={resetCircuit}
            disabled={!adminKey}
            className="rounded bg-deny px-3 py-1 font-medium text-white disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
          >
            Break glass: reset breaker
          </button>
        </div>
      )}

      <div className="mt-5">
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
          Error rate (%) over recent polls
        </h3>
        <div className="h-40 rounded border border-slate-800 bg-slate-950 p-2">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={history}>
              <CartesianGrid stroke="#1e293b" />
              <XAxis dataKey="t" tick={{ fontSize: 10, fill: '#64748b' }} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: '#64748b' }} />
              <Tooltip
                contentStyle={{
                  background: '#0f172a',
                  border: '1px solid #334155',
                  fontSize: 11,
                }}
              />
              <Line
                type="monotone"
                dataKey="errorRate"
                stroke="#dc2626"
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="mt-5 grid gap-4 md:grid-cols-2">
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
            Rate-limit windows
          </h3>
          <p className="mb-2 text-[11px] text-slate-500">
            limits: {data.rate_limits.delegate_per_min}/min delegate,{' '}
            {data.rate_limits.verify_per_min}/min verify
            {data.rate_limits.exempt_agents.length > 0 && (
              <span className="text-pending">
                {' '}
                · exempt: {data.rate_limits.exempt_agents.join(', ')} (must be empty in
                production)
              </span>
            )}
          </p>
          <div className="max-h-32 overflow-auto rounded border border-slate-800 text-[11px]">
            {windows.length === 0 ? (
              <p className="p-2 text-slate-500">No traffic in the current window.</p>
            ) : (
              <table className="w-full">
                <tbody>
                  {windows.map(([key, count]) => (
                    <tr key={key} className="border-b border-slate-800/70">
                      <td className="px-2 py-1 font-mono text-slate-400">{key}</td>
                      <td className="px-2 py-1 text-right text-slate-300">{count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
            Audit chain integrity
          </h3>
          <button
            type="button"
            onClick={checkIntegrity}
            disabled={checking}
            className="rounded bg-slate-700 px-3 py-1 text-xs font-medium text-white hover:bg-slate-600 disabled:opacity-60"
          >
            {checking ? 'Walking the chain…' : 'Verify integrity now'}
          </button>
          {integrity && (
            <div
              className={`mt-3 rounded border p-3 text-xs ${
                integrity.intact
                  ? 'border-allow/50 bg-allow/10 text-allow'
                  : 'border-deny/50 bg-deny/10 text-deny'
              }`}
            >
              <p className="font-semibold">
                {integrity.intact ? 'PASS — chain intact' : 'FAIL — tampering detected'}
              </p>
              <p className="mt-1 text-slate-300">
                {integrity.rows_checked} row(s) checked. {integrity.detail}
              </p>
              {integrity.first_broken_row_id !== null && (
                <p className="mt-1 text-slate-300">
                  First broken row id: {integrity.first_broken_row_id}
                </p>
              )}
            </div>
          )}
          <p className="mt-2 text-[11px] text-slate-500">
            Sensitive scopes: {data.sensitive_scopes.join(', ')} · max delegation depth:{' '}
            {data.max_delegation_depth}
          </p>
        </div>
      </div>
    </Panel>
  );
}

function Stat({
  label,
  value,
  note,
  tone,
}: {
  label: string;
  value: string;
  note?: string;
  tone: 'good' | 'bad' | 'warn' | 'neutral';
}) {
  const toneClass = {
    good: 'text-allow',
    bad: 'text-deny',
    warn: 'text-pending',
    neutral: 'text-slate-200',
  }[tone];
  return (
    <div className="rounded border border-slate-800 bg-slate-950 p-3">
      <p className="text-[11px] uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`mt-1 text-lg font-semibold ${toneClass}`}>{value}</p>
      {note && <p className="mt-1 text-[11px] leading-snug text-slate-500">{note}</p>}
    </div>
  );
}
