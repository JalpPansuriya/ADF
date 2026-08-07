import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Tree from 'react-d3-tree';
import { api, type TreeNode } from '../api/client';

interface D3Node {
  name: string;
  attributes?: Record<string, string>;
  children?: D3Node[];
  __adf: TreeNode;
}

function toD3(node: TreeNode): D3Node {
  return {
    name: node.label,
    attributes: {
      depth: String(node.depth),
      scopes: node.scopes.join(', ') || '(none)',
    },
    children: node.children.map(toD3),
    __adf: node,
  };
}

function statusOf(node: TreeNode): { label: string; fill: string } {
  if (node.revoked) return { label: 'revoked', fill: '#6b7280' };
  if (node.expired) return { label: 'expired', fill: '#a16207' };
  return { label: 'active', fill: '#16a34a' };
}

/**
 * Live delegation forest.
 *
 * Revoked and expired subtrees are greyed rather than hidden: the point of an
 * audit view is that a killed branch stays visible, so an operator can see what
 * *was* granted, not only what is currently live.
 */
export default function DelegationTree({
  adminKey,
  onSelect,
}: {
  adminKey: string;
  onSelect?: (jti: string) => void;
}) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['tree'],
    queryFn: api.tree,
  });
  const [selected, setSelected] = useState<TreeNode | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const forest = useMemo(() => (data?.roots ?? []).map(toD3), [data]);

  async function revoke(node: TreeNode) {
    if (!adminKey) {
      setMessage('An admin key is required to revoke.');
      return;
    }
    const confirmed = window.confirm(
      `Revoke ${node.label} (depth ${node.depth}) and every token beneath it?\n\n` +
        'This is immediate and cannot be undone. Descendants will be refused at ' +
        'their next /verify call.',
    );
    if (!confirmed) return;
    try {
      const result = await api.revoke(node.jti, adminKey);
      setMessage(
        `Revoked ${result.subtree_count} token(s) in ${result.latency_ms.toFixed(2)}ms.`,
      );
    } catch (exc) {
      setMessage(`Revoke failed: ${(exc as Error).message}`);
    }
  }

  if (isLoading) return <Panel title="Delegation Tree">Loading…</Panel>;
  if (error)
    return (
      <Panel title="Delegation Tree">
        <span className="text-deny">Could not load: {(error as Error).message}</span>
      </Panel>
    );

  return (
    <Panel
      title="Delegation Tree"
      subtitle={`${data?.node_count ?? 0} token(s) across ${forest.length} root(s)`}
    >
      {message && <p className="mb-3 text-xs text-pending">{message}</p>}
      {forest.length === 0 ? (
        <p className="text-sm text-slate-400">
          No tokens yet. Mint a root token, or run{' '}
          <code className="text-slate-300">python demo_agents/run_demo.py</code>.
        </p>
      ) : (
        <div className="adf-tree h-[420px] w-full rounded border border-slate-800 bg-slate-950">
          <Tree
            data={forest.length === 1 ? forest[0] : { name: 'roots', children: forest, __adf: forest[0].__adf }}
            orientation="vertical"
            pathFunc="step"
            collapsible={false}
            zoomable
            translate={{ x: 360, y: 60 }}
            separation={{ siblings: 1.6, nonSiblings: 2 }}
            nodeSize={{ x: 190, y: 110 }}
            renderCustomNodeElement={({ nodeDatum }) => {
              const adf = (nodeDatum as unknown as D3Node).__adf;
              if (!adf) return <g />;
              const status = statusOf(adf);
              return (
                <g
                  onClick={() => {
                    setSelected(adf);
                    onSelect?.(adf.jti);
                  }}
                  style={{ cursor: 'pointer' }}
                >
                  <circle r={11} fill={status.fill} stroke="#0f172a" strokeWidth={2} />
                  <text
                    x={16}
                    y={-2}
                    fill={adf.revoked ? '#94a3b8' : '#e2e8f0'}
                    fontSize={12}
                    fontWeight={600}
                    style={{ textDecoration: adf.revoked ? 'line-through' : 'none' }}
                  >
                    {String(nodeDatum.name)}
                  </text>
                  <text x={16} y={13} fill="#94a3b8" fontSize={10}>
                    d{adf.depth} · {adf.scopes.length} scope
                    {adf.scopes.length === 1 ? '' : 's'} · {status.label}
                  </text>
                </g>
              );
            }}
          />
        </div>
      )}

      {selected && (
        <div className="mt-4 rounded border border-slate-800 bg-slate-900/50 p-4 text-xs">
          <div className="mb-2 flex items-center gap-3">
            <span className="font-semibold text-slate-200">{selected.label}</span>
            <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-300">
              depth {selected.depth} / max {selected.max_depth}
            </span>
            <span className="text-slate-400">{statusOf(selected).label}</span>
            <button
              type="button"
              onClick={() => revoke(selected)}
              disabled={selected.revoked || !adminKey}
              className="ml-auto rounded bg-deny px-3 py-1 font-medium text-white disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
              title={
                selected.revoked
                  ? 'Already revoked'
                  : !adminKey
                    ? 'Admin key required'
                    : 'Revoke this token and its whole subtree'
              }
            >
              Revoke subtree
            </button>
          </div>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-slate-400">
            <Row label="jti" value={selected.jti} />
            <Row label="subject" value={selected.subject_id} />
            <Row label="scopes" value={selected.scopes.join(', ') || '(none)'} />
            <Row label="issued" value={selected.issued_at} />
            <Row label="expires" value={selected.expires_at} />
            <Row
              label="approval"
              value={
                selected.approval_required
                  ? `required, approved by ${selected.approved_by ?? '(unknown)'}`
                  : 'not required'
              }
            />
          </dl>
        </div>
      )}
    </Panel>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt className="text-slate-500">{label}</dt>
      <dd className="truncate font-mono text-slate-300" title={value}>
        {value}
      </dd>
    </>
  );
}

export function Panel({
  title,
  subtitle,
  children,
  actions,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900/40 p-5">
      <div className="mb-4 flex items-baseline gap-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-300">
          {title}
        </h2>
        {subtitle && <span className="text-xs text-slate-500">{subtitle}</span>}
        {actions && <div className="ml-auto">{actions}</div>}
      </div>
      {children}
    </section>
  );
}
