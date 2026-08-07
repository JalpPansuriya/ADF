/**
 * Typed client for the Checkpoint Service.
 *
 * The admin key is held in component state (never persisted to localStorage) so a
 * shared browser or an XSS payload cannot lift it after the fact. It is only sent
 * on the endpoints that require it: approve, deny, revoke, and the breaker reset.
 */

const BASE_URL = (import.meta.env.VITE_ADF_API_URL ?? '').replace(/\/$/, '');
const API = `${BASE_URL}/api/v1`;

export type Decision = 'allow' | 'deny' | 'pending' | 'revoke' | 'flag' | null;

export interface AuditEntry {
  id: number;
  ts: string;
  action: string;
  actor_id: string | null;
  jti: string | null;
  parent_jti: string | null;
  root_jti: string | null;
  scopes: string[] | null;
  denied_scopes: string[] | null;
  required_scope: string | null;
  decision: Decision;
  reason: string | null;
  depth: number | null;
  detail: Record<string, unknown> | null;
  latency_ms: number | null;
  row_hash: string;
  prev_hash: string;
}

export interface AuditLogPage {
  total: number;
  limit: number;
  offset: number;
  entries: AuditEntry[];
}

export interface TreeNode {
  jti: string;
  subject_id: string;
  label: string;
  parent_jti: string | null;
  root_jti: string;
  depth: number;
  max_depth: number;
  scopes: string[];
  issued_at: string;
  expires_at: string;
  revoked: boolean;
  expired: boolean;
  approval_required: boolean;
  approved_by: string | null;
  children: TreeNode[];
}

export interface TreeResponse {
  roots: TreeNode[];
  node_count: number;
}

export interface ApprovalRow {
  approval_id: string;
  parent_jti: string;
  parent_subject_id: string;
  child_agent_id: string;
  requested_scopes: string[];
  sensitive_scopes: string[];
  status: string;
  created_at: string;
  expires_at: string;
  decided_at: string | null;
  approved_by: string | null;
  child_jti: string | null;
}

export interface HealthResponse {
  status: 'ok' | 'degraded';
  circuit: {
    open: boolean;
    reason: string | null;
    error_rate: number;
    samples: number;
    errors: number;
    window_seconds: number;
    threshold: number;
    min_samples: number;
  };
  redis: { available: boolean; note: string };
  rate_limits: {
    delegate_per_min: number;
    verify_per_min: number;
    current_windows: Record<string, number>;
    exempt_agents: string[];
  };
  counts: {
    tokens: number;
    revocations: number;
    audit_rows: number;
    pending_approvals: number;
  };
  sensitive_scopes: string[];
  max_delegation_depth: number;
}

export interface IntegrityResponse {
  intact: boolean;
  rows_checked: number;
  first_broken_row_id: number | null;
  detail: string;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  adminKey?: string,
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((init.headers as Record<string, string>) ?? {}),
  };
  if (adminKey) headers['X-Admin-Key'] = adminKey;

  const response = await fetch(`${API}${path}`, { ...init, headers });
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const body = await response.json();
      const detail = body?.detail;
      message =
        typeof detail === 'string'
          ? detail
          : (detail?.error ?? detail?.reason ?? JSON.stringify(detail ?? body));
    } catch {
      /* non-JSON error body; keep the status line */
    }
    throw new ApiError(message, response.status);
  }
  return (await response.json()) as T;
}

export const api = {
  health: () => request<HealthResponse>('/health'),

  tree: () => request<TreeResponse>('/audit/tree'),

  auditLog: (params: { limit?: number; action?: string; decision?: string } = {}) => {
    const query = new URLSearchParams();
    query.set('limit', String(params.limit ?? 100));
    if (params.action) query.set('action', params.action);
    if (params.decision) query.set('decision', params.decision);
    return request<AuditLogPage>(`/audit/log?${query.toString()}`);
  },

  approvals: (status?: string) =>
    request<{ total: number; approvals: ApprovalRow[] }>(
      `/audit/approvals${status ? `?status=${encodeURIComponent(status)}` : ''}`,
    ),

  chain: (jti: string) => request<unknown>(`/audit/chain/${encodeURIComponent(jti)}`),

  verifyIntegrity: () => request<IntegrityResponse>('/audit/verify_integrity'),

  approve: (approvalId: string, adminKey: string) =>
    request<unknown>(
      '/tokens/approve',
      { method: 'POST', body: JSON.stringify({ approval_id: approvalId, decision: 'approve' }) },
      adminKey,
    ),

  deny: (approvalId: string, adminKey: string) =>
    request<unknown>(
      '/tokens/deny',
      { method: 'POST', body: JSON.stringify({ approval_id: approvalId, decision: 'deny' }) },
      adminKey,
    ),

  revoke: (jti: string, adminKey: string, reason = 'revoked from dashboard') =>
    request<{ revoked: boolean; subtree_count: number; latency_ms: number }>(
      '/tokens/revoke',
      { method: 'POST', body: JSON.stringify({ jti, reason }) },
      adminKey,
    ),

  resetCircuit: (adminKey: string) =>
    request<{ circuit_open: boolean; was_open: boolean }>(
      '/admin/circuit/reset',
      { method: 'POST' },
      adminKey,
    ),
};
