import DelegationTree from '../components/DelegationTree';
import AuditLogTable from '../components/AuditLogTable';
import ApprovalsQueue from '../components/ApprovalsQueue';
import SystemHealth from '../components/SystemHealth';

/**
 * The four screens from PRD 17.2, stacked on one polled page.
 *
 * Kept as a single scrollable console rather than routed tabs: during an incident
 * the breaker state, the pending approvals and the audit tail are all needed at
 * once, and hiding any of them behind a tab costs a click at the worst moment.
 */
export default function Dashboard({ adminKey }: { adminKey: string }) {
  return (
    <div className="space-y-6">
      <SystemHealth adminKey={adminKey} />
      <div className="grid gap-6 xl:grid-cols-2">
        <DelegationTree adminKey={adminKey} />
        <ApprovalsQueue adminKey={adminKey} />
      </div>
      <AuditLogTable />
      <footer className="pb-8 pt-2 text-center text-[11px] text-slate-600">
        Polling every 2s. Read-only except approve / deny / revoke / breaker reset,
        which require the admin key.
      </footer>
    </div>
  );
}
