// Audit Trail — immutable hash-chained audit (tamper verification) plus the live
// tenant-scoped security event feed. Requires an admin key (offline shows guidance).
import AuditView from "../components/AuditView";
import ThreatFeed from "../components/ThreatFeed";
import { Panel } from "../components/ui";

export default function AuditTrail() {
  return (
    <div className="space-y-4">
      <Panel title="Immutable Audit" icon="lock" subtitle="Hash-chained, tamper-evident record (S6 / S7 / S13)">
        <AuditView />
      </Panel>
      <Panel title="Live Audit Feed" icon="scroll" subtitle="Tenant-scoped security events from the gateway audit store">
        <ThreatFeed />
      </Panel>
    </div>
  );
}
