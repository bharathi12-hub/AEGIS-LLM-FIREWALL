// Threat Model — the firewall's self-security posture (S1–S14): the appliance
// defends its own attack surface. Every row has a mitigation and a test.
import ThreatModelView from "../components/ThreatModelView";
import { Panel } from "../components/ui";

export default function ThreatModel() {
  return (
    <div className="space-y-4">
      <Panel title="Firewall Self-Security (S1–S14)" icon="shield" subtitle="A security appliance is itself a target — the platform hardens its own surface">
        <ThreatModelView />
      </Panel>
    </div>
  );
}
