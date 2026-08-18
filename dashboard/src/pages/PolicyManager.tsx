// Policy Manager — the existing policy-as-code editor (validated, versioned,
// audited) plus a compliance-alignment overview. Governance surface for the SOC.
import PolicyEditor from "../components/PolicyEditor";
import { Panel } from "../components/ui";
import { Icon } from "../components/icons";

const FRAMEWORKS = [
  { id: "GDPR", note: "Raw prompts never stored; digest + PII redaction" },
  { id: "SOC 2", note: "Immutable hash-chained audit trail" },
  { id: "ISO 27001", note: "Access control, key rotation, tenant isolation" },
  { id: "HIPAA", note: "Output DLP + encryption at rest option" },
  { id: "PCI DSS", note: "Secret handling, transport hardening" },
  { id: "NIST AI RMF", note: "Adversarial robustness, monitoring" },
  { id: "MITRE ATLAS", note: "Technique mapping & coverage" },
  { id: "CIS", note: "Hardened deploy baseline (K8s/Helm)" },
];

export default function PolicyManager() {
  return (
    <div className="space-y-4">
      <Panel title="Policy-as-Code" icon="sliders" subtitle="Thresholds & rules — schema-validated, versioned and audited on every change (S13)">
        <PolicyEditor />
      </Panel>

      <Panel title="Compliance Alignment" icon="shieldCheck" subtitle="How the platform's controls map to common frameworks">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          {FRAMEWORKS.map((f) => (
            <div key={f.id} className="rounded-lg p-3 bg-white/[0.02] border border-white/[0.06]">
              <div className="flex items-center gap-2">
                <Icon name="check" size={14} className="text-aegis-ok" />
                <span className="text-sm font-semibold text-slate-100">{f.id}</span>
              </div>
              <p className="text-[11px] text-slate-400 mt-1 leading-tight">{f.note}</p>
            </div>
          ))}
        </div>
        <p className="text-[11px] text-slate-600 mt-3">
          Alignment reflects implemented controls (see docs/THREAT_MODEL.md &amp; docs/PRODUCTION.md); it is not a certification.
        </p>
      </Panel>
    </div>
  );
}
