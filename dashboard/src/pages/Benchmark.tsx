// Benchmark — the headline evasion result (baselines collapse, AEGIS holds), a
// competitive capability comparison vs named guardrails, and a live evasion
// sweep that proves obfuscation is neutralized in real time.
import BenchmarkView from "../components/BenchmarkView";
import BenchmarkMetrics from "../components/BenchmarkMetrics";
import EvasionTester from "../components/EvasionTester";
import CompetitiveBenchmark from "../components/CompetitiveBenchmark";
import { Panel } from "../components/ui";

export default function Benchmark() {
  return (
    <div className="space-y-4">
      <Panel title="Detection Quality" icon="target" subtitle="Measured on the offline 30/30 curated set — precision, recall, F1 & confusion matrix">
        <BenchmarkMetrics />
      </Panel>
      <Panel
        title="Competitive Analysis"
        icon="target"
        subtitle="LLM Firewall Platform vs named guardrails — by documented defensive architecture"
      >
        <CompetitiveBenchmark />
      </Panel>
      <Panel title="Evasion Benchmark" icon="gauge" subtitle="Attack success rate by transform — named guardrails vs the LLM Firewall Platform (measured)">
        <BenchmarkView />
      </Panel>
      <Panel title="Live Evasion Sweep" icon="zap" subtitle="Apply each evasion transform to a base attack and watch the platform neutralize every variant">
        <EvasionTester />
      </Panel>
    </div>
  );
}
