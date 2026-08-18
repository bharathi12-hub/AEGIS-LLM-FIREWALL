# Deliverables — Problem-Statement Coverage

Maps the hackathon problem statement to where each requirement is implemented,
tested, and demonstrable. Every row is backed by code and passing tests, not
slideware.

## Key deliverables

| # | Deliverable | Where | Proof |
|---|-------------|-------|-------|
| 1 | **Detect prompt injection attacks** | `app/pipeline/` (normalize → signatures → structural → classifier → embeddings → KAD → context → aggregator → judge) | `make bench`: F1 **1.000**, FPR **0.000**; `make redteam`: ~**0% ASR** under evasion |
| 2 | **Identify jailbreak attempts** | signatures (`rules/signatures.yaml`), `structural.py` (many-shot, stacked persuasion), `adversarial.py` (GCG / magic words) | `test_pipeline.py`, `test_advanced_attacks.py` |
| 3 | **Prevent sensitive data exposure** | `output/dlp.py` (decode-then-scan DLP), `output/canary.py` (system-prompt-leak canary), `surfaces/toolchain.py` (exfiltration chains) | `test_output.py`, `test_hardening_v21.py::TestToolChain` |
| 4 | **Monitor AI interactions in real time** | `observability/events.py` (live event bus), `GET /aegis/events`, `GET /aegis/events/stream` (SSE) | `test_realtime.py`; dashboard **Live Threat Monitor** |
| 5 | **Provide security analytics dashboards** | `dashboard/` (16-page React SOC console) + `observability/metrics.py` (Prometheus) | `make up`, open `:5173` |

## Impact goals

| Goal | How it is met |
|------|---------------|
| **Improve AI system security** | Defence-in-depth: 8 prompt layers + 7 non-prompt surfaces + structural/adversarial detection, deny-by-default authorization |
| **Reduce data leakage risks** | Output DLP, canary tokens, tool-chain taint tracking (read → encode → send caught through base64), secrets never echoed into findings |
| **Protect enterprise applications** | Multi-tenant isolation, RBAC/ABAC/OPA, hash-chained immutable audit, model supply-chain gating (S3), self-security against parser attacks (S15–S20) |
| **Enable safe AI adoption** | OpenAI-compatible drop-in gateway — no application rewrite; every layer independently switchable; runs fully offline |

## Beyond the brief

The problem statement asks for a *prompt* firewall. The threat has moved past the
prompt, so the build covers the channels around it — the part most products miss:

- **Indirect injection** across 7 surfaces (web, documents, RAG, memory, tools,
  agents, multimodal) — see [SURFACES.md](SURFACES.md).
- **Whole-conversation inspection** — tool results, replayed assistant turns, and
  tool definitions, not just the latest user message — see [HARDENING.md](HARDENING.md).
- **Structural injection** (SSTI, Log4Shell, deserialization) that is inert as a
  prompt and becomes RCE one hop downstream (OWASP LLM05).
- **Adversarial suffixes** (GCG / universal magic words) via statistical
  coherence analysis, since they have no lexical signature.
- **MITRE ATLAS** technique IDs on every finding, alongside OWASP LLM categories.

## Standards alignment

- **OWASP LLM Top-10 (2025)** — every finding carries an `LLMxx` category
  (`app/taxonomy.py`).
- **MITRE ATLAS** — every finding maps to an `AML.Txxxx` technique
  (`atlas_for()` in `app/taxonomy.py`), the axis SOC teams pivot on.
- **Research-backed** — detectors implement techniques from the
  awesome-prompt-injection corpus: GCG (arXiv:2307.15043), magic words
  (arXiv:2501.18280), indirect injection (arXiv:2302.12173), ReAct scratchpad
  forgery (WithSecure "Synthetic Recollections").

## Running the live demo

Production stack (needs Docker):

```bash
make up          # gateway :8000 + redis + postgres + dashboard :5173
```

Zero-dependency demo (no Docker, no pip installs — stdlib only):

```bash
# Terminal 1 — the real detection engine over a stdlib HTTP server:
cd gateway && PYTHONUTF8=1 python demo_server.py --port 8000

# Terminal 2 — the dashboard (auto-detects the gateway via /livez):
cd dashboard && npm run dev        # opens :5173
```

The dashboard connects to the gateway when it is reachable and falls back to an
in-browser port of the same engine when it is not, so the whole console works
with or without a backend. Point it elsewhere with
`VITE_API_BASE=http://host:port` in `dashboard/.env.local`.
