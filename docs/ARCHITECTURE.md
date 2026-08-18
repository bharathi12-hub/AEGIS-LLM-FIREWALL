# AEGIS v2 — Architecture

## Design principles
1. **Neutralize before you classify.** Character-injection defeats classifiers,
   so Normalization v2 runs first and everything downstream sees canonical text.
2. **Behavior beats features.** Known-Answer Detection is robust to adaptive
   evasion because it checks whether a controlled canary task survives, not
   whether the input *looks* like an attack.
3. **Disagreement is signal.** When detectors diverge, or obfuscation is high but
   classifiers are calm, that pattern itself is escalated.
4. **Secure by design, not just detection.** The appliance defends its own attack
   surface (S1–S14) and forwards least-privilege, sanitized bytes.
5. **Offline-first, model-pluggable.** The engine is pure stdlib; real models are
   optional and safetensors-gated.

## Layers (`gateway/app/pipeline/`)
| Layer | File | Role | Closes |
|-------|------|------|--------|
| Normalization v2 | `normalize.py` | strip emoji-tag/bidi/zero-width, fold homoglyphs, multi-pass decode, risk score | G2/T2 |
| Signatures | `signatures.py` + `rules/signatures.yaml` | fast regex on normalized text | — |
| Classifier ensemble | `classifier.py` | two diverse detectors (lexical + structural); HF-pluggable | G1 |
| Embeddings | `embeddings.py` | near-duplicate/paraphrase vs known + evasion corpus | — |
| KAD | `kad.py` | behavioral known-answer canary | G1/T1 |
| Context | `context.py` | multi-turn crescendo / split-payload | G5 |
| Aggregator | `aggregator.py` | noisy-OR fusion + disagreement & evasion tripwires + over-defense guard | G1/G3 |
| Judge | `judge.py` | hardened, data-not-instructions, JSON-only, fail-closed | S1 |
| Output DLP | `output/dlp.py` | decode-then-scan PII/secrets | G4/S12 |
| Canary | `output/canary.py` | rotating system-prompt-leak marker | S11 |

## Hardening layers (v2.1 audit)

Three layers added after the security audit; see [HARDENING.md](HARDENING.md).

| Layer | File | Role | Closes |
|-------|------|------|--------|
| Conversation | `pipeline/conversation.py` | inspects **every** message by role (tool results, assistant/system turns, tool + parameter descriptions) with per-role trust weighting; the latest user turn keeps the unchanged v2.0 prompt path | S21 |
| Structural | `pipeline/structural.py` | SSTI, JNDI/Log4Shell, deserialization, NoSQL/LDAP/XPath, prototype pollution, CRLF — plus many-shot and stacked persuasion. Runs on the prompt path **and** inside the surface engine | S22 (LLM05) |
| Authorization | `policy/rbac.py` | RBAC + ABAC + OPA-compatible, deny-overrides with default-deny, plus dynamic trust that withdraws high-consequence actions after repeated blocks | S23, S24 |
| Tool chain | `surfaces/toolchain.py` | per-session taint tracking from sensitive sources to outbound sinks, surviving base64/reflow/embedding | S25 |

The conversation layer is where the trust asymmetry lives, and it is the reason
the firewall can block a poisoned tool result without breaking a user who writes
"ignore the formatting errors in my draft": the latest user turn keeps
over-defense relief, everything else gets the data prior.

## Surfaces (`gateway/app/surfaces/`) — v2.1

The layers above inspect a *conversation turn*. Surfaces inspect everything else
that reaches the model. They reuse the same normalizer, signature rules, and
classifier ensemble, but fuse them under an inverted prior — *a prompt may be
odd; data must not instruct* — and weight every finding by how concealed its
channel is. Full design in [SURFACES.md](SURFACES.md).

| Module | Guards | Key detections |
|--------|--------|----------------|
| `base.py` | — | segment/channel model, data-channel fusion, sanitized rendering |
| `imperative.py` | — | instruction-in-data primitive (turn delimiters, model address, concealment, tool/exfil directives, delayed triggers, recursion, authority claims) |
| `browser.py` | fetched HTML | CSS invisibility, colour camouflage, comments, attributes, `<meta>`, scripts, SVG |
| `documents.py` | PDF/OOXML/CSV/MD/XML/JSON/email | review comments, tracked deletions, speaker notes, PDF metadata + active content, CSV formula injection |
| `rag.py` | retrieval | chunk scanning, trust tiers, provenance, retrieval anomalies, quarantine, citation verification |
| `memory.py` | persistent state | standing privilege, self-propagation, identity rewrite, delayed triggers, contradictions |
| `tools.py` | function/MCP/shell/HTTP calls | shell/path/URL/SQL analyzers, SSRF, secret exfil, intent consistency, MCP pinning |
| `agent.py` | multi-agent bus | role charters, capability routing, taint propagation, worm shapes |
| `multimodal.py` | images/audio | metadata channels, polyglot files, OCR/ASR provider hooks + coverage reporting |

Surfaces are **additive**: they run only when a caller invokes them or posts to
`/aegis/surface/*`, and each is independently switchable via
`AEGIS_SURFACE_<NAME>=0`. A disabled surface returns an explicit ALLOW with
`enabled=False`, so the audit trail records a skipped layer rather than a clean
one. Like the pipeline, they are pure stdlib.

**Surface output parity.** `SurfaceResult.sanitized` is the surface analogue of
R9/S2: it is the artifact reduced to what a human would have seen, and it is
what the caller forwards. Surfaces guarding an action expose the decision
directly instead (`filtered_chunks`, `persist_allowed`, `execute_allowed`,
`deliver_allowed`).

## Forensics (`app/observability/forensics.py`)

The audit log answers *what was decided* and proves it was not altered. Traces
answer *why*: normalized content, decoded payloads, triggered rules, a per-layer
timeline, policy decisions, and tool requests. A trace is sealed at the end of a
request; its **summary** is anchored in the hash-chained audit log while the full
detail lives in a bounded, retention-scoped buffer — keeping attacker-controlled
text out of the tamper-evident chain while still binding the two together.

## Request lifecycle (`api/proxy.py`)
`auth → rate-limit → policy (allow/deny) → INPUT inspection → block? →
forward sanitized bytes → OUTPUT inspection (DLP + canary) → timing-normalize →
respond`. An audit record is written on both allow and block.

## Inspection/forward parity (R9/S2)
`NormalizationResult.sanitized` is the one canonical string that (a) every
detector inspects and (b) is forwarded upstream. Decoded views are auxiliary
*signal only* and never forwarded. `test_parity.py` asserts the invariant.

## Fail modes & degradation (S4, Section 6)
Per-tenant fail mode; on a layer error the orchestrator applies the fallback:
fail-closed ⇒ treat as attack, fail-open ⇒ benign **+ alarm**. The degradation
ladder drops the judge first, then embeddings, then heavy classifiers (heuristic
floor always remains) — protection is never silently disabled.

## Persistence & scaling
In-memory stores by default (offline, tests). Redis provides classifier cache and
session/canary state when configured. A Postgres/SQLAlchemy store is the
documented production swap behind the same `InMemoryStore` interface. Metrics are
Prometheus (or an in-process fallback); audit is append-only + hash-chained.
