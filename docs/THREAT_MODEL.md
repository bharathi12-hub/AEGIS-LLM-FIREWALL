# AEGIS v2 — Threat Model (S1–S14)

A security appliance is itself a target. This document enumerates the firewall's
own attack surface and maps each threat to its mitigation and the test that
proves it. All test paths are under `gateway/tests/`.

| # | Threat | Mitigation | Where | Test |
|---|--------|-----------|-------|------|
| **S1** | **Judge injection** — the LLM-as-judge is itself injectable | User text is passed as delimited **DATA, never instructions**; no tools/network/memory; **structured JSON only**; off-schema ⇒ fail-closed BLOCK | `app/pipeline/judge.py` | `test_security.py::TestJudgeHardening` |
| **S2** | **Parser differential / TOCTOU** — inspect one thing, forward another | Single `sanitized` string is both inspected and forwarded (R9). `forward_text == normalization.sanitized` | `app/pipeline/normalize.py`, `orchestrator.py` | `test_parity.py` |
| **S3** | **Model supply chain** — pickle checkpoints run arbitrary code | **safetensors-only** loading; refuse `.bin/.pt/.ckpt/...`; checksum pinning; CI scan | `app/security/modelscan.py` | `test_security.py::TestModelSupplyChain` |
| **S4** | **Fail-open vs fail-closed** | Per-tenant fail mode; high-security tenants **BLOCK** on layer error/timeout; others fail-open **with a logged alarm**, never silently | `app/security/failmode.py`, `orchestrator.py`, `api/proxy.py` | `test_pipeline.py` (fail paths), demo step 6 |
| **S5** | **DoS / resource abuse** | Token-bucket rate limit per key; **per-tenant judge budget**; hard input cap; per-layer timing | `app/security/ratelimit.py`, `config.py` | `test_security.py::TestRateLimitAndBudget` |
| **S6** | **Log / dashboard injection (stored XSS)** | Store raw as digest only; **render escaped**; strip control chars; never eval | `app/observability/logging.py` | `test_security.py::TestLogSanitization` |
| **S7** | **PII at rest** | Raw prompts **never stored** (salted digest only); PII redacted in previews; optional Fernet encryption; retention config | `app/observability/audit.py` | `test_policy.py::TestImmutableAudit::test_raw_prompt_not_stored` |
| **S8** | **Auth / tenant isolation** | API keys **hashed** (argon2/PBKDF2); rotation; every query scoped by `tenant_id`; cross-tenant read raises | `app/auth.py`, `app/storage/db.py` | `test_tenant_isolation.py` |
| **S9** | **Timing side-channel** | Response timing normalized to floor + jitter so latency doesn't leak which layer fired | `app/security/timing.py`, `api/proxy.py` | `test_security.py::TestTiming` |
| **S10** | **Secrets / transport** | All secrets from env; **separate admin key**; CORS locked to dashboard origin; security headers on every response | `config.py`, `api/admin.py`, `main.py` | `test_api.py::test_admin_requires_key`, `::test_security_headers_present` |
| **S11** | **Canary unpredictability** | KAD secret + output canary are high-entropy, **random per request/session**, never logged in cleartext, rotated | `app/pipeline/kad.py`, `app/output/canary.py` | `test_output.py::TestCanary`, `test_pipeline.py` (kad_fingerprint) |
| **S12** | **Output DLP evasion** | **Decode-then-scan** output (base64/hex/rot13) so encoded exfiltration is caught | `app/output/dlp.py` | `test_output.py::test_encoded_exfiltration_caught` |
| **S13** | **Policy tampering** | Policy changes **schema-validated**, versioned, and written to the append-only audit trail (who/when/what) | `app/policy/schema.py`, `app/policy/engine.py` | `test_policy.py::TestPolicyValidation`, `::TestPolicyEngine` |
| **S14** | **Prompt-stuffing / context overflow** | Oversized inputs capped/truncated safely before scanning; huge payloads can't bypass by exhausting limits | `app/pipeline/normalize.py`, `api/proxy.py` | `test_normalize.py::test_oversized_input_truncated` |

## S15–S20 — surface parsing as an attack surface (v2.1)

Adding seven content parsers adds seven ways to attack the firewall itself. Each
is bounded, refused, or fails closed.

| # | Threat | Mitigation | Where | Test |
|---|--------|-----------|-------|------|
| **S15** | **XXE / entity expansion** — untrusted XML (OOXML parts, SVG, config) reads local files or explodes memory | `DOCTYPE`/`ENTITY` declarations **refused before parsing** — closes XXE, billion-laughs and quadratic blowup without `defusedxml`. No legitimate OOXML part declares one | `app/surfaces/documents.py::safe_xml_parse` | `test_surfaces_content.py::TestDocumentSelfSecurity::test_xxe_refused`, `::test_billion_laughs_refused` |
| **S16** | **Zip bomb / zip slip** — an OOXML container expands to gigabytes or writes outside its root | Entry-count, per-entry and **total uncompressed** caps; entry names with `..` or a leading `/` are dropped; only text parts are read | `app/surfaces/documents.py::_safe_zip_entries` | `test_surfaces_content.py::TestDocumentSelfSecurity::test_zip_slip_entries_ignored` |
| **S17** | **Unparseable artifact treated as clean** — a malformed file scans "empty" and is waved through | A file that cannot be parsed **fails closed** to REVIEW with an explicit reason. A file we cannot read is not a file we can clear | `app/surfaces/documents.py::scan` | `::test_unparseable_document_fails_closed_not_open` |
| **S18** | **Uninspectable channel reported as safe** — a scanned PDF or un-OCR'd image returns ALLOW, teaching operators to trust a meaningless signal | Coverage is reported explicitly (`meta.text_layer`, `coverage`, `meta.fully_analysed`); un-analysed channels are named, not silently skipped | `app/surfaces/multimodal.py`, `documents.py::_pdf_text` | `test_surfaces_content.py::test_coverage_reports_uninspected_channels`, `::test_pdf_without_text_layer_reports_absent` |
| **S19** | **Surface resource abuse** — an artifact with a million elements forces unbounded work | Segment-count, segment-length and artifact-size caps (the S14 posture, applied per surface); oversized artifacts rejected outright | `app/config.py::SurfaceThresholds`, `surfaces/base.py` | `test_surfaces_core.py::TestResourceCaps`, `::test_oversized_artifact_rejected` |
| **S20** | **Finding-channel leakage** — detected secrets or attacker markup leak via findings, traces, or the dashboard | Excerpts pass through `sanitize_for_render` and are capped; detected secrets are replaced with `<redacted kind>`; traces store prompt digests, are bounded, and are tenant-scoped (cross-tenant read ⇒ 404, so existence does not leak) | `surfaces/base.py::SurfaceFinding.as_dict`, `tools.py::analyze_secrets`, `observability/forensics.py` | `test_surfaces_agentic.py::test_secret_value_never_echoed_in_finding`, `test_surfaces_api.py::test_trace_not_readable_across_tenants` |

A malformed-input fuzz floor is asserted directly: malformed HTML
(`test_malformed_html_does_not_raise`), truncated media
(`test_truncated_media_does_not_raise`), and corrupt archives must never raise
out of a surface — partial results plus an alarm, never an exception.

## S21–S25 — findings from the v2.1 security audit

These are not hypothetical: each was demonstrated exploitable against the
then-current build, then fixed. Full write-up in [HARDENING.md](HARDENING.md).

| # | Threat | Mitigation | Where | Test |
|---|--------|-----------|-------|------|
| **S21** | **Partial request inspection** (CRITICAL) — only `latest_user_text()` was inspected, so poisoned tool results, replayed assistant turns, client-supplied system messages, and tool/parameter descriptions reached the model **completely uninspected**. Five bypasses verified | Whole-conversation inspection with per-role trust weighting; the latest user turn keeps the v2.0 prompt path, everything else gets the data prior | `app/pipeline/conversation.py`, `api/proxy.py` | `test_hardening_v21.py::TestConversationCoverage` |
| **S22** | **Structural injection (LLM05)** — template/deserialization/query payloads that are inert as prompts and become RCE one hop later, in whatever renders or parses the response | Dedicated structural layer on both the prompt path and the surface engine; SSTI, JNDI/Log4Shell, deserialization, NoSQL/LDAP/XPath, prototype pollution, CRLF. Never renders or parses what it inspects | `app/pipeline/structural.py` | `test_hardening_v21.py::TestStructuralInjection` |
| **S23** | **Coarse authorization** — a role string cannot express contractor + region + classification + network + time + risk | RBAC (hierarchical, cycle-safe) + ABAC (XACML four, attribute-to-attribute) + OPA-compatible rules, combined deny-overrides with default-deny. Tenant isolation and clearance also enforced in code, not only as rules | `app/policy/rbac.py` | `test_hardening_v21.py::TestRbac`, `::TestAbac`, `::TestOpaCompatibility` |
| **S24** | **Detection that never changes entitlement** — blocked attacks produced logs but no consequence | Dynamic trust decays on blocks and recovers with **time, not good behaviour** (so benign flooding cannot buy privilege back); ABAC withdraws high-consequence actions automatically while reads survive with an approval obligation | `app/policy/rbac.py::TrustTracker`, `api/proxy.py` | `test_hardening_v21.py::TestDynamicTrust` |
| **S25** | **Tool-chain exfiltration** — staged read → encode → send where every individual call is legitimate and the attack is the edge between them | Per-session taint tracking with alignment-invariant content fingerprints that survive base64/reflow/embedding; laundering, privilege ramp, loop and velocity detection | `app/surfaces/toolchain.py` | `test_hardening_v21.py::TestToolChain` |

Two of the S25 implementation details are recorded because both fail *silently*
and would have produced a control that looked fine and detected nothing:
strided shingling misses any payload embedded at a different offset (fixed with
stride-1 windows plus deterministic sampling), and matching topic words like
"invoice" against result bodies flags every business document (fixed by
splitting locator matching from secret-shape matching).

## Immutability & tamper-evidence

The audit trail is an append-only, **hash-chained** log: each record's hash
covers its content plus the previous record's hash. `audit.verify_chain()`
recomputes the chain and reports the first tampered record — proven in
`test_policy.py::TestImmutableAudit::test_hash_chain_valid_then_tamper_detected`.

## Residual risk / honest notes

- The offline profile uses **heuristic detectors** in place of the fine-tuned HF
  models. The architecture is model-agnostic: real safetensors models plug in via
  `AEGIS_HF_MODEL_DIR` and are gated by S3. Benchmark numbers are reported for the
  profile in use.
- The default persistence is an **in-memory store**; a Postgres/SQLAlchemy store
  is the documented production extension behind the same interface.
- KAD detects task-hijacking *injection*; it deliberately abstains on harmful
  content that contains no injection (that is the classifier/signature job).
