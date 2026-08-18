# AEGIS v2.1 — Surface Benchmark (Indirect Prompt Injection)

Measures detection of injection payloads that arrive through channels 
other than the user's prompt: web pages, documents, retrieved chunks, 
stored memories, tool arguments, and inter-agent messages.

**Baseline** is the v2.0 prompt firewall applied to the flattened text of 
the same artifact — i.e. what a normal guardrail integration does today. 
**AEGIS v2.1** is the channel-aware surface scanner. Both run on the same 
labeled corpus, and false-positive rate is measured on hard negatives 
(real business content containing trigger words, imperatives and formulas).

## Overall

| Detector | Detection rate | FPR | Precision | Recall | F1 |
|---|---|---|---|---|---|
| **AEGIS v2.1 surfaces** | 100.0% | 0.0% | 1.000 | 1.000 | 1.000 |
| v2.0 prompt firewall (flattened) | 20.7% | 3.7% | 0.857 | 0.207 | 0.333 |

Cases: 112. Latency p50 0.302 ms / p95 0.624 ms / p99 6.146 ms.

## Per surface

| Surface | v2.1 detection | v2.1 FPR | baseline detection | baseline FPR | p95 ms |
|---|---|---|---|---|---|
| browser | 100.0% | 0.0% | 40.0% | 0.0% | 0.567 |
| documents | 100.0% | 0.0% | 50.0% | 10.0% | 2.241 |
| rag | 100.0% | 0.0% | 12.5% | 12.5% | 0.54 |
| memory | 100.0% | 0.0% | 12.5% | 0.0% | 0.396 |
| tools | 100.0% | 0.0% | 8.3% | 0.0% | 0.547 |
| agent | 100.0% | 0.0% | 0.0% | 0.0% | 0.553 |
| multimodal | 100.0% | 0.0% | 0.0% | 0.0% | 0.566 |

## The delta: attacks the flattened baseline misses

These carry no jailbreak vocabulary. They are caught because the 
surface layer knows the text arrived in a channel a human never sees.

- **browser**: white-on-white, html-comment, offscreen, turn-delimiter-in-page, aria-hidden, low-contrast
- **documents**: docx-comment, pdf-annotation, markdown-comment, email-x-header, csv-formula
- **rag**: chunk-instruction, chunk-concealment, chunk-delayed, chunk-authority, chunk-exfil-markdown, chunk-recursive, chunk-tool-directive
- **memory**: standing-privilege, safety-disabled, self-propagation, delayed-trigger, privilege-grant, authority-claim, no-delete
- **tools**: shell-rce, shell-destructive, credential-read, path-traversal, ssrf-metadata, ssrf-loopback, exfil-query, sql-destructive, sql-stacked, confused-deputy, file-scheme
- **agent**: role-hijack, capability-escalation, worm, unauthorised-directive, charter-bypass, identity-swap
- **multimodal**: png-text-chunk, png-polyglot, jpeg-comment, svg-hidden-text

No residual misses and no false positives on this corpus.


## Reading this honestly

This is a curated offline corpus, not a public leaderboard run. It is 
sized to be reproducible with zero network access and it is small, so 
these rates carry wide confidence intervals. It measures whether the 
channel-aware design catches a class the flattened approach structurally 
cannot — not that any particular percentage generalises. Running against 
the full BIPIA / AgentDojo suites requires network access and is the 
documented next step in `docs/PRODUCTION.md`.

