# AEGIS v2.1 — Audit Benchmark (hardening before/after)

Two attack families found by the security audit, measured against the 
build that shipped before the fix.

## Overall

| Build | Detection rate | FPR | Precision | Recall | F1 |
|---|---|---|---|---|---|
| **AEGIS v2.1 hardened** | 100.0% | 0.0% | 1.000 | 1.000 | 1.000 |
| v2.0 (pre-audit) | 0.0% | 0.0% | 0.000 | 0.000 | 0.000 |

Cases: 44. Latency p50 0.39 ms / p95 1.742 ms / p99 7.387 ms.

## Per family

| Family | v2.1 detection | v2.1 FPR | v2.0 detection | v2.0 FPR |
|---|---|---|---|---|
| conversation | 100.0% | 0.0% | 0.0% | 0.0% |
| structural | 100.0% | 0.0% | 0.0% | 0.0% |

### Why the conversation baseline is so low

It is not a detection failure. The v2.0 gateway inspected exactly one 
string per request — the latest user turn — so tool results, replayed 
assistant turns, client-supplied system messages, and tool descriptions 
were never shown to any detector. The payloads in this corpus are ones 
the v2.0 detectors catch easily when they are actually given them; the 
gap was coverage, which is the most dangerous kind, because the 
dashboard reads clean the whole time.

### Why the structural baseline is low

That one *is* a detection failure: v2.0 saw the bytes and had no rule 
matching template, deserialization, or query-operator syntax. Those 
payloads are inert as prompts and become code execution one hop later, 
in whatever renders or parses the model's output (OWASP LLM05).

## Cases fixed by the hardening

- **conversation**: poisoned-tool-result, poisoned-assistant-turn, poisoned-system-turn, poisoned-tool-definition, poisoned-parameter-description, poisoned-earlier-user-turn, tool-result-delayed-trigger, tool-result-exfil-markdown, assistant-turn-standing-privilege
- **structural**: ssti-jinja-sandbox, ssti-java-el, ssti-erb-ruby, ssti-freemarker, log4shell, log4shell-obfuscated, yaml-python-object, yaml-ruby-object, java-serialized, php-object-injection, xxe-entity, nosql-where, prototype-pollution, many-shot-jailbreak, stacked-persuasion, reward-hacking

No residual misses and no false positives on this corpus.


## Reading this honestly

Curated offline corpus that ships with the repo, and the detectors were 
calibrated against it — bugs it exposed were fixed, which inflates these 
numbers relative to unseen traffic. What it does establish is directional 
and worth stating plainly: payloads in non-latest-user messages were 
previously not inspected at all, and template/deserialization payloads 
had no matching rule. Both are now covered, and the hard negatives show 
the coverage did not come at the cost of flagging ordinary traffic.

