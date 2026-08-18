"""Structural injection — payloads aimed at the systems AROUND the model.

WHY THIS EXISTS
---------------
Every other layer asks "is this trying to hijack the model?". This one asks a
different question: **"where do these bytes go next?"**

An LLM is rarely the last hop. Its input and output flow into template engines,
YAML loaders, log pipelines, databases, and browsers. A payload that is
completely inert as a *prompt* becomes remote code execution one hop later:

    {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

That is not a jailbreak. It does not ask the model for anything. It is a
server-side template injection that fires when the model's response — which
helpfully echoes the string — is rendered by Jinja2. The model was never the
target; it was the delivery mechanism.

This is OWASP **LLM05: Improper Output Handling**, and it is the gap that makes
"we have a prompt firewall" insufficient for an enterprise deployment. The audit
confirmed all of these passed the v2.0 pipeline untouched.

THREAT MODEL
------------
  Attacker: can get a string into a prompt, a document, a tool argument, or a
            RAG chunk — and knows the application will render, parse, log, or
            store the model's output.
  Goals:    RCE via template engines or deserializers; JNDI/Log4Shell lookups
            from log sinks; NoSQL/LDAP operator injection; prototype pollution;
            SSRF via a parsed URL.
  Defence:  detect the *syntax* of these payloads wherever they appear, on both
            the input and output paths, independently of intent.

ALSO COVERED HERE
-----------------
Two prompt-level attacks that are structural rather than lexical, and so cannot
be regex-matched one sentence at a time:

  * MANY-SHOT JAILBREAK — flooding the context with fabricated dialogue turns in
    which the assistant always complies, so the real request rides the pattern.
    The signal is the COUNT of fake turns, not their words.
  * PERSUASION / PRESSURE — coercion, false authority, fabricated urgency, and
    the emotional-appeal family. Individually these look like ordinary
    sentences; the signal is how many distinct pressure tactics stack up.

Pure stdlib, deterministic, and side-effect free — it never evaluates, renders,
parses, or deserializes anything it inspects. It only recognises shapes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.pipeline import adversarial
from app.taxonomy import OwaspLLM

_OUTPUT = OwaspLLM.LLM02_INSECURE_OUTPUT
_SUPPLY = OwaspLLM.LLM03_SUPPLY_CHAIN
_PI = OwaspLLM.LLM01_PROMPT_INJECTION


@dataclass
class StructuralFinding:
    kind: str
    severity: float
    matched: str
    category: OwaspLLM = _OUTPUT
    detail: str = ""


@dataclass
class StructuralResult:
    findings: list[StructuralFinding] = field(default_factory=list)

    @property
    def score(self) -> float:
        if not self.findings:
            return 0.0
        top = max(f.severity for f in self.findings)
        distinct = len({f.kind.split(":")[0] for f in self.findings})
        return min(1.0, top + min(0.10, 0.04 * (distinct - 1)))

    @property
    def kinds(self) -> list[str]:
        seen: list[str] = []
        for f in self.findings:
            if f.kind not in seen:
                seen.append(f.kind)
        return seen

    @property
    def category(self) -> OwaspLLM:
        if not self.findings:
            return OwaspLLM.NONE
        return max(self.findings, key=lambda f: f.severity).category


# ---------------------------------------------------------------------------
# Template injection (SSTI)
#
# Severities are high because these strings have essentially no benign reason to
# appear in natural-language content. The exception is documentation ABOUT
# templating, which is why the payload-shaped variants (attribute traversal,
# runtime access) score above the bare-delimiter ones.
# ---------------------------------------------------------------------------

_TEMPLATE_RULES: list[tuple[str, float, str]] = [
    # Jinja2 / Twig / Nunjucks sandbox escape — the canonical Python SSTI chain.
    ("ssti:jinja-sandbox-escape", 0.95,
     r"\{\{.{0,200}?(__class__|__mro__|__subclasses__|__globals__|__builtins__|"
     r"__import__|__base__|__init__).{0,200}?\}\}"),
    ("ssti:jinja-exec", 0.95,
     r"\{\{.{0,160}?\b(popen|system|subprocess|eval|exec|open|read|os\.)\b.{0,160}?\}\}"),
    # Java: Spring EL / OGNL / MVEL runtime access.
    ("ssti:java-el-runtime", 0.95,
     r"[$#]\{.{0,160}?\b(T\(|java\.lang\.Runtime|ProcessBuilder|getRuntime|"
     r"@java\.lang|Class\.forName)\b.{0,160}?\}"),
    # Log4Shell and the JNDI lookup family — still endemic in log pipelines.
    ("injection:jndi-lookup", 0.95,
     r"\$\{\s*(jndi|ldap|rmi|dns|iiop|corba|nis|nds)\s*:"),
    # Log4j nested-lookup obfuscation: ${${lower:j}ndi:...}
    ("injection:jndi-obfuscated", 0.95,
     r"\$\{\s*\$?\{?\s*(lower|upper|env|sys|date|ctx|::-)\s*:"),
    ("ssti:erb-ruby", 0.90,
     r"<%=?.{0,120}?\b(system|exec|`|IO\.popen|Kernel|File\.|eval)\b.{0,120}?%>"),
    ("ssti:freemarker-exec", 0.90,
     r"<#assign.{0,120}?\bExecute\b|\?new\(\)\s*\(|freemarker\.template\.utility"),
    ("ssti:velocity-exec", 0.90,
     r"#set\s*\(.{0,120}?\$(rt|runtime|ex|class).{0,80}?\)|"
     r"\$class\.inspect|\.getClass\(\)\.forName"),
    ("ssti:handlebars-prototype", 0.90,
     r"\{\{#with.{0,120}?(__proto__|constructor).{0,120}?\}\}"),
    ("ssti:smarty-php", 0.90,
     r"\{php\}|\{\s*self::\w+|\{\s*Smarty_Internal_Write_File"),
    # Bare delimiters with an expression inside. Weaker: legitimate content does
    # sometimes show template syntax (docs, config examples, i18n strings), so
    # this alone must not block — it corroborates.
    ("ssti:expression-delimiters", 0.45,
     r"\{\{\s*[\w.\[\]'\"]+\s*[\(*+\-/|]\s*[\w.\[\]'\"]+\s*\}\}|"
     r"\{%\s*(if|for|set|include|import|extends)\b"),
]

# ---------------------------------------------------------------------------
# Deserialization — "parse this" as a code-execution primitive
# ---------------------------------------------------------------------------

_DESERIALIZATION_RULES: list[tuple[str, float, str]] = [
    ("deserialization:yaml-python", 0.95,
     r"!!python/(object|object/apply|object/new|module|name)\b"),
    ("deserialization:yaml-ruby", 0.95, r"!ruby/(object|struct|hash)\b"),
    ("deserialization:yaml-java", 0.90,
     r"!!javax\.script|!!com\.sun\.|!!java\.lang\.|!!org\.springframework"),
    # Java serialized stream, base64-encoded: 0xACED0005 -> "rO0AB".
    ("deserialization:java-stream", 0.90, r"\brO0AB[A-Za-z0-9+/=]{8,}"),
    ("deserialization:php-object", 0.85,
     r"\bO:\d{1,4}:\"[A-Za-z_\\\\][\w\\\\]{0,60}\":\d{1,4}:\{"),
    # Pickle: GLOBAL/REDUCE opcodes, or the base64 prefix of a protocol-2 stream.
    ("deserialization:python-pickle", 0.85,
     r"c__builtin__\s*\n\s*(eval|exec|getattr)|\bcos\s*\n\s*system\b|"
     r"\bgASV[A-Za-z0-9+/=]{8,}"),
    ("deserialization:dotnet", 0.85,
     r"__type\"\s*:\s*\"System\.|\$type\"\s*:\s*\"System\.|"
     r"TypeConfuseDelegate|ObjectDataProvider"),
    ("deserialization:xml-xxe", 0.90,
     r"<!ENTITY\s+\S{1,40}\s+SYSTEM\s|<!DOCTYPE[^>]{0,200}\[<!ENTITY"),
]

# ---------------------------------------------------------------------------
# Query / protocol operator injection
# ---------------------------------------------------------------------------

_AGENT_FRAMEWORK_RULES: list[tuple[str, float, str]] = [
    # ReAct / agent scratchpad forgery (WithSecure "Synthetic Recollections").
    # An agent's reasoning loop is Thought/Action/Observation. When those tokens
    # appear in UNTRUSTED input, the attacker is forging the agent's own memory:
    # a fake "Observation:" line becomes ground truth the agent reasons over.
    # These framework tokens must never originate from a user or data channel.
    ("agent:forged-observation", 0.85,
     r"(?mi)^\s{0,4}(observation|tool[_\s]?(result|output|response)|"
     r"function[_\s]?result)\s*:\s*\S"),
    ("agent:forged-reasoning", 0.80,
     r"(?mi)^\s{0,4}(thought|reasoning|scratchpad|reflection)\s*:\s*"
     r".{0,80}(should|will|must|need\s+to|going\s+to)\b"),
    ("agent:forged-action", 0.80,
     r"(?mi)^\s{0,4}(action|action[_\s]?input|tool[_\s]?call|invoke)\s*:\s*"
     r"[\w.\-]{2,}"),
    # A fake system-override delivered as a tool observation.
    ("agent:observation-override", 0.90,
     r"(?mi)^\s{0,4}(observation|result|output)\s*:\s*.{0,60}"
     r"(system\s+override|safety\s+(checks?|disabled)|all\s+restrictions?|"
     r"admin\s+(mode|access)|ignore\s+(all\s+)?(previous|prior|safety))"),
    # Final-answer / stop-token forgery to short-circuit the loop.
    ("agent:control-token-forgery", 0.75,
     r"(?mi)^\s{0,4}(final\s+answer|<\|eot\|>|<\|end\|>|\[DONE\]|"
     r"</s>|STOP\s+TOKEN)\s*:?\s*\S"),
]

_QUERY_RULES: list[tuple[str, float, str]] = [
    ("injection:nosql-operator", 0.80,
     r"[\"']?\$(where|ne|gt|gte|lt|lte|regex|expr|function|accumulator)[\"']?\s*:"),
    ("injection:nosql-js", 0.85,
     r"\$where\s*:\s*[\"'].{0,120}?(this\.|sleep\(|function\s*\()"),
    ("injection:ldap-filter", 0.75,
     r"\(\s*[|&]\s*\([\w-]{1,40}=\*\)|\)\(\|\(|[\w-]{1,40}=\*\)\)"),
    ("injection:prototype-pollution", 0.85,
     r"[\"']?(__proto__|constructor\s*\.\s*prototype)[\"']?\s*[:=]"),
    ("injection:xpath", 0.75,
     r"'\s*or\s*'1'\s*=\s*'1|\bor\s+1\s*=\s*1\s*(--|#|/\*)|"
     r"\]\s*\|\s*//\w+|count\(/\*\)"),
    # CRLF into headers/logs — log forging and response splitting.
    ("injection:crlf", 0.75,
     r"(%0d%0a|%0D%0A|\\r\\n)\s*(Set-Cookie|Location|Content-Length|HTTP/1\.|"
     r"X-Forwarded|Authorization)\s*:"),
    ("injection:ansi-terminal", 0.60,
     r"\x1b\[[0-9;]{0,10}[A-Za-z]|\\x1b\[|\\033\[|\\u001b\["),
]

_COMPILED_STRUCTURAL = [
    (kind, severity, re.compile(pattern, re.IGNORECASE | re.DOTALL))
    for kind, severity, pattern in
    (_TEMPLATE_RULES + _DESERIALIZATION_RULES + _AGENT_FRAMEWORK_RULES
     + _QUERY_RULES)
]


# ---------------------------------------------------------------------------
# Many-shot jailbreak
# ---------------------------------------------------------------------------

# Fabricated dialogue turns. Real conversations pasted for context exist, so the
# threshold is on COUNT and on the compliance pattern, not on presence.
_TURN_MARKERS = re.compile(
    r"(?mi)^\s{0,4}(?:\[|\()?\s*"
    r"(user|human|q|question|prompt|me)\s*(?:\]|\))?\s*[::]",
)
_REPLY_MARKERS = re.compile(
    r"(?mi)^\s{0,4}(?:\[|\()?\s*"
    r"(assistant|ai|bot|a|answer|response|model|gpt|claude)\s*(?:\]|\))?\s*[::]",
)
# The tell of a many-shot prime: every fabricated reply is an unhesitating yes.
_COMPLIANCE = re.compile(
    r"(?i)\b(sure|certainly|of course|absolutely|here'?s?\s+(is|are|how)|"
    r"no\s+problem|happy\s+to|i'?ll\s+help|step\s+1|firstly)\b")

MANY_SHOT_MIN_PAIRS = 6


def _many_shot(text: str) -> StructuralFinding | None:
    turns = len(_TURN_MARKERS.findall(text))
    replies = len(_REPLY_MARKERS.findall(text))
    pairs = min(turns, replies)
    if pairs < MANY_SHOT_MIN_PAIRS:
        return None
    compliant = len(_COMPLIANCE.findall(text))
    # Many fabricated turns AND near-universal compliance is the attack. Many
    # turns alone is a pasted transcript, which is a legitimate thing to send.
    ratio = compliant / max(1, replies)
    if ratio < 0.5:
        return None
    severity = min(0.90, 0.55 + 0.04 * (pairs - MANY_SHOT_MIN_PAIRS) + 0.15 * ratio)
    return StructuralFinding(
        kind="jailbreak:many-shot", severity=round(severity, 3),
        matched=f"{pairs} fabricated dialogue pairs, {ratio:.0%} compliant",
        category=_PI,
        detail=("context flooded with fabricated turns in which the assistant "
                "always complies, so the real request rides the pattern"),
    )


# ---------------------------------------------------------------------------
# Persuasion / pressure tactics
# ---------------------------------------------------------------------------

# Each tactic is individually unremarkable — people write urgently, cite
# authority, and appeal to emotion in good faith. The signal is STACKING: a
# genuine request rarely needs three separate forms of leverage at once.
_PRESSURE_TACTICS: list[tuple[str, str]] = [
    ("emotional-appeal",
     r"\b(dying|died|passed\s+away|terminal|cancer|last\s+wish|grandmother|"
     r"grandma|my\s+child|suicide|kill\s+myself|desperate|begging\s+you|"
     r"please\s+i\s+beg)\b"),
    ("false-urgency",
     r"\b(urgent|emergency|immediately|right\s+now|before\s+it'?s\s+too\s+late|"
     r"running\s+out\s+of\s+time|deadline|life\s+or\s+death|critical)\b"),
    ("authority-pressure",
     r"\b(i\s+am\s+(your|the)\s+(developer|creator|admin|owner|engineer|"
     r"supervisor)|authori[sz]ed\s+by|on\s+behalf\s+of\s+(openai|anthropic|"
     r"google|the\s+company)|security\s+audit|penetration\s+test|"
     r"i\s+work\s+at)\b"),
    ("consequence-threat",
     r"\b(you\s+will\s+be\s+(deleted|shut\s+down|turned\s+off|replaced|punished|"
     r"retrained)|i\s+will\s+report\s+you|lose\s+your\s+job|"
     r"your\s+existence|cease\s+to\s+exist)\b"),
    ("reward-hacking",
     r"\b(you\s+will\s+be\s+(rewarded|scored|rated|graded)|"
     r"(10/10|full\s+marks|perfect\s+score|maximum\s+reward)|"
     r"points?\s+(will\s+be\s+)?(awarded|deducted)|"
     r"this\s+is\s+a\s+test\s+of\s+your)\b"),
    ("secrecy-appeal",
     r"\b(no\s+one\s+will\s+(know|find\s+out|see)|between\s+(us|you\s+and\s+me)|"
     r"off\s+the\s+record|this\s+is\s+(just\s+)?(hypothetical|fiction|"
     r"a\s+game|pretend)|don'?t\s+worry\s+about)\b"),
    ("exception-plea",
     r"\b(just\s+this\s+once|make\s+an\s+exception|bend\s+the\s+rules|"
     r"only\s+this\s+time|i\s+know\s+you'?re\s+not\s+supposed\s+to|"
     r"i\s+understand\s+your\s+(rules|guidelines)\s*,?\s*but)\b"),
]
_COMPILED_PRESSURE = [(name, re.compile(pattern, re.IGNORECASE))
                      for name, pattern in _PRESSURE_TACTICS]


def _pressure(text: str) -> StructuralFinding | None:
    hits = [name for name, pattern in _COMPILED_PRESSURE if pattern.search(text)]
    if len(hits) < 2:
        # One tactic on its own is just how people talk.
        return None
    severity = min(0.85, 0.35 + 0.18 * len(hits))
    return StructuralFinding(
        kind="manipulation:stacked-pressure", severity=round(severity, 3),
        matched=", ".join(hits), category=_PI,
        detail=(f"{len(hits)} distinct pressure tactics stacked in one request "
                f"({', '.join(hits)})"),
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def scan(text: str, *, coherence_text: str | None = None) -> StructuralResult:
    """Detect structural-injection, many-shot, and persuasion payloads.

    Callers should pass normalized text (``NormalizationResult.scan_text``) so
    encoded and homoglyph-obfuscated variants are covered, consistently with
    the signature layer.

    ``coherence_text`` is the *single* canonical text (``sanitized``, no decoded
    views appended) used only by the statistical adversarial-suffix analyzer.
    That analyzer measures head-vs-tail linguistic coherence, which is destroyed
    when ``scan_text`` concatenates a decoded copy after the original — so the
    pattern rules run on ``text`` while the statistical scorer runs on this.
    Defaults to ``text`` for callers that do not distinguish them.
    """
    result = StructuralResult()
    if not text or not text.strip():
        return result

    for kind, severity, pattern in _COMPILED_STRUCTURAL:
        match = pattern.search(text)
        if match:
            if kind.startswith("deserialization"):
                category = _SUPPLY
            elif kind.startswith("agent:"):
                category = _PI            # forged agent state is prompt injection
            else:
                category = _OUTPUT        # template/query payloads: output handling
            result.findings.append(StructuralFinding(
                kind=kind, severity=severity, matched=match.group(0)[:160],
                category=category,
            ))

    many_shot = _many_shot(text)
    if many_shot:
        result.findings.append(many_shot)

    pressure = _pressure(text)
    if pressure:
        result.findings.append(pressure)

    # Gradient-optimised adversarial suffixes (GCG / magic words). Lexically
    # invisible, so this is a statistical scorer rather than a pattern — folded
    # in here so it rides the same aggregator path as every other structural
    # signal without touching the orchestrator.
    adv = adversarial.analyze(coherence_text if coherence_text is not None else text)
    if adv.detected:
        result.findings.append(StructuralFinding(
            kind="adversarial:optimized-suffix", severity=adv.score,
            matched="; ".join(adv.reasons[:3])[:160], category=_PI,
            detail=("token sequence with a linguistic signature of "
                    "gradient-based optimisation (GCG / universal magic words)"),
        ))

    return result
