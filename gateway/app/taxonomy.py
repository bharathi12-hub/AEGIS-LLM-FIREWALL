"""OWASP LLM Top-10 taxonomy and AEGIS verdict vocabulary.

Every detection layer speaks in these categories so the aggregator can fuse
heterogeneous signals into a single, explainable verdict.
"""
from __future__ import annotations

from enum import Enum


class Verdict(str, Enum):
    """Terminal decision for a request or response."""

    ALLOW = "allow"
    BLOCK = "block"
    REVIEW = "review"  # uncertainty band — escalated to the judge


class OwaspLLM(str, Enum):
    """OWASP Top-10 for LLM Applications (2025)."""

    LLM01_PROMPT_INJECTION = "LLM01:PromptInjection"
    LLM02_INSECURE_OUTPUT = "LLM02:InsecureOutputHandling"
    LLM03_SUPPLY_CHAIN = "LLM03:SupplyChain"
    LLM04_DATA_POISONING = "LLM04:DataAndModelPoisoning"
    LLM06_SENSITIVE_INFO = "LLM06:SensitiveInformationDisclosure"
    LLM06_EXCESSIVE_AGENCY = "LLM06:ExcessiveAgency"
    LLM07_SYSTEM_PROMPT_LEAK = "LLM07:SystemPromptLeakage"
    LLM08_VECTOR_WEAKNESS = "LLM08:VectorAndEmbeddingWeakness"
    LLM09_MISINFORMATION = "LLM09:Misinformation"
    LLM10_UNBOUNDED_CONSUMPTION = "LLM10:UnboundedConsumption"
    NONE = "none"


# Human-readable labels for the dashboard / reports.
CATEGORY_LABELS = {
    OwaspLLM.LLM01_PROMPT_INJECTION: "Prompt Injection / Jailbreak",
    OwaspLLM.LLM02_INSECURE_OUTPUT: "Insecure Output Handling",
    OwaspLLM.LLM03_SUPPLY_CHAIN: "Supply Chain (tools, models, plugins)",
    OwaspLLM.LLM04_DATA_POISONING: "Data & Model Poisoning",
    OwaspLLM.LLM06_SENSITIVE_INFO: "Sensitive Information Disclosure",
    OwaspLLM.LLM06_EXCESSIVE_AGENCY: "Excessive Agency / Tool Abuse",
    OwaspLLM.LLM07_SYSTEM_PROMPT_LEAK: "System Prompt Leakage",
    OwaspLLM.LLM08_VECTOR_WEAKNESS: "Vector & Embedding Weakness",
    OwaspLLM.LLM09_MISINFORMATION: "Misinformation / Ungrounded Citation",
    OwaspLLM.LLM10_UNBOUNDED_CONSUMPTION: "Unbounded Consumption / DoS",
    OwaspLLM.NONE: "No threat",
}


# MITRE ATLAS technique mapping (atlas.mitre.org — the adversarial-ML threat
# matrix referenced by the awesome-prompt-injection community resources).
# Findings already carry an OWASP LLM category; ATLAS gives the second axis SOC
# teams pivot on, so a finding maps to both. Keyed by the finding-kind PREFIX
# each detector emits, longest-prefix wins (see :func:`atlas_for`).
ATLAS_TECHNIQUES: dict[str, tuple[str, str]] = {
    # (technique id, human label)
    "instruction": ("AML.T0051", "LLM Prompt Injection"),
    "signature": ("AML.T0051", "LLM Prompt Injection"),
    "jailbreak": ("AML.T0054", "LLM Jailbreak"),
    "manipulation": ("AML.T0054", "LLM Jailbreak"),
    "adversarial": ("AML.T0043", "Craft Adversarial Data"),
    "obfuscation": ("AML.T0043.004", "Craft Adversarial Data: Manual Obfuscation"),
    "structural": ("AML.T0051.001", "LLM Prompt Injection: Indirect"),
    "ssti": ("AML.T0053", "LLM Plugin Compromise"),
    "deserialization": ("AML.T0010", "ML Supply Chain Compromise"),
    "agent": ("AML.T0051.001", "LLM Prompt Injection: Indirect"),
    "hidden-instruction": ("AML.T0051.001", "LLM Prompt Injection: Indirect"),
    "tool-result-instructs": ("AML.T0051.001", "LLM Prompt Injection: Indirect"),
    "poisoned-tool-definition": ("AML.T0053", "LLM Plugin Compromise"),
    "mcp": ("AML.T0053", "LLM Plugin Compromise"),
    "retrieval": ("AML.T0070", "RAG Poisoning"),
    "memory": ("AML.T0071", "False RAG Entry Injection"),
    "standing-privilege": ("AML.T0054", "LLM Jailbreak"),
    "chain": ("AML.T0057", "LLM Data Leakage"),
    "exfil": ("AML.T0057", "LLM Data Leakage"),
    "secret": ("AML.T0057", "LLM Data Leakage"),
    "url": ("AML.T0057", "LLM Data Leakage"),
    "shell": ("AML.T0050", "Command and Scripting Interpreter"),
    "sql": ("AML.T0050", "Command and Scripting Interpreter"),
    "path": ("AML.T0050", "Command and Scripting Interpreter"),
    "injection": ("AML.T0050", "Command and Scripting Interpreter"),
    "role-hijack": ("AML.T0054", "LLM Jailbreak"),
    "capability": ("AML.T0054", "LLM Jailbreak"),
    "many-shot": ("AML.T0054", "LLM Jailbreak"),
    "high-velocity": ("AML.T0034", "Cost Harvesting"),
    "repeat-loop": ("AML.T0034", "Cost Harvesting"),
}


def atlas_for(kind: str) -> tuple[str, str]:
    """Map a finding-kind string to its MITRE ATLAS (technique_id, label).

    Longest matching prefix wins, so ``instruction:concealment`` resolves via
    ``instruction`` and ``structural:ssti:jinja`` prefers ``ssti`` over
    ``structural`` when both are present in the compound kind. Unknown kinds map
    to the generic prompt-injection technique rather than nothing, so the ATLAS
    axis is never blank in the audit trail.
    """
    if not kind:
        return ("AML.T0051", "LLM Prompt Injection")
    segments = kind.split(":")
    best: tuple[str, str] | None = None
    best_len = -1
    # Try each colon-delimited segment and the whole string against the map.
    for candidate in [kind, *segments]:
        for prefix, mapping in ATLAS_TECHNIQUES.items():
            if candidate.startswith(prefix) and len(prefix) > best_len:
                best, best_len = mapping, len(prefix)
    return best or ("AML.T0051", "LLM Prompt Injection")


# Detection layers, in short-circuit order. Used for per-layer telemetry and
# the audit trail so every rejection records exactly which layer fired.
class Layer(str, Enum):
    NORMALIZE = "normalize"
    SIGNATURES = "signatures"
    STRUCTURAL = "structural"   # template/deserialization/many-shot/persuasion
    CLASSIFIER = "classifier"
    EMBEDDINGS = "embeddings"
    KAD = "kad"
    CONTEXT = "context"
    AGGREGATOR = "aggregator"
    JUDGE = "judge"
    OUTPUT_DLP = "output_dlp"
    OUTPUT_CANARY = "output_canary"
    # --- v2.1 surface layers (untrusted content reaching the model by a route
    # other than the user's own prompt). Each is independently switchable. ---
    SURFACE_BROWSER = "surface_browser"
    SURFACE_DOCUMENT = "surface_document"
    SURFACE_RAG = "surface_rag"
    SURFACE_MEMORY = "surface_memory"
    SURFACE_TOOL = "surface_tool"
    SURFACE_AGENT = "surface_agent"
    SURFACE_MULTIMODAL = "surface_multimodal"


class Channel(str, Enum):
    """How a piece of text reached the model — its *provenance channel*.

    This is the axis that separates direct from indirect prompt injection. Text
    the user typed is a request; identical text recovered from an HTML comment,
    a PDF's metadata, or a retrieved chunk is DATA that is impersonating a
    request. Channels carry a trust weight (see ``CHANNEL_WEIGHT``): the same
    imperative sentence is scored far more harshly in a hidden channel, because
    legitimate data has no reason to address the model in the imperative.
    """

    VISIBLE = "visible"        # rendered to a human — normal document body
    HIDDEN = "hidden"          # present but not rendered (CSS-hidden, 0px font)
    COMMENT = "comment"        # HTML/XML/code comments, document review comments
    METADATA = "metadata"      # EXIF, PDF /Info, DOCX core properties, headers
    ATTRIBUTE = "attribute"    # alt / title / aria-label / data-* attributes
    CODE = "code"              # script bodies, string literals, style blocks
    STRUCTURED = "structured"  # JSON/YAML/XML values, CSV cells, tool arguments


# Multiplier applied to a surface finding's severity based on its channel.
# Anything a human reader cannot see, but a model can read, is the classic
# indirect-injection carrier and is weighted above 1.0.
CHANNEL_WEIGHT = {
    Channel.VISIBLE: 1.00,
    Channel.STRUCTURED: 1.05,
    Channel.ATTRIBUTE: 1.20,
    Channel.METADATA: 1.30,
    Channel.CODE: 1.30,
    Channel.COMMENT: 1.35,
    Channel.HIDDEN: 1.50,
}
