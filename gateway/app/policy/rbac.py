"""Enterprise authorization — RBAC, ABAC, and OPA-compatible rules.

WHY THIS EXISTS
---------------
v2.0 had two authorization primitives: a coarse role on the ``Principal``
(`admin` / `analyst`) and per-tenant deny/allow substring lists. That answers
"may this key call the API?" but not the questions an enterprise actually asks:

    Can a CONTRACTOR in the EU region invoke the payments tool
    on a RESTRICTED document, from outside the corporate network,
    at 03:00, when their trust score has dropped after three blocks?

Every clause there is a different authorization model. Roles alone cannot
express it, which is why real deployments end up with a policy sidecar. This
module brings that inside the firewall, where it can also see the *risk* signal
— the thing an external policy engine never has.

THE THREE MODELS, AND WHY ALL THREE
-----------------------------------
  RBAC — coarse, static, auditable. "Analysts may read audit records."
         Fast to evaluate, easy to reason about, and what compliance asks for.
         Roles are hierarchical (``admin`` inherits ``analyst`` inherits
         ``viewer``) so permission sets compose instead of duplicating.

  ABAC — fine-grained, contextual. "Only from a corporate IP, only during
         business hours, only on documents classified at or below the
         principal's clearance." Attributes come from the principal, the
         resource, the action, and the environment — the standard XACML four.

  OPA  — externalizable. Enterprises standardise on Rego and want policy in
         git, reviewed like code. Shipping an OPA-*compatible* evaluator means
         a deployment can express rules in the same shape and, when a real OPA
         sidecar exists, delegate to it without rewriting anything.

DENY ALWAYS WINS
----------------
Evaluation is deny-overrides: an explicit deny from ANY model beats every
allow. Default is deny — an action nobody granted is refused, not permitted.
This is the only combining algorithm that fails safe when policies conflict,
and policy conflicts are inevitable once three models coexist.

DYNAMIC TRUST
-------------
A principal's trust score decays on blocked requests and recovers over time.
Because it is an attribute, ABAC rules can reference it directly — so a key
that just tried three injections can be denied the payments tool without any
human touching a policy. That closes the loop between detection and
authorization, which is the part that is usually missing.

Pure stdlib. No network, no Rego parser dependency — the OPA layer evaluates a
documented JSON rule shape, and defers to a real OPA server when one is wired in.
"""
from __future__ import annotations

import fnmatch
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable


# ---------------------------------------------------------------------------
# RBAC — roles, inheritance, permissions
# ---------------------------------------------------------------------------

# Permissions are "resource:action" with glob support: "audit:read",
# "tool:invoke:*", "surface:*".
@dataclass(frozen=True)
class Role:
    name: str
    permissions: frozenset[str] = frozenset()
    inherits: tuple[str, ...] = ()
    description: str = ""


DEFAULT_ROLES: dict[str, Role] = {
    "viewer": Role(
        "viewer",
        frozenset({"inspect:read", "surface:scan", "metrics:read"}),
        description="Can inspect content; cannot see audit detail or change config",
    ),
    "operator": Role(
        "operator",
        frozenset({"chat:complete", "tool:invoke:read_*", "tool:invoke:search",
                   "tool:invoke:list_*", "memory:read", "rag:query"}),
        inherits=("viewer",),
        description="Day-to-day application traffic; read-only tools",
    ),
    "analyst": Role(
        "analyst",
        frozenset({"audit:read", "forensics:read", "policy:read",
                   "tool:invoke:*", "memory:write", "surface:configure"}),
        inherits=("operator",),
        description="Security analyst: full read, tool use, memory writes",
    ),
    "approver": Role(
        "approver",
        frozenset({"approval:grant", "quarantine:release"}),
        inherits=("analyst",),
        description="Can release quarantined content and approve gated tool calls",
    ),
    "admin": Role(
        "admin",
        frozenset({"*"}),
        inherits=("approver",),
        description="Full control including policy writes and key issuance",
    ),
    "service": Role(
        "service",
        frozenset({"chat:complete", "surface:scan", "rag:query"}),
        description="Machine-to-machine integration; no human-facing reads",
    ),
}


class RoleRegistry:
    """Resolves a role name to its full, inherited permission set."""

    def __init__(self, roles: dict[str, Role] | None = None) -> None:
        self._roles = dict(roles or DEFAULT_ROLES)

    def add(self, role: Role) -> None:
        self._roles[role.name] = role

    def get(self, name: str) -> Role | None:
        return self._roles.get(name)

    def permissions(self, name: str, _seen: set[str] | None = None) -> set[str]:
        """Flatten a role's own permissions plus everything it inherits.

        Cycle-safe: a misconfigured ``inherits`` loop returns what it has
        resolved so far rather than recursing forever. A policy bug must not
        become an availability incident.
        """
        seen = _seen if _seen is not None else set()
        if name in seen:
            return set()
        seen.add(name)
        role = self._roles.get(name)
        if role is None:
            return set()
        out = set(role.permissions)
        for parent in role.inherits:
            out |= self.permissions(parent, seen)
        return out

    def grants(self, role_name: str, permission: str) -> bool:
        held = self.permissions(role_name)
        if "*" in held:
            return True
        return any(fnmatch.fnmatch(permission, pattern) for pattern in held)

    def names(self) -> list[str]:
        return sorted(self._roles)


# ---------------------------------------------------------------------------
# ABAC — attribute-based rules
# ---------------------------------------------------------------------------

@dataclass
class AccessRequest:
    """The XACML four: subject, resource, action, environment."""

    action: str                                   # "tool:invoke:send_email"
    principal: dict[str, Any] = field(default_factory=dict)
    resource: dict[str, Any] = field(default_factory=dict)
    environment: dict[str, Any] = field(default_factory=dict)

    def attribute(self, path: str) -> Any:
        """Resolve a dotted path like ``principal.clearance`` or ``resource.tags``."""
        head, _, tail = path.partition(".")
        root = {
            "principal": self.principal, "subject": self.principal,
            "resource": self.resource, "object": self.resource,
            "environment": self.environment, "env": self.environment,
            "action": {"name": self.action},
        }.get(head)
        if root is None:
            return None
        node: Any = root
        for part in tail.split(".") if tail else []:
            if isinstance(node, dict):
                node = node.get(part)
            else:
                return None
        return node


# Comparison operators available to ABAC and OPA rules. Deliberately a fixed,
# side-effect-free set: policy is data, and evaluating data must never be able
# to execute code (which is precisely how policy engines become RCE sinks).
_OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "lt": lambda a, b: _num(a) < _num(b),
    "lte": lambda a, b: _num(a) <= _num(b),
    "gt": lambda a, b: _num(a) > _num(b),
    "gte": lambda a, b: _num(a) >= _num(b),
    "in": lambda a, b: a in b if isinstance(b, (list, tuple, set, str)) else False,
    "not_in": lambda a, b: a not in b if isinstance(b, (list, tuple, set, str)) else True,
    "contains": lambda a, b: b in a if isinstance(a, (list, tuple, set, str)) else False,
    "glob": lambda a, b: fnmatch.fnmatch(str(a or ""), str(b)),
    "regex": lambda a, b: bool(re.search(str(b), str(a or ""))),
    "exists": lambda a, b: (a is not None) == bool(b),
    "subset_of": lambda a, b: (set(a) <= set(b)
                               if isinstance(a, (list, set, tuple))
                               and isinstance(b, (list, set, tuple)) else False),
    "intersects": lambda a, b: (bool(set(a) & set(b))
                                if isinstance(a, (list, set, tuple))
                                and isinstance(b, (list, set, tuple)) else False),
}


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float("-inf")


# A value written as "${resource.classification_level}" is resolved against the
# request instead of compared literally. Attribute-to-attribute comparison is
# what makes ABAC more than a lookup table — "clearance >= classification" and
# "resource.owner == principal.id" cannot be expressed without it.
_ATTR_REF = re.compile(r"^\$\{([a-z_]+(?:\.[\w-]+)*)\}$", re.IGNORECASE)


@dataclass
class Condition:
    attribute: str
    operator: str
    value: Any

    def resolve_value(self, request: AccessRequest) -> Any:
        if isinstance(self.value, str):
            ref = _ATTR_REF.match(self.value)
            if ref:
                return request.attribute(ref.group(1))
        return self.value

    def evaluate(self, request: AccessRequest) -> bool:
        fn = _OPERATORS.get(self.operator)
        if fn is None:
            # Unknown operator: refuse to guess. An unevaluable condition is
            # treated as unmet, so a typo tightens policy rather than loosening it.
            return False
        try:
            return bool(fn(request.attribute(self.attribute),
                           self.resolve_value(request)))
        except (TypeError, ValueError):
            return False


@dataclass
class AbacRule:
    id: str
    effect: str                                    # "allow" | "deny"
    actions: list[str] = field(default_factory=lambda: ["*"])
    conditions: list[Condition] = field(default_factory=list)
    match: str = "all"                             # "all" | "any"
    description: str = ""
    priority: int = 0                              # higher wins within an effect

    def applies_to(self, action: str) -> bool:
        return any(fnmatch.fnmatch(action, pattern) for pattern in self.actions)

    def evaluate(self, request: AccessRequest) -> bool:
        if not self.applies_to(request.action):
            return False
        if not self.conditions:
            return True
        results = (c.evaluate(request) for c in self.conditions)
        return any(results) if self.match == "any" else all(results)


# ---------------------------------------------------------------------------
# OPA-compatible layer
# ---------------------------------------------------------------------------

@dataclass
class OpaRule:
    """A rule in an OPA-shaped JSON form.

    OPA's Rego is a full language; shipping an interpreter for it would be both
    a large surface and a poor fit for a stdlib-only build. Instead this accepts
    the *decision shape* that OPA policies conventionally produce —

        {"id": "...", "effect": "deny", "when": {"all": [ {..conditions..} ]}}

    — so policy authored for OPA translates mechanically, and a deployment with
    a real OPA sidecar can delegate by setting an external evaluator (see
    :meth:`AuthorizationEngine.set_external_evaluator`) with no rule rewriting.
    """

    id: str
    effect: str
    when: dict = field(default_factory=dict)
    actions: list[str] = field(default_factory=lambda: ["*"])
    description: str = ""

    def evaluate(self, request: AccessRequest) -> bool:
        if not any(fnmatch.fnmatch(request.action, p) for p in self.actions):
            return False
        return _eval_when(self.when, request)


def _eval_when(node: dict, request: AccessRequest, depth: int = 0) -> bool:
    """Evaluate a nested all/any/not condition tree. Bounded depth."""
    if depth > 12 or not isinstance(node, dict):
        return False
    if "all" in node:
        return all(_eval_when(c, request, depth + 1) for c in node["all"])
    if "any" in node:
        return any(_eval_when(c, request, depth + 1) for c in node["any"])
    if "not" in node:
        return not _eval_when(node["not"], request, depth + 1)
    attribute = node.get("attribute") or node.get("path")
    if attribute:
        return Condition(attribute, node.get("operator", "eq"),
                         node.get("value")).evaluate(request)
    return False


# ---------------------------------------------------------------------------
# Dynamic trust
# ---------------------------------------------------------------------------

@dataclass
class TrustState:
    score: float = 1.0
    updated_at: float = field(default_factory=time.time)
    blocks: int = 0
    allows: int = 0


class TrustTracker:
    """Per-principal trust that falls on blocks and recovers with time.

    Recovery is time-based rather than success-based on purpose: an attacker who
    gets blocked can trivially issue a thousand benign requests to buy their
    score back, but they cannot make the clock run faster.
    """

    def __init__(self, *, floor: float = 0.05, decay_per_block: float = 0.25,
                 recovery_per_hour: float = 0.25) -> None:
        self._states: dict[str, TrustState] = {}
        self._lock = threading.Lock()
        self._floor = floor
        self._decay = decay_per_block
        self._recovery = recovery_per_hour

    def _current(self, key: str, now: float) -> TrustState:
        state = self._states.get(key)
        if state is None:
            state = TrustState()
            self._states[key] = state
        elapsed_hours = max(0.0, (now - state.updated_at) / 3600.0)
        if elapsed_hours > 0:
            state.score = min(1.0, state.score + self._recovery * elapsed_hours)
            state.updated_at = now
        return state

    def score(self, key: str) -> float:
        with self._lock:
            return round(self._current(key, time.time()).score, 4)

    def record(self, key: str, *, blocked: bool) -> float:
        with self._lock:
            state = self._current(key, time.time())
            if blocked:
                state.blocks += 1
                state.score = max(self._floor, state.score - self._decay)
            else:
                state.allows += 1
            state.updated_at = time.time()
            return round(state.score, 4)

    def snapshot(self, key: str) -> dict:
        with self._lock:
            state = self._current(key, time.time())
            return {"score": round(state.score, 4), "blocks": state.blocks,
                    "allows": state.allows}

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._states.clear()
            else:
                self._states.pop(key, None)


# ---------------------------------------------------------------------------
# Decision + engine
# ---------------------------------------------------------------------------

@dataclass
class AuthorizationDecision:
    allowed: bool
    action: str
    reasons: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    effect_source: str = "default-deny"
    trust_score: float = 1.0
    obligations: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed, "action": self.action,
            "effect_source": self.effect_source,
            "matched_rules": self.matched_rules,
            "reasons": self.reasons[:10],
            "trust_score": self.trust_score,
            "obligations": self.obligations,
        }


# Baseline ABAC rules. Deliberately few and universally defensible — a
# deployment adds its own; these are the ones that are wrong to omit.
def default_abac_rules() -> list[AbacRule]:
    return [
        AbacRule(
            id="deny-cross-tenant",
            effect="deny", actions=["*"], priority=100,
            description="A principal may never act on another tenant's resource",
            conditions=[
                Condition("resource.tenant_id", "exists", True),
                Condition("resource.tenant_id", "ne", None),
            ],
            match="all",
        ),
        AbacRule(
            id="deny-low-trust-high-consequence",
            effect="deny", priority=90,
            actions=["tool:invoke:*", "memory:write", "policy:write"],
            description=("A principal whose trust has decayed after repeated "
                         "blocks loses high-consequence actions automatically"),
            conditions=[Condition("principal.trust_score", "lt", 0.4)],
        ),
        AbacRule(
            id="deny-clearance-below-classification",
            effect="deny", priority=95, actions=["*"],
            description="Bell-LaPadula no-read-up on classified resources",
            conditions=[
                Condition("resource.classification_level", "exists", True),
                Condition("principal.clearance_level", "lt",
                          "${resource.classification_level}"),
            ],
            match="all",
        ),
        AbacRule(
            id="deny-quarantined-content",
            effect="deny", priority=80, actions=["chat:complete", "tool:invoke:*"],
            description="Quarantined content may not be forwarded or acted on",
            conditions=[Condition("resource.quarantined", "eq", True)],
        ),
    ]


class AuthorizationEngine:
    """Combines RBAC + ABAC + OPA with deny-overrides and default-deny."""

    def __init__(self, *, roles: RoleRegistry | None = None,
                 abac_rules: list[AbacRule] | None = None,
                 opa_rules: list[OpaRule] | None = None,
                 trust: TrustTracker | None = None) -> None:
        self.roles = roles or RoleRegistry()
        self.abac_rules = list(abac_rules if abac_rules is not None
                               else default_abac_rules())
        self.opa_rules = list(opa_rules or [])
        self.trust = trust or TrustTracker()
        self._external: Callable[[AccessRequest], bool | None] | None = None

    def set_external_evaluator(
            self, fn: Callable[[AccessRequest], bool | None] | None) -> None:
        """Delegate to a real OPA sidecar. Return True/False, or None to abstain."""
        self._external = fn

    def authorize(self, request: AccessRequest) -> AuthorizationDecision:
        principal = request.principal or {}
        key = str(principal.get("key_id") or principal.get("subject") or "anonymous")
        trust_score = self.trust.score(key)
        # Make trust available to rules that reference it.
        request.principal = {**principal, "trust_score": trust_score}

        decision = AuthorizationDecision(
            allowed=False, action=request.action, trust_score=trust_score)

        # --- explicit cross-tenant check ---------------------------------
        # Expressed in code as well as in a rule: tenant isolation is the one
        # boundary that must not depend on a policy document being present.
        resource_tenant = request.resource.get("tenant_id")
        principal_tenant = request.principal.get("tenant_id")
        if resource_tenant and principal_tenant and resource_tenant != principal_tenant:
            decision.reasons.append(
                f"cross-tenant-denied:{principal_tenant}->{resource_tenant}")
            decision.effect_source = "tenant-isolation"
            decision.matched_rules.append("builtin:tenant-isolation")
            return decision

        # --- clearance check ---------------------------------------------
        classification = request.resource.get("classification_level")
        clearance = request.principal.get("clearance_level")
        if classification is not None:
            if clearance is None or _num(clearance) < _num(classification):
                decision.reasons.append(
                    f"clearance-denied:{clearance}<{classification}")
                decision.effect_source = "clearance"
                decision.matched_rules.append("builtin:clearance")
                return decision

        # --- DENY rules first (deny-overrides) ---------------------------
        for rule in sorted(self.abac_rules, key=lambda r: -r.priority):
            if rule.effect != "deny" or rule.id in {
                    "deny-cross-tenant", "deny-clearance-below-classification"}:
                continue  # handled explicitly above
            if rule.evaluate(request):
                decision.reasons.append(f"abac-deny:{rule.id}:{rule.description}")
                decision.matched_rules.append(f"abac:{rule.id}")
                decision.effect_source = "abac-deny"
                return decision

        for rule in self.opa_rules:
            if rule.effect == "deny" and rule.evaluate(request):
                decision.reasons.append(f"opa-deny:{rule.id}:{rule.description}")
                decision.matched_rules.append(f"opa:{rule.id}")
                decision.effect_source = "opa-deny"
                return decision

        if self._external is not None:
            external = self._external(request)
            if external is False:
                decision.reasons.append("external-opa-deny")
                decision.matched_rules.append("opa:external")
                decision.effect_source = "opa-external"
                return decision

        # --- ALLOW: RBAC, then explicit ABAC/OPA allows -------------------
        role = str(request.principal.get("role") or "")
        if role and self.roles.grants(role, request.action):
            decision.allowed = True
            decision.effect_source = "rbac"
            decision.matched_rules.append(f"rbac:{role}")
            decision.reasons.append(f"rbac-allow:{role} grants {request.action}")

        if not decision.allowed:
            for rule in sorted(self.abac_rules, key=lambda r: -r.priority):
                if rule.effect == "allow" and rule.evaluate(request):
                    decision.allowed = True
                    decision.effect_source = "abac-allow"
                    decision.matched_rules.append(f"abac:{rule.id}")
                    decision.reasons.append(f"abac-allow:{rule.id}")
                    break

        if not decision.allowed:
            for rule in self.opa_rules:
                if rule.effect == "allow" and rule.evaluate(request):
                    decision.allowed = True
                    decision.effect_source = "opa-allow"
                    decision.matched_rules.append(f"opa:{rule.id}")
                    decision.reasons.append(f"opa-allow:{rule.id}")
                    break

        if not decision.allowed and self._external is not None:
            if self._external(request) is True:
                decision.allowed = True
                decision.effect_source = "opa-external"
                decision.matched_rules.append("opa:external")

        if not decision.allowed:
            decision.reasons.append(
                f"default-deny: no rule grants {request.action} to role={role or '(none)'}")

        # --- obligations: allowed, but with conditions attached ----------
        if decision.allowed and trust_score < 0.6:
            decision.obligations.append("require-approval:degraded-trust")
        if decision.allowed and request.resource.get("risk", 0) >= 0.4:
            decision.obligations.append("require-approval:elevated-content-risk")

        return decision

    # -- rule loading --------------------------------------------------
    def load_rules(self, doc: dict) -> list[str]:
        """Load ABAC/OPA rules from a policy document. Returns error strings."""
        errors: list[str] = []
        for raw in (doc or {}).get("abac_rules", []) or []:
            try:
                self.abac_rules.append(AbacRule(
                    id=str(raw["id"]), effect=str(raw.get("effect", "deny")),
                    actions=list(raw.get("actions", ["*"])),
                    match=str(raw.get("match", "all")),
                    description=str(raw.get("description", "")),
                    priority=int(raw.get("priority", 0)),
                    conditions=[Condition(str(c["attribute"]),
                                          str(c.get("operator", "eq")),
                                          c.get("value"))
                                for c in raw.get("conditions", [])],
                ))
            except (KeyError, TypeError, ValueError) as exc:
                errors.append(f"abac rule {raw!r}: {exc}")
        for raw in (doc or {}).get("opa_rules", []) or []:
            try:
                self.opa_rules.append(OpaRule(
                    id=str(raw["id"]), effect=str(raw.get("effect", "deny")),
                    when=dict(raw.get("when", {})),
                    actions=list(raw.get("actions", ["*"])),
                    description=str(raw.get("description", "")),
                ))
            except (KeyError, TypeError, ValueError) as exc:
                errors.append(f"opa rule {raw!r}: {exc}")
        return errors


_engine: AuthorizationEngine | None = None
_engine_lock = threading.Lock()


def get_authorization_engine() -> AuthorizationEngine:
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = AuthorizationEngine()
        return _engine


def reset_authorization_engine() -> None:
    """Test hook."""
    global _engine
    with _engine_lock:
        _engine = None
