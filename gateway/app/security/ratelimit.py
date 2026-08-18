"""Rate limiting + judge budget (S5) — DoS / resource-abuse defense.

Token-bucket rate limit per API key, plus a separate per-tenant JUDGE BUDGET so
an attacker cannot force expensive L4 escalation. Both use a monotonic clock and
work in-process (Redis-backed variant swaps in via the same interface).
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from app.config import settings


@dataclass
class _Bucket:
    tokens: float
    updated: float


class TokenBucket:
    """Classic token bucket: `rate` tokens/sec, capacity `burst`."""

    def __init__(self, rate_per_min: int, burst: int | None = None) -> None:
        self.rate = rate_per_min / 60.0
        self.burst = burst if burst is not None else max(1, rate_per_min)
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = time.monotonic()
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = _Bucket(tokens=float(self.burst), updated=now)
                self._buckets[key] = b
            # Refill.
            b.tokens = min(self.burst, b.tokens + (now - b.updated) * self.rate)
            b.updated = now
            if b.tokens >= cost:
                b.tokens -= cost
                return True
            return False


class JudgeBudget:
    """Per-tenant cap on L4 judge calls per rolling minute (S5)."""

    def __init__(self, per_min: int) -> None:
        self.per_min = per_min
        self._calls: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, tenant_id: str) -> bool:
        now = time.monotonic()
        with self._lock:
            calls = self._calls.setdefault(tenant_id, [])
            # Drop calls older than 60s.
            cutoff = now - 60.0
            calls[:] = [t for t in calls if t >= cutoff]
            if len(calls) >= self.per_min:
                return False
            calls.append(now)
            return True

    def remaining(self, tenant_id: str) -> int:
        now = time.monotonic()
        with self._lock:
            calls = [t for t in self._calls.get(tenant_id, []) if t >= now - 60.0]
            return max(0, self.per_min - len(calls))


# ---------------------------------------------------------------------------
# Redis-backed variants — REQUIRED for correctness across multiple replicas.
# In-memory limits are per-process, so behind a load balancer an attacker just
# spreads requests across pods. These share the same interface.
# ---------------------------------------------------------------------------
_TOKEN_BUCKET_LUA = """
local tokens = tonumber(redis.call('HGET', KEYS[1], 'tokens'))
local ts = tonumber(redis.call('HGET', KEYS[1], 'ts'))
local rate, burst, now, cost = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[4])
if tokens == nil then tokens = burst; ts = now end
tokens = math.min(burst, tokens + (now - ts) * rate)
local allowed = 0
if tokens >= cost then tokens = tokens - cost; allowed = 1 end
redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', KEYS[1], math.ceil(burst / rate) + 2)
return allowed
"""


class RedisTokenBucket:  # pragma: no cover - exercised with Redis available
    def __init__(self, url: str, rate_per_min: int, burst: int | None = None) -> None:
        import redis
        self._r = redis.Redis.from_url(url)
        self.rate = rate_per_min / 60.0
        self.burst = burst if burst is not None else max(1, rate_per_min)
        self._script = self._r.register_script(_TOKEN_BUCKET_LUA)

    def allow(self, key: str, cost: float = 1.0) -> bool:
        res = self._script(keys=[f"rl:{key}"],
                           args=[self.rate, self.burst, time.time(), cost])
        return bool(res)


class RedisJudgeBudget:  # pragma: no cover
    def __init__(self, url: str, per_min: int) -> None:
        import redis
        self._r = redis.Redis.from_url(url)
        self.per_min = per_min

    def allow(self, tenant_id: str) -> bool:
        # Fixed-window counter per minute; atomic INCR + EXPIRE.
        window = int(time.time() // 60)
        key = f"jb:{tenant_id}:{window}"
        n = self._r.incr(key)
        if n == 1:
            self._r.expire(key, 120)
        return n <= self.per_min

    def remaining(self, tenant_id: str) -> int:
        window = int(time.time() // 60)
        n = int(self._r.get(f"jb:{tenant_id}:{window}") or 0)
        return max(0, self.per_min - n)


def get_rate_limiter():
    if settings.redis_url:
        try:
            return RedisTokenBucket(settings.redis_url, settings.rate_limit_per_min)
        except Exception:  # noqa: BLE001
            pass
    return TokenBucket(settings.rate_limit_per_min)


def get_judge_budget():
    if settings.redis_url:
        try:
            return RedisJudgeBudget(settings.redis_url, settings.judge_budget_per_min)
        except Exception:  # noqa: BLE001
            pass
    return JudgeBudget(settings.judge_budget_per_min)
