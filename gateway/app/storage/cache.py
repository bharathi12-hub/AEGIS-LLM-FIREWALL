"""Cache abstraction (Redis in Docker; in-memory otherwise).

Used for classifier result caching (by prompt hash), per-session context windows,
and canary/session state. The interface is tiny and identical across backends so
the pipeline never knows which one it is talking to.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any

from app.config import settings


class InMemoryCache:
    def __init__(self) -> None:
        self._data: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()

    def get_json(self, key: str) -> Any | None:
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            expires, raw = item
            if expires and expires < time.time():
                self._data.pop(key, None)
                return None
            return json.loads(raw)

    def set_json(self, key: str, value: Any, ttl: int = 600) -> None:
        with self._lock:
            expires = time.time() + ttl if ttl else 0
            self._data[key] = (expires, json.dumps(value))


class RedisCache:  # pragma: no cover - exercised only with Redis available
    def __init__(self, url: str) -> None:
        import redis  # type: ignore
        self._r = redis.Redis.from_url(url, decode_responses=True)

    def get_json(self, key: str) -> Any | None:
        raw = self._r.get(key)
        return json.loads(raw) if raw else None

    def set_json(self, key: str, value: Any, ttl: int = 600) -> None:
        self._r.set(key, json.dumps(value), ex=ttl or None)


_cache = None


def get_cache():
    global _cache
    if _cache is None:
        if settings.redis_url:
            try:
                _cache = RedisCache(settings.redis_url)
            except Exception:  # noqa: BLE001
                _cache = InMemoryCache()
        else:
            _cache = InMemoryCache()
    return _cache
