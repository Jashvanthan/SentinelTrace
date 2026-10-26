"""
SentinelTrace Backend — Unified Multi-Tier Cache Manager

Provides two-tier caching:
- Tier 1: In-memory TTL cache (sub-millisecond local cache with auto-expiration)
- Tier 2: Redis cache (distributed cache across multiple workers/nodes if Redis is online)

Significantly accelerates IOC threat intelligence lookups, IP geolocations,
and reverse DNS resolutions, while protecting external API quotas.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Optional

from app.core.dependencies import redis_manager
from app.core.logging import get_logger

logger = get_logger("sentineltrace.cache")


class InMemoryTTLCache:
    """Thread-safe, lightweight in-memory cache with per-key TTL."""

    def __init__(self, max_items: int = 5000):
        self._store: dict[str, tuple[float, Any]] = {}
        self._max_items = max_items
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        now = time.monotonic()
        async with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            expiry, value = item
            if now > expiry:
                del self._store[key]
                return None
            return value

    async def set(self, key: str, value: Any, ttl_seconds: int = 3600) -> None:
        now = time.monotonic()
        expiry = now + ttl_seconds
        async with self._lock:
            if len(self._store) >= self._max_items:
                # Evict expired keys or oldest entry
                expired_keys = [k for k, (exp, _) in self._store.items() if exp < now]
                if expired_keys:
                    for k in expired_keys[:100]:
                        del self._store[k]
                else:
                    # Pop first 50 keys if none expired
                    for k in list(self._store.keys())[:50]:
                        del self._store[k]
            self._store[key] = (expiry, value)

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._store.pop(key, None)

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()


class CacheManager:
    """Coordinates local memory and Redis cache tiers."""

    def __init__(self):
        self.memory = InMemoryTTLCache(max_items=10000)

    async def get(self, key: str) -> Optional[Any]:
        # Check Tier 1: In-memory
        val = await self.memory.get(key)
        if val is not None:
            return val

        # Check Tier 2: Redis
        try:
            redis_client = redis_manager.client
            raw = await redis_client.get(key)
            if raw:
                try:
                    deserialized = json.loads(raw)
                except Exception:
                    deserialized = raw
                # Populate Tier 1 for next request
                await self.memory.set(key, deserialized, ttl_seconds=600)
                return deserialized
        except Exception:
            # Redis offline or unavailable, fallback gracefully
            pass

        return None

    async def set(self, key: str, value: Any, ttl_seconds: int = 3600) -> None:
        # Write Tier 1: In-memory
        await self.memory.set(key, value, ttl_seconds=ttl_seconds)

        # Write Tier 2: Redis
        try:
            redis_client = redis_manager.client
            serialized = json.dumps(value, default=str)
            await redis_client.set(key, serialized, ex=ttl_seconds)
        except Exception:
            pass

    async def delete(self, key: str) -> None:
        await self.memory.delete(key)
        try:
            await redis_manager.client.delete(key)
        except Exception:
            pass


cache_manager = CacheManager()


def get_cache_manager() -> CacheManager:
    return cache_manager
