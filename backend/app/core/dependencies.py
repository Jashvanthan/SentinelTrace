"""
SentinelTrace Backend — Core Dependencies
"""
from __future__ import annotations

import redis.asyncio as redis_async
from app.core.config import get_settings

settings = get_settings()

class RedisManager:
    def __init__(self):
        url = settings.REDIS_URL if settings.REDIS_URL else "redis://localhost:6379/0"
        if not (url.startswith("redis://") or url.startswith("rediss://") or url.startswith("unix://")):
            url = "redis://localhost:6379/0"
        try:
            self.client = redis_async.from_url(url, decode_responses=True)
        except Exception:
            self.client = redis_async.from_url("redis://localhost:6379/0", decode_responses=True)

    async def ping(self) -> bool:
        try:
            return await self.client.ping()
        except Exception:
            return False

    async def close(self):
        try:
            await self.client.aclose()
        except Exception:
            pass

redis_manager = RedisManager()

def get_redis():
    return redis_manager.client

