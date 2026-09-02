"""
SentinelTrace Backend — Core Dependencies
"""
from __future__ import annotations

import redis.asyncio as redis_async
from app.core.config import get_settings

settings = get_settings()

class RedisManager:
    def __init__(self):
        self.client = redis_async.from_url(settings.REDIS_URL, decode_responses=True)

    async def ping(self) -> bool:
        try:
            return await self.client.ping()
        except Exception:
            return False

    async def close(self):
        await self.client.aclose()

redis_manager = RedisManager()

def get_redis():
    return redis_manager.client
