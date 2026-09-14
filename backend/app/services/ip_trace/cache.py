"""
SentinelTrace Backend — IP Trace Cache & Rate Limiting Guard
"""
from __future__ import annotations

import time
from typing import Any

from app.core.logging import get_logger

logger = get_logger("sentineltrace.ip_trace.cache")

# Fast in-memory cache with expiration timestamp: { ip: (expiry_epoch, payload) }
_IP_TRACE_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
DEFAULT_CACHE_TTL_SECONDS = 3600  # 1 hour


def get_cached_trace(ip: str) -> dict[str, Any] | None:
    """Retrieve cached IP trace result if still within TTL."""
    clean_ip = ip.strip()
    entry = _IP_TRACE_CACHE.get(clean_ip)
    if entry:
        expires_at, data = entry
        if time.time() < expires_at:
            return data
        else:
            del _IP_TRACE_CACHE[clean_ip]
    return None


def set_cached_trace(ip: str, data: dict[str, Any], ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS) -> None:
    """Store IP trace result with TTL."""
    clean_ip = ip.strip()
    _IP_TRACE_CACHE[clean_ip] = (time.time() + ttl_seconds, data)
