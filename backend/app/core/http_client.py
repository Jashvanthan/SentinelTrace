"""
SentinelTrace Backend — Global HTTP Client Manager

Provides high-performance persistent connection pooling for outgoing HTTP requests:
- Geolocation API lookups (ipwho.is, ip-api.com, ipinfo.io)
- Threat intelligence providers (VirusTotal, AbuseIPDB, Shodan)
- Resend / external webhook notification calls

Reusing connections avoids repeated TCP/TLS handshakes, saves CPU cycles,
prevents ephemeral socket exhaustion, and drastically cuts request latencies.
"""
from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from app.core.logging import get_logger

logger = get_logger("sentineltrace.http_client")

_http_client: Optional[httpx.AsyncClient] = None
_client_lock = asyncio.Lock()


def get_default_limits() -> httpx.Limits:
    """Configures high-throughput connection limits for concurrent async tasks."""
    return httpx.Limits(
        max_connections=100,
        max_keepalive_connections=50,
        keepalive_expiry=30.0,
    )


def get_default_timeout() -> httpx.Timeout:
    """Default HTTP timeout bounds."""
    return httpx.Timeout(
        connect=5.0,
        read=12.0,
        write=8.0,
        pool=5.0,
    )


async def get_http_client() -> httpx.AsyncClient:
    """
    Retrieve or initialize the singleton AsyncClient instance.
    Safe for high-concurrency event-loop operations and multiple test loops.
    """
    global _http_client
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None

    if _http_client is not None and not _http_client.is_closed:
        loop_closed = False
        try:
            transport = getattr(_http_client, "_transport", None)
            pool = getattr(transport, "_pool", None)
            pool_loop = getattr(pool, "_loop", None)
            if pool_loop is not None and (pool_loop.is_closed() or pool_loop != current_loop):
                loop_closed = True
        except Exception:
            pass

        if not loop_closed:
            return _http_client
        else:
            _http_client = None

    _http_client = httpx.AsyncClient(
        limits=get_default_limits(),
        timeout=get_default_timeout(),
        follow_redirects=True,
        headers={"User-Agent": "SentinelTrace-Forensics/1.0"},
    )
    logger.info("persistent_http_client_initialized")
    return _http_client


async def close_http_client() -> None:
    """Gracefully close the singleton AsyncClient on application shutdown."""
    global _http_client
    if _http_client is not None and not _http_client.is_closed:
        try:
            await _http_client.aclose()
            logger.info("persistent_http_client_closed")
        except Exception as e:
            logger.warning("persistent_http_client_close_error", error=str(e))
        finally:
            _http_client = None

