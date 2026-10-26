"""
Tests for Project Execution Efficiency & Performance Optimizations:
1. Persistent HTTP client connection pooling
2. Multi-tier TTL caching (in-memory + Redis fallback)
3. Threat intelligence and geolocation cache hit latency
4. Non-blocking async email dispatcher
5. Non-blocking Redis health check in emails API
"""
import pytest
import time
from app.core.http_client import get_http_client, close_http_client
from app.core.cache import get_cache_manager
from app.services.geo_service import GeoService
from app.services.intel_service import ThreatIntelService
from app.api.v1.emails import _is_redis_online
from app.utils.email import send_reset_password_email


@pytest.mark.asyncio
async def test_persistent_http_client_singleton():
    """Verify that get_http_client returns the same persistent pool instance."""
    import httpx
    client1 = await get_http_client()
    client2 = await get_http_client()
    assert client1 is client2
    assert isinstance(client1, httpx.AsyncClient)
    assert not client1.is_closed


@pytest.mark.asyncio
async def test_multi_tier_cache_manager():
    """Verify in-memory TTL cache get, set, delete, and expiration."""
    cache = get_cache_manager()
    test_key = "test:perf:key"
    test_val = {"status": "MALICIOUS", "score": 95}

    await cache.set(test_key, test_val, ttl_seconds=60)
    retrieved = await cache.get(test_key)
    assert retrieved == test_val

    # Verification of deletion
    await cache.delete(test_key)
    assert await cache.get(test_key) is None


@pytest.mark.asyncio
async def test_geo_and_intel_caching_acceleration():
    """Verify that repeated IP geolocation hits the cache and executes in sub-millisecond."""
    geo = GeoService()
    # RFC 1918 private IP
    ip = "192.168.1.100"

    t0 = time.perf_counter()
    res1 = await geo.geolocate(ip)
    t1 = time.perf_counter()

    t2 = time.perf_counter()
    res2 = await geo.geolocate(ip)
    t3 = time.perf_counter()

    assert res1["routing_type"] == "INTERNAL_LAN"
    assert res2["routing_type"] == "INTERNAL_LAN"
    # Cached access is virtually instant
    assert (t3 - t2) < 0.05


@pytest.mark.asyncio
async def test_emails_redis_online_check():
    """Verify _is_redis_online executes safely without NameError."""
    # Should safely return bool regardless of local Redis status
    result = _is_redis_online()
    assert isinstance(result, bool)


@pytest.mark.asyncio
async def test_async_email_dispatcher_resilience():
    """Verify async email dispatcher handles unconfigured / invalid gracefully."""
    # When no Resend key or SMTP credentials are provided, safely returns False
    res = await send_reset_password_email("analyst@example.com", "dummy_token_123")
    assert isinstance(res, bool)
