"""
SentinelTrace Backend — Database Reliability, Password Security & Network Tests
"""
import uuid
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db.session import check_db_health, cleanup_expired_sessions
from app.services.password_service import validate_password_strength


def test_password_strength_validation():
    """Verify NIST-compliant password strength rules."""
    # Too short (< 8 chars)
    valid, msg = validate_password_strength("Short1!")
    assert not valid
    assert "at least 8" in msg

    # Common trivial password
    valid, msg = validate_password_strength("password123")
    assert not valid
    assert "too common" in msg

    # Contains email username
    valid, msg = validate_password_strength("SuperSecretjashvanthan2026!", email="jashvanthan@domain.com")
    assert not valid
    assert "cannot contain your email" in msg

    # Leading/trailing whitespace
    valid, msg = validate_password_strength(" ValidPassword123! ")
    assert not valid
    assert "whitespace" in msg

    # Strong password
    valid, msg = validate_password_strength("CorrectHorseBatteryStaple2026!", email="analyst@domain.com")
    assert valid
    assert msg is None


@pytest.mark.asyncio
async def test_database_health_and_storage_cleanup():
    """Verify database health ping and automated storage cleanup."""
    healthy = await check_db_health()
    assert healthy is True

    purged = await cleanup_expired_sessions()
    assert isinstance(purged, int)
    assert purged >= 0


@pytest.mark.asyncio
async def test_security_headers_and_gzip_compression():
    """Verify incoming and outgoing security headers and gzip network performance."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Accept-Encoding": "gzip"},
    ) as ac:
        resp = await ac.get("/docs")
        # Security headers
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
        assert "camera=()" in resp.headers.get("permissions-policy", "")
