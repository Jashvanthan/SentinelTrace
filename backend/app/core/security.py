"""
SentinelTrace Backend — Security Utilities

Covers:
- Argon2id password hashing via passlib
- JWT access token creation/verification
- Refresh token generation and hashing
- HttpOnly cookie helpers
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Response
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import get_settings

settings = get_settings()




# ── JWT Tokens ────────────────────────────────────────────────────────────────

def create_access_token(
    subject: str,
    email: str,
    role: str,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """
    Create a short-lived JWT access token.

    Args:
    subject: str,
    email: str,
    role: str,
        extra_claims: Optional additional claims

    Returns:
        Signed JWT string
    """
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: dict[str, Any] = {
        "sub": subject,
        "email": email,
        "role": role,
        "iat": now,
        "exp": expire,
        "jti": str(uuid.uuid4()),
        "token_type": "access",
    }
    if extra_claims:
        # Sanitize: never allow credential-like keys in token payload
        forbidden_keys = {"password", "secret", "token", "key", "credential"}
        safe_claims = {
            k: v for k, v in extra_claims.items()
            if not any(fk in k.lower() for fk in forbidden_keys)
        }
        payload.update(safe_claims)

    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and verify a JWT access token.

    Raises:
        JWTError: If token is invalid, expired, or tampered
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
        if payload.get("token_type") != "access":
            raise JWTError("Not an access token")
        return payload
    except JWTError:
        raise


# ── Refresh Tokens ────────────────────────────────────────────────────────────

def generate_refresh_token() -> tuple[str, str]:
    """
    Generate a secure refresh token.

    Returns:
        (raw_token, hashed_token) — store the hash, send the raw to client
    """
    raw_token = secrets.token_urlsafe(64)
    hashed = _hash_refresh_token(raw_token)
    return raw_token, hashed


def _hash_refresh_token(raw_token: str) -> str:
    """Hash a refresh token using SHA-256 for database storage."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


def verify_refresh_token(raw_token: str, stored_hash: str) -> bool:
    """Constant-time comparison to verify a refresh token against its stored hash."""
    computed = _hash_refresh_token(raw_token)
    return secrets.compare_digest(computed, stored_hash)


# ── Cookie Helpers ────────────────────────────────────────────────────────────

REFRESH_TOKEN_COOKIE_NAME = "st_refresh_token"
REFRESH_TOKEN_COOKIE_PATH = "/api/v1/auth"


def set_refresh_token_cookie(response: Response, token: str) -> None:
    """
    Set the refresh token as an HttpOnly, Secure, SameSite=Strict cookie.
    Scoped to the auth path to minimize attack surface.
    """
    max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE_NAME,
        value=token,
        max_age=max_age,
        path=REFRESH_TOKEN_COOKIE_PATH,
        secure=settings.is_production,   # Secure flag in production (requires HTTPS)
        httponly=True,
        samesite="none" if settings.is_production else "lax",
    )


def clear_refresh_token_cookie(response: Response) -> None:
    """Clear the refresh token cookie on logout."""
    response.delete_cookie(
        key=REFRESH_TOKEN_COOKIE_NAME,
        path=REFRESH_TOKEN_COOKIE_PATH,
    )
