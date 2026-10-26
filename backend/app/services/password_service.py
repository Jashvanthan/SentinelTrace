"""
SentinelTrace Backend — Password Security Service

Provides Argon2id (with bcrypt fallback compatibility) password hashing and verification.
Enforces minimum password length policy (8 characters).
Includes timing-attack safe dummy hash evaluation and non-blocking asynchronous verification.
"""
from __future__ import annotations

import asyncio
import logging
from passlib.context import CryptContext

logger = logging.getLogger("sentineltrace.password")

# Argon2id is the current NIST/OWASP recommended algorithm.
# Tuned for high-performance authentication without starving CPU event loop.
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    default="argon2",
    deprecated="auto",
    argon2__memory_cost=32768,   # 32 MiB (OWASP compliant, ~4x faster than 64MiB)
    argon2__time_cost=2,         # 2 iterations
    argon2__parallelism=1,       # 1 thread
)

MIN_PASSWORD_LENGTH = 8

# Pre-computed valid Argon2id hash for constant-time dummy verification on nonexistent users
DUMMY_ARGON2_HASH = "$argon2id$v=19$m=32768,t=2,p=1$hNB6r9X6X8s5RwjhHIPwng$MC+xjWcReFlmUOcMSMquoAOauhWctmwOIafmX/a9IWA"


def hash_password(plain_password: str) -> str:
    """
    Hash a password using Argon2id.
    Enforces minimum length of 8 characters.
    """
    if not plain_password or len(plain_password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    return pwd_context.hash(plain_password)


async def hash_password_async(plain_password: str) -> str:
    """Non-blocking async wrapper to prevent event-loop CPU starvation."""
    return await asyncio.to_thread(hash_password, plain_password)


def verify_password(plain_password: str, hashed_password: str | None) -> bool:
    """
    Verify a plain password against an Argon2id/bcrypt hash safely.
    Catches format errors and returns False gracefully to prevent 500 crashes.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as exc:
        logger.warning(f"Password verification encountered error: {exc}")
        return False


async def verify_password_async(plain_password: str, hashed_password: str | None) -> bool:
    """Non-blocking async wrapper for password verification off the event loop."""
    return await asyncio.to_thread(verify_password, plain_password, hashed_password)


def needs_rehash(hashed_password: str | None) -> bool:
    """
    Check whether a stored hash needs to be updated (e.g. from bcrypt or older argon2 parameters).
    """
    if not hashed_password:
        return False
    try:
        return pwd_context.needs_update(hashed_password)
    except Exception:
        return False


COMMON_WEAK_PASSWORDS = {
    "password", "password123", "password1234", "admin1234", "12345678",
    "123456789", "qwerty1234", "sentineltrace", "sentinel123", "letmein123",
    "welcome123", "iloveyou123", "secret1234", "administrator", "changeme123"
}


def validate_password_strength(password: str, email: str | None = None) -> tuple[bool, str | None]:
    """
    Validate password strength according to NIST SP 800-63B guidelines:
    - Minimum length 8 characters, maximum 128 (prevents DoS)
    - Rejects common weak passwords
    - Disallows user email as password
    - Disallows leading/trailing whitespace
    """
    if not password:
        return False, "Password cannot be empty."
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters."
    if password.strip() != password:
        return False, "Password cannot start or end with whitespace."
    if password.lower() in COMMON_WEAK_PASSWORDS:
        return False, "Password is too common and easily guessed. Please choose a stronger password."
    if email and len(email.split("@")[0]) >= 3 and email.split("@")[0].lower() in password.lower():
        return False, "Password cannot contain your email or username."
    return True, None

