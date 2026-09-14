"""
SentinelTrace Backend — Password Security Service

Provides Argon2id (with bcrypt fallback compatibility) password hashing and verification.
Enforces minimum password length policy (12 characters).
Includes timing-attack safe dummy hash evaluation.
"""
from __future__ import annotations

import logging
from passlib.context import CryptContext

logger = logging.getLogger("sentineltrace.password")

# Argon2id is the current NIST/OWASP recommended algorithm.
# Includes bcrypt scheme for backward compatibility if needed.
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    default="argon2",
    deprecated="auto",
    argon2__memory_cost=65536,   # 64 MiB
    argon2__time_cost=3,         # 3 iterations
    argon2__parallelism=1,       # 1 thread
)

MIN_PASSWORD_LENGTH = 12

# Pre-computed valid Argon2id hash for constant-time dummy verification on nonexistent users
DUMMY_ARGON2_HASH = "$argon2id$v=19$m=65536,t=3,p=1$0rr3vrdWqhVirJVSCsEY4w$bo2daFd+K3RqdIEoJjn14y/YLXQeawcDiQM5Q6v4TRI"


def hash_password(plain_password: str) -> str:
    """
    Hash a password using Argon2id.
    Enforces minimum length of 12 characters.
    """
    if not plain_password or len(plain_password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    return pwd_context.hash(plain_password)


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
