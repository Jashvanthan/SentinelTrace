"""
SentinelTrace Backend — Password Security Service

Provides Argon2id password hashing and verification.
Enforces minimum password length policy (12 characters).
"""
from __future__ import annotations

from passlib.context import CryptContext

# Argon2id is the current NIST/OWASP recommended algorithm.
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=65536,   # 64 MiB
    argon2__time_cost=3,         # 3 iterations
    argon2__parallelism=1,       # 1 thread
)

MIN_PASSWORD_LENGTH = 12


def hash_password(plain_password: str) -> str:
    """
    Hash a password using Argon2id.
    Enforces minimum length of 12 characters.
    """
    if len(plain_password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against an Argon2id hash.
    """
    if not hashed_password:
        return False
    return pwd_context.verify(plain_password, hashed_password)


def needs_rehash(hashed_password: str) -> bool:
    """
    Check whether a stored hash needs to be updated.
    """
    return pwd_context.needs_update(hashed_password)
