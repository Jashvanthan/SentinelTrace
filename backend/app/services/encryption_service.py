"""
SentinelTrace Backend — Encryption Service
"""
import logging
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, status

from app.core.config import get_settings

import base64
import hashlib

def _get_fernet() -> Fernet:
    settings = get_settings()
    key = settings.GMAIL_ENCRYPTION_KEY
    if key and len(key.strip()) > 0:
        try:
            return Fernet(key.strip().encode("utf-8"))
        except Exception:
            pass

    # Deterministically derive 32-byte base64 Fernet key from APP_SECRET_KEY
    secret = settings.APP_SECRET_KEY or "sentineltrace-default-super-secure-secret-key-32chars"
    derived_key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
    return Fernet(derived_key)

def encrypt_token(plain_token: str) -> str:
    """
    Encrypts a plaintext token using Fernet authenticated encryption.
    """
    if not plain_token:
        return plain_token
    
    f = _get_fernet()
    try:
        cipher_bytes = f.encrypt(plain_token.encode("utf-8"))
        return cipher_bytes.decode("utf-8")
    except Exception as e:
        logger.error(f"Failed to encrypt token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Encryption failed"
        )

def decrypt_token(cipher_token: str) -> str:
    """
    Decrypts a ciphertext token back to plaintext.
    """
    if not cipher_token:
        return cipher_token
        
    f = _get_fernet()
    try:
        plain_bytes = f.decrypt(cipher_token.encode("utf-8"))
        return plain_bytes.decode("utf-8")
    except InvalidToken:
        logger.error("Invalid or corrupted token decryption attempt")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Decryption failed due to invalid token"
        )
    except Exception as e:
        logger.error(f"Failed to decrypt token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Decryption failed"
        )
