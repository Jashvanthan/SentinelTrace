"""
SentinelTrace Backend — Encryption Service
"""
import logging
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, status

from app.core.config import get_settings

logger = logging.getLogger(__name__)

def _get_fernet() -> Fernet:
    settings = get_settings()
    key = settings.GMAIL_ENCRYPTION_KEY
    if not key:
        logger.error("GMAIL_ENCRYPTION_KEY is not set in environment")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Encryption key configuration missing"
        )
    try:
        return Fernet(key.encode("utf-8"))
    except Exception as e:
        logger.error(f"Invalid GMAIL_ENCRYPTION_KEY format: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invalid encryption key configuration"
        )

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
