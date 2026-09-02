"""
SentinelTrace Backend — GCS Storage Service

Handles:
- Encrypting and uploading .eml files to Google Cloud Storage
- Generating signed URLs for secure download
- Uploading generated PDF reports
"""
from __future__ import annotations

import io
import os
from datetime import timedelta
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger

settings = get_settings()
logger = get_logger("sentineltrace.gcs")


def _get_storage_client():
    """Return a GCS client, using credentials from env or ADC."""
    from google.cloud import storage
    from google.oauth2 import service_account

    if settings.GCS_CREDENTIALS_JSON:
        credentials = service_account.Credentials.from_service_account_file(
            settings.GCS_CREDENTIALS_JSON,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        return storage.Client(project=settings.GCS_PROJECT_ID, credentials=credentials)
    return storage.Client(project=settings.GCS_PROJECT_ID)


def _encrypt_bytes(data: bytes) -> bytes:
    """AES-256-CBC encrypt bytes using FILE_ENCRYPTION_KEY from env."""
    if not settings.FILE_ENCRYPTION_KEY:
        logger.warning("file_encryption_key_missing", msg="Storing unencrypted")
        return data

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import secrets as sec_mod

    key = bytes.fromhex(settings.FILE_ENCRYPTION_KEY)
    iv = sec_mod.token_bytes(16)

    # Pad to AES block size (16 bytes)
    pad_len = 16 - (len(data) % 16)
    data = data + bytes([pad_len] * pad_len)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()


def _decrypt_bytes(data: bytes) -> bytes:
    """AES-256-CBC decrypt bytes."""
    if not settings.FILE_ENCRYPTION_KEY:
        return data

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    key = bytes.fromhex(settings.FILE_ENCRYPTION_KEY)
    iv = data[:16]
    ciphertext = data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    pad_len = plaintext[-1]
    return plaintext[:-pad_len]


class GCSService:
    """Google Cloud Storage service for encrypted evidence storage."""

    def __init__(self) -> None:
        self._bucket_name = settings.GCS_BUCKET_NAME
        self._configured = bool(settings.GCS_BUCKET_NAME and settings.GCS_PROJECT_ID)

    def is_configured(self) -> bool:
        return self._configured

    async def upload_eml(
        self,
        analysis_id: str,
        raw_bytes: bytes,
        content_type: str = "message/rfc822",
    ) -> str | None:
        """
        Encrypt and upload raw .eml bytes to GCS.

        Returns:
            GCS object path, or None if GCS not configured
        """
        if not self._configured:
            logger.warning("gcs_not_configured", msg="Skipping upload")
            return None

        try:
            client = _get_storage_client()
            bucket = client.bucket(self._bucket_name)
            blob_path = f"emails/{analysis_id}.eml.enc"
            blob = bucket.blob(blob_path)

            encrypted = _encrypt_bytes(raw_bytes)
            blob.upload_from_string(
                encrypted,
                content_type="application/octet-stream",
            )
            blob.metadata = {
                "analysis_id": analysis_id,
                "encrypted": "true",
                "original_content_type": content_type,
            }
            blob.patch()

            logger.info("eml_uploaded", path=blob_path, size_bytes=len(encrypted))
            return blob_path
        except Exception as e:
            logger.error("gcs_upload_error", error=str(e))
            return None

    async def upload_report(self, analysis_id: str, pdf_bytes: bytes) -> str | None:
        """Upload a generated PDF report to GCS."""
        if not self._configured:
            return None

        try:
            client = _get_storage_client()
            bucket = client.bucket(self._bucket_name)
            blob_path = f"reports/{analysis_id}.pdf"
            blob = bucket.blob(blob_path)
            blob.upload_from_string(pdf_bytes, content_type="application/pdf")
            logger.info("report_uploaded", path=blob_path)
            return blob_path
        except Exception as e:
            logger.error("gcs_report_upload_error", error=str(e))
            return None

    async def generate_signed_url(self, blob_path: str) -> str | None:
        """Generate a time-limited signed URL for secure file download."""
        if not self._configured:
            return None

        try:
            client = _get_storage_client()
            bucket = client.bucket(self._bucket_name)
            blob = bucket.blob(blob_path)
            url = blob.generate_signed_url(
                version="v4",
                expiration=timedelta(minutes=settings.GCS_SIGNED_URL_EXPIRE_MINUTES),
                method="GET",
            )
            return url
        except Exception as e:
            logger.error("gcs_signed_url_error", error=str(e))
            return None
