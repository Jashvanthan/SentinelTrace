"""
SentinelTrace Backend — Centralized IOC Normalization Service
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any

from app.core.logging import get_logger
from app.services.ip_trace.classifier import classify_ip, normalize_ip_string

logger = get_logger("sentineltrace.ioc_normalization")


class IOCNormalizationService:
    """Normalizes IOCs into canonical representations while preserving original raw values."""

    @staticmethod
    def normalize_ip(ip_str: str) -> dict[str, Any]:
        """
        Normalize IP (IPv4 or IPv6), classify routing status, and check public geolocatability.
        """
        clean_ip = normalize_ip_string(ip_str)
        info = classify_ip(clean_ip)
        return {
            "type": "IP",
            "original_value": ip_str,
            "normalized_value": info.ip,
            "version": info.version,
            "classification": info.classification.value,
            "is_public": info.is_public,
            "is_private": info.is_private,
            "is_geolocatable": info.is_geolocatable,
        }

    @staticmethod
    def normalize_domain(domain_str: str) -> dict[str, Any]:
        """
        Normalize domain name (lowercase, strip trailing dots/spaces, IDNA punycode decode).
        """
        raw = domain_str.strip()
        norm = raw.lower()
        if norm.endswith("."):
            norm = norm[:-1]
        
        # Strip scheme if accidentally included
        if "://" in norm:
            norm = urllib.parse.urlparse(norm).netloc or norm

        # Strip port if present
        if ":" in norm and not norm.startswith("["):
            norm = norm.split(":")[0]

        try:
            norm = norm.encode("idna").decode("ascii")
        except Exception:
            pass

        return {
            "type": "DOMAIN",
            "original_value": domain_str,
            "normalized_value": norm,
        }

    @staticmethod
    def normalize_url(url_str: str) -> dict[str, Any]:
        """
        Normalize URL safely while preserving forensic query/path structure.
        """
        raw = url_str.strip()
        try:
            parsed = urllib.parse.urlparse(raw)
            scheme = parsed.scheme.lower() if parsed.scheme else "http"
            netloc = parsed.netloc.lower()
            
            # Remove default ports
            if scheme == "http" and netloc.endswith(":80"):
                netloc = netloc[:-3]
            elif scheme == "https" and netloc.endswith(":443"):
                netloc = netloc[:-4]

            path = parsed.path or "/"
            canonical = urllib.parse.urlunparse((
                scheme,
                netloc,
                path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
            domain = parsed.hostname.lower() if parsed.hostname else netloc
        except Exception as err:
            logger.debug("url_parse_error", error=str(err), raw_url=raw[:50])
            canonical = raw.lower()
            domain = ""

        return {
            "type": "URL",
            "original_value": url_str,
            "normalized_value": canonical,
            "domain": domain,
        }

    @staticmethod
    def normalize_hash(hash_str: str) -> dict[str, Any]:
        """
        Normalize file hash (MD5, SHA1, SHA256) auto-detecting algorithm by string length.
        """
        clean_hash = hash_str.strip().lower()
        algo = "FILE_HASH_SHA256"
        length = len(clean_hash)
        
        if length == 32:
            algo = "FILE_HASH_MD5"
        elif length == 40:
            algo = "FILE_HASH_SHA1"
        elif length == 64:
            algo = "FILE_HASH_SHA256"

        return {
            "type": algo,
            "original_value": hash_str,
            "normalized_value": clean_hash,
            "length": length,
        }

    @classmethod
    def normalize(cls, ioc_type: str, value: str) -> dict[str, Any]:
        """Generic normalization dispatcher."""
        norm_type = ioc_type.upper()
        if norm_type in ["IP", "IP_ADDRESS"]:
            return cls.normalize_ip(value)
        elif norm_type in ["DOMAIN"]:
            return cls.normalize_domain(value)
        elif norm_type in ["URL"]:
            return cls.normalize_url(value)
        elif "HASH" in norm_type or len(value.strip()) in [32, 40, 64]:
            return cls.normalize_hash(value)
        else:
            return {
                "type": norm_type,
                "original_value": value,
                "normalized_value": value.strip(),
            }
