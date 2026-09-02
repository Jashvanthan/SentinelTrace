"""MCP Tool: Email Header Parsing and IOC Extraction"""
from __future__ import annotations

import base64
import email
import hashlib
import re
from email.header import decode_header as _decode_header
from typing import Any


def parse_email_headers(raw_headers: str) -> dict[str, Any]:
    """Parse raw email headers and extract security-relevant fields."""
    try:
        msg = email.message_from_string(raw_headers)
        from_raw = msg.get("From", "")
        auth_results = msg.get("Authentication-Results", "") or ""

        return {
            "subject": _decode(msg.get("Subject", "")),
            "from": _decode(from_raw),
            "to": _decode(msg.get("To", "")),
            "reply_to": _decode(msg.get("Reply-To", "")),
            "message_id": msg.get("Message-ID", "").strip(),
            "date": msg.get("Date", ""),
            "received_chain": msg.get_all("Received") or [],
            "x_originating_ip": msg.get("X-Originating-IP", ""),
            "authentication_results": {
                "raw": auth_results,
                "spf": _extract_auth(auth_results, "spf"),
                "dkim": _extract_auth(auth_results, "dkim"),
                "dmarc": _extract_auth(auth_results, "dmarc"),
            },
            "x_mailer": msg.get("X-Mailer", ""),
            "mime_version": msg.get("MIME-Version", ""),
        }
    except Exception as e:
        return {"error": str(e)}


def compute_file_hash(file_b64: str, filename: str = "unknown") -> dict[str, Any]:
    """Compute SHA-256 and MD5 hashes of base64-encoded file bytes."""
    try:
        data = base64.b64decode(file_b64)
        return {
            "filename": filename,
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),  # noqa: S324
            "sha1": hashlib.sha1(data).hexdigest(),  # noqa: S324
        }
    except Exception as e:
        return {"error": str(e)}


def extract_iocs_from_text(text: str) -> dict[str, Any]:
    """Extract IOCs from text: IPs, domains, URLs, emails, file hashes."""
    url_pattern = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
    ip_pattern = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
    sha256_pattern = re.compile(r"\b[A-Fa-f0-9]{64}\b")
    md5_pattern = re.compile(r"\b[A-Fa-f0-9]{32}\b")
    domain_pattern = re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
        re.IGNORECASE,
    )

    urls = list(set(url_pattern.findall(text)))
    ips = list(set(ip_pattern.findall(text)))
    emails = list(set(email_pattern.findall(text)))
    sha256s = list(set(sha256_pattern.findall(text)))
    md5s = [h for h in set(md5_pattern.findall(text)) if h not in sha256s]
    domains = list(set(domain_pattern.findall(text)))

    return {
        "urls": urls[:50],
        "ip_addresses": ips[:30],
        "email_addresses": emails[:30],
        "sha256_hashes": sha256s[:20],
        "md5_hashes": md5s[:20],
        "domains": domains[:50],
        "total_iocs": len(urls) + len(ips) + len(emails) + len(sha256s) + len(md5s),
    }


def _decode(value: str) -> str:
    try:
        parts = _decode_header(value)
        decoded = []
        for part, charset in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                decoded.append(part)
        return " ".join(decoded).strip()
    except Exception:
        return value


def _extract_auth(auth_results: str, protocol: str) -> str | None:
    pattern = re.compile(rf"{protocol}=(\w+)", re.IGNORECASE)
    match = pattern.search(auth_results)
    return match.group(1).lower() if match else None
