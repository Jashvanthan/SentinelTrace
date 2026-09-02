"""
SentinelTrace Backend — Email Parsing Service

Parses raw .eml content, extracts:
- Headers (From, To, Subject, Date, Reply-To, Received chain)
- Authentication results (SPF, DKIM, DMARC)
- MIME parts and attachments with SHA-256 hashes
- IOC extraction from URLs, IPs, and attachment hashes
"""
from __future__ import annotations

import email
import hashlib
import re
from dataclasses import dataclass, field
from email.message import Message


# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class ParsedAttachment:
    filename: str | None
    content_type: str | None
    size_bytes: int
    sha256_hash: str
    md5_hash: str
    content: bytes


@dataclass
class ParsedEmail:
    subject: str | None
    sender_email: str | None
    sender_display_name: str | None
    sender_domain: str | None
    reply_to: str | None
    recipients: list[str]
    message_id: str | None
    email_date: str | None
    received_headers: list[str]
    all_headers: dict[str, str]
    authentication_results: dict[str, str]
    spf_result: str | None
    dkim_result: str | None
    dmarc_result: str | None
    body_text: str | None
    body_html: str | None
    attachments: list[ParsedAttachment]
    extracted_urls: list[str] = field(default_factory=list)
    extracted_ips: list[str] = field(default_factory=list)


# ── URL / IP Patterns ─────────────────────────────────────────────────────────

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

AUTH_RESULT_PATTERNS = {
    "spf": re.compile(r"spf=(\w+)", re.IGNORECASE),
    "dkim": re.compile(r"dkim=(\w+)", re.IGNORECASE),
    "dmarc": re.compile(r"dmarc=(\w+)", re.IGNORECASE),
}


# ── Core Parser ───────────────────────────────────────────────────────────────

def parse_eml(raw_bytes: bytes) -> ParsedEmail:
    """
    Parse raw .eml bytes into a structured ParsedEmail.

    Args:
        raw_bytes: Raw email bytes (content of .eml file)

    Returns:
        ParsedEmail dataclass with all extracted fields
    """
    msg: Message = email.message_from_bytes(raw_bytes)

    # ── Basic Headers ─────────────────────────────────────────────────────────
    subject = _decode_header_value(msg.get("Subject", ""))
    from_raw = msg.get("From", "")
    sender_email, sender_display_name = _parse_address(from_raw)
    sender_domain = sender_email.split("@")[-1] if sender_email and "@" in sender_email else None
    reply_to_raw = msg.get("Reply-To", "")
    reply_to, _ = _parse_address(reply_to_raw)

    # ── Recipients ────────────────────────────────────────────────────────────
    recipients: list[str] = []
    for header in ("To", "Cc", "Bcc"):
        val = msg.get(header)
        if val:
            for part in val.split(","):
                addr, _ = _parse_address(part.strip())
                if addr:
                    recipients.append(addr)

    message_id = msg.get("Message-ID", "").strip()
    email_date = msg.get("Date", "")

    # ── Received Chain ────────────────────────────────────────────────────────
    received_headers = msg.get_all("Received") or []

    # ── All Headers as dict ───────────────────────────────────────────────────
    all_headers: dict[str, str] = {}
    for key in msg.keys():
        all_headers[key] = _decode_header_value(msg.get(key, ""))

    # ── Authentication Results ────────────────────────────────────────────────
    auth_results_raw = msg.get("Authentication-Results", "") or ""
    arc_auth = msg.get("ARC-Authentication-Results", "") or ""
    full_auth = f"{auth_results_raw} {arc_auth}"

    spf_result = _extract_auth_result(full_auth, "spf")
    dkim_result = _extract_auth_result(full_auth, "dkim")
    dmarc_result = _extract_auth_result(full_auth, "dmarc")

    authentication_results = {
        "spf": spf_result,
        "dkim": dkim_result,
        "dmarc": dmarc_result,
        "raw": auth_results_raw,
    }

    # ── Body & Attachments ────────────────────────────────────────────────────
    body_text = None
    body_html = None
    attachments: list[ParsedAttachment] = []
    extracted_urls: list[str] = []
    extracted_ips: list[str] = []

    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = str(part.get("Content-Disposition", ""))

        if "attachment" in disposition or part.get_filename():
            # ── Attachment ─────────────────────────────────────────────────
            payload = part.get_payload(decode=True)
            if payload:
                sha256 = hashlib.sha256(payload).hexdigest()
                md5 = hashlib.md5(payload).hexdigest()  # noqa: S324 (for IOC matching, not security)
                attachments.append(ParsedAttachment(
                    filename=_decode_header_value(part.get_filename() or ""),
                    content_type=content_type,
                    size_bytes=len(payload),
                    sha256_hash=sha256,
                    md5_hash=md5,
                    content=payload,
                ))
        elif content_type == "text/plain" and body_text is None:
            body_text = _decode_part(part)
        elif content_type == "text/html" and body_html is None:
            body_html = _decode_part(part)

    # Extract IOCs from body
    body_combined = f"{body_text or ''} {body_html or ''}"
    extracted_urls = list(set(URL_PATTERN.findall(body_combined)))
    extracted_ips = list(set(IP_PATTERN.findall(body_combined)))

    # Also extract IPs from Received headers
    for received in received_headers:
        extracted_ips.extend(IP_PATTERN.findall(received))
    extracted_ips = list(set(extracted_ips))

    return ParsedEmail(
        subject=subject or None,
        sender_email=sender_email or None,
        sender_display_name=sender_display_name or None,
        sender_domain=sender_domain,
        reply_to=reply_to or None,
        recipients=recipients,
        message_id=message_id or None,
        email_date=email_date or None,
        received_headers=received_headers,
        all_headers=all_headers,
        authentication_results=authentication_results,
        spf_result=spf_result,
        dkim_result=dkim_result,
        dmarc_result=dmarc_result,
        body_text=body_text,
        body_html=body_html,
        attachments=attachments,
        extracted_urls=extracted_urls,
        extracted_ips=extracted_ips,
    )


def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()


# ── Private Helpers ───────────────────────────────────────────────────────────

def _decode_header_value(value: str) -> str:
    """Decode RFC 2047 encoded header values."""
    import email.header
    try:
        parts = email.header.decode_header(value)
        decoded = []
        for part, charset in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                decoded.append(part)
        return " ".join(decoded).strip()
    except Exception:
        return value


def _parse_address(raw: str) -> tuple[str, str]:
    """
    Parse an email address string like "Display Name <addr@example.com>".

    Returns:
        (email_address, display_name)
    """
    from email.utils import parseaddr
    display_name, addr = parseaddr(raw)
    return addr.lower().strip(), display_name.strip()


def _decode_part(part: Message) -> str | None:
    """Decode a MIME message part to a string."""
    payload = part.get_payload(decode=True)
    if not payload:
        return None
    charset = part.get_param("charset") or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("latin-1", errors="replace")


def _extract_auth_result(auth_results: str, protocol: str) -> str | None:
    """Extract SPF/DKIM/DMARC result from Authentication-Results header."""
    pattern = AUTH_RESULT_PATTERNS.get(protocol)
    if not pattern or not auth_results:
        return None
    match = pattern.search(auth_results)
    return match.group(1).lower() if match else None
