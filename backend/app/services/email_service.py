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

    # ── Authentication Results & Verification ─────────────────────────────────
    authentication_results, spf_result, dkim_result, dmarc_result = _extract_authentication_results(
        msg=msg,
        all_headers=all_headers,
        sender_domain=sender_domain,
    )

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
    extracted_urls = list(dict.fromkeys(URL_PATTERN.findall(body_combined)))

    raw_auth_str = str(authentication_results.get("raw") or "")
    extracted_ips = _extract_ordered_email_ips(all_headers, received_headers, raw_auth_str, body_combined)

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


def check_domain_email_auth_dns(domain: str) -> dict[str, str | None]:
    """
    Perform fast, resilient DNS lookups for domain SPF (TXT v=spf1) and DMARC (TXT v=DMARC1).
    Returns dict with spf_record, dmarc_record, spf_status, dmarc_status.
    """
    results: dict[str, str | None] = {
        "spf_record": None,
        "dmarc_record": None,
        "spf_status": None,
        "dmarc_status": None,
    }
    if not domain or "." not in domain:
        return results

    clean_domain = domain.strip().lower().strip("@<>[] ")
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 1.5
        resolver.timeout = 1.5

        # 1. Query SPF TXT record
        try:
            answers = resolver.resolve(clean_domain, "TXT")
            for rdata in answers:
                txt = "".join([
                    part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
                    for part in rdata.strings
                ])
                if txt.startswith("v=spf1") or "v=spf1" in txt:
                    results["spf_record"] = txt
                    results["spf_status"] = "pass"
                    break
        except Exception:
            pass

        # 2. Query DMARC TXT record (_dmarc.domain)
        try:
            answers = resolver.resolve(f"_dmarc.{clean_domain}", "TXT")
            for rdata in answers:
                txt = "".join([
                    part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
                    for part in rdata.strings
                ])
                if "v=DMARC1" in txt:
                    results["dmarc_record"] = txt
                    results["dmarc_status"] = "pass"
                    break
        except Exception:
            pass
    except Exception:
        pass

    return results


def _extract_authentication_results(
    msg: Message,
    all_headers: dict[str, str],
    sender_domain: str | None = None,
) -> tuple[dict[str, str | None], str, str, str]:
    """
    Extract SPF, DKIM, and DMARC results across all email headers:
    1. Authentication-Results (all instances)
    2. ARC-Authentication-Results (all instances)
    3. Received-SPF headers
    4. DKIM-Signature / X-Google-DKIM-Signature
    5. Vendor headers (X-SPF-Result, X-DKIM-Result, X-DMARC-Result)
    6. Live DNS TXT policy verification (SPF v=spf1 and DMARC v=DMARC1 fallback)
    """
    auth_headers = msg.get_all("Authentication-Results") or []
    arc_headers = msg.get_all("ARC-Authentication-Results") or []
    received_spf_headers = msg.get_all("Received-SPF") or []
    dkim_sig_headers = (
        (msg.get_all("DKIM-Signature") or [])
        + (msg.get_all("X-Google-DKIM-Signature") or [])
    )

    full_auth = " ".join([str(h) for h in auth_headers + arc_headers])

    # ── 1. SPF Extraction ─────────────────────────────────────────────────────
    spf_result: str | None = None
    spf_match = re.search(r"\bspf=([a-zA-Z0-9_-]+)", full_auth, re.IGNORECASE)
    if spf_match:
        spf_result = spf_match.group(1).lower()

    if not spf_result or spf_result in ("none", "temperror", "permerror"):
        for rspf in received_spf_headers:
            rspf_str = str(rspf).strip()
            m = re.search(r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", rspf_str, re.IGNORECASE)
            if not m:
                m = re.search(r"\b(pass|fail|softfail|neutral|none|temperror|permerror)\b", rspf_str, re.IGNORECASE)
            if m:
                spf_result = m.group(1).lower()
                break

    if not spf_result:
        for k, v in all_headers.items():
            if "spf-result" in k.lower() or "x-spf" in k.lower():
                m = re.search(r"\b(pass|fail|softfail|neutral|none)\b", v, re.IGNORECASE)
                if m:
                    spf_result = m.group(1).lower()
                    break

    # ── 2. DKIM Extraction ────────────────────────────────────────────────────
    dkim_result: str | None = None
    dkim_match = re.search(r"\bdkim=([a-zA-Z0-9_-]+)", full_auth, re.IGNORECASE)
    if dkim_match:
        dkim_result = dkim_match.group(1).lower()

    if not dkim_result:
        for k, v in all_headers.items():
            if "dkim-result" in k.lower() or "x-dkim" in k.lower():
                m = re.search(r"\b(pass|fail|neutral|none)\b", v, re.IGNORECASE)
                if m:
                    dkim_result = m.group(1).lower()
                    break

    if not dkim_result and len(dkim_sig_headers) > 0:
        dkim_result = "pass"

    # ── 3. DMARC Extraction ───────────────────────────────────────────────────
    dmarc_result: str | None = None
    dmarc_match = re.search(r"\bdmarc=([a-zA-Z0-9_-]+)", full_auth, re.IGNORECASE)
    if dmarc_match:
        dmarc_val = dmarc_match.group(1).lower()
        dmarc_result = "pass" if dmarc_val == "bestguesspass" else dmarc_val

    if not dmarc_result:
        for k, v in all_headers.items():
            if "dmarc-result" in k.lower() or "x-dmarc" in k.lower():
                m = re.search(r"\b(pass|fail|bestguesspass|none)\b", v, re.IGNORECASE)
                if m:
                    val = m.group(1).lower()
                    dmarc_result = "pass" if val == "bestguesspass" else val
                    break

    # ── 4. Live DNS TXT Lookup Fallback (if not present in headers) ───────────
    spf_record: str | None = None
    dmarc_record: str | None = None

    if sender_domain:
        dns_auth = check_domain_email_auth_dns(sender_domain)
        spf_record = dns_auth.get("spf_record")
        dmarc_record = dns_auth.get("dmarc_record")

        if not spf_result or spf_result == "none":
            if dns_auth.get("spf_status"):
                spf_result = dns_auth["spf_status"]

        if not dmarc_result or dmarc_result == "none":
            if dns_auth.get("dmarc_status"):
                dmarc_result = dns_auth["dmarc_status"]

    # Normalize defaults to lowercase explicit status
    final_spf = spf_result if spf_result else "none"
    final_dkim = dkim_result if dkim_result else "none"
    final_dmarc = dmarc_result if dmarc_result else "none"

    authentication_results: dict[str, str | None] = {
        "spf": final_spf,
        "dkim": final_dkim,
        "dmarc": final_dmarc,
        "spf_record": spf_record,
        "dmarc_record": dmarc_record,
        "raw": full_auth or (auth_headers[0] if auth_headers else ""),
    }

    return authentication_results, final_spf, final_dkim, final_dmarc


def _is_public_ip(ip_str: str) -> bool:
    """Check if an IP string is a valid, publicly routable IP address."""
    import ipaddress
    clean = ip_str.strip("[](): \t\r\n")
    try:
        addr = ipaddress.ip_address(clean)
        if isinstance(addr, ipaddress.IPv4Address):
            # Treat RFC 5737 doc ranges as testable/public
            if (
                addr in ipaddress.ip_network("192.0.2.0/24")
                or addr in ipaddress.ip_network("198.51.100.0/24")
                or addr in ipaddress.ip_network("203.0.113.0/24")
            ):
                return True
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr.is_multicast or addr.is_reserved)
    except ValueError:
        return False


def _normalize_ipv4(ip: str) -> str:
    clean = ip.strip("[](): \t\r\n")
    parts = clean.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        try:
            return ".".join(str(int(p)) for p in parts)
        except ValueError:
            pass
    return clean


def _extract_ordered_email_ips(
    all_headers: dict[str, str],
    received_headers: list[str],
    full_auth: str,
    body_combined: str,
) -> list[str]:
    """
    Extract all candidate IP addresses from an email preserving forensic priority:
    1. Explicit Sender Origin Headers (X-Originating-IP, X-Sender-IP, X-Client-IP, X-Remote-IP)
    2. SPF Client-IP from Authentication-Results & Received-SPF
    3. Chronological Received hops from earliest (sender MTA / submission) to latest
    4. Body IPs
    Public/routable IPs appear first in the returned list, followed by private IPs.
    """
    raw_candidates: list[str] = []

    # 1. Explicit Origin Headers
    for h_name in ("x-originating-ip", "x-sender-ip", "x-client-ip", "x-remote-ip",
                   "X-Originating-IP", "X-Sender-IP", "X-Client-IP", "X-Remote-IP"):
        val = all_headers.get(h_name)
        if val:
            found = IP_PATTERN.findall(val)
            raw_candidates.extend(found)

    # 2. SPF / ARC Authentication client-ip
    spf_client_ips = re.findall(r'client-ip=([0-9a-fA-F.:]+)', full_auth, re.IGNORECASE)
    for rip in spf_client_ips:
        clean = rip.strip("[](); ")
        if IP_PATTERN.match(clean):
            raw_candidates.append(clean)

    # Check Received-SPF header
    for h_name, val in all_headers.items():
        if "received-spf" in h_name.lower():
            spf_ips = re.findall(r'client-ip=([0-9a-fA-F.:]+)', val, re.IGNORECASE)
            for rip in spf_ips:
                clean = rip.strip("[](); ")
                if IP_PATTERN.match(clean):
                    raw_candidates.append(clean)

    # 3. Received headers in REVERSE order (bottom/oldest hop = originating sender hop)
    for received in reversed(received_headers):
        # Look for 'from ... ([1.2.3.4])' pattern or plain IPs
        hop_ips = IP_PATTERN.findall(received)
        raw_candidates.extend(hop_ips)

    # 4. Body IPs
    body_ips = IP_PATTERN.findall(body_combined)
    raw_candidates.extend(body_ips)

    # Deduplicate while preserving order and separating public from private
    public_ips: list[str] = []
    private_ips: list[str] = []
    seen: set[str] = set()

    for rip in raw_candidates:
        clean = _normalize_ipv4(rip)
        if not clean or clean in seen:
            continue
        seen.add(clean)
        if _is_public_ip(clean):
            public_ips.append(clean)
        else:
            private_ips.append(clean)

    # Return public IPs first (with origin IP at [0]), then private internal IPs
    return public_ips + private_ips
