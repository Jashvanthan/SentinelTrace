"""
SentinelTrace Backend — IP Address Classifier Service

Standard library `ipaddress` powered classification for IPv4 and IPv6 addresses.
Accurately categorizes addresses into:
- PUBLIC (Routable Internet IP)
- PRIVATE (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- LOOPBACK (127.0.0.0/8, ::1)
- LINK_LOCAL (169.254.0.0/16, fe80::/10)
- MULTICAST (224.0.0.0/4, ff00::/8)
- RESERVED (240.0.0.0/4, 0.0.0.0/8, IETF reserved)
- UNSPECIFIED (0.0.0.0, ::)
- UNIQUE_LOCAL (fc00::/7, fd00::/8)
- DOCUMENTATION (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
"""
from __future__ import annotations

from dataclasses import dataclass
import enum
import ipaddress
import re
from typing import Any


class IPClassification(str, enum.Enum):
    PUBLIC = "PUBLIC"
    PRIVATE = "PRIVATE"
    LOOPBACK = "LOOPBACK"
    LINK_LOCAL = "LINK_LOCAL"
    MULTICAST = "MULTICAST"
    RESERVED = "RESERVED"
    UNSPECIFIED = "UNSPECIFIED"
    UNIQUE_LOCAL = "UNIQUE_LOCAL"
    DOCUMENTATION = "DOCUMENTATION"
    INVALID = "INVALID"


@dataclass(frozen=True)
class NormalizedIPInfo:
    ip: str
    version: int
    classification: IPClassification
    is_public: bool
    is_private: bool
    is_geolocatable: bool
    location_accuracy: str  # "approximate" | "internal-network" | "unknown"
    routing_role: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "version": self.version,
            "classification": self.classification.value,
            "is_public": self.is_public,
            "is_private": self.is_private,
            "is_geolocatable": self.is_geolocatable,
            "location_accuracy": self.location_accuracy,
            "routing_role": self.routing_role,
            "reason": self.reason,
        }


def normalize_ip_string(raw: str) -> str:
    """Normalize raw IP string by stripping enclosing brackets, parentheses, and whitespace."""
    clean = raw.strip(" \t\r\n'\"")
    # Strip enclosing square brackets or parentheses e.g. [192.168.1.1] or [::1] or (10.0.0.1)
    if (clean.startswith("[") and clean.endswith("]")) or (clean.startswith("(") and clean.endswith(")")):
        clean = clean[1:-1].strip()
    
    parts = clean.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        try:
            return ".".join(str(int(p)) for p in parts)
        except ValueError:
            pass
    return clean


def classify_ip(raw_ip: str) -> NormalizedIPInfo:
    """
    Classify an IPv4 or IPv6 address with strict standard compliance.

    Distinguishes RFC 1918 from loopback (127.0.0.1), link-local APIPA (169.254.x.x),
    multicast, unique-local IPv6, and public routable space.
    """
    cleaned = normalize_ip_string(raw_ip)
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        return NormalizedIPInfo(
            ip=cleaned,
            version=0,
            classification=IPClassification.INVALID,
            is_public=False,
            is_private=True,
            is_geolocatable=False,
            location_accuracy="unknown",
            routing_role="Invalid IP",
            reason="Syntactically invalid IP address",
        )

    version = addr.version

    # 1. Loopback (127.0.0.0/8, ::1)
    if addr.is_loopback:
        return NormalizedIPInfo(
            ip=str(addr),
            version=version,
            classification=IPClassification.LOOPBACK,
            is_public=False,
            is_private=True,
            is_geolocatable=False,
            location_accuracy="unknown",
            routing_role="Localhost / Loopback",
            reason="Host-internal loopback address (no external or geographic routing)",
        )

    # 2. Link-Local / APIPA (169.254.0.0/16, fe80::/10)
    if addr.is_link_local:
        return NormalizedIPInfo(
            ip=str(addr),
            version=version,
            classification=IPClassification.LINK_LOCAL,
            is_public=False,
            is_private=True,
            is_geolocatable=False,
            location_accuracy="internal-network",
            routing_role="Link-Local / APIPA",
            reason="Non-routable single-link address (autoconfiguration / link-local)",
        )

    # 3. Multicast (224.0.0.0/4, ff00::/8)
    if addr.is_multicast:
        return NormalizedIPInfo(
            ip=str(addr),
            version=version,
            classification=IPClassification.MULTICAST,
            is_public=False,
            is_private=True,
            is_geolocatable=False,
            location_accuracy="unknown",
            routing_role="Multicast Group",
            reason="Multicast group delivery (not assigned to a single host)",
        )

    # 4. Unspecified (0.0.0.0, ::)
    if addr.is_unspecified:
        return NormalizedIPInfo(
            ip=str(addr),
            version=version,
            classification=IPClassification.UNSPECIFIED,
            is_public=False,
            is_private=True,
            is_geolocatable=False,
            location_accuracy="unknown",
            routing_role="Unspecified Address",
            reason="Unspecified / bind-all address",
        )

    # 5. IPv6 Specifics: Unique-Local (fc00::/7, fd00::/8)
    if version == 6 and (
        addr in ipaddress.ip_network("fc00::/7") or addr in ipaddress.ip_network("fd00::/8")
    ):
        return NormalizedIPInfo(
            ip=str(addr),
            version=version,
            classification=IPClassification.UNIQUE_LOCAL,
            is_public=False,
            is_private=True,
            is_geolocatable=False,
            location_accuracy="internal-network",
            routing_role="IPv6 Unique Local (ULA)",
            reason="Private internal IPv6 address space (RFC 4193)",
        )

    # 6. IPv4 Specifics: RFC 5737 Documentation / Benchmark Ranges
    if isinstance(addr, ipaddress.IPv4Address):
        if (
            addr in ipaddress.ip_network("192.0.2.0/24")
            or addr in ipaddress.ip_network("198.51.100.0/24")
            or addr in ipaddress.ip_network("203.0.113.0/24")
        ):
            return NormalizedIPInfo(
                ip=str(addr),
                version=version,
                classification=IPClassification.DOCUMENTATION,
                is_public=True,
                is_private=False,
                is_geolocatable=True,
                location_accuracy="approximate",
                routing_role="Public Documentation / Example Network",
                reason="RFC 5737 documentation test block (treated as public/routable for lab emulation)",
            )

        # Carrier-grade NAT (100.64.0.0/10)
        if addr in ipaddress.ip_network("100.64.0.0/10"):
            return NormalizedIPInfo(
                ip=str(addr),
                version=version,
                classification=IPClassification.PRIVATE,
                is_public=False,
                is_private=True,
                is_geolocatable=False,
                location_accuracy="internal-network",
                routing_role="Carrier-Grade NAT (CGNAT)",
                reason="Shared address space for service provider NAT (RFC 6598)",
            )

        # Reserved Class E (240.0.0.0/4)
        if addr in ipaddress.ip_network("240.0.0.0/4"):
            return NormalizedIPInfo(
                ip=str(addr),
                version=version,
                classification=IPClassification.RESERVED,
                is_public=False,
                is_private=True,
                is_geolocatable=False,
                location_accuracy="unknown",
                routing_role="Reserved (Class E)",
                reason="Reserved address space for future use (RFC 1112)",
            )

    # 7. Private LAN (RFC 1918 IPv4)
    if addr.is_private:
        return NormalizedIPInfo(
            ip=str(addr),
            version=version,
            classification=IPClassification.PRIVATE,
            is_public=False,
            is_private=True,
            is_geolocatable=False,
            location_accuracy="internal-network",
            routing_role="Internal LAN / Private Subnet",
            reason="Private address space (RFC 1918). Physical location requires internal telemetry.",
        )

    # 8. Reserved
    if addr.is_reserved:
        return NormalizedIPInfo(
            ip=str(addr),
            version=version,
            classification=IPClassification.RESERVED,
            is_public=False,
            is_private=True,
            is_geolocatable=False,
            location_accuracy="unknown",
            routing_role="IETF Reserved",
            reason="Reserved address space (non-routable on the public internet)",
        )

    # 9. Public Routable Internet IP
    return NormalizedIPInfo(
        ip=str(addr),
        version=version,
        classification=IPClassification.PUBLIC,
        is_public=True,
        is_private=False,
        is_geolocatable=True,
        location_accuracy="approximate",
        routing_role="Public Internet Node",
        reason="Publicly routable IP address with approximate geographical network mapping",
    )
