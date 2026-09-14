"""
SentinelTrace Backend — Autonomous System & Network Operator Service
"""
from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.services.geo_service import GeoService
from app.services.ip_trace.classifier import classify_ip

logger = get_logger("sentineltrace.ip_trace.asn")


class ASNService:
    """Enriches public IPs with Autonomous System (ASN), carrier/ISP, and organization metadata."""

    def __init__(self) -> None:
        self._geo_service = GeoService()

    async def get_asn(self, ip: str) -> dict[str, Any]:
        classification = classify_ip(ip)
        if not classification.is_public:
            return {
                "ip": classification.ip,
                "asn": None,
                "organization": None,
                "isp": None,
                "routing_type": classification.classification.value,
                "routing_label": classification.routing_role,
                "status": "NOT_APPLICABLE",
                "is_hosting": False,
                "is_vpn": False,
                "is_tor": False,
                "is_proxy": False,
            }

        try:
            raw_geo = await self._geo_service.geolocate(classification.ip)
            asn = raw_geo.get("asn")
            isp = raw_geo.get("isp")
            org = raw_geo.get("org")

            return {
                "ip": classification.ip,
                "asn": asn,
                "organization": org or isp,
                "isp": isp or org,
                "routing_type": raw_geo.get("routing_type", "DIRECT_ENTERPRISE"),
                "routing_label": raw_geo.get("routing_label", "Direct Public Routing"),
                "status": "RESOLVED" if (asn or isp or org) else "UNAVAILABLE",
                "is_hosting": bool(raw_geo.get("is_hosting", False)),
                "is_vpn": bool(raw_geo.get("is_vpn", False)),
                "is_tor": bool(raw_geo.get("is_tor", False)),
                "is_proxy": bool(raw_geo.get("is_proxy", False)),
            }
        except Exception as e:
            logger.warning("asn_lookup_failed", ip=ip, error=str(e))
            return {
                "ip": classification.ip,
                "asn": None,
                "organization": None,
                "isp": None,
                "routing_type": "UNKNOWN",
                "routing_label": "Autonomous System Query Failed",
                "status": "ERROR",
                "is_hosting": False,
                "is_vpn": False,
                "is_tor": False,
                "is_proxy": False,
            }
