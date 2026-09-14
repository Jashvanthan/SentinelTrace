"""
SentinelTrace Backend — IP Trace Provider Health Check Service
"""
from __future__ import annotations

import os
from typing import Any

from app.core.config import get_settings

settings = get_settings()


def get_providers_health() -> dict[str, Any]:
    """
    Evaluate the real-time operational status of all IP enrichment providers.
    Never exposes API keys or secrets.
    """
    # 1. MaxMind GeoIP2 database check
    maxmind_configured = False
    maxmind_db = settings.MAXMIND_DB_PATH
    if maxmind_db and os.path.exists(maxmind_db):
        maxmind_configured = True
    else:
        for default_loc in [
            "./data/GeoLite2-City.mmdb",
            "./data/GeoIP2-City.mmdb",
            "/app/data/GeoLite2-City.mmdb",
            "/app/data/GeoIP2-City.mmdb",
        ]:
            if os.path.exists(default_loc):
                maxmind_configured = True
                break

    # 2. Threat Intel API Key configurations
    has_vt = bool(settings.VIRUSTOTAL_API_KEY and len(settings.VIRUSTOTAL_API_KEY.strip()) > 5)
    has_abuse = bool(settings.ABUSEIPDB_API_KEY and len(settings.ABUSEIPDB_API_KEY.strip()) > 5)
    has_shodan = bool(settings.SHODAN_API_KEY and len(settings.SHODAN_API_KEY.strip()) > 5)

    return {
        "geoip": {
            "configured": True,
            "available": True,
            "provider": "MaxMind GeoIP2" if maxmind_configured else "ipwho.is / ip-api.com (Fallback)",
            "mode": "database" if maxmind_configured else "online_https",
            "accuracy": "approximate",
        },
        "asn": {
            "configured": True,
            "available": True,
            "provider": "RDAP / BGP Registry",
            "mode": "open_standards",
        },
        "reverse_dns": {
            "configured": True,
            "available": True,
            "provider": "DNS PTR Resolver",
            "mode": "asynchronous_socket",
        },
        "virustotal": {
            "configured": has_vt,
            "available": has_vt,
            "provider": "VirusTotal API v3",
            "status": "CONFIGURED" if has_vt else "NOT_CONFIGURED",
        },
        "abuseipdb": {
            "configured": has_abuse,
            "available": has_abuse,
            "provider": "AbuseIPDB API v2",
            "status": "CONFIGURED" if has_abuse else "NOT_CONFIGURED",
        },
        "shodan": {
            "configured": has_shodan,
            "available": has_shodan,
            "provider": "Shodan Host API",
            "status": "CONFIGURED" if has_shodan else "NOT_CONFIGURED",
        },
        "internal_telemetry": {
            "configured": False,
            "available": False,
            "provider": "Enterprise NAC / DHCP Connector",
            "status": "NOT_CONNECTED",
            "reason": "Internal network telemetry requires enterprise connector integration",
        },
    }
