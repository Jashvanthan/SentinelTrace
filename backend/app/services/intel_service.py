"""
SentinelTrace Backend — Threat Intelligence Service

Abstract interface with concrete adapters for:
- VirusTotal
- AbuseIPDB
- Shodan

Each adapter returns a normalized dict. Results are merged and scored.
API keys are never logged or passed through to AI layer.
"""
from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

settings = get_settings()
logger = get_logger("sentineltrace.intel")


# ── Abstract Interface ────────────────────────────────────────────────────────

class ThreatIntelProvider(ABC):
    """Abstract base class for threat intelligence providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str: ...

    @abstractmethod
    async def enrich_ip(self, ip: str) -> dict[str, Any]: ...

    @abstractmethod
    async def enrich_domain(self, domain: str) -> dict[str, Any]: ...

    @abstractmethod
    async def enrich_hash(self, file_hash: str) -> dict[str, Any]: ...

    @abstractmethod
    async def enrich_url(self, url: str) -> dict[str, Any]: ...

    def is_configured(self) -> bool:
        """Return True if this provider has a valid API key configured."""
        return bool(self._get_api_key())

    @abstractmethod
    def _get_api_key(self) -> str: ...


# ── VirusTotal Adapter ────────────────────────────────────────────────────────

class VirusTotalAdapter(ThreatIntelProvider):
    BASE_URL = "https://www.virustotal.com/api/v3"

    @property
    def provider_name(self) -> str:
        return "virustotal"

    def _get_api_key(self) -> str:
        return settings.VIRUSTOTAL_API_KEY

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self._get_api_key(), "Accept": "application/json"}

    async def enrich_ip(self, ip: str) -> dict[str, Any]:
        return await self._get(f"/ip_addresses/{ip}")

    async def enrich_domain(self, domain: str) -> dict[str, Any]:
        return await self._get(f"/domains/{domain}")

    async def enrich_hash(self, file_hash: str) -> dict[str, Any]:
        return await self._get(f"/files/{file_hash}")

    async def enrich_url(self, url: str) -> dict[str, Any]:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return await self._get(f"/urls/{url_id}")

    async def _get(self, path: str) -> dict[str, Any]:
        if not self.is_configured():
            return {"error": "VirusTotal API key not configured"}
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(f"{self.BASE_URL}{path}", headers=self._headers())
                resp.raise_for_status()
                return self._normalize(resp.json())
        except httpx.HTTPStatusError as e:
            logger.warning("virustotal_error", status=e.response.status_code, path=path)
            return {"error": f"VirusTotal HTTP {e.response.status_code}"}
        except Exception as e:
            logger.error("virustotal_error", error=str(e))
            return {"error": str(e)}

    def _normalize(self, raw: dict) -> dict[str, Any]:
        data = raw.get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "provider": "virustotal",
            "malicious_count": stats.get("malicious", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "harmless_count": stats.get("harmless", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "threat_names": list(attrs.get("popular_threat_classification", {})
                                  .get("suggested_threat_label", {}).values()
                                  if isinstance(attrs.get("popular_threat_classification"), dict)
                                  else []),
            "reputation": attrs.get("reputation"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "categories": attrs.get("categories", {}),
        }


# ── AbuseIPDB Adapter ─────────────────────────────────────────────────────────

class AbuseIPDBAdapter(ThreatIntelProvider):
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    @property
    def provider_name(self) -> str:
        return "abuseipdb"

    def _get_api_key(self) -> str:
        return settings.ABUSEIPDB_API_KEY

    def _headers(self) -> dict[str, str]:
        return {"Key": self._get_api_key(), "Accept": "application/json"}

    async def enrich_ip(self, ip: str) -> dict[str, Any]:
        if not self.is_configured():
            return {"error": "AbuseIPDB API key not configured"}
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self.BASE_URL}/check",
                    headers=self._headers(),
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                )
                resp.raise_for_status()
                d = resp.json().get("data", {})
                return {
                    "provider": "abuseipdb",
                    "ip_address": d.get("ipAddress"),
                    "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                    "total_reports": d.get("totalReports", 0),
                    "country_code": d.get("countryCode"),
                    "isp": d.get("isp"),
                    "domain": d.get("domain"),
                    "is_whitelisted": d.get("isWhitelisted", False),
                    "usage_type": d.get("usageType"),
                }
        except Exception as e:
            logger.error("abuseipdb_error", error=str(e))
            return {"error": str(e)}

    async def enrich_domain(self, domain: str) -> dict[str, Any]:
        return {"error": "AbuseIPDB does not support domain enrichment"}

    async def enrich_hash(self, file_hash: str) -> dict[str, Any]:
        return {"error": "AbuseIPDB does not support hash enrichment"}

    async def enrich_url(self, url: str) -> dict[str, Any]:
        return {"error": "AbuseIPDB does not support URL enrichment"}


# ── Shodan Adapter ────────────────────────────────────────────────────────────

class ShodanAdapter(ThreatIntelProvider):
    BASE_URL = "https://api.shodan.io"

    @property
    def provider_name(self) -> str:
        return "shodan"

    def _get_api_key(self) -> str:
        return settings.SHODAN_API_KEY

    async def enrich_ip(self, ip: str) -> dict[str, Any]:
        if not self.is_configured():
            return {"error": "Shodan API key not configured"}
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self.BASE_URL}/shodan/host/{ip}",
                    params={"key": self._get_api_key()},
                )
                resp.raise_for_status()
                d = resp.json()
                return {
                    "provider": "shodan",
                    "ip_str": d.get("ip_str"),
                    "ports": d.get("ports", []),
                    "hostnames": d.get("hostnames", []),
                    "country_name": d.get("country_name"),
                    "city": d.get("city"),
                    "org": d.get("org"),
                    "isp": d.get("isp"),
                    "os": d.get("os"),
                    "vulns": list(d.get("vulns", {}).keys()),
                    "last_update": d.get("last_update"),
                    "open_ports": d.get("ports", []),
                }
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return {"provider": "shodan", "ip_str": ip, "ports": [], "hostnames": [],
                        "vulns": [], "note": "No Shodan data available"}
            return {"error": f"Shodan HTTP {e.response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    async def enrich_domain(self, domain: str) -> dict[str, Any]:
        if not self.is_configured():
            return {"error": "Shodan API key not configured"}
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self.BASE_URL}/dns/domain/{domain}",
                    params={"key": self._get_api_key()},
                )
                resp.raise_for_status()
                return {"provider": "shodan", **resp.json()}
        except Exception as e:
            return {"error": str(e)}

    async def enrich_hash(self, file_hash: str) -> dict[str, Any]:
        return {"error": "Shodan does not support hash enrichment"}

    async def enrich_url(self, url: str) -> dict[str, Any]:
        return {"error": "Shodan does not support URL enrichment"}


# ── Aggregated Enrichment Service ─────────────────────────────────────────────

class ThreatIntelService:
    """
    Aggregates results from multiple providers.
    All calls are async/concurrent. Keys never logged.
    """

    def __init__(self) -> None:
        self._providers: list[ThreatIntelProvider] = [
            VirusTotalAdapter(),
            AbuseIPDBAdapter(),
            ShodanAdapter(),
        ]

    async def enrich(
        self,
        indicator: str,
        indicator_type: str,
        providers: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Enrich an indicator against all (or specified) providers concurrently.

        Args:
            indicator: The value to enrich (IP, domain, hash, URL)
            indicator_type: One of: ip, domain, hash, url, email
            providers: Optional whitelist of provider names

        Returns:
            Aggregated dict with per-provider results and composite threat score
        """
        active_providers = [
            p for p in self._providers
            if (providers is None or p.provider_name in providers) and p.is_configured()
        ]

        method_map = {
            "ip": "enrich_ip",
            "domain": "enrich_domain",
            "hash": "enrich_hash",
            "url": "enrich_url",
        }
        method_name = method_map.get(indicator_type, "enrich_ip")

        tasks = [
            getattr(provider, method_name)(indicator)
            for provider in active_providers
        ]

        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        results: dict[str, Any] = {}
        for provider, result in zip(active_providers, results_list):
            if isinstance(result, Exception):
                results[provider.provider_name] = {"error": str(result)}
            else:
                results[provider.provider_name] = result

        composite_score = self._compute_threat_score(results)

        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "providers": results,
            "aggregate_threat_score": composite_score,
            "is_malicious": composite_score >= 50,
        }

    def _compute_threat_score(self, results: dict[str, Any]) -> int:
        """Compute a 0-100 composite threat score from provider results."""
        score = 0
        weight_sum = 0

        vt = results.get("virustotal", {})
        if "malicious_count" in vt and vt.get("total_engines", 0) > 0:
            vt_ratio = vt["malicious_count"] / vt["total_engines"]
            score += vt_ratio * 70  # VirusTotal carries 70% of the weight
            weight_sum += 70

        abip = results.get("abuseipdb", {})
        if "abuse_confidence_score" in abip:
            score += abip["abuse_confidence_score"] * 0.3
            weight_sum += 30

        return min(100, int(score))
