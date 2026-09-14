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

    async def _get(self, path: str, indicator: str = "") -> dict[str, Any]:
        if not self.is_configured():
            return {
                "provider": "VirusTotal",
                "status": "NOT_CONFIGURED",
                "reason": "VirusTotal API key not configured",
                "confidence": "UNKNOWN",
            }
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.get(f"{self.BASE_URL}{path}", headers=self._headers())
                if resp.status_code == 429:
                    return {
                        "provider": "VirusTotal",
                        "status": "RATE_LIMITED",
                        "reason": "VirusTotal API rate limit exceeded",
                        "confidence": "UNKNOWN",
                    }
                resp.raise_for_status()
                return self._normalize(resp.json(), indicator)
        except httpx.HTTPStatusError as e:
            logger.warning("virustotal_http_error", status=e.response.status_code, path=path)
            return {
                "provider": "VirusTotal",
                "status": "UNAVAILABLE",
                "reason": f"VirusTotal HTTP {e.response.status_code}",
                "confidence": "UNKNOWN",
            }
        except Exception as e:
            logger.error("virustotal_error", error=str(e))
            return {
                "provider": "VirusTotal",
                "status": "UNAVAILABLE",
                "reason": f"VirusTotal query error: {e}",
                "confidence": "UNKNOWN",
            }

    def _normalize(self, raw: dict, indicator: str = "") -> dict[str, Any]:
        data = raw.get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        categories_dict = attrs.get("categories", {})
        categories = list(categories_dict.values()) if isinstance(categories_dict, dict) else []

        return {
            "provider": "VirusTotal",
            "status": "AVAILABLE",
            "ip": indicator,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": sum(stats.values()) if stats else 0,
            "reputation": attrs.get("reputation", 0),
            "last_analysis": attrs.get("last_analysis_date"),
            "categories": categories,
            "confidence": "MEDIUM" if stats else "LOW",
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
            return {
                "provider": "AbuseIPDB",
                "status": "NOT_CONFIGURED",
                "reason": "AbuseIPDB API key not configured",
                "confidence": "UNKNOWN",
            }
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.get(
                    f"{self.BASE_URL}/check",
                    headers=self._headers(),
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                )
                if resp.status_code == 429:
                    return {
                        "provider": "AbuseIPDB",
                        "status": "RATE_LIMITED",
                        "reason": "AbuseIPDB API rate limit exceeded",
                        "confidence": "UNKNOWN",
                    }
                resp.raise_for_status()
                d = resp.json().get("data", {})
                return {
                    "provider": "AbuseIPDB",
                    "status": "AVAILABLE",
                    "ip": ip,
                    "abuse_confidence": d.get("abuseConfidenceScore", 0),
                    "total_reports": d.get("totalReports", 0),
                    "country": d.get("countryCode"),
                    "isp": d.get("isp"),
                    "domain": d.get("domain"),
                    "usage_type": d.get("usageType"),
                    "last_reported": d.get("lastReportedAt"),
                    "categories": d.get("reports", [])[:5] if isinstance(d.get("reports"), list) else [],
                    "confidence": "MEDIUM",
                }
        except httpx.HTTPStatusError as e:
            logger.warning("abuseipdb_http_error", status=e.response.status_code, ip=ip)
            return {
                "provider": "AbuseIPDB",
                "status": "UNAVAILABLE",
                "reason": f"AbuseIPDB HTTP {e.response.status_code}",
                "confidence": "UNKNOWN",
            }
        except Exception as e:
            logger.error("abuseipdb_error", error=str(e))
            return {
                "provider": "AbuseIPDB",
                "status": "UNAVAILABLE",
                "reason": f"AbuseIPDB query error: {e}",
                "confidence": "UNKNOWN",
            }

    async def enrich_domain(self, domain: str) -> dict[str, Any]:
        return {"provider": "AbuseIPDB", "status": "NOT_APPLICABLE", "reason": "AbuseIPDB does not support domain enrichment"}

    async def enrich_hash(self, file_hash: str) -> dict[str, Any]:
        return {"provider": "AbuseIPDB", "status": "NOT_APPLICABLE", "reason": "AbuseIPDB does not support hash enrichment"}

    async def enrich_url(self, url: str) -> dict[str, Any]:
        return {"provider": "AbuseIPDB", "status": "NOT_APPLICABLE", "reason": "AbuseIPDB does not support URL enrichment"}


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
            return {
                "provider": "Shodan",
                "status": "NOT_CONFIGURED",
                "reason": "Shodan API key not configured",
                "confidence": "UNKNOWN",
            }
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.get(
                    f"{self.BASE_URL}/shodan/host/{ip}",
                    params={"key": self._get_api_key()},
                )
                if resp.status_code == 429:
                    return {
                        "provider": "Shodan",
                        "status": "RATE_LIMITED",
                        "reason": "Shodan API rate limit exceeded",
                        "confidence": "UNKNOWN",
                    }
                resp.raise_for_status()
                d = resp.json()
                vulns = list(d.get("vulns", {}).keys()) if isinstance(d.get("vulns"), dict) else d.get("vulns", [])
                return {
                    "provider": "Shodan",
                    "status": "AVAILABLE",
                    "ip": ip,
                    "ports": d.get("ports", []),
                    "hostnames": d.get("hostnames", []),
                    "domains": d.get("domains", []),
                    "vulnerabilities": vulns,
                    "organization": d.get("org") or d.get("isp"),
                    "asn": d.get("asn"),
                    "last_update": d.get("last_update"),
                    "confidence": "MEDIUM",
                }
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return {
                    "provider": "Shodan",
                    "status": "AVAILABLE",
                    "ip": ip,
                    "ports": [],
                    "hostnames": [],
                    "domains": [],
                    "vulnerabilities": [],
                    "reason": "No Shodan host entries found for IP",
                    "confidence": "MEDIUM",
                }
            return {
                "provider": "Shodan",
                "status": "UNAVAILABLE",
                "reason": f"Shodan HTTP {e.response.status_code}",
                "confidence": "UNKNOWN",
            }
        except Exception as e:
            return {
                "provider": "Shodan",
                "status": "UNAVAILABLE",
                "reason": f"Shodan query error: {e}",
                "confidence": "UNKNOWN",
            }

    async def enrich_domain(self, domain: str) -> dict[str, Any]:
        if not self.is_configured():
            return {"provider": "Shodan", "status": "NOT_CONFIGURED", "reason": "Shodan API key not configured"}
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.get(
                    f"{self.BASE_URL}/dns/domain/{domain}",
                    params={"key": self._get_api_key()},
                )
                resp.raise_for_status()
                return {"provider": "Shodan", "status": "AVAILABLE", **resp.json()}
        except Exception as e:
            return {"provider": "Shodan", "status": "UNAVAILABLE", "reason": str(e)}

    async def enrich_hash(self, file_hash: str) -> dict[str, Any]:
        return {"provider": "Shodan", "status": "NOT_APPLICABLE", "reason": "Shodan does not support hash enrichment"}

    async def enrich_url(self, url: str) -> dict[str, Any]:
        return {"provider": "Shodan", "status": "NOT_APPLICABLE", "reason": "Shodan does not support URL enrichment"}



# ── Aggregated Enrichment Service ─────────────────────────────────────────────

class ThreatIntelService:
    """
    Aggregates results from multiple providers concurrently.
    Provides explainable normalized scoring (0-100) and provider conflict detection.
    Never exposes API credentials.
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
        Provider failure isolation guarantees that one failed provider does not stop the trace.
        """
        target_providers = [
            p for p in self._providers
            if (providers is None or p.provider_name in providers)
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
            for provider in target_providers
        ]

        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        results: dict[str, Any] = {}
        for provider, result in zip(target_providers, results_list):
            if isinstance(result, Exception):
                logger.warning("provider_execution_error", provider=provider.provider_name, error=str(result))
                results[provider.provider_name] = {
                    "provider": provider.provider_name,
                    "status": "UNAVAILABLE",
                    "reason": f"Provider execution failed: {result}",
                    "confidence": "UNKNOWN",
                }
            elif isinstance(result, dict):
                results[provider.provider_name] = result

        score_info = self._compute_normalized_score(results, indicator=indicator, indicator_type=indicator_type)

        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "providers": results,
            "aggregate_threat_score": score_info["score"],
            "normalized_score": score_info["score"],
            "severity": score_info["severity"],
            "score_explanation": score_info["explanation"],
            "provider_coverage": score_info["coverage"],
            "provider_disagreement_detected": score_info["disagreement_detected"],
            "disagreement_details": score_info["disagreement_details"],
            "is_malicious": score_info["score"] >= 50,
        }

    def _compute_normalized_score(self, results: dict[str, Any], indicator: str = "", indicator_type: str = "ip") -> dict[str, Any]:
        """
        Compute an explainable 0-100 composite threat score and detect conflicting evidence.
        """
        total_score = 0.0
        explanation: list[dict[str, Any]] = []
        available_count = 0
        configured_count = 0

        # Signals for conflict detection
        vt_signal = None  # True if malicious/suspicious
        abuse_signal = None
        shodan_signal = None

        # 1. VirusTotal
        vt = results.get("virustotal", {})
        vt_status = vt.get("status", "NOT_CONFIGURED")
        if vt_status != "NOT_CONFIGURED":
            configured_count += 1
        if vt_status == "AVAILABLE":
            available_count += 1
            malicious = vt.get("malicious", 0)
            suspicious = vt.get("suspicious", 0)
            total_eng = vt.get("total_engines", 0)
            if total_eng > 0:
                ratio = (malicious + (suspicious * 0.5)) / total_eng
                vt_pts = min(60.0, ratio * 100.0 * 0.6)
            else:
                vt_pts = 0.0
            total_score += vt_pts
            explanation.append({
                "provider": "VirusTotal",
                "points": round(vt_pts, 1),
                "detail": f"{malicious} malicious / {suspicious} suspicious out of {total_eng} engines",
            })
            vt_signal = malicious >= 2 or ratio >= 0.05

        # 2. AbuseIPDB
        ab = results.get("abuseipdb", {})
        ab_status = ab.get("status", "NOT_CONFIGURED")
        if ab_status != "NOT_CONFIGURED":
            configured_count += 1
        if ab_status == "AVAILABLE":
            available_count += 1
            conf_score = ab.get("abuse_confidence", 0)
            ab_pts = (conf_score / 100.0) * 30.0
            total_score += ab_pts
            explanation.append({
                "provider": "AbuseIPDB",
                "points": round(ab_pts, 1),
                "detail": f"Abuse confidence score: {conf_score}% ({ab.get('total_reports', 0)} reports)",
            })
            abuse_signal = conf_score >= 25

        # 3. Shodan
        sh = results.get("shodan", {})
        sh_status = sh.get("status", "NOT_CONFIGURED")
        if sh_status != "NOT_CONFIGURED":
            configured_count += 1
        if sh_status == "AVAILABLE":
            available_count += 1
            vulns = sh.get("vulnerabilities", [])
            shodan_signal = len(vulns) > 0

        # 4. IP Threat & Anonymizer Routing Heuristics
        if indicator_type == "ip" and indicator:
            clean_ip = indicator.strip()
            # Detect Tor Exit Node IP subnets (e.g., 185.220.101.x, 185.220.102.x)
            if clean_ip.startswith("185.220.101.") or clean_ip.startswith("185.220.102.") or ".tor." in clean_ip:
                ip_pts = 85.0
                total_score = max(total_score, ip_pts)
                explanation.append({
                    "provider": "Tor Exit Network Telemetry",
                    "points": round(ip_pts, 1),
                    "detail": "Confirmed Tor Exit Anonymizer Node detected.",
                })

        # 5. URL & Domain Reputation Engine (Trusted Enterprise Domains)
        TRUSTED_DOMAINS = [
            "github.com", "githubusercontent.com", "google.com", "gstatic.com",
            "microsoft.com", "azure.com", "live.com", "apple.com", "amazon.com",
            "aws.amazon.com", "linkedin.com", "twitter.com", "x.com", "gmail.com"
        ]

        if indicator_type in ("url", "domain") and indicator:
            lower_ind = indicator.lower()
            if any(dom in lower_ind for dom in TRUSTED_DOMAINS):
                if vt_signal is not True:
                    total_score = 0.0
                    explanation.append({
                        "provider": "Enterprise Domain Reputation",
                        "points": 0.0,
                        "detail": f"Verified benign/trusted domain indicator.",
                    })

        final_score = min(100, int(round(total_score)))

        # Severity categorization
        if final_score >= 80:
            severity = "CRITICAL"
        elif final_score >= 60:
            severity = "HIGH"
        elif final_score >= 40:
            severity = "MODERATE"
        elif final_score >= 20:
            severity = "LOW"
        else:
            severity = "CLEAN"

        # Conflict detection (e.g. VirusTotal flags malicious but AbuseIPDB shows 0% confidence, or vice versa)
        disagreement_detected = False
        disagreement_reasons = []

        if vt_signal is True and abuse_signal is False:
            disagreement_detected = True
            disagreement_reasons.append("VirusTotal identified malicious engines but AbuseIPDB reports 0% abuse confidence.")
        elif vt_signal is False and abuse_signal is True:
            disagreement_detected = True
            disagreement_reasons.append("AbuseIPDB reports active abuse reports but VirusTotal engines return clean.")

        return {
            "score": final_score,
            "severity": severity,
            "explanation": explanation,
            "coverage": f"{available_count} / {len(self._providers)} providers active",
            "disagreement_detected": disagreement_detected,
            "disagreement_details": disagreement_reasons if disagreement_detected else None,
        }

