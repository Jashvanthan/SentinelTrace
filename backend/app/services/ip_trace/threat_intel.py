"""
SentinelTrace Backend — IP Threat Intelligence Service
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.core.logging import get_logger
from app.services.intel_service import ThreatIntelService
from app.services.ip_trace.classifier import classify_ip

logger = get_logger("sentineltrace.ip_trace.threat_intel")


class ThreatIntelTraceService:
    """Enriches IP addresses with reputation scores and threat engine signals."""

    def __init__(self) -> None:
        self._intel_service = ThreatIntelService()

    async def get_threat_intel(self, ip: str) -> dict[str, Any]:
        classification = classify_ip(ip)
        if not classification.is_public:
            return {
                "ip": classification.ip,
                "threat_score": 0,
                "status": "NOT_APPLICABLE",
                "is_malicious": False,
                "confidence_score": 1.0,
                "virustotal": None,
                "abuseipdb": None,
                "shodan": None,
                "reason": "Internal or non-routable IP — external threat intelligence not queried",
            }

        try:
            result = await self._intel_service.enrich(classification.ip, "ip")
            providers = result.get("providers", {})
            vt = providers.get("virustotal")
            ab = providers.get("abuseipdb")
            sh = providers.get("shodan")

            score = int(result.get("normalized_score", result.get("aggregate_threat_score", 0)))
            severity = result.get("severity", "CLEAN")
            is_mal = bool(result.get("is_malicious", False))
            disagreement = bool(result.get("provider_disagreement_detected", False))

            # Filter evidence items
            evidence_items = []
            now_iso = datetime.now(UTC).isoformat()

            if vt and vt.get("status") == "AVAILABLE":
                evidence_items.append({
                    "source_type": "VIRUSTOTAL",
                    "source": "VirusTotal API v3",
                    "timestamp": now_iso,
                    "value": f"Malicious: {vt.get('malicious', 0)} / {vt.get('total_engines', 0)} engines",
                    "confidence": vt.get("confidence", "MEDIUM"),
                })

            if ab and ab.get("status") == "AVAILABLE":
                evidence_items.append({
                    "source_type": "ABUSEIPDB",
                    "source": "AbuseIPDB API v2",
                    "timestamp": now_iso,
                    "value": f"Abuse Confidence: {ab.get('abuse_confidence', 0)}% ({ab.get('total_reports', 0)} reports)",
                    "confidence": ab.get("confidence", "MEDIUM"),
                })

            if sh and sh.get("status") == "AVAILABLE":
                evidence_items.append({
                    "source_type": "SHODAN",
                    "source": "Shodan Host API",
                    "timestamp": now_iso,
                    "value": f"Open Ports: {len(sh.get('ports', []))} | Vulns: {len(sh.get('vulnerabilities', []))}",
                    "confidence": sh.get("confidence", "MEDIUM"),
                })

            return {
                "ip": classification.ip,
                "threat_score": score,
                "severity": severity,
                "status": severity if any(p and p.get("status") == "AVAILABLE" for p in [vt, ab, sh]) else "NOT_CONFIGURED",
                "is_malicious": is_mal,
                "confidence_score": 0.85 if (vt and vt.get("status") == "AVAILABLE") else 0.5,
                "provider_coverage": result.get("provider_coverage"),
                "score_explanation": result.get("score_explanation", []),
                "provider_disagreement_detected": disagreement,
                "disagreement_details": result.get("disagreement_details"),
                "virustotal": vt if (vt and vt.get("status") == "AVAILABLE") else None,
                "abuseipdb": ab if (ab and ab.get("status") == "AVAILABLE") else None,
                "shodan": sh if (sh and sh.get("status") == "AVAILABLE") else None,
                "evidence_items": evidence_items,
                "reason": "Normalized multi-provider threat intelligence completed",
            }
        except Exception as e:
            logger.warning("ip_threat_intel_failed", ip=ip, error=str(e))
            return {
                "ip": classification.ip,
                "threat_score": 0,
                "severity": "CLEAN",
                "status": "UNAVAILABLE",
                "is_malicious": False,
                "confidence_score": 0.0,
                "provider_coverage": "0 / 3 providers active",
                "score_explanation": [],
                "provider_disagreement_detected": False,
                "disagreement_details": None,
                "virustotal": None,
                "abuseipdb": None,
                "shodan": None,
                "evidence_items": [],
                "reason": f"Threat intel query encountered an error: {e}",
            }

