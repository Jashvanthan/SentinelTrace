"""
SentinelTrace Backend — Threat Analysis Orchestrator

Coordinates the full threat analysis pipeline:
1. Parse .eml
2. Upload to GCS (encrypted)
3. Concurrent threat intel enrichment (VirusTotal, AbuseIPDB, Shodan)
4. IP geolocation for all extracted IPs
5. AI classification and summary generation
6. Write results to PostgreSQL
7. Update Neo4j campaign graph
"""
from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.email_analysis import AnalysisStatus, EmailAnalysis, EmailAttachment
from app.models.ioc import IOC, IOCType
from app.models.threat_record import ThreatProvider, ThreatRecord
from app.services.ai_service import EmailThreatContext, get_ai_service
from app.services.email_service import ParsedEmail, parse_eml
from app.services.gcs_service import GCSService
from app.services.geo_service import GeoService
from app.services.intel_service import ThreatIntelService
from app.services.neo4j_service import get_neo4j_service

logger = get_logger("sentineltrace.threat_pipeline")


class ThreatAnalysisPipeline:
    """Orchestrates the full email threat analysis pipeline."""

    def __init__(self) -> None:
        self._intel = ThreatIntelService()
        self._geo = GeoService()
        self._gcs = GCSService()
        self._ai = get_ai_service()
        self._neo4j = get_neo4j_service()

    async def run(
        self,
        db: AsyncSession,
        analysis: EmailAnalysis,
        raw_eml_bytes: bytes,
    ) -> EmailAnalysis:
        """
        Execute the full analysis pipeline for an uploaded .eml file.

        Updates the EmailAnalysis record in-place and commits results.
        """
        analysis.status = AnalysisStatus.PROCESSING
        await db.flush()

        try:
            # ── Step 1: Parse EML ─────────────────────────────────────────────
            logger.info("pipeline_step", step="parse", analysis_id=str(analysis.id))
            parsed = parse_eml(raw_eml_bytes)
            self._populate_parsed_fields(analysis, parsed, raw_eml_bytes)

            # ── Step 2: Upload to GCS ─────────────────────────────────────────
            logger.info("pipeline_step", step="gcs_upload", analysis_id=str(analysis.id))
            gcs_path = await self._gcs.upload_eml(str(analysis.id), raw_eml_bytes)
            analysis.raw_eml_gcs_path = gcs_path

            # ── Step 3: Concurrent Enrichment ─────────────────────────────────
            logger.info("pipeline_step", step="enrichment", analysis_id=str(analysis.id))
            all_ioc_values = (
                parsed.extracted_ips + parsed.extracted_urls +
                [a.sha256_hash for a in parsed.attachments]
            )
            enrich_results = await self._run_enrichment(parsed)

            # ── Step 4: Geolocation for IPs ───────────────────────────────────
            logger.info("pipeline_step", step="geolocation", analysis_id=str(analysis.id))
            geo_results = await self._run_geolocation(parsed.extracted_ips, parsed.sender_domain)

            # ── Step 5: Write IOCs ────────────────────────────────────────────
            ioc_records = await self._write_iocs(db, analysis.id, analysis.workspace_id, parsed, enrich_results)

            # ── Step 6: Write Attachments ─────────────────────────────────────
            await self._write_attachments(db, analysis.id, analysis.workspace_id, parsed, enrich_results)

            # ── Step 7: Write Threat Records ──────────────────────────────────
            await self._write_threat_records(db, analysis.id, analysis.workspace_id, enrich_results)

            # ── Step 8: AI Classification ─────────────────────────────────────
            logger.info("pipeline_step", step="ai_classify", analysis_id=str(analysis.id))
            intel_summary = self._build_intel_summary(enrich_results)
            context = EmailThreatContext(
                subject=parsed.subject,
                sender_email=parsed.sender_email,
                sender_domain=parsed.sender_domain,
                reply_to=parsed.reply_to,
                recipient_count=len(parsed.recipients),
                spf_result=parsed.spf_result,
                dkim_result=parsed.dkim_result,
                dmarc_result=parsed.dmarc_result,
                extracted_urls=parsed.extracted_urls,
                extracted_ips=parsed.extracted_ips,
                attachment_count=len(parsed.attachments),
                attachment_names=[a.filename or "" for a in parsed.attachments],
                attachment_types=[a.content_type or "" for a in parsed.attachments],
                body_text_snippet=parsed.body_text,
                threat_intel_summary=intel_summary,
            )
            classification = await self._ai.classify_threat(context)
            summary = await self._ai.generate_summary(context, classification)

            analysis.threat_category = classification.threat_category  # type: ignore[assignment]
            analysis.severity = classification.severity  # type: ignore[assignment]
            analysis.confidence_score = classification.confidence_score
            analysis.ai_summary = summary
            analysis.ai_reasoning = classification.reasoning
            analysis.ai_indicators = classification.indicators
            analysis.ai_model_used = classification.model_used

            # ── Step 9: Compute threat score & structure telemetry ───────────────
            analysis.threat_score = self._compute_composite_score(enrich_results, classification, parsed)

            # Inherit contextual threat score for extracted IOCs if direct enrichment had 0/None
            email_score = int(analysis.threat_score or 0)
            if email_score >= 45:
                for ioc in ioc_records:
                    val_lower = (ioc.value or "").lower()
                    is_trusted = any(dom in val_lower for dom in ["google.com", "microsoft.com", "apple.com", "github.com", "schema.org", "w3.org", "googleapis.com", "x.com", "gmail.com", "gstatic.com"])
                    if not is_trusted and (ioc.threat_score is None or ioc.threat_score == 0):
                        if email_score >= 75:
                            ioc.threat_score = max(int(email_score * 0.85), 72)
                            ioc.is_malicious = True
                        else:
                            ioc.threat_score = max(int(email_score * 0.65), 52)

            # Determine primary public/observed geolocation candidate
            primary_geo = None
            for g in geo_results:
                if isinstance(g, dict) and g.get("country") and g.get("routing_type") not in ("INTERNAL_LAN", "UNKNOWN") and not g.get("error"):
                    primary_geo = g
                    break
            if not primary_geo:
                for g in geo_results:
                    if isinstance(g, dict) and g.get("routing_type") != "INTERNAL_LAN":
                        primary_geo = g
                        break
            if not primary_geo and geo_results:
                primary_geo = geo_results[0] if isinstance(geo_results[0], dict) else None

            analysis.geo_data = {
                **(primary_geo or {}),
                "ips": geo_results,
                "primary_ip": primary_geo.get("ip_address") if primary_geo else None,
            }

            # Map primary IP enrichment for immediate frontend inspection
            primary_ip_enrich = None
            if primary_geo and primary_geo.get("ip_address"):
                primary_ip_enrich = enrich_results.get(f"ip_{primary_geo['ip_address']}")
            if not primary_ip_enrich and parsed.extracted_ips:
                primary_ip_enrich = enrich_results.get(f"ip_{parsed.extracted_ips[0]}")

            vt_data = None
            abuse_data = None
            shodan_data = None
            if primary_ip_enrich and isinstance(primary_ip_enrich, dict):
                providers = primary_ip_enrich.get("providers", {})
                vt_data = providers.get("virustotal")
                abuse_data = providers.get("abuseipdb")
                shodan_data = providers.get("shodan")

            analysis.enrichment_data = {
                **enrich_results,
                "primary_indicator": primary_geo.get("ip_address") if primary_geo else (parsed.extracted_ips[0] if parsed.extracted_ips else None),
                "virustotal": vt_data,
                "abuseipdb": abuse_data,
                "shodan": shodan_data,
            }

            # ── Step 10: Neo4j graph update ───────────────────────────────────
            logger.info("pipeline_step", step="neo4j_write", analysis_id=str(analysis.id))
            try:
                ioc_dicts = [
                    {"value": ioc.value, "ioc_type": ioc.ioc_type.value,
                     "is_malicious": ioc.is_malicious, "threat_score": ioc.threat_score}
                    for ioc in ioc_records
                ]
                await self._neo4j.upsert_email_analysis(
                    workspace_id=str(analysis.workspace_id),
                    analysis_id=str(analysis.id),
                    sender_email=parsed.sender_email,
                    sender_domain=parsed.sender_domain,
                    subject=parsed.subject,
                    threat_category=classification.threat_category,
                    severity=classification.severity,
                    iocs=ioc_dicts,
                    received_ips=parsed.extracted_ips[:20],
                )
            except Exception as e:
                # Neo4j failure should not block the analysis
                logger.error("neo4j_write_error", error=str(e))

            analysis.completed_at = datetime.now(UTC)
            analysis.status = AnalysisStatus.COMPLETE

            await db.commit()
            await db.refresh(analysis)
            logger.info(
                "pipeline_complete",
                analysis_id=str(analysis.id),
                threat_category=str(analysis.threat_category),
                severity=str(analysis.severity),
                threat_score=analysis.threat_score,
            )

        except Exception as e:
            logger.error("pipeline_error", analysis_id=str(analysis.id), error=str(e), exc_info=True)
            analysis.status = AnalysisStatus.FAILED
            analysis.error_message = str(e)
            await db.commit()
            raise

        return analysis

    # ── Private Helpers ───────────────────────────────────────────────────────

    def _parse_email_date(self, date_str: str | None) -> datetime | None:
        if not date_str:
            return None
        try:
            return parsedate_to_datetime(date_str)
        except Exception:
            try:
                return datetime.fromisoformat(date_str)
            except Exception:
                return None

    def _populate_parsed_fields(
        self, analysis: EmailAnalysis, parsed: ParsedEmail, raw_bytes: bytes
    ) -> None:
        analysis.subject = parsed.subject
        analysis.sender_email = parsed.sender_email
        analysis.sender_display_name = parsed.sender_display_name
        analysis.sender_domain = parsed.sender_domain
        analysis.reply_to = parsed.reply_to
        analysis.recipients = parsed.recipients
        analysis.message_id = parsed.message_id
        analysis.email_date = self._parse_email_date(parsed.email_date)
        analysis.received_headers = parsed.received_headers
        analysis.all_headers = parsed.all_headers
        analysis.authentication_results = parsed.authentication_results
        analysis.spf_result = parsed.spf_result
        analysis.dkim_result = parsed.dkim_result
        analysis.dmarc_result = parsed.dmarc_result
        analysis.raw_eml_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        analysis.raw_eml_size_bytes = len(raw_bytes)

    async def _run_enrichment(self, parsed: ParsedEmail) -> dict[str, Any]:
        tasks: dict[str, Any] = {}

        for ip in parsed.extracted_ips[:5]:  # Limit to 5 IPs
            tasks[f"ip_{ip}"] = self._intel.enrich(ip, "ip")

        for url in parsed.extracted_urls[:5]:  # Limit to 5 URLs
            tasks[f"url_{url[:50]}"] = self._intel.enrich(url, "url")

        for att in parsed.attachments[:3]:  # Limit to 3 attachments
            tasks[f"hash_{att.sha256_hash}"] = self._intel.enrich(att.sha256_hash, "hash")

        if parsed.sender_domain:
            tasks[f"domain_{parsed.sender_domain}"] = self._intel.enrich(parsed.sender_domain, "domain")

        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        return {k: (v if not isinstance(v, Exception) else {"error": str(v)})
                for k, v in zip(tasks.keys(), results)}

    async def _run_geolocation(self, ips: list[str], sender_domain: str | None = None) -> list[dict]:
        target_ips = list(ips[:10]) if ips else []
        if sender_domain:
            import socket
            try:
                domain_clean = sender_domain.strip().lower()
                if domain_clean and not domain_clean.endswith(".local") and not domain_clean.endswith(".lan"):
                    dom_ip = socket.gethostbyname(domain_clean)
                    if dom_ip and dom_ip not in target_ips:
                        target_ips.insert(0, dom_ip)
            except Exception:
                pass

        if not target_ips:
            target_ips = ["1.1.1.1"]

        tasks = [self._geo.geolocate(ip) for ip in target_ips]
        return await asyncio.gather(*tasks)

    async def _write_iocs(
        self, db: AsyncSession, analysis_id: uuid.UUID, workspace_id: uuid.UUID,
        parsed: ParsedEmail, enrich_results: dict,
    ) -> list[IOC]:
        from app.services.email_service import _normalize_ipv4
        from app.api.v1.emails import classify_ip_candidate

        TRUSTED_DOMAINS = (
            "github.com", "google.com", "microsoft.com", "azure.com", "live.com",
            "apple.com", "amazon.com", "aws.amazon.com", "linkedin.com", "twitter.com",
            "x.com", "gmail.com", "gstatic.com"
        )

        iocs: list[IOC] = []
        for ip in parsed.extracted_ips:
            ip_clean = _normalize_ipv4(ip)
            enrich_key = f"ip_{ip_clean}"
            enrich = enrich_results.get(enrich_key) or enrich_results.get(f"ip_{ip}") or {}
            
            norm_ip, classification, is_private = classify_ip_candidate(ip_clean)
            if is_private:
                is_malicious = False
                threat_score = 0
            else:
                is_malicious = enrich.get("is_malicious")
                threat_score = enrich.get("aggregate_threat_score")
                if is_malicious is None:
                    is_malicious = False
                if threat_score is None:
                    threat_score = 0

            ioc = IOC(
                workspace_id=workspace_id,
                analysis_id=analysis_id,
                ioc_type=IOCType.IP_ADDRESS,
                value=norm_ip,
                is_malicious=bool(is_malicious),
                threat_score=int(threat_score),
                enrichment_data=enrich or {"classification": classification},
            )
            db.add(ioc)
            iocs.append(ioc)

        for url in parsed.extracted_urls:
            enrich_key = f"url_{url[:50]}"
            enrich = enrich_results.get(enrich_key, {})
            url_lower = url.lower()
            is_trusted = any(dom in url_lower for dom in TRUSTED_DOMAINS)
            if is_trusted:
                is_malicious = False
                threat_score = 0
            else:
                is_malicious = enrich.get("is_malicious")
                threat_score = enrich.get("aggregate_threat_score")
                if is_malicious is None:
                    is_malicious = False
                if threat_score is None:
                    threat_score = 0

            ioc = IOC(
                workspace_id=workspace_id,
                analysis_id=analysis_id,
                ioc_type=IOCType.URL,
                value=url[:2048],
                is_malicious=bool(is_malicious),
                threat_score=int(threat_score),
                enrichment_data=enrich or {"trusted": is_trusted},
            )
            db.add(ioc)
            iocs.append(ioc)

        return iocs

    async def _write_attachments(
        self, db: AsyncSession, analysis_id: uuid.UUID, workspace_id: uuid.UUID,
        parsed: ParsedEmail, enrich_results: dict,
    ) -> None:
        for att in parsed.attachments:
            enrich = enrich_results.get(f"hash_{att.sha256_hash}", {})
            vt = enrich.get("providers", {}).get("virustotal", {})
            attachment = EmailAttachment(
                workspace_id=workspace_id,
                analysis_id=analysis_id,
                filename=att.filename,
                content_type=att.content_type,
                size_bytes=att.size_bytes,
                sha256_hash=att.sha256_hash,
                md5_hash=att.md5_hash,
                is_malicious=bool(enrich.get("is_malicious", False)),
                vt_detections=vt.get("malicious_count"),
                vt_total_engines=vt.get("total_engines"),
            )
            db.add(attachment)

    async def _write_threat_records(
        self, db: AsyncSession, analysis_id: uuid.UUID, workspace_id: uuid.UUID,
        enrich_results: dict,
    ) -> None:
        for key, result in enrich_results.items():
            if isinstance(result, dict) and "providers" in result:
                for provider_name, provider_data in result["providers"].items():
                    if "error" in provider_data:
                        continue
                    provider_map = {
                        "virustotal": ThreatProvider.VIRUSTOTAL,
                        "abuseipdb": ThreatProvider.ABUSEIPDB,
                        "shodan": ThreatProvider.SHODAN,
                    }
                    provider = provider_map.get(provider_name, ThreatProvider.INTERNAL)
                    record = ThreatRecord(
                        workspace_id=workspace_id,
                        analysis_id=analysis_id,
                        provider=provider,
                        indicator=result.get("indicator", ""),
                        indicator_type=result.get("indicator_type", ""),
                        raw_response=provider_data,
                        threat_score=result.get("aggregate_threat_score", 0),
                    )
                    db.add(record)

    def _build_intel_summary(self, enrich_results: dict[str, Any]) -> dict[str, Any]:
        max_threat_score = 0.0
        malicious_count = 0
        provider_breakdown: dict[str, int] = {}

        for key, result in enrich_results.items():
            if isinstance(result, dict):
                score = float(result.get("aggregate_threat_score", 0) or 0)
                if score > max_threat_score:
                    max_threat_score = score
                if result.get("is_malicious"):
                    malicious_count += 1
                for prov_name, prov_data in result.get("providers", {}).items():
                    if isinstance(prov_data, dict) and not prov_data.get("error"):
                        provider_breakdown[prov_name] = provider_breakdown.get(prov_name, 0) + 1

        return {
            "max_threat_score": max_threat_score,
            "malicious_count": malicious_count,
            "total_enrichments": len(enrich_results),
            "providers_queried": list(provider_breakdown.keys()),
        }

    def _compute_composite_score(self, enrich_results: dict, classification, parsed: ParsedEmail | None = None) -> float:
        intel_max_score = self._build_intel_summary(enrich_results).get("max_threat_score", 0)
        
        auth_penalty = 0.0
        if parsed:
            if parsed.spf_result in ("fail", "softfail"):
                auth_penalty += 30.0
            if parsed.dkim_result in ("fail", "none"):
                auth_penalty += 15.0
            if parsed.dmarc_result in ("fail", "none"):
                auth_penalty += 25.0
            
            if parsed.spf_result == "pass" and parsed.dkim_result == "pass" and parsed.dmarc_result == "pass" and intel_max_score == 0:
                cat = str(getattr(classification, "threat_category", "")).upper()
                if "PHISHING" not in cat and "MALWARE" not in cat and "SPOOFING" not in cat:
                    return 0.0

        ai_cat = str(getattr(classification, "threat_category", "")).upper()
        ai_sev = str(getattr(classification, "severity", "")).upper()
        
        if "BENIGN" in ai_cat or "CLEAN" in ai_cat or "INFO" in ai_sev or "LOW" in ai_sev:
            ai_score = 10.0
        elif "SUSPICIOUS" in ai_cat or "MEDIUM" in ai_sev:
            ai_score = 45.0
        elif "CRITICAL" in ai_sev or "PHISHING" in ai_cat or "MALWARE" in ai_cat:
            ai_score = 85.0
        else:
            ai_score = 25.0

        composite = (intel_max_score * 0.4) + (auth_penalty * 0.4) + (ai_score * 0.2)
        return round(min(100.0, max(0.0, composite)), 1)

