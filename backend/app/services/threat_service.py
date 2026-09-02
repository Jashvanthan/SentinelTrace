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
            self._populate_parsed_fields(analysis, parsed)

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
            geo_results = await self._run_geolocation(parsed.extracted_ips)

            # ── Step 5: Write IOCs ────────────────────────────────────────────
            ioc_records = await self._write_iocs(db, analysis.id, parsed, enrich_results)

            # ── Step 6: Write Attachments ─────────────────────────────────────
            await self._write_attachments(db, analysis.id, parsed, enrich_results)

            # ── Step 7: Write Threat Records ──────────────────────────────────
            await self._write_threat_records(db, analysis.id, enrich_results)

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

            # ── Step 9: Compute threat score ──────────────────────────────────
            analysis.threat_score = self._compute_composite_score(enrich_results, classification)
            analysis.enrichment_data = enrich_results
            analysis.geo_data = {"ips": geo_results}

            # ── Step 10: Neo4j graph update ───────────────────────────────────
            logger.info("pipeline_step", step="neo4j_write", analysis_id=str(analysis.id))
            try:
                ioc_dicts = [
                    {"value": ioc.value, "ioc_type": ioc.ioc_type.value,
                     "is_malicious": ioc.is_malicious, "threat_score": ioc.threat_score}
                    for ioc in ioc_records
                ]
                await self._neo4j.upsert_email_analysis(
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

            analysis.status = AnalysisStatus.COMPLETE
            analysis.completed_at = datetime.now(UTC)
            logger.info("pipeline_complete", analysis_id=str(analysis.id), severity=classification.severity)

        except Exception as e:
            logger.error("pipeline_error", analysis_id=str(analysis.id), error=str(e))
            analysis.status = AnalysisStatus.FAILED
            analysis.error_message = str(e)
            raise

        return analysis

    # ── Private Helpers ───────────────────────────────────────────────────────

    def _populate_parsed_fields(self, analysis: EmailAnalysis, parsed: ParsedEmail) -> None:
        analysis.subject = parsed.subject
        analysis.sender_email = parsed.sender_email
        analysis.sender_display_name = parsed.sender_display_name
        analysis.sender_domain = parsed.sender_domain
        analysis.reply_to = parsed.reply_to
        analysis.recipients = parsed.recipients
        analysis.message_id = parsed.message_id
        analysis.email_date = None  # parsed from string — skip for now
        analysis.received_headers = parsed.received_headers
        analysis.all_headers = parsed.all_headers
        analysis.authentication_results = parsed.authentication_results
        analysis.spf_result = parsed.spf_result
        analysis.dkim_result = parsed.dkim_result
        analysis.dmarc_result = parsed.dmarc_result
        analysis.raw_eml_sha256 = hashlib.sha256(b"").hexdigest()  # Will be set by caller

    async def _run_enrichment(self, parsed: ParsedEmail) -> dict:
        tasks = {}

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

    async def _run_geolocation(self, ips: list[str]) -> list[dict]:
        tasks = [self._geo.geolocate(ip) for ip in ips[:10]]
        return await asyncio.gather(*tasks)

    async def _write_iocs(
        self, db: AsyncSession, analysis_id: uuid.UUID,
        parsed: ParsedEmail, enrich_results: dict,
    ) -> list[IOC]:
        iocs: list[IOC] = []
        for ip in parsed.extracted_ips:
            enrich_key = f"ip_{ip}"
            enrich = enrich_results.get(enrich_key, {})
            vt = enrich.get("providers", {}).get("virustotal", {})
            ioc = IOC(
                analysis_id=analysis_id,
                ioc_type=IOCType.IP_ADDRESS,
                value=ip,
                is_malicious=enrich.get("is_malicious"),
                threat_score=enrich.get("aggregate_threat_score"),
                enrichment_data=enrich,
            )
            db.add(ioc)
            iocs.append(ioc)

        for url in parsed.extracted_urls:
            ioc = IOC(
                analysis_id=analysis_id,
                ioc_type=IOCType.URL,
                value=url[:2048],
                enrichment_data=enrich_results.get(f"url_{url[:50]}"),
            )
            db.add(ioc)
            iocs.append(ioc)

        return iocs

    async def _write_attachments(
        self, db: AsyncSession, analysis_id: uuid.UUID,
        parsed: ParsedEmail, enrich_results: dict,
    ) -> None:
        for att in parsed.attachments:
            enrich = enrich_results.get(f"hash_{att.sha256_hash}", {})
            vt = enrich.get("providers", {}).get("virustotal", {})
            attachment = EmailAttachment(
                analysis_id=analysis_id,
                filename=att.filename,
                content_type=att.content_type,
                size_bytes=att.size_bytes,
                sha256_hash=att.sha256_hash,
                md5_hash=att.md5_hash,
                is_malicious=enrich.get("is_malicious"),
                vt_detections=vt.get("malicious_count"),
                vt_total_engines=vt.get("total_engines"),
            )
            db.add(attachment)

    async def _write_threat_records(
        self, db: AsyncSession, analysis_id: uuid.UUID, enrich_results: dict,
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
                        analysis_id=analysis_id,
                        provider=provider,
                        indicator=result.get("indicator", ""),
                        indicator_type=result.get("indicator_type", ""),
                        raw_response=provider_data,
                        threat_score=result.get("aggregate_threat_score"),
                    )
                    db.add(record)

    def _build_intel_summary(self, enrich_results: dict) -> dict:
        return {
            "total_indicators": len(enrich_results),
            "malicious_count": sum(
                1 for r in enrich_results.values()
                if isinstance(r, dict) and r.get("is_malicious")
            ),
            "max_threat_score": max(
                (r.get("aggregate_threat_score", 0)
                 for r in enrich_results.values() if isinstance(r, dict)),
                default=0,
            ),
        }

    def _compute_composite_score(self, enrich_results: dict, classification) -> float:
        intel_score = self._build_intel_summary(enrich_results).get("max_threat_score", 0)
        ai_score = classification.confidence_score * 100

        severity_bonus = {
            "CRITICAL": 20, "HIGH": 10, "MEDIUM": 0, "LOW": -10, "INFO": -20
        }.get(classification.severity, 0)

        return min(100.0, (intel_score * 0.4 + ai_score * 0.6 + severity_bonus))
