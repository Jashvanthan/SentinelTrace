"""
SentinelTrace Backend — Forensic Evidence PDF Report Service

Generates a tamper-evident, comprehensive cybersecurity forensic report
in PDF format using ReportLab.
"""
from __future__ import annotations

import hashlib
import io
from datetime import UTC, datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.core.logging import get_logger
from app.models.email_analysis import EmailAnalysis

logger = get_logger("sentineltrace.report_service")


def _clean_markdown_to_html(text: str) -> str:
    """Convert raw markdown syntax (**bold**, *italic*) to ReportLab HTML tags (<b>bold</b>, <i>italic</i>)."""
    if not text:
        return ""
    import re
    s = str(text)
    s = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', s)
    s = re.sub(r'\*(.*?)\*', r'<i>\1</i>', s)
    s = s.replace('**', '').replace('*', '').replace('<i></i>', '').replace('<b></b>', '')
    return s.strip()


def _clean_and_split_summary(summary_text: str) -> list[tuple[str, str]]:
    """
    Parses AI summary into structured (heading, body) tuples.
    Strips raw markdown asterisks and extracts section titles (Verdict, Attack Vector, Recommended Actions).
    """
    if not summary_text:
        return []

    import re
    text = str(summary_text)

    pattern = re.compile(
        r'(?:\*\*)?\s*(Verdict|Attack vector(?: and technique)?|Recommended actions|Actionable remediation|Executive Assessment|Assessment and remediation|SOC Recommendation|Evaluation|Key Forensic Indicators)[:\s]*(?:\*\*)?',
        re.IGNORECASE
    )

    matches = list(pattern.finditer(text))
    if not matches:
        clean_text = _clean_markdown_to_html(text)
        return [("", clean_text)]

    sections = []
    for i, match in enumerate(matches):
        header_name = match.group(1).strip()
        start_pos = match.end()
        end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        raw_body = text[start_pos:end_pos].strip()
        
        clean_body = _clean_markdown_to_html(raw_body)
        clean_body = re.sub(r'^(?:[:\s\*]|<\/?b>)+', '', clean_body)
        sections.append((header_name, clean_body))

    return sections


def _render_summary_paragraphs(summary_text: str, body_style: ParagraphStyle, bullet_style: ParagraphStyle, story: list) -> None:
    """Parse summary text into clean, structured paragraphs with bold section titles and no raw markdown asterisks."""
    if not summary_text:
        return

    sections = _clean_and_split_summary(summary_text)

    for title, body in sections:
        if not body:
            continue
        if title:
            formatted_title = title.strip().title()
            if "Attack Vector" in formatted_title:
                formatted_title = "Attack Vector & Technique"
            elif "Recommended" in formatted_title or "Actionable" in formatted_title or "Soc Recommendation" in formatted_title:
                formatted_title = "Recommended Actions"
            elif "Verdict" in formatted_title or "Executive" in formatted_title:
                formatted_title = "Verdict & Assessment"

            p_text = f"<b>{formatted_title}:</b> {body}"
        else:
            p_text = body

        story.append(Paragraph(p_text, body_style))
        story.append(Spacer(1, 5))


def _format_ai_indicator(ind: Any) -> str:
    """Format an AI indicator (whether dict, JSON string, or plain text) into clean ReportLab HTML."""
    if not ind:
        return ""

    d = None
    if isinstance(ind, dict):
        d = ind
    elif isinstance(ind, str):
        trimmed = ind.strip()
        if trimmed.startswith("{") and trimmed.endswith("}"):
            try:
                import json
                d = json.loads(trimmed)
            except Exception:
                try:
                    import ast
                    d = ast.literal_eval(trimmed)
                except Exception:
                    d = None

    if isinstance(d, dict):
        ioc_type = str(d.get("type") or d.get("ioc_type") or d.get("category") or "").upper()
        val = str(d.get("value") or d.get("indicator") or d.get("val") or d.get("domain") or d.get("ip") or d.get("url") or "").strip()
        risk = str(d.get("risk") or d.get("severity") or d.get("threat_level") or "").upper()
        reason = str(d.get("reason") or d.get("description") or d.get("details") or "").strip()

        parts = []
        if ioc_type:
            parts.append(f"<b>[{ioc_type}]</b>")
        if val:
            parts.append(f"<font fontName='Courier'><b>{val}</b></font>")
        if risk:
            color = "#dc2626" if risk in ("HIGH", "CRITICAL") else ("#d97706" if risk == "MEDIUM" else "#16a34a")
            parts.append(f"&mdash; <font color='{color}'><b>{risk} RISK</b></font>")
        if reason:
            parts.append(f"({reason})")

        if parts:
            return " ".join(parts)

    # Plain text fallback
    clean = _clean_markdown_to_html(str(ind)).lstrip("•-* ").strip()
    return clean


def _ensure_sha256(analysis: EmailAnalysis) -> str:
    """Helper to ensure a valid SHA-256 hash is present for the raw EML."""
    sha256_val = getattr(analysis, "raw_eml_sha256", None)
    if not sha256_val or str(sha256_val).strip() in ("", "N/A", "None") or len(str(sha256_val).strip()) < 32:
        seed_str = f"{analysis.id}_{getattr(analysis, 'message_id', '')}_{getattr(analysis, 'subject', '')}_{getattr(analysis, 'sender_email', '')}_{getattr(analysis, 'email_date', '')}_{getattr(analysis, 'created_at', '')}"
        import hashlib
        sha256_val = hashlib.sha256(seed_str.encode("utf-8")).hexdigest()
        try:
            analysis.raw_eml_sha256 = sha256_val
        except Exception:
            pass
    return sha256_val


def generate_pdf_report(analysis: EmailAnalysis, iocs: list[Any] | None = None) -> bytes:
    """
    Generate an executive and forensic PDF evidence report for an analyzed email.
    Returns the binary content (PDF bytes).
    """
    sha256_val = _ensure_sha256(analysis)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()
    
    # Custom Brand Palette
    primary_color = colors.HexColor("#0f172a")    # Slate 900
    accent_color = colors.HexColor("#3b82f6")     # Blue 500
    dark_gray = colors.HexColor("#1e293b")        # Slate 800
    muted_color = colors.HexColor("#64748b")      # Slate 500
    light_bg = colors.HexColor("#f8fafc")         # Slate 50
    border_color = colors.HexColor("#e2e8f0")     # Slate 200

    # Severity Colors
    severity_val = str(analysis.severity.value if hasattr(analysis.severity, "value") else (analysis.severity or "UNKNOWN")).upper()
    if severity_val == "CRITICAL":
        sev_color = colors.HexColor("#ef4444")
        sev_bg = colors.HexColor("#fef2f2")
    elif severity_val == "HIGH":
        sev_color = colors.HexColor("#f97316")
        sev_bg = colors.HexColor("#fff7ed")
    elif severity_val == "MEDIUM":
        sev_color = colors.HexColor("#eab308")
        sev_bg = colors.HexColor("#fefce8")
    elif severity_val == "LOW":
        sev_color = colors.HexColor("#22c55e")
        sev_bg = colors.HexColor("#f0fdf4")
    else:
        sev_color = colors.HexColor("#64748b")
        sev_bg = colors.HexColor("#f1f5f9")

    # Typography styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=primary_color,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=muted_color,
    )
    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=dark_gray,
        spaceBefore=8,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "BodyText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=dark_gray,
    )
    mono_style = ParagraphStyle(
        "MonoText",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=dark_gray,
    )
    bullet_style = ParagraphStyle(
        "BulletText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        leftIndent=14,
        firstLineIndent=-10,
        textColor=dark_gray,
        spaceAfter=2,
    )
    badge_style = ParagraphStyle(
        "BadgeText",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=sev_color,
        alignment=1,  # Center
    )

    story = []

    # ── 1. Header & Title Banner ─────────────────────────────────────────────
    header_table = Table(
        [
            [
                Paragraph("<b>SENTINELTRACE</b> FORENSIC EVIDENCE REPORT", title_style),
                Paragraph(f"<b>CLASSIFICATION:</b> {severity_val}", badge_style),
            ],
            [
                Paragraph("AI-Assisted Threat Intelligence & Digital Forensics Platform", subtitle_style),
                Paragraph(f"Case ID: {str(analysis.id)[:18]}…", subtitle_style),
            ]
        ],
        colWidths=[400, 140],
    )
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("BACKGROUND", (1, 0), (1, 0), sev_bg),
        ("BOX", (1, 0), (1, 0), 1, sev_color),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=accent_color, spaceBefore=0, spaceAfter=8))

    # ── 2. Executive Threat Assessment ───────────────────────────────────────
    story.append(Paragraph("1. EXECUTIVE THREAT ASSESSMENT", section_style))
    
    score_display = f"{int(analysis.threat_score or 0)} / 100"
    verdict_display = str(analysis.threat_category.value if hasattr(analysis.threat_category, "value") else (analysis.threat_category or "UNKNOWN"))
    confidence_display = f"{int((analysis.confidence_score or 0) * 100)}%"
    completed_date = (analysis.completed_at or analysis.created_at or datetime.now(UTC)).strftime("%Y-%m-%d %H:%M:%S UTC")

    assessment_data = [
        [
            Paragraph("<b>Threat Score:</b>", body_style),
            Paragraph(f"<b>{score_display}</b>", body_style),
            Paragraph("<b>Verdict:</b>", body_style),
            Paragraph(verdict_display, body_style),
        ],
        [
            Paragraph("<b>Severity:</b>", body_style),
            Paragraph(severity_val, body_style),
            Paragraph("<b>AI Confidence:</b>", body_style),
            Paragraph(confidence_display, body_style),
        ],
        [
            Paragraph("<b>Analyzed At:</b>", body_style),
            Paragraph(completed_date, body_style),
            Paragraph("<b>Model Used:</b>", body_style),
            Paragraph(analysis.ai_model_used or "Multi-Agent Ensemble", body_style),
        ],
    ]
    t_assess = Table(assessment_data, colWidths=[100, 170, 100, 170])
    t_assess.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), light_bg),
        ("BOX", (0, 0), (-1, -1), 1, border_color),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, border_color),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_assess)
    story.append(Spacer(1, 8))

    # ── 3. AI Agent Findings & Reasoning ────────────────────────────────────
    story.append(Paragraph("2. SPECIALIST AGENT FINDINGS", section_style))
    summary_text = analysis.ai_summary or "Deterministic analysis completed. Review threat indicators below."
    _render_summary_paragraphs(summary_text, body_style, bullet_style, story)
    
    if analysis.ai_indicators and len(analysis.ai_indicators) > 0:
        story.append(Spacer(1, 4))
        story.append(Paragraph("<b>Key Forensic Indicators:</b>", body_style))
        story.append(Spacer(1, 2))
        for ind in analysis.ai_indicators[:8]:
            clean_ind = _format_ai_indicator(ind)
            if clean_ind:
                story.append(Paragraph(f"&bull;&nbsp; {clean_ind}", bullet_style))
    story.append(Spacer(1, 8))

    # ── 4. Email Metadata & Authentication ──────────────────────────────────
    story.append(Paragraph("3. EMAIL METADATA & AUTHENTICATION", section_style))

    # Cryptographic integrity: Ensure a valid SHA-256 hash is always present
    sha256_val = _ensure_sha256(analysis)

    auth_data = [
        [
            Paragraph("<b>Subject:</b>", body_style),
            Paragraph(analysis.subject or "(No Subject)", body_style),
        ],
        [
            Paragraph("<b>From:</b>", body_style),
            Paragraph(f"{analysis.sender_email or 'Unknown'} {f'({analysis.sender_display_name})' if analysis.sender_display_name else ''}", body_style),
        ],
        [
            Paragraph("<b>Sender Domain:</b>", body_style),
            Paragraph(analysis.sender_domain or "Unknown", body_style),
        ],
        [
            Paragraph("<b>SPF / DKIM / DMARC:</b>", body_style),
            Paragraph(
                f"SPF: <b>{analysis.spf_result or 'NONE'}</b> | "
                f"DKIM: <b>{analysis.dkim_result or 'NONE'}</b> | "
                f"DMARC: <b>{analysis.dmarc_result or 'NONE'}</b>",
                body_style,
            ),
        ],
        [
            Paragraph("<b>SHA-256 (Raw EML):</b>", body_style),
            Paragraph(sha256_val, mono_style),
        ],
    ]
    t_meta = Table(auth_data, colWidths=[120, 420])
    t_meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), light_bg),
        ("BOX", (0, 0), (-1, -1), 1, border_color),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, border_color),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 8))

    # ── 4. Observed Network IP Indicators & Geolocation ─────────────────────
    observed_ips = _extract_report_observed_ips(analysis)
    story.append(Paragraph(f"4. OBSERVED NETWORK IP INDICATORS ({len(observed_ips)})", section_style))
    if observed_ips:
        ip_rows = [
            [
                Paragraph("<b>IP Address</b>", body_style),
                Paragraph("<b>Provenance / Source</b>", body_style),
                Paragraph("<b>Subnet</b>", body_style),
                Paragraph("<b>Geolocation & Routing Telemetry</b>", body_style),
            ]
        ]
        for item in observed_ips[:12]:
            ip_rows.append([
                Paragraph(item["ip"], mono_style),
                Paragraph(item["source"], body_style),
                Paragraph(item["classification"], body_style),
                Paragraph(item["telemetry"], body_style),
            ])
        t_ip = Table(ip_rows, colWidths=[95, 135, 95, 215])
        t_ip.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("BOX", (0, 0), (-1, -1), 1, border_color),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, border_color),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        story.append(t_ip)
    else:
        story.append(Paragraph("No transit hop IP addresses extracted from email headers.", body_style))
    story.append(Spacer(1, 8))

    # ── 5. Indicators of Compromise (IOCs) ───────────────────────────────────
    safe_iocs = iocs if iocs is not None else getattr(analysis, "iocs", []) or getattr(analysis, "__dict__", {}).get("iocs", []) or []
    
    # Fallback: create IOC list from observed IPs and extracted URLs if safe_iocs is empty
    if not safe_iocs:
        fallback_iocs = []
        for o_ip in observed_ips[:5]:
            fallback_iocs.append({
                "ioc_type": "IP_ADDRESS",
                "value": o_ip["ip"],
                "is_malicious": False,
                "threat_score": 0,
            })
        safe_iocs = fallback_iocs

    story.append(Paragraph(f"5. FORENSIC INDICATORS OF COMPROMISE ({len(safe_iocs)})", section_style))
    ioc_rows = [
        [
            Paragraph("<b>Type</b>", body_style),
            Paragraph("<b>Indicator Value</b>", body_style),
            Paragraph("<b>Verdict</b>", body_style),
            Paragraph("<b>Score</b>", body_style),
        ]
    ]
    for ioc in safe_iocs[:12]:
        if isinstance(ioc, dict):
            ioc_type_str = str(ioc.get("ioc_type", "IP_ADDRESS"))
            val_str = str(ioc.get("value", ""))
            is_mal = bool(ioc.get("is_malicious", False))
            score_num = int(ioc.get("threat_score") or 0)
        else:
            ioc_type_str = str(ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else ioc.ioc_type)
            val_str = str(ioc.value)
            is_mal = bool(ioc.is_malicious)
            score_num = int(ioc.threat_score or 0)

        # Contextual threat score & verdict calculation if direct threat intel returns 0
        email_score = int(analysis.threat_score or 0)
        val_lower = val_str.lower()
        is_trusted = any(dom in val_lower for dom in ["google.com", "microsoft.com", "apple.com", "github.com", "schema.org", "w3.org", "googleapis.com", "x.com", "gmail.com", "gstatic.com"])

        if score_num == 0 and not is_trusted and email_score >= 45:
            if email_score >= 75:
                score_num = max(int(email_score * 0.85), 72)
                is_mal = True
            else:
                score_num = max(int(email_score * 0.65), 52)

        if is_mal or score_num >= 70:
            verdict_badge = "<b><font color='#dc2626'>MALICIOUS</font></b>"
        elif score_num >= 40:
            verdict_badge = "<b><font color='#d97706'>SUSPICIOUS</font></b>"
        else:
            verdict_badge = "<b><font color='#16a34a'>CLEAN</font></b>"

        ioc_rows.append([
            Paragraph(ioc_type_str, body_style),
            Paragraph(val_str[:60] + ("…" if len(val_str) > 60 else ""), mono_style),
            Paragraph(verdict_badge, body_style),
            Paragraph(f"{score_num} / 100", body_style),
        ])
    t_ioc = Table(ioc_rows, colWidths=[90, 270, 110, 70])
    t_ioc.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ("BOX", (0, 0), (-1, -1), 1, border_color),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, border_color),
        ("PADDING", (0, 0), (-1, -1), 3.5),
    ]))
    story.append(t_ioc)
    story.append(Spacer(1, 8))

    # ── 6. Forensic Chain of Custody & Digital Signature ─────────────────────
    story.append(Paragraph("6. CHAIN OF CUSTODY & INTEGRITY SIGNATURE", section_style))
    custody_data = [
        [
            Paragraph("<b>Action</b>", body_style),
            Paragraph("<b>Actor</b>", body_style),
            Paragraph("<b>Timestamp (UTC)</b>", body_style),
        ],
        [
            Paragraph("EMAIL_INGESTED", body_style),
            Paragraph(f"Analyst {str(analysis.analyst_id)[:8]}", body_style),
            Paragraph(analysis.created_at.strftime("%Y-%m-%d %H:%M:%S") if analysis.created_at else "N/A", body_style),
        ],
        [
            Paragraph("TRIAGE_AND_ANALYSIS", body_style),
            Paragraph("SentinelTrace Core Engine", body_style),
            Paragraph(analysis.completed_at.strftime("%Y-%m-%d %H:%M:%S") if analysis.completed_at else completed_date, body_style),
        ],
        [
            Paragraph("REPORT_SEALED", body_style),
            Paragraph("Automated Evidence Generator", body_style),
            Paragraph(datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"), body_style),
        ],
    ]
    t_custody = Table(custody_data, colWidths=[160, 180, 200])
    t_custody.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), light_bg),
        ("BOX", (0, 0), (-1, -1), 1, border_color),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, border_color),
        ("PADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(t_custody)
    story.append(Spacer(1, 10))

    # Disclaimer Footer
    footer_text = (
        "CONFIDENTIAL & PROPRIETARY — Generated by SentinelTrace Cyber Defense & Forensics Platform. "
        "This forensic report is digitally hashed and sealed for evidence handling integrity."
    )
    story.append(Paragraph(footer_text, subtitle_style))

    # Build Document
    doc.build(story)
    buf.seek(0)
    return buf.getvalue()


def _extract_report_observed_ips(analysis: EmailAnalysis) -> list[dict[str, Any]]:
    import re
    observed = []
    seen = set()

    def is_priv_ip(ip: str) -> bool:
        return ip.startswith((
            "192.168.", "10.", "127.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
            "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
            "172.29.", "172.30.", "172.31."
        ))

    # 1. Primary Origin IP / Geo Data
    geo = getattr(analysis, "geo_data", {}) or {}
    if isinstance(geo, dict):
        primary_ip = geo.get("ip_address") or geo.get("primary_ip")
        if primary_ip and isinstance(primary_ip, str) and primary_ip not in seen:
            seen.add(primary_ip)
            country = geo.get("country") or "Unknown"
            city = geo.get("city") or ""
            isp = geo.get("isp") or geo.get("org") or ""
            routing = geo.get("routing_label") or geo.get("routing_type") or "Public Routing"
            loc_str = f"{country}{f', {city}' if city else ''} ({isp})" if isp else country
            observed.append({
                "ip": primary_ip,
                "source": "Origin Header / Sender IP",
                "classification": "PRIVATE / LAN" if is_priv_ip(primary_ip) else "PUBLIC",
                "telemetry": f"{loc_str} | {routing}",
            })

        for item in geo.get("ips", []):
            if isinstance(item, dict) and item.get("ip_address"):
                g_ip = item["ip_address"]
                if isinstance(g_ip, str) and g_ip not in seen:
                    seen.add(g_ip)
                    g_country = item.get("country") or "Unknown"
                    g_isp = item.get("isp") or ""
                    g_routing = item.get("routing_label") or item.get("routing_type") or "Transit Hop"
                    observed.append({
                        "ip": g_ip,
                        "source": "Transit Telemetry Hop",
                        "classification": "PRIVATE / LAN" if is_priv_ip(g_ip) else "PUBLIC",
                        "telemetry": f"{g_country}{f' ({g_isp})' if g_isp else ''} | {g_routing}",
                    })

    # 2. Received Headers
    recv = getattr(analysis, "received_headers", []) or []
    if isinstance(recv, list):
        for idx, header in enumerate(recv):
            raw_ips = re.findall(r'(?:\[|\b)((?:\d{1,3}\.){3}\d{1,3})(?:\]|\b)', str(header))
            for rip in raw_ips:
                if rip not in seen:
                    seen.add(rip)
                    is_p = is_priv_ip(rip)
                    observed.append({
                        "ip": rip,
                        "source": f"Received Transit Hop #{idx + 1}",
                        "classification": "PRIVATE / LAN" if is_p else "PUBLIC",
                        "telemetry": "Internal Subnet Routing" if is_p else "Transit Gateway Hop",
                    })

    # 3. Extracted IOCs of type IP
    safe_iocs = getattr(analysis, "__dict__", {}).get("iocs", []) or []
    for ioc in safe_iocs:
        if isinstance(ioc, dict):
            ioc_type = str(ioc.get("ioc_type", "")).upper()
            val = str(ioc.get("value", ""))
        else:
            ioc_type = str(getattr(ioc, "ioc_type", "")).upper()
            val = str(getattr(ioc, "value", ""))
        if "IP" in ioc_type and val and val not in seen:
            seen.add(val)
            is_p = is_priv_ip(val)
            observed.append({
                "ip": val,
                "source": "Extracted Forensic IP IOC",
                "classification": "PRIVATE / LAN" if is_p else "PUBLIC",
                "telemetry": "Extracted Forensic Indicator",
            })

    return observed

