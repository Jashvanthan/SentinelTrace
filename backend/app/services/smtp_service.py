"""
SentinelTrace Backend — Free Gmail SMTP Service & Custom HTML Email Templates

Dispatches dark-themed cybersecurity operational tickets, feedback submissions,
and complaint reports directly to administrators with automated user receipts.
"""
from __future__ import annotations

import asyncio
import html
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, Optional

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("sentineltrace.smtp")
settings = get_settings()


def get_sla_details(priority: str) -> tuple[str, str, str, str]:
    """Returns (sla_text, sla_bg, sla_border, sla_color) based on priority level."""
    prio_upper = priority.upper()
    if prio_upper == "CRITICAL":
        return (
            "🚨 CRITICAL SLA: 1 – 2 Hours Immediate Incident Escalation",
            "#450a0a",
            "#dc2626",
            "#fca5a5"
        )
    elif prio_upper == "HIGH":
        return (
            "⚡ HIGH SLA: 4 – 8 Hours Accelerated Priority Response",
            "#431407",
            "#ea580c",
            "#fdba74"
        )
    elif prio_upper == "MEDIUM":
        return (
            "⏱️ MEDIUM SLA: Within 24 Business Hours Standard Review",
            "#0c2340",
            "#2563eb",
            "#93c5fd"
        )
    else:
        return (
            "📋 LOW SLA: 48 – 72 Hours Standard Backlog Triage",
            "#1e293b",
            "#475569",
            "#cbd5e1"
        )


def build_ticket_html(
    *,
    name: str,
    email: str,
    category: str,
    priority: str,
    subject: str,
    message: str,
    ticket_id: str,
    timestamp_str: str,
    platform_url: str = "http://localhost:5173",
) -> str:
    """Renders a Clean Enterprise Minimalist Dark HTML Ticket Template."""
    cat_upper = category.upper()
    prio_upper = priority.upper()

    # Category badge styling
    if cat_upper in ("SECURITY", "VULNERABILITY"):
        cat_badge_bg = "#4c0519"
        cat_badge_border = "#e11d48"
        cat_badge_text = "#fda4af"
        cat_icon = "🛡️ Security Issue"
    elif cat_upper in ("BUG", "COMPLAINT", "DEFECT"):
        cat_badge_bg = "#450a0a"
        cat_badge_border = "#ef4444"
        cat_badge_text = "#fca5a5"
        cat_icon = "🚨 Defect / Bug Report"
    elif cat_upper in ("FEATURE", "IMPROVEMENT"):
        cat_badge_bg = "#083344"
        cat_badge_border = "#06b6d4"
        cat_badge_text = "#67e8f9"
        cat_icon = "✨ Feature Request"
    else:
        cat_badge_bg = "#064e3b"
        cat_badge_border = "#10b981"
        cat_badge_text = "#6ee7b7"
        cat_icon = "💬 User Feedback"

    # Priority styling
    if prio_upper == "CRITICAL":
        prio_color = "#f87171"
        prio_dot = "🔴"
    elif prio_upper == "HIGH":
        prio_color = "#fb923c"
        prio_dot = "🟠"
    elif prio_upper == "MEDIUM":
        prio_color = "#60a5fa"
        prio_dot = "🔵"
    else:
        prio_color = "#94a3b8"
        prio_dot = "⚪"

    sla_text, sla_bg, sla_border, sla_color = get_sla_details(priority)

    safe_name = html.escape(name)
    safe_email = html.escape(email)
    safe_subject = html.escape(subject)
    safe_message = html.escape(message).replace("\n", "<br/>")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SentinelTrace Support Ticket</title>
</head>
<body style="margin:0; padding:0; background-color:#090d16; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; color:#e2e8f0; -webkit-font-smoothing:antialiased;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:#090d16; padding:40px 16px;">
    <tr>
      <td align="center">
        <!-- Main Card Wrapper -->
        <table role="presentation" width="100%" max-width="640" style="max-width:640px; background-color:#0f172a; border-radius:12px; border:1px solid #1e293b; overflow:hidden; box-shadow:0 12px 36px rgba(0,0,0,0.45);" cellspacing="0" cellpadding="0" border="0">
          
          <!-- Clean Header with SentinelTrace Brand -->
          <tr>
            <td style="padding:28px 32px 22px 32px; background:linear-gradient(180deg, #131d35 0%, #0f172a 100%); border-bottom:1px solid #1e293b;">
              <table width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                  <td>
                    <div style="font-size:11px; font-weight:700; color:#3b82f6; letter-spacing:1.2px; text-transform:uppercase; margin-bottom:6px; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">
                      🛡️ SENTINELTRACE • SECURITY OPERATIONS DESK
                    </div>
                    <div style="font-size:20px; font-weight:700; color:#f8fafc; letter-spacing:-0.3px; line-height:1.3;">
                      New Operational Ticket Received
                    </div>
                  </td>
                  <td align="right" style="vertical-align:top;">
                    <div style="display:inline-block; font-size:12px; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background-color:#1e293b; color:#93c5fd; border:1px solid #334155; border-radius:6px; padding:5px 10px; font-weight:600;">
                      {ticket_id}
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Badges & Submission Date Bar -->
          <tr>
            <td style="padding:16px 32px; background-color:#111a2e; border-bottom:1px solid #1e293b;">
              <table width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                  <td>
                    <!-- Category Badge -->
                    <span style="display:inline-block; font-size:12px; font-weight:600; background-color:{cat_badge_bg}; color:{cat_badge_text}; border:1px solid {cat_badge_border}; border-radius:6px; padding:4px 11px; margin-right:6px;">
                      {cat_icon}
                    </span>
                    <!-- Priority Badge -->
                    <span style="display:inline-block; font-size:12px; font-weight:600; background-color:#1e293b; color:{prio_color}; border:1px solid #334155; border-radius:6px; padding:4px 11px;">
                      {prio_dot} {prio_upper} Priority
                    </span>
                  </td>
                  <td align="right" style="font-size:12px; color:#94a3b8; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">
                    {timestamp_str}
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- SLA Response Guarantee Banner -->
          <tr>
            <td style="padding:16px 32px 0 32px;">
              <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:{sla_bg}; border:1px solid {sla_border}; border-radius:8px; padding:10px 16px;">
                <tr>
                  <td style="font-size:12px; font-weight:600; color:{sla_color}; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">
                    {sla_text}
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Subject Section -->
          <tr>
            <td style="padding:22px 32px 10px 32px;">
              <div style="font-size:11px; font-weight:700; color:#64748b; text-transform:uppercase; letter-spacing:1px; margin-bottom:6px; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">
                Ticket Subject
              </div>
              <div style="font-size:16px; font-weight:600; color:#ffffff; line-height:1.4;">
                {safe_subject}
              </div>
            </td>
          </tr>

          <!-- Reporter Contact Information Card -->
          <tr>
            <td style="padding:10px 32px 16px 32px;">
              <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:#090d16; border:1px solid #1e293b; border-radius:8px; padding:14px 18px;">
                <tr>
                  <td width="50%" style="vertical-align:top;">
                    <div style="font-size:10px; font-weight:700; color:#64748b; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; text-transform:uppercase; margin-bottom:3px;">
                      Reporter Name
                    </div>
                    <div style="font-size:13px; font-weight:600; color:#f1f5f9;">
                      {safe_name}
                    </div>
                  </td>
                  <td width="50%" style="vertical-align:top;">
                    <div style="font-size:10px; font-weight:700; color:#64748b; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; text-transform:uppercase; margin-bottom:3px;">
                      Email Address
                    </div>
                    <div>
                      <a href="mailto:{safe_email}" style="font-size:13px; font-weight:600; color:#38bdf8; text-decoration:none; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">
                        {safe_email}
                      </a>
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Message Body Card -->
          <tr>
            <td style="padding:0 32px 24px 32px;">
              <div style="font-size:11px; font-weight:700; color:#64748b; text-transform:uppercase; letter-spacing:1px; margin-bottom:8px; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">
                Detailed Description & Notes
              </div>
              <div style="background-color:#090d16; border:1px solid #1e293b; border-left:3px solid #2563eb; border-radius:8px; padding:16px 20px; font-size:13px; color:#cbd5e1; line-height:1.7; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">
                {safe_message}
              </div>
            </td>
          </tr>

          <!-- Action CTA Buttons -->
          <tr>
            <td style="padding:0 32px 28px 32px;" align="center">
              <table cellspacing="0" cellpadding="0" border="0">
                <tr>
                  <td style="padding-right:12px;">
                    <a href="mailto:{safe_email}?subject=Re:%20[SentinelTrace%20Ticket%20{ticket_id}]%20{safe_subject}" style="display:inline-block; background-color:#2563eb; color:#ffffff; font-weight:600; font-size:13px; text-decoration:none; padding:10px 22px; border-radius:6px; letter-spacing:0.2px;">
                      ✉️ Reply to Reporter
                    </a>
                  </td>
                  <td>
                    <a href="{platform_url}/help" style="display:inline-block; background-color:#1e293b; color:#e2e8f0; font-weight:600; font-size:13px; text-decoration:none; padding:10px 22px; border-radius:6px; border:1px solid #334155; letter-spacing:0.2px;">
                      🛡️ Open SentinelTrace SOC
                    </a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Clean Minimalist Footer -->
          <tr>
            <td style="background-color:#090d16; padding:16px 32px; border-top:1px solid #1e293b; text-align:center;">
              <p style="margin:0; font-size:11px; color:#64748b; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">
                SentinelTrace SOC Threat Intelligence • Automated Ticket Dispatch System
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def build_confirmation_html(
    *,
    name: str,
    category: str,
    subject: str,
    ticket_id: str,
    timestamp_str: str,
    priority: str = "MEDIUM",
) -> str:
    """Renders a Clean Enterprise Minimalist User Confirmation Receipt."""
    safe_name = html.escape(name)
    safe_subject = html.escape(subject)
    sla_text, sla_bg, sla_border, sla_color = get_sla_details(priority)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SentinelTrace Support Receipt</title>
</head>
<body style="margin:0; padding:0; background-color:#090d16; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; color:#e2e8f0; -webkit-font-smoothing:antialiased;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:#090d16; padding:36px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" max-width="580" style="max-width:580px; background-color:#0f172a; border-radius:12px; border:1px solid #1e293b; overflow:hidden; box-shadow:0 10px 30px rgba(0,0,0,0.4);" cellspacing="0" cellpadding="0" border="0">
          <tr>
            <td style="padding:24px 30px; background:linear-gradient(180deg, #131d35 0%, #0f172a 100%); border-bottom:1px solid #1e293b;">
              <div style="font-size:11px; font-weight:700; color:#3b82f6; letter-spacing:1px; text-transform:uppercase; font-family:ui-monospace, monospace;">
                🛡️ SENTINELTRACE SUPPORT DESK
              </div>
              <div style="font-size:18px; font-weight:700; color:#ffffff; margin-top:4px;">
                Report Acknowledged (Ticket #{ticket_id})
              </div>
            </td>
          </tr>
          <tr>
            <td style="padding:16px 30px 0 30px;">
              <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:{sla_bg}; border:1px solid {sla_border}; border-radius:8px; padding:10px 14px;">
                <tr>
                  <td style="font-size:12px; font-weight:600; color:{sla_color}; font-family:ui-monospace, monospace;">
                    {sla_text}
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:20px 30px 24px 30px; font-size:13px; line-height:1.6; color:#cbd5e1;">
              <p style="margin-top:0;">Hello <strong>{safe_name}</strong>,</p>
              <p>Thank you for reaching out to SentinelTrace. Your submission regarding <strong>"{safe_subject}"</strong> has been logged into our operations queue with ticket reference <code style="background:#1e293b; padding:2px 6px; border-radius:4px; color:#93c5fd; font-family:ui-monospace, monospace;">{ticket_id}</code>.</p>
              <p style="margin-bottom:0;">Our security engineering and support team is actively reviewing your ticket and will follow up with you directly at this email address.</p>
            </td>
          </tr>
          <tr>
            <td style="background-color:#090d16; padding:14px 30px; border-top:1px solid #1e293b; text-align:center; font-size:11px; color:#64748b; font-family:ui-monospace, monospace;">
              SentinelTrace Threat Detection & Forensics • {timestamp_str}
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def _send_smtp_sync(
    *,
    to_email: str,
    subject: str,
    html_content: str,
    reply_to: Optional[str] = None,
) -> bool:
    """Synchronous SMTP dispatcher executed in worker thread."""
    host = settings.SMTP_HOST or "smtp.gmail.com"
    port = settings.SMTP_PORT or 465
    user = settings.SMTP_USER
    raw_pass = settings.SMTP_PASSWORD or ""
    # Strip spaces in case 16-letter app password has spaces
    password = raw_pass.replace(" ", "").strip()
    from_name = settings.SMTP_FROM_NAME or "SentinelTrace SOC Alert Desk"

    if not user or not password:
        logger.warning(
            "smtp_credentials_missing",
            msg="SMTP_USER or SMTP_PASSWORD is not set in backend .env",
        )
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{user}>"
    msg["To"] = to_email
    if reply_to:
        msg["Reply-To"] = reply_to

    part = MIMEText(html_content, "html", "utf-8")
    msg.attach(part)

    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=15) as server:
                server.login(user, password)
                server.sendmail(user, [to_email], msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=15) as server:
                server.starttls()
                server.login(user, password)
                server.sendmail(user, [to_email], msg.as_string())

        logger.info("smtp_email_sent_successfully", to=to_email, subject=subject)
        return True
    except Exception as e:
        logger.error("smtp_send_failed", error=str(e), to=to_email)
        return False


class SMTPService:
    """Asynchronous wrapper for SMTP communications."""

    @staticmethod
    async def dispatch_ticket_email(
        *,
        name: str,
        email: str,
        category: str,
        priority: str,
        subject: str,
        message: str,
        admin_email: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Dispatches an administrative incident ticket and sends receipt to user."""
        target_admin = admin_email or settings.SUPPORT_RECEIVER_EMAIL or settings.SMTP_USER or "jashvan467@gmail.com"
        ticket_id = f"ST-{datetime.now(timezone.utc).strftime('%y%m%d')}-{abs(hash(subject + email)) % 10000:04d}"
        now_str = datetime.now().strftime("%d %b %Y, %I:%M %p")

        email_subject = f"[SentinelTrace {category.upper()}] [{priority.upper()}] {subject} ({ticket_id})"
        admin_html = build_ticket_html(
            name=name,
            email=email,
            category=category,
            priority=priority,
            subject=subject,
            message=message,
            ticket_id=ticket_id,
            timestamp_str=now_str,
            platform_url=settings.FRONTEND_URL,
        )

        # 1. Send primary ticket email to Administrator
        admin_sent = await asyncio.to_thread(
            _send_smtp_sync,
            to_email=target_admin,
            subject=email_subject,
            html_content=admin_html,
            reply_to=email,
        )

        # 2. Send polite confirmation receipt back to reporter if different and valid
        if admin_sent and email and "@" in email and email.lower() != target_admin.lower():
            confirm_html = build_confirmation_html(
                name=name,
                category=category,
                subject=subject,
                ticket_id=ticket_id,
                timestamp_str=now_str,
                priority=priority,
            )
            asyncio.create_task(
                asyncio.to_thread(
                    _send_smtp_sync,
                    to_email=email,
                    subject=f"SentinelTrace Support Ticket Confirmation ({ticket_id})",
                    html_content=confirm_html,
                )
            )

        return {
            "success": admin_sent,
            "ticket_id": ticket_id,
            "admin_email": target_admin,
            "delivered_via": "GMAIL_SMTP_SSL",
        }


smtp_service = SMTPService()
