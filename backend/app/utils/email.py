import asyncio
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.core.config import get_settings
from app.core.http_client import get_http_client

logger = logging.getLogger(__name__)
settings = get_settings()


def _send_smtp_sync(email: str, html: str) -> bool:
    """Internal synchronous worker for SMTP sending run inside a thread pool."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Password Reset Request - SentinelTrace"
    msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_USER}>"
    msg["To"] = email

    part = MIMEText(html, "html")
    msg.attach(part)

    with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT) as server:
        password = settings.SMTP_PASSWORD.replace(" ", "") if settings.SMTP_PASSWORD else ""
        server.login(settings.SMTP_USER, password)
        server.send_message(msg)

    logger.info(f"Password reset email sent to {email} via SMTP")
    return True


async def send_reset_password_email(email: str, token: str) -> bool:
    """
    Non-blocking async email dispatcher.
    Supports Resend HTTP API (primary) and SMTP SSL fallback.
    """
    try:
        reset_link = f"{settings.FRONTEND_URL}/reset-password?token={token}"

        html = f"""
        <html>
          <body>
            <h2>Password Reset</h2>
            <p>You requested a password reset for your SentinelTrace account.</p>
            <p>Click the link below to reset your password:</p>
            <a href="{reset_link}">{reset_link}</a>
            <p>If you did not request this, please ignore this email.</p>
          </body>
        </html>
        """

        # Priority 1: Use Resend HTTP API if configured (bypasses Render SMTP port blocking)
        resend_key = (getattr(settings, "RESEND_API_KEY", "") or "").strip()
        if resend_key:
            from_email = (getattr(settings, "RESEND_FROM_EMAIL", "") or "onboarding@resend.dev").strip()
            client = await get_http_client()
            res = await client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {resend_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": f"{settings.SMTP_FROM_NAME} <{from_email}>",
                    "to": [email],
                    "subject": "Password Reset Request - SentinelTrace",
                    "html": html,
                },
                timeout=10.0,
            )
            if res.status_code in (200, 201):
                logger.info(f"Password reset email sent to {email} via Resend API")
                return True
            else:
                logger.error(f"Resend API error ({res.status_code}): {res.text}")

        # Priority 2: Fall back to SMTP (for local dev)
        if not settings.SMTP_HOST or not settings.SMTP_USER or not settings.SMTP_PASSWORD:
            logger.warning("Neither Resend API key nor valid SMTP credentials configured. Skipping email send.")
            return False

        return await asyncio.to_thread(_send_smtp_sync, email, html)
    except Exception as e:
        logger.error(f"Failed to send password reset email to {email}: {e}")
        return False
