import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import httpx
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

def send_reset_password_email(email: str, token: str) -> bool:
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
            res = httpx.post(
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
    except Exception as e:
        logger.error(f"Failed to send password reset email to {email}: {e}")
        return False

