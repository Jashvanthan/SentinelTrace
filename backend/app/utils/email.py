import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

def send_reset_password_email(email: str, token: str) -> bool:
    try:
        if not settings.SMTP_HOST or not settings.SMTP_USER or not settings.SMTP_PASSWORD:
            logger.warning("SMTP credentials not configured. Skipping email send.")
            return False

        reset_link = f"{settings.FRONTEND_URL}/reset-password?token={token}"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Password Reset Request - SentinelTrace"
        msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_USER}>"
        msg["To"] = email

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

        part = MIMEText(html, "html")
        msg.attach(part)

        with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            password = settings.SMTP_PASSWORD.replace(" ", "") if settings.SMTP_PASSWORD else ""
            server.login(settings.SMTP_USER, password)
            server.send_message(msg)

        logger.info(f"Password reset email sent to {email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send password reset email to {email}: {e}")
        return False
