import smtplib
from email.message import EmailMessage

from config import get_settings


def send_email_summary(subject: str, body_text: str) -> tuple[bool, str]:
    settings = get_settings()
    if not settings.smtp_host or not settings.smtp_from or not settings.smtp_to:
        return False, "SMTP email not configured (SMTP_HOST / SMTP_FROM / SMTP_TO unset)."

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = settings.smtp_to
    msg.set_content(body_text)

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
            if settings.smtp_use_tls:
                server.starttls()
            if settings.smtp_user and settings.smtp_password:
                server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(msg)
        return True, f"Email summary delivered to {settings.smtp_to}."
    except Exception as exc:
        return False, f"SMTP delivery failed: {exc}"
