"""Generic SMTP email sender (stdlib only - no vendor SDK required).

Works with literally any SMTP-capable provider: Resend, SendGrid, Mailgun,
Amazon SES, Postmark, or a plain Gmail app password for testing. Configure
via environment variables:

    SMTP_HOST=smtp.resend.com
    SMTP_PORT=587
    SMTP_USER=resend
    SMTP_PASSWORD=re_xxxxxxxx
    SMTP_FROM="Sanctum <alerts@yourdomain.com>"

If SMTP_HOST is not set, emails are written to outbox.log instead of being
sent, and the app keeps working normally (password reset links and
watchlist alerts just show up in the log instead of an inbox) - useful
while you're still setting up a provider.

Recommendation if you don't have one yet: Resend (resend.com) has the
simplest signup and a generous free tier, and exposes a standard SMTP
relay so this exact code works with it unchanged.
"""

import logging
import os
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage

logger = logging.getLogger(__name__)

OUTBOX_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outbox.log")


def _write_to_outbox(to_email: str, subject: str, body: str, error: str = None) -> None:
    with open(OUTBOX_PATH, "a", encoding="utf-8") as f:
        f.write(f"\n--- {datetime.now(timezone.utc).isoformat()} ---\n")
        f.write(f"To: {to_email}\nSubject: {subject}\n")
        if error:
            f.write(f"[NOT SENT - SMTP error: {error}]\n")
        else:
            f.write("[NOT SENT - no SMTP_HOST configured]\n")
        f.write(f"\n{body}\n")
    logger.info("Email to %s logged to outbox.log instead of sent (subject: %s)", to_email, subject)


def send_email(to_email: str, subject: str, body: str) -> bool:
    """Returns True if actually sent via SMTP, False if it fell back to the
    local outbox log (either because SMTP isn't configured, or it failed)."""
    smtp_host = os.environ.get("SMTP_HOST")
    if not smtp_host:
        _write_to_outbox(to_email, subject, body)
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.environ.get("SMTP_FROM", "no-reply@example.com")
    msg["To"] = to_email
    msg.set_content(body)

    port = int(os.environ.get("SMTP_PORT", 587))
    use_tls = os.environ.get("SMTP_USE_TLS", "true").lower() != "false"
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD")

    try:
        with smtplib.SMTP(smtp_host, port, timeout=15) as server:
            if use_tls:
                server.starttls()
            if user and password:
                server.login(user, password)
            server.send_message(msg)
        return True
    except (smtplib.SMTPException, OSError) as e:
        logger.warning("SMTP send failed: %s", e)
        _write_to_outbox(to_email, subject, body, error=str(e))
        return False
