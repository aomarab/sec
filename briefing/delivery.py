"""Email the rendered briefing over SMTP."""
from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from config import EmailConfig

log = logging.getLogger("briefing.delivery")


def send_email(cfg: EmailConfig, subject: str, html_body: str,
               markdown_body: str) -> bool:
    if not cfg.enabled:
        log.info("Email disabled (EMAIL_ENABLED=false); skipping send.")
        return False
    if not (cfg.to and cfg.sender and cfg.smtp_host):
        log.warning("Email enabled but EMAIL_TO/EMAIL_FROM/SMTP_HOST incomplete; skipping.")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.sender
    msg["To"] = cfg.to
    msg.set_content(markdown_body)            # plain-text fallback
    msg.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=30) as server:
            if cfg.use_tls:
                server.starttls()
            if cfg.smtp_username:
                server.login(cfg.smtp_username, cfg.smtp_password)
            server.send_message(msg)
        log.info("Briefing emailed to %s", cfg.to)
        return True
    except Exception as err:
        log.error("Email send failed: %s", err)
        return False
