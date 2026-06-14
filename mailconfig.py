"""Editable SMTP / outbound-email settings store. Admins set the SMTP host,
port, sender, username, password, and TLS flag in the UI (Settings → Email
server); values are persisted to email_settings.json and overlaid onto the live
EmailConfig so they take effect immediately, no restart needed. Stored values
override the matching .env variables. The password is write-only in the UI
(shown only as "set")."""
from __future__ import annotations

import copy
import json
import logging
import os

from config import CONFIG, EmailConfig

log = logging.getLogger("mailconfig")

SETTINGS_FILE = os.getenv("EMAIL_SETTINGS_FILE", "email_settings.json")


def load() -> dict:
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save(data: dict) -> None:
    with open(SETTINGS_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def apply(email: EmailConfig) -> EmailConfig:
    """Overlay stored settings onto a live EmailConfig (mutated in place)."""
    data = load()
    if "smtp_host" in data:
        email.smtp_host = data["smtp_host"]
    if "sender" in data:
        email.sender = data["sender"]
    if "smtp_username" in data:
        email.smtp_username = data["smtp_username"]
    if "smtp_password" in data:
        email.smtp_password = data["smtp_password"]
    if "smtp_port" in data:
        try:
            email.smtp_port = int(data["smtp_port"])
        except (TypeError, ValueError):
            pass
    if "use_tls" in data:
        email.use_tls = bool(data["use_tls"])
    return email


def save_form(form) -> None:
    """Persist SMTP settings from a submitted form. The password is only
    replaced when a new value is provided; ticking clear_smtp_password removes
    the stored password (reverting to the .env value, if any)."""
    data = load()
    data["smtp_host"] = (form.get("smtp_host") or "").strip()
    data["sender"] = (form.get("sender") or "").strip()
    data["smtp_username"] = (form.get("smtp_username") or "").strip()
    try:
        data["smtp_port"] = int(form.get("smtp_port") or 587)
    except (TypeError, ValueError):
        data["smtp_port"] = 587
    data["use_tls"] = form.get("use_tls") == "on"
    if form.get("clear_smtp_password") == "on":
        data.pop("smtp_password", None)
    else:
        pw = form.get("smtp_password") or ""
        if pw:
            data["smtp_password"] = pw
    _save(data)


def config_from_form(form) -> EmailConfig:
    """Build an EmailConfig from a submitted form for a connectivity test.
    Starts from the live config (so a blank, masked password falls back to the
    stored/effective one), then overrides with whatever the form supplies."""
    cfg = copy.deepcopy(CONFIG.email)
    cfg.enabled = True
    host = (form.get("smtp_host") or "").strip()
    if host:
        cfg.smtp_host = host
    sender = (form.get("sender") or "").strip()
    if sender:
        cfg.sender = sender
    # Username is shown in the form, so take it verbatim (allowing a clear).
    cfg.smtp_username = (form.get("smtp_username") or "").strip()
    port = form.get("smtp_port")
    if port:
        try:
            cfg.smtp_port = int(port)
        except (TypeError, ValueError):
            pass
    cfg.use_tls = form.get("use_tls") == "on"
    pw = form.get("smtp_password") or ""
    if pw:
        cfg.smtp_password = pw
    return cfg


def status() -> dict:
    """Effective values for display in the UI (password never revealed)."""
    eff = apply(EmailConfig())
    return {
        "smtp_host": eff.smtp_host,
        "smtp_port": eff.smtp_port,
        "sender": eff.sender,
        "smtp_username": eff.smtp_username,
        "password_set": bool(eff.smtp_password),
        "use_tls": eff.use_tls,
    }
