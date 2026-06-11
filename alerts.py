"""Alerting: notify on scan findings via Email, Microsoft Teams, Slack, or a
generic webhook. Channels are configured by an admin and stored in alerts.json."""
from __future__ import annotations

import copy
import json
import logging
import os

import requests

from briefing import delivery
from config import CONFIG

log = logging.getLogger("alerts")

ALERTS_FILE = os.getenv("ALERTS_FILE", "alerts.json")
SEV_ORDER = ["critical", "high", "medium", "low"]


def load_config() -> dict:
    try:
        with open(ALERTS_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"enabled": False, "min_severity": "high", "email_to": "",
                "teams_webhook": "", "slack_webhook": "", "webhook_url": ""}


def save_config(cfg: dict) -> None:
    with open(ALERTS_FILE, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)


def _threshold_met(stats: dict, min_sev: str) -> bool:
    counts = stats.get("counts", {})
    if stats.get("kev", 0) > 0:
        return True
    idx = SEV_ORDER.index(min_sev) if min_sev in SEV_ORDER else 1
    return any(counts.get(s, 0) > 0 for s in SEV_ORDER[:idx + 1])


def _message(stats: dict, target: str, filename: str) -> str:
    c = stats.get("counts", {})
    return (f"Network scan alert — {target}\n"
            f"Risk: {stats.get('risk')}/100 ({stats.get('label')})\n"
            f"{c.get('critical', 0)} critical, {c.get('high', 0)} high, "
            f"{c.get('medium', 0)} medium findings; {stats.get('cves', 0)} potential "
            f"CVEs ({stats.get('kev', 0)} in CISA KEV).\nReport: {filename}")


def _send_all(cfg: dict, text: str, payload: dict) -> tuple[list, list]:
    sent, errors = [], []
    if cfg.get("teams_webhook"):
        try:
            requests.post(cfg["teams_webhook"], timeout=15, json={
                "@type": "MessageCard", "@context": "http://schema.org/extensions",
                "summary": "Network scan alert", "themeColor": "b42318",
                "title": "Network scan alert", "text": text.replace("\n", "\n\n")}).raise_for_status()
            sent.append("teams")
        except Exception as err:
            errors.append(f"teams: {err}")
    if cfg.get("slack_webhook"):
        try:
            requests.post(cfg["slack_webhook"], timeout=15, json={"text": text}).raise_for_status()
            sent.append("slack")
        except Exception as err:
            errors.append(f"slack: {err}")
    if cfg.get("webhook_url"):
        try:
            requests.post(cfg["webhook_url"], timeout=15, json=payload).raise_for_status()
            sent.append("webhook")
        except Exception as err:
            errors.append(f"webhook: {err}")
    if cfg.get("email_to"):
        try:
            mail_cfg = copy.deepcopy(CONFIG.email)
            mail_cfg.enabled = True
            mail_cfg.to = cfg["email_to"]
            ok = delivery.send_email(mail_cfg, subject="[Alert] " + text.splitlines()[0],
                                     html_body="<pre>" + text + "</pre>", markdown_body=text)
            sent.append("email") if ok else errors.append("email: not sent (check SMTP)")
        except Exception as err:
            errors.append(f"email: {err}")
    if errors:
        log.warning("alert send errors: %s", errors)
    return sent, errors


def dispatch(stats: dict, target: str, filename: str) -> dict:
    cfg = load_config()
    if not cfg.get("enabled"):
        return {"skipped": "disabled"}
    if not _threshold_met(stats, cfg.get("min_severity", "high")):
        return {"skipped": "below threshold"}
    text = _message(stats, target, filename)
    sent, errors = _send_all(cfg, text, {"target": target, "filename": filename, **stats})
    log.info("Alert dispatched for %s via %s", target, sent or "no channels")
    return {"sent": sent, "errors": errors}


def send_test(cfg: dict) -> dict:
    text = ("Test alert from your Threat Intelligence Briefing Agent. "
            "If you received this, the channel is configured correctly.")
    sent, errors = _send_all(cfg, text, {"test": True})
    return {"sent": sent, "errors": errors}
