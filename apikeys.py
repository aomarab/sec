"""Vendor API key store. Admins set keys in the UI (persisted to api_keys.json);
lookups call get(name), which returns the stored key or falls back to the
matching environment variable. Keys are write-only in the UI (shown masked)."""
from __future__ import annotations

import json
import logging
import os

log = logging.getLogger("apikeys")

KEYS_FILE = os.getenv("API_KEYS_FILE", "api_keys.json")

# (env var name, display label, what it enables)
VENDORS = [
    ("ANTHROPIC_API_KEY", "Anthropic (Claude)", "LLM engine — briefings, analysis, scan/recon narratives, intel"),
    ("OPENAI_API_KEY", "OpenAI", "Alternative LLM engine (when provider = openai)"),
    ("VT_API_KEY", "VirusTotal", "File / IP / domain / hash reputation"),
    ("ABUSEIPDB_API_KEY", "AbuseIPDB", "IP abuse reputation"),
    ("SHODAN_API_KEY", "Shodan", "Host / port / vuln data in recon"),
    ("HUNTER_API_KEY", "Hunter.io", "Email discovery in recon"),
    ("NVD_API_KEY", "NVD", "Higher rate limits for CVE lookups"),
    ("WPSCAN_API_KEY", "WPScan", "WordPress vulnerability database"),
]
_NAMES = {v[0] for v in VENDORS}


def _load() -> dict:
    try:
        with open(KEYS_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save(data: dict) -> None:
    with open(KEYS_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def get(name: str) -> str:
    """Stored key takes precedence, then the environment variable."""
    return (_load().get(name) or os.getenv(name, "")).strip()


def status() -> list[dict]:
    """For the admin UI: per-vendor configured flag + a non-revealing hint."""
    stored = _load()
    out = []
    for env, label, desc in VENDORS:
        sv, ev = stored.get(env, ""), os.getenv(env, "")
        if sv:
            hint = f"set (••••{sv[-4:]})" if len(sv) > 4 else "set"
        elif ev:
            hint = "from .env"
        else:
            hint = ""
        out.append({"key": env, "label": label, "desc": desc,
                    "configured": bool(sv or ev), "hint": hint})
    return out


def save_form(form) -> None:
    """Update keys from a submitted form. A non-empty value sets/replaces a key;
    ticking clear_<KEY> removes the stored key (reverting to .env if present)."""
    stored = _load()
    for env in _NAMES:
        if form.get("clear_" + env) == "on":
            stored.pop(env, None)
        else:
            val = (form.get(env) or "").strip()
            if val:
                stored[env] = val
    _save(stored)
