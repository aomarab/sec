"""Endpoint fleet store: the enrollment token plus the latest inventory from
each host running the optional endpoint agent. Persisted to fleet.json. Mirrors
the apikeys.py pattern (one JSON file; the path is overridable via env)."""
from __future__ import annotations

import hmac
import json
import logging
import os
import secrets

log = logging.getLogger("fleet")

FLEET_FILE = os.getenv("FLEET_FILE", "fleet.json")
MAX_ENDPOINTS = 1000


def _load() -> dict:
    try:
        with open(FLEET_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save(data: dict) -> None:
    with open(FLEET_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


# ── enrollment token ─────────────────────────────────────────────────────────
def get_token() -> str:
    """Return the enrollment token, generating one on first use."""
    data = _load()
    tok = data.get("enroll_token")
    if not tok:
        tok = secrets.token_urlsafe(24)
        data["enroll_token"] = tok
        _save(data)
    return tok


def rotate_token() -> str:
    data = _load()
    data["enroll_token"] = secrets.token_urlsafe(24)
    _save(data)
    return data["enroll_token"]


def token_hint() -> str:
    tok = get_token()
    return f"••••{tok[-4:]}" if len(tok) > 4 else "set"


def verify_token(presented: str) -> bool:
    """Constant-time comparison of a presented bearer token."""
    if not presented:
        return False
    return hmac.compare_digest(str(get_token()), str(presented))


# ── check-ins ────────────────────────────────────────────────────────────────
def record_checkin(agent_id: str, payload: dict, remote_addr: str, when: str) -> dict:
    """Upsert one endpoint's latest inventory. Returns a compact summary."""
    data = _load()
    eps = data.setdefault("endpoints", {})
    inv = payload.get("inventory") or {}
    ident = inv.get("identity") or {}
    key = agent_id or payload.get("hostname") or remote_addr
    if key not in eps and len(eps) >= MAX_ENDPOINTS:
        raise ValueError("endpoint limit reached")
    record = {
        "agent_id": agent_id,
        "hostname": ident.get("hostname") or payload.get("hostname") or "",
        "os": ident.get("os", ""),
        "os_release": ident.get("os_release", ""),
        "distro": ident.get("distro", ""),
        "ip_addresses": inv.get("ip_addresses", []),
        "remote_addr": remote_addr,
        "tags": payload.get("tags", []),
        "agent_version": payload.get("agent_version", ""),
        "last_checkin": when,
        "summary": inv.get("summary", {}),
        "inventory": inv,
    }
    eps[key] = record
    _save(data)
    return {"hostname": record["hostname"], "summary": record["summary"]}


def list_endpoints() -> list[dict]:
    """Compact rows for the admin UI (without the full inventory blob)."""
    eps = _load().get("endpoints", {})
    rows = []
    for key, r in eps.items():
        rows.append({
            "id": key,
            "hostname": r.get("hostname", ""),
            "os": (r.get("distro") or f"{r.get('os', '')} {r.get('os_release', '')}").strip(),
            "ip": ", ".join(r.get("ip_addresses", [])[:3]),
            "tags": ", ".join(r.get("tags", [])),
            "agent_version": r.get("agent_version", ""),
            "last_checkin": r.get("last_checkin", ""),
            "summary": r.get("summary", {}),
        })
    rows.sort(key=lambda x: x["last_checkin"], reverse=True)
    return rows


def get_endpoint(key: str) -> dict:
    return _load().get("endpoints", {}).get(key, {})
