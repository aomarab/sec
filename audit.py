"""Application activity / audit log.

Append-only JSONL stored under the data volume and capped to the most recent
events. Records two kinds of entries:
  • explicit user actions via record() (with the acting user), and
  • the app's own log output via AuditHandler (captured as 'system'/module events).

Read back with filters for the admin-only Logs tab."""
from __future__ import annotations

import datetime
import json
import logging
import os
import threading

LOG_FILE = os.getenv("AUDIT_LOG_FILE", "audit_log.jsonl")
MAX_EVENTS = int(os.getenv("AUDIT_MAX_EVENTS", "5000"))

CATEGORIES = ["auth", "briefing", "analysis", "scan", "recon", "cloud", "intel",
              "assets", "schedule", "alerts", "admin", "system"]
LEVELS = ["info", "success", "warning", "error"]

# Map a logger name (first dotted segment) to an audit category.
_LOGGER_CATEGORY = {
    "scan": "scan", "recon": "recon", "cloud": "cloud", "intel": "intel",
    "analysis": "analysis", "briefing": "briefing", "collectors": "system",
    "webapp": "system", "apikeys": "system", "alerts": "alerts", "auth": "auth",
}

_LOCK = threading.Lock()
_writes = 0


def record(category: str, action: str, user: str = "", level: str = "info",
           detail: str = "", status: str = "") -> None:
    """Append one event. Never raises."""
    global _writes
    evt = {
        "ts": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "category": category if category in CATEGORIES else "system",
        "action": (action or "")[:200],
        "user": (user or "")[:80],
        "level": level if level in LEVELS else "info",
        "status": (status or "")[:60],
        "detail": (detail or "")[:500],
    }
    line = json.dumps(evt, ensure_ascii=False)
    with _LOCK:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            return
        _writes += 1
        if _writes % 25 == 0:
            _trim()


def _trim() -> None:
    try:
        with open(LOG_FILE, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return
    if len(lines) > MAX_EVENTS:
        try:
            with open(LOG_FILE, "w", encoding="utf-8") as fh:
                fh.writelines(lines[-MAX_EVENTS:])
        except OSError:
            pass


def read(category: str = "", level: str = "", user: str = "", query: str = "",
         limit: int = 500) -> list[dict]:
    """Return newest-first events matching the filters."""
    try:
        with open(LOG_FILE, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out = []
    for ln in reversed(lines):
        try:
            e = json.loads(ln)
        except ValueError:
            continue
        if category and e.get("category") != category:
            continue
        if level and e.get("level") != level:
            continue
        if user and user.lower() not in (e.get("user") or "").lower():
            continue
        if query:
            hay = f"{e.get('action','')} {e.get('detail','')} {e.get('status','')}".lower()
            if query.lower() not in hay:
                continue
        out.append(e)
        if len(out) >= limit:
            break
    return out


def stats() -> dict:
    """Per-category counts for the most recent events (for the UI summary)."""
    counts = {}
    for e in read(limit=MAX_EVENTS):
        counts[e.get("category", "system")] = counts.get(e.get("category", "system"), 0) + 1
    return counts


def clear() -> None:
    with _LOCK:
        try:
            os.remove(LOG_FILE)
        except OSError:
            pass


class AuditHandler(logging.Handler):
    """Capture app log records into the audit store. Skips werkzeug HTTP noise
    and the audit logger itself to avoid spam/recursion."""

    def emit(self, record_obj: logging.LogRecord) -> None:
        try:
            name = (record_obj.name or "").split(".")[0]
            if name in ("werkzeug", "audit", "httpx", "urllib3"):
                return
            level = ("error" if record_obj.levelno >= logging.ERROR
                     else "warning" if record_obj.levelno >= logging.WARNING else "info")
            category = _LOGGER_CATEGORY.get(name, "system")
            record(category, record_obj.getMessage(), user="", level=level,
                   detail=f"logger: {record_obj.name}")
        except Exception:
            pass


def install_handler(level: int = logging.INFO) -> None:
    """Attach the AuditHandler to the root logger once."""
    root = logging.getLogger()
    if any(isinstance(h, AuditHandler) for h in root.handlers):
        return
    h = AuditHandler()
    h.setLevel(level)
    root.addHandler(h)
