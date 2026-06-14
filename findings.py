"""Findings register — dedup + lifecycle tracking across scans.

Each finding is fingerprinted (host + severity + title) so repeat runs update the
same record instead of creating duplicates. Tracks status (open/triaged/fixed/
accepted), owner, first/last-seen, and how many times it's been observed."""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import threading

import compliance

FINDINGS_FILE = os.getenv("FINDINGS_FILE", "findings.json")
STATUSES = ["open", "triaged", "fixed", "accepted"]
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
_TS_FMT = "%Y-%m-%d %H:%M UTC"
_LOCK = threading.Lock()


def _parse(ts: str):
    try:
        return datetime.datetime.strptime(ts, _TS_FMT)
    except (ValueError, TypeError):
        return None


def _age_days(ts: str) -> int | None:
    dt = _parse(ts)
    return (datetime.datetime.utcnow() - dt).days if dt else None


def _load() -> dict:
    try:
        with open(FINDINGS_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save(data: dict) -> None:
    try:
        with open(FINDINGS_FILE, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    except OSError:
        pass


def _fingerprint(target: str, severity: str, title: str, host: str) -> str:
    raw = f"{(host or target).lower()}|{severity.lower()}|{title.lower().strip()}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def ingest(target: str, source: str, items: list[dict]) -> tuple[int, int]:
    """Upsert normalized findings ({severity, title|name, host}). Returns
    (new, updated). A re-seen finding keeps its status/owner and bumps last_seen."""
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    new = upd = 0
    with _LOCK:
        data = _load()
        for it in items or []:
            sev = (it.get("severity") or "info").lower()
            title = (it.get("title") or it.get("name") or "").strip()
            if not title:
                continue
            host = it.get("host") or ""
            fid = _fingerprint(target, sev, title, host)
            e = data.get(fid)
            if e:
                e["last_seen"] = now
                e["count"] = e.get("count", 1) + 1
                if e.get("status") == "fixed":   # reappeared after being marked fixed
                    e["status"] = "open"
                    e.pop("fixed_at", None)
                upd += 1
            else:
                src = source or it.get("source", "")
                data[fid] = {"id": fid, "target": target, "source": src,
                             "severity": sev, "title": title[:240], "host": host,
                             "owasp": compliance.map_owasp(title, src),
                             "status": "open", "owner": "", "first_seen": now,
                             "last_seen": now, "count": 1}
                new += 1
        _save(data)
    return new, upd


def list_findings(status: str = "", severity: str = "", target: str = "",
                  query: str = "", limit: int = 1000) -> list[dict]:
    out = []
    for e in _load().values():
        if status and e.get("status") != status:
            continue
        if severity and e.get("severity") != severity:
            continue
        if target and target.lower() not in (e.get("target") or "").lower():
            continue
        if query:
            hay = f"{e.get('title','')} {e.get('host','')} {e.get('source','')}".lower()
            if query.lower() not in hay:
                continue
        out.append(e)
    out.sort(key=lambda e: (_SEV_RANK.get(e.get("severity"), 9), e.get("last_seen", "")), reverse=False)
    return out[:limit]


def update(fid: str, status: str | None = None, owner: str | None = None) -> bool:
    with _LOCK:
        data = _load()
        e = data.get(fid)
        if not e:
            return False
        if status in STATUSES:
            if status == "fixed" and e.get("status") != "fixed":
                e["fixed_at"] = datetime.datetime.utcnow().strftime(_TS_FMT)
            elif status != "fixed":
                e.pop("fixed_at", None)
            e["status"] = status
        if owner is not None:
            e["owner"] = owner[:80]
        _save(data)
    return True


def stats() -> dict:
    data = list(_load().values())
    by_status = {s: 0 for s in STATUSES}
    by_sev = {}
    aging = {"<7d": 0, "7-30d": 0, "30-90d": 0, ">90d": 0}
    mttr_samples = []
    for e in data:
        by_status[e.get("status", "open")] = by_status.get(e.get("status", "open"), 0) + 1
        by_sev[e.get("severity", "info")] = by_sev.get(e.get("severity", "info"), 0) + 1
        if e.get("status") in ("open", "triaged"):
            age = _age_days(e.get("first_seen", ""))
            if age is not None:
                bucket = "<7d" if age < 7 else "7-30d" if age < 30 else "30-90d" if age < 90 else ">90d"
                aging[bucket] += 1
        if e.get("status") == "fixed" and e.get("fixed_at"):
            opened, closed = _parse(e.get("first_seen", "")), _parse(e["fixed_at"])
            if opened and closed:
                mttr_samples.append((closed - opened).days)
    mttr = round(sum(mttr_samples) / len(mttr_samples), 1) if mttr_samples else None
    return {"total": sum(by_status.values()), "by_status": by_status, "by_severity": by_sev,
            "aging": aging, "mttr_days": mttr, "open_overdue": aging["30-90d"] + aging[">90d"]}


def clear() -> None:
    with _LOCK:
        try:
            os.remove(FINDINGS_FILE)
        except OSError:
            pass
