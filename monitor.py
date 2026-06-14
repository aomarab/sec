"""Per-target run snapshots, change detection, and run history.

Each scan/recon run stores a snapshot keyed by (kind, target) plus a history
entry summarising what changed. The next run for the same target is compared to
produce a 'Changes Since Last Run' report section, and the Monitoring tab reads
the snapshots/history to show tracked targets and their change timeline."""
from __future__ import annotations

import datetime
import json
import os
import threading

SNAP_FILE = os.getenv("MONITOR_FILE", "monitor_snapshots.json")
MAX_HISTORY = int(os.getenv("MONITOR_MAX_HISTORY", "1000"))
_LOCK = threading.Lock()


def _load() -> dict:
    try:
        with open(SNAP_FILE, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"snapshots": {}, "history": []}
    if "snapshots" in raw or "history" in raw:          # current shape
        return {"snapshots": raw.get("snapshots", {}), "history": raw.get("history", [])}
    return {"snapshots": raw, "history": []}            # migrate legacy flat shape


def _save(data: dict) -> None:
    try:
        with open(SNAP_FILE, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    except OSError:
        pass


def diff(prev: dict | None, categories: dict, metrics: dict | None = None) -> dict:
    out = {"baseline": prev is None, "categories": {}, "metrics": {}, "changed": False}
    if prev is None:
        return out
    for label, items in categories.items():
        cur, old = set(items), set(prev.get("categories", {}).get(label, []))
        added, removed = sorted(cur - old), sorted(old - cur)
        if added or removed:
            out["changed"] = True
            out["categories"][label] = {"added": added, "removed": removed}
    for name, val in (metrics or {}).items():
        old = prev.get("metrics", {}).get(name)
        if old is not None and old != val:
            out["changed"] = True
            out["metrics"][name] = {"from": old, "to": val}
    return out


def _render(d: dict, prev_ts: str | None) -> str:
    if d["baseline"]:
        return ("## Changes Since Last Run\n\n_First run for this target — baseline "
                "captured. Future runs will highlight what changed._")
    lines = ["## Changes Since Last Run", "",
             f"_Compared with the previous run on {prev_ts}._", ""]
    if not d["changed"]:
        lines.append("- No changes since the last run. ✅")
        return "\n".join(lines)
    for name, mv in d["metrics"].items():
        arrow = "▲" if (isinstance(mv["to"], (int, float)) and mv["to"] > mv["from"]) else "▼"
        lines.append(f"- **{name}**: {mv['from']} → {mv['to']} {arrow}")
    for label, cv in d["categories"].items():
        if cv["added"]:
            lines.append(f"- **New {label} ({len(cv['added'])})**: " +
                         ", ".join(f"`{a}`" for a in cv["added"][:40]) +
                         (" …" if len(cv["added"]) > 40 else ""))
        if cv["removed"]:
            lines.append(f"- **Removed {label} ({len(cv['removed'])})**: " +
                         ", ".join(f"`{r}`" for r in cv["removed"][:40]) +
                         (" …" if len(cv["removed"]) > 40 else ""))
    return "\n".join(lines)


def record(kind: str, key: str, categories: dict, metrics: dict | None = None) -> dict:
    """Store this run's snapshot + history entry; return {markdown, diff}."""
    sk = f"{kind}:{key}"
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    with _LOCK:
        data = _load()
        prev = data["snapshots"].get(sk)
        d = diff(prev, categories, metrics)
        data["snapshots"][sk] = {
            "ts": now,
            "categories": {c: sorted(set(v)) for c, v in categories.items()},
            "metrics": metrics or {},
        }
        data["history"].append({
            "kind": kind, "key": key, "ts": now,
            "baseline": d["baseline"], "changed": d["changed"],
            "added": {c: len(v["added"]) for c, v in d["categories"].items() if v["added"]},
            "removed": {c: len(v["removed"]) for c, v in d["categories"].items() if v["removed"]},
            "metrics": d["metrics"],
            "values": metrics or {},
            "totals": {c: len(set(v)) for c, v in categories.items()},
        })
        data["history"] = data["history"][-MAX_HISTORY:]
        _save(data)
    return {"markdown": _render(d, prev["ts"] if prev else None), "diff": d}


def list_targets() -> list[dict]:
    """Tracked targets with their latest snapshot + last-change time + run count."""
    data = _load()
    hist = data["history"]
    out = []
    for sk, snap in data["snapshots"].items():
        kind, _, key = sk.partition(":")
        runs = [h for h in hist if f"{h['kind']}:{h['key']}" == sk]
        last_change = next((h["ts"] for h in reversed(runs) if h.get("changed")), None)
        out.append({
            "kind": kind, "key": key, "ts": snap["ts"],
            "metrics": snap.get("metrics", {}),
            "totals": {c: len(v) for c, v in snap.get("categories", {}).items()},
            "runs": len(runs), "last_change": last_change,
        })
    out.sort(key=lambda t: t["ts"], reverse=True)
    return out


def history(kind: str, key: str, limit: int = 60) -> list[dict]:
    sk = f"{kind}:{key}"
    rows = [h for h in _load()["history"] if f"{h['kind']}:{h['key']}" == sk]
    return list(reversed(rows))[:limit]


def clear() -> None:
    with _LOCK:
        try:
            os.remove(SNAP_FILE)
        except OSError:
            pass
