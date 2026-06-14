"""Per-target run snapshots + change detection for scans and recon.

Each scan/recon run stores a snapshot keyed by (kind, target). The next run for
the same target is compared against it to produce a 'Changes Since Last Run'
report section — new/removed items per category and metric deltas (e.g. risk
score). Enables continuous-monitoring workflows."""
from __future__ import annotations

import datetime
import json
import os
import threading

SNAP_FILE = os.getenv("MONITOR_FILE", "monitor_snapshots.json")
_LOCK = threading.Lock()


def _load() -> dict:
    try:
        with open(SNAP_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save(data: dict) -> None:
    try:
        with open(SNAP_FILE, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    except OSError:
        pass


def diff(prev: dict | None, categories: dict, metrics: dict | None = None) -> dict:
    """Compute added/removed per category and metric deltas (no I/O)."""
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
    """Store this run's snapshot and return {markdown, diff} vs the prior run."""
    sk = f"{kind}:{key}"
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    with _LOCK:
        data = _load()
        prev = data.get(sk)
        d = diff(prev, categories, metrics)
        data[sk] = {"ts": now,
                    "categories": {c: sorted(set(v)) for c, v in categories.items()},
                    "metrics": metrics or {}}
        _save(data)
    return {"markdown": _render(d, prev["ts"] if prev else None), "diff": d}
