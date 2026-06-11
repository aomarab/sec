"""FIRST EPSS (Exploit Prediction Scoring System) — probability that a CVE will
be exploited in the next 30 days. Free, no key. Great for prioritization."""
from __future__ import annotations

from .http import get_json

EPSS_API = "https://api.first.org/data/v1/epss"


def fetch_epss(cves: list[str]) -> dict:
    """Return EPSS probability + percentile for a list of CVE IDs (max ~100)."""
    if not cves:
        return {"source": "EPSS", "count": 0, "scores": []}
    data = get_json(EPSS_API, params={"cve": ",".join(cves[:100])})
    scores = [{
        "cve": d.get("cve"),
        "epss": float(d.get("epss", 0)),
        "percentile": float(d.get("percentile", 0)),
        "date": d.get("date"),
    } for d in data.get("data", [])]
    scores.sort(key=lambda x: x["epss"], reverse=True)
    return {"source": "EPSS", "count": len(scores), "scores": scores}
