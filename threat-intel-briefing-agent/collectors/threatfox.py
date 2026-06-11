"""abuse.ch ThreatFox — recent indicators of compromise (IOCs) tied to malware
and threat actors. abuse.ch now requires a free Auth-Key for API access; set
ABUSECH_AUTH_KEY in the environment. Failures are returned gracefully so the
agent loop can continue without this source."""
from __future__ import annotations

import os

import requests

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"


def fetch_recent_iocs(days: int = 1, limit: int = 25) -> dict:
    auth_key = os.getenv("ABUSECH_AUTH_KEY", "")
    headers = {"Auth-Key": auth_key} if auth_key else {}
    try:
        resp = requests.post(
            THREATFOX_API,
            json={"query": "get_iocs", "days": max(1, min(days, 7))},
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
        payload = resp.json()
    except (requests.RequestException, ValueError) as err:
        return {"source": "ThreatFox", "error": str(err), "count": 0, "iocs": []}

    if payload.get("query_status") != "ok":
        return {"source": "ThreatFox", "error": payload.get("query_status"),
                "count": 0, "iocs": []}

    iocs = [{
        "ioc": d.get("ioc"),
        "type": d.get("ioc_type"),
        "malware": d.get("malware_printable"),
        "threat_type": d.get("threat_type"),
        "confidence": d.get("confidence_level"),
        "first_seen": d.get("first_seen"),
    } for d in payload.get("data", [])[:limit]]
    return {"source": "ThreatFox", "count": len(iocs), "iocs": iocs}
