"""CISA Known Exploited Vulnerabilities (KEV) catalog — vulnerabilities with
confirmed in-the-wild exploitation. Free, no key required."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .http import get_json

KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev(look_back_days: int = 7, limit: int = 25,
              keywords: list[str] | None = None) -> dict:
    """Return KEV entries added within `look_back_days`, optionally filtered by
    vendor/product keywords. These are the highest-priority threats: known to be
    actively exploited."""
    data = get_json(KEV_FEED)
    cutoff = datetime.now(timezone.utc).date() - timedelta(days=look_back_days)
    kws = [k.lower() for k in (keywords or [])]

    recent = []
    for v in data.get("vulnerabilities", []):
        try:
            added = datetime.strptime(v["dateAdded"], "%Y-%m-%d").date()
        except (KeyError, ValueError):
            continue
        if added < cutoff:
            continue
        if kws:
            haystack = f"{v.get('vendorProject','')} {v.get('product','')} {v.get('vulnerabilityName','')}".lower()
            if not any(k in haystack for k in kws):
                continue
        recent.append({
            "cve": v.get("cveID"),
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "name": v.get("vulnerabilityName"),
            "date_added": v.get("dateAdded"),
            "due_date": v.get("dueDate"),
            "ransomware": v.get("knownRansomwareCampaignUse"),
            "action": v.get("requiredAction"),
        })

    recent.sort(key=lambda x: x["date_added"], reverse=True)
    return {
        "source": "CISA KEV",
        "catalog_version": data.get("catalogVersion"),
        "look_back_days": look_back_days,
        "count": len(recent),
        "vulnerabilities": recent[:limit],
    }
