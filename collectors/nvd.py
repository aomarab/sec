"""NVD (National Vulnerability Database) CVE API 2.0. Free; an API key raises
rate limits but is not required."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .http import get_json

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_recent_cves(look_back_days: int = 7, min_cvss: float = 7.0,
                      limit: int = 25, keyword: str | None = None,
                      api_key: str = "") -> dict:
    """Return recently published CVEs with CVSS >= min_cvss. NVD limits the
    pub date window to 120 days, so look_back_days is clamped."""
    look_back_days = min(look_back_days, 119)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=look_back_days)

    params = {
        "pubStartDate": _iso(start),
        "pubEndDate": _iso(end),
        "resultsPerPage": 2000,
    }
    if keyword:
        params["keywordSearch"] = keyword
    headers = {"apiKey": api_key} if api_key else None

    data = get_json(NVD_API, params=params, headers=headers, timeout=45)

    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        score, severity, vector = _best_cvss(metrics)
        if score is None or score < min_cvss:
            continue
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        out.append({
            "cve": cve.get("id"),
            "published": cve.get("published"),
            "cvss": score,
            "severity": severity,
            "vector": vector,
            "description": desc[:500],
        })

    out.sort(key=lambda x: x["cvss"], reverse=True)
    return {
        "source": "NVD",
        "look_back_days": look_back_days,
        "min_cvss": min_cvss,
        "count": len(out),
        "cves": out[:limit],
    }


def search_by_keyword(keyword: str, min_cvss: float = 7.0, limit: int = 8,
                      api_key: str = "") -> dict:
    """Search NVD for CVEs matching a product/keyword (no date window). Used to
    correlate discovered network services with known vulnerabilities."""
    headers = {"apiKey": api_key} if api_key else None
    data = get_json(NVD_API, params={"keywordSearch": keyword, "resultsPerPage": 30},
                    headers=headers, timeout=45)
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        score, severity, _ = _best_cvss(cve.get("metrics", {}))
        if score is None or score < min_cvss:
            continue
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        out.append({"cve": cve.get("id"), "cvss": score, "severity": severity,
                    "description": desc[:240], "product": keyword})
    out.sort(key=lambda x: x["cvss"], reverse=True)
    return {"source": "NVD", "keyword": keyword, "count": len(out), "cves": out[:limit]}


def _best_cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            severity = entries[0].get("baseSeverity") or data.get("baseSeverity")
            return data.get("baseScore"), severity, data.get("vectorString")
    return None, None, None
