"""Vendor-API enrichment for analyzed files/reports: compute file hashes and
look them up on VirusTotal, and enrich extracted IOCs via VirusTotal + AbuseIPDB.
All lookups are gated on API keys (VT_API_KEY, ABUSEIPDB_API_KEY) and degrade
gracefully — no key means that source is simply skipped."""
from __future__ import annotations

import hashlib
import logging
import os

import requests

import apikeys

log = logging.getLogger("analysis.enrich")

VT = "https://www.virustotal.com/api/v3"
ENRICH_BUDGET = int(os.getenv("ENRICH_BUDGET", "12"))


def file_hashes(path: str) -> dict:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def _vt_stats(endpoint: str, key: str) -> dict | None:
    try:
        r = requests.get(f"{VT}/{endpoint}", headers={"x-apikey": key}, timeout=20)
        if r.status_code == 404:
            return {"found": False}
        r.raise_for_status()
        attrs = r.json()["data"]["attributes"]
        st = attrs.get("last_analysis_stats", {})
        mal = st.get("malicious", 0) + st.get("suspicious", 0)
        total = sum(st.values()) or 0
        label = (attrs.get("popular_threat_classification", {}) or {}).get("suggested_threat_label", "")
        return {"found": True, "malicious": mal, "total": total, "label": label}
    except Exception as err:
        log.info("VT %s failed: %s", endpoint, err)
        return None


def file_reputation(path: str) -> dict:
    """Return file hashes plus a VirusTotal verdict (if VT_API_KEY is set)."""
    hashes = file_hashes(path)
    out = {"hashes": hashes, "vt": None}
    key = apikeys.get("VT_API_KEY")
    if key:
        vt = _vt_stats(f"files/{hashes['sha256']}", key)
        if vt and vt.get("found"):
            vt["link"] = f"https://www.virustotal.com/gui/file/{hashes['sha256']}"
        out["vt"] = vt
    return out


def _abuseipdb(ip: str, key: str) -> dict | None:
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": key, "Accept": "application/json"},
                         params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=20)
        r.raise_for_status()
        d = r.json()["data"]
        return {"score": d.get("abuseConfidenceScore", 0), "reports": d.get("totalReports", 0),
                "country": d.get("countryCode", "")}
    except Exception as err:
        log.info("AbuseIPDB %s failed: %s", ip, err)
        return None


def enrich_iocs(iocs: dict) -> list[dict]:
    """Look up indicators with vendor APIs. Returns rows:
    {indicator, type, source, verdict, confidence, link}. Respects a small call
    budget to stay within free-tier rate limits."""
    vt_key = apikeys.get("VT_API_KEY")
    abuse_key = apikeys.get("ABUSEIPDB_API_KEY")
    rows: list[dict] = []
    budget = ENRICH_BUDGET

    if not (vt_key or abuse_key):
        return rows

    for ip in iocs.get("ipv4", []):
        if budget <= 0:
            break
        if abuse_key:
            a = _abuseipdb(ip, abuse_key)
            budget -= 1
            if a:
                rows.append({"indicator": ip, "type": "IP", "source": "AbuseIPDB",
                             "verdict": f"{a['score']}% abuse, {a['reports']} reports ({a['country']})",
                             "confidence": a["score"],
                             "link": f"https://www.abuseipdb.com/check/{ip}"})
        if vt_key and budget > 0:
            v = _vt_stats(f"ip_addresses/{ip}", vt_key)
            budget -= 1
            if v and v.get("found"):
                conf = round(100 * v["malicious"] / v["total"]) if v["total"] else 0
                rows.append({"indicator": ip, "type": "IP", "source": "VirusTotal",
                             "verdict": f"{v['malicious']}/{v['total']} engines malicious",
                             "confidence": conf,
                             "link": f"https://www.virustotal.com/gui/ip-address/{ip}"})

    if vt_key:
        for dom in iocs.get("domain", []):
            if budget <= 0:
                break
            v = _vt_stats(f"domains/{dom}", vt_key)
            budget -= 1
            if v and v.get("found"):
                conf = round(100 * v["malicious"] / v["total"]) if v["total"] else 0
                rows.append({"indicator": dom, "type": "Domain", "source": "VirusTotal",
                             "verdict": f"{v['malicious']}/{v['total']} engines malicious",
                             "confidence": conf,
                             "link": f"https://www.virustotal.com/gui/domain/{dom}"})
        for h in (iocs.get("sha256", []) + iocs.get("sha1", []) + iocs.get("md5", [])):
            if budget <= 0:
                break
            v = _vt_stats(f"files/{h}", vt_key)
            budget -= 1
            if v and v.get("found"):
                conf = round(100 * v["malicious"] / v["total"]) if v["total"] else 0
                rows.append({"indicator": h, "type": "File hash", "source": "VirusTotal",
                             "verdict": f"{v['malicious']}/{v['total']} engines malicious"
                                        + (f" — {v['label']}" if v.get("label") else ""),
                             "confidence": conf,
                             "link": f"https://www.virustotal.com/gui/file/{h}"})
    return rows


def sections_markdown(path: str, iocs: dict) -> str:
    """Build the File Hashes / File Reputation / IOC Reputation report sections."""
    rep = file_reputation(path)
    h = rep["hashes"]
    parts = ["## File Hashes", "",
             f"- **MD5:** `{h['md5']}`",
             f"- **SHA1:** `{h['sha1']}`",
             f"- **SHA256:** `{h['sha256']}`"]

    vt = rep.get("vt")
    if vt is not None:
        parts += ["", "## File Reputation (VirusTotal)", ""]
        if vt.get("found"):
            label = f" — classified as **{vt['label']}**" if vt.get("label") else ""
            parts.append(f"<a href='{vt['link']}' target='_blank'>**{vt['malicious']}/{vt['total']} "
                         f"engines flagged this file as malicious**</a>{label}.")
        else:
            parts.append("This file's hash was **not found** on VirusTotal (no prior detections / not seen).")

    rows = enrich_iocs(iocs)
    if rows:
        rows.sort(key=lambda r: r.get("confidence", 0), reverse=True)
        parts += ["", "## IOC Reputation (vendor APIs)", "",
                  "| Indicator | Type | Source | Verdict | Confidence |",
                  "|-----------|------|--------|---------|-----------|"]
        for r in rows:
            parts.append(f"| <a href='{r['link']}' target='_blank'>`{r['indicator']}`</a> | {r['type']} "
                         f"| {r['source']} | {r['verdict']} | {r['confidence']}% |")
    return "\n".join(parts)
