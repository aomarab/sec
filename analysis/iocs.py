"""Deterministic IOC extraction from text, with reputation lookup links and
optional VirusTotal enrichment. We extract indicators with regex (so long
hashes are never mangled) and never fabricate reputation scores."""
from __future__ import annotations

import logging
import os
import re
from urllib.parse import quote

import apikeys

log = logging.getLogger("analysis.iocs")

# Common defang patterns -> real form, so [.] / hxxp / [@] etc. are detected.
_DEFANG = [
    ("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."),
    ("hxxps", "https"), ("hxxp", "http"),
    ("[://]", "://"), ("[:]", ":"),
    ("[@]", "@"), ("(at)", "@"), ("[at]", "@"),
]

_PATTERNS = {
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "url": r"\bhttps?://[^\s)\]\"'<>]+",
    "email": r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
    "cve": r"\bCVE-\d{4}-\d{4,7}\b",
    "domain": r"\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,24}\b",
}

# Order controls extraction + de-dup precedence (longer hashes first).
_ORDER = ["cve", "sha256", "sha1", "md5", "ipv4", "url", "email", "domain"]

_DOMAIN_SKIP_SUFFIX = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js",
                       ".exe", ".dll", ".pdf", ".doc", ".docx", ".xls", ".xlsx")

# Benign reporting/vendor infrastructure commonly cited in advisories — not IOCs.
_BENIGN_DOMAINS = {
    "cisa.gov", "www.cisa.gov", "us-cert.cisa.gov", "fbi.gov", "www.fbi.gov",
    "ic3.gov", "stopransomware.gov", "cisecurity.org", "msisac.cisecurity.org",
    "mitre.org", "attack.mitre.org", "nist.gov", "nvd.nist.gov",
    "virustotal.com", "www.virustotal.com", "abuseipdb.com", "microsoft.com",
    "ncsc.gov.uk", "cyber.gov.au",
}


def _benign(domain_or_email: str) -> bool:
    host = domain_or_email.split("@")[-1].lower()
    return host in _BENIGN_DOMAINS


def refang(text: str) -> str:
    out = text
    for a, b in _DEFANG:
        out = out.replace(a, b)
    return out


def _valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Return de-duplicated indicators by type from already-refanged text."""
    found: dict[str, list[str]] = {}
    seen: set[str] = set()

    for kind in _ORDER:
        matches = re.findall(_PATTERNS[kind], text)
        items: list[str] = []
        for m in matches:
            val = m.rstrip(".,);]'\"")
            low = val.lower()

            if kind == "ipv4" and not _valid_ipv4(val):
                continue
            if kind == "email" and _benign(low):
                continue
            if kind == "domain":
                if _valid_ipv4(val):           # IPs already captured
                    continue
                if low.endswith(_DOMAIN_SKIP_SUFFIX) or _benign(low):
                    continue
                if low in seen or any(low in s for s in seen if "@" in s or "//" in s):
                    continue
            if low in seen:
                continue

            seen.add(low)
            items.append(val)
        if items:
            found[kind] = sorted(set(items), key=str.lower)
    return found


# ── reputation ───────────────────────────────────────────────────────────────
def _vt_link(kind: str, ind: str) -> str:
    if kind == "ipv4":
        return (f"<a href='https://www.virustotal.com/gui/ip-address/{ind}' target='_blank'>VT</a> · "
                f"<a href='https://www.abuseipdb.com/check/{ind}' target='_blank'>AbuseIPDB</a>")
    if kind in {"md5", "sha1", "sha256"}:
        return f"<a href='https://www.virustotal.com/gui/file/{ind}' target='_blank'>VT</a>"
    if kind == "domain":
        return f"<a href='https://www.virustotal.com/gui/domain/{ind}' target='_blank'>VT</a>"
    return f"<a href='https://www.virustotal.com/gui/search/{quote(ind, safe='')}' target='_blank'>VT</a>"


def _vt_score(kind: str, ind: str, api_key: str) -> str | None:
    """Best-effort VirusTotal reputation. Returns 'N/M malicious (VT)' or None."""
    import requests
    endpoint = {
        "ipv4": f"ip_addresses/{ind}",
        "domain": f"domains/{ind}",
        "md5": f"files/{ind}",
        "sha1": f"files/{ind}",
        "sha256": f"files/{ind}",
    }.get(kind)
    if not endpoint:
        return None
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/{endpoint}",
            headers={"x-apikey": api_key}, timeout=15,
        )
        if resp.status_code == 404:
            return "not found (VT)"
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        total = sum(stats.values()) or 0
        mal = stats.get("malicious", 0) + stats.get("suspicious", 0)
        return f"{mal}/{total} malicious (VT)"
    except Exception as err:
        log.info("VT lookup failed for %s: %s", ind, err)
        return None


def reputation(kind: str, ind: str, enrich_budget: list[int]) -> str:
    """Reputation cell: live VT score if VT_API_KEY is set (within budget),
    otherwise a clickable lookup link. enrich_budget is a 1-item list used as a
    mutable counter so we respect VT free-tier rate limits."""
    api_key = apikeys.get("VT_API_KEY")
    if api_key and kind in {"ipv4", "domain", "md5", "sha1", "sha256"} and enrich_budget[0] > 0:
        enrich_budget[0] -= 1
        score = _vt_score(kind, ind, api_key)
        if score:
            return f"{score} · {_vt_link(kind, ind)}"
    return _vt_link(kind, ind)


_TYPE_LABEL = {"ipv4": "IP address", "md5": "MD5", "sha1": "SHA1",
               "sha256": "SHA256", "url": "URL", "email": "Email", "domain": "Domain"}


def ioc_table_markdown(iocs: dict[str, list[str]]) -> str:
    """Build the IOC markdown table (excludes CVEs, which get their own section).
    VT_API_KEY enables live scores for up to 8 indicators; otherwise lookup links."""
    rows = []
    budget = [int(os.getenv("VT_ENRICH_LIMIT", "8"))]
    for kind in ("ipv4", "domain", "url", "email", "md5", "sha1", "sha256"):
        for ind in iocs.get(kind, []):
            rows.append((ind, _TYPE_LABEL[kind], reputation(kind, ind, budget)))

    if not rows:
        return "## Indicators of Compromise (IOCs)\n\n_No network or file indicators were detected in this document._"

    out = ["## Indicators of Compromise (IOCs)", "",
           "| Indicator | Type | Reputation / Lookup |",
           "|-----------|------|---------------------|"]
    for ind, typ, rep in rows:
        out.append(f"| `{ind}` | {typ} | {rep} |")
    return "\n".join(out)
