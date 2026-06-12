"""On-demand vendor analysis for the File Analysis tab.

The user pastes a vendor API key (no keys are stored anywhere) plus an indicator
or a file. We *discover* which vendor the key belongs to by validating it against
each vendor's identity endpoint, then run the matching lookup. Supported vendors:
VirusTotal, AbuseIPDB, Shodan, Hunter.io, NVD."""
from __future__ import annotations

import base64
import logging
import re

import requests

from analysis.enrich import _abuseipdb, _vt_stats, file_hashes
from collectors import nvd
from recon.harvester import hunter_emails, shodan_host

log = logging.getLogger("analysis.vendor")

# Vendor key -> (display label, indicator types it can analyze).
# Types: "ip", "domain", "url", "hash", "file", "keyword".
VENDOR_CAPS: dict[str, tuple[str, set[str]]] = {
    "VT_API_KEY": ("VirusTotal", {"ip", "domain", "url", "hash", "file"}),
    "ABUSEIPDB_API_KEY": ("AbuseIPDB", {"ip"}),
    "SHODAN_API_KEY": ("Shodan", {"ip"}),
    "HUNTER_API_KEY": ("Hunter.io", {"domain"}),
    "NVD_API_KEY": ("NVD", {"keyword"}),
}

TYPE_LABEL = {"ip": "IP address", "domain": "Domain", "url": "URL",
              "hash": "File hash", "file": "File", "keyword": "Keyword / product"}


def detect_type(value: str) -> str:
    """Classify a raw indicator string."""
    v = (value or "").strip()
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", v) and all(
            0 <= int(p) <= 255 for p in v.split(".")):
        return "ip"
    if re.fullmatch(r"[a-fA-F0-9]{32}", v) or re.fullmatch(r"[a-fA-F0-9]{40}", v) \
            or re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return "hash"
    if re.match(r"^https?://", v, re.I):
        return "url"
    if re.fullmatch(r"(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,24}", v):
        return "domain"
    return "keyword"


# ── vendor key discovery ──────────────────────────────────────────────────────
def _validate_vt(key: str) -> bool:
    r = requests.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                     headers={"x-apikey": key}, timeout=12)
    return r.status_code == 200


def _validate_abuse(key: str) -> bool:
    r = requests.get("https://api.abuseipdb.com/api/v2/check",
                     headers={"Key": key, "Accept": "application/json"},
                     params={"ipAddress": "8.8.8.8", "maxAgeInDays": 90}, timeout=12)
    return r.status_code == 200


def _validate_shodan(key: str) -> bool:
    r = requests.get("https://api.shodan.io/api-info", params={"key": key}, timeout=12)
    return r.status_code == 200


def _validate_hunter(key: str) -> bool:
    r = requests.get("https://api.hunter.io/v2/account", params={"api_key": key}, timeout=12)
    return r.status_code == 200


def _validate_nvd(key: str) -> bool:
    # NVD accepts the key via the apiKey header; an invalid key yields 403/404.
    r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                     headers={"apiKey": key}, params={"resultsPerPage": 1}, timeout=20)
    return r.status_code == 200


_VALIDATORS = {
    "VT_API_KEY": _validate_vt,
    "ABUSEIPDB_API_KEY": _validate_abuse,
    "SHODAN_API_KEY": _validate_shodan,
    "HUNTER_API_KEY": _validate_hunter,
    "NVD_API_KEY": _validate_nvd,
}


def _format_guess(key: str) -> str | None:
    """Guess the vendor from the key's shape, to probe the likeliest first."""
    k = key.strip()
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", k):
        return "NVD_API_KEY"
    if re.fullmatch(r"[0-9a-f]{64}", k):
        return "VT_API_KEY"
    if re.fullmatch(r"[0-9a-f]{80}", k):
        return "ABUSEIPDB_API_KEY"
    if re.fullmatch(r"[0-9a-f]{40}", k):
        return "HUNTER_API_KEY"
    if re.fullmatch(r"[A-Za-z0-9]{32}", k):
        return "SHODAN_API_KEY"
    return None


def discover_vendor(api_key: str) -> str | None:
    """Return the VENDOR_CAPS key whose API the given key authenticates against,
    or None if it matches no supported vendor. Probes the format-guessed vendor
    first to minimise calls."""
    key = (api_key or "").strip()
    if not key:
        return None
    order = list(_VALIDATORS)
    guess = _format_guess(key)
    if guess:
        order = [guess] + [e for e in order if e != guess]
    for env in order:
        try:
            if _VALIDATORS[env](key):
                return env
        except Exception as err:  # noqa: BLE001 — a failed probe just means "not this one"
            log.info("vendor probe %s failed: %s", env, err)
    return None


# ── per-vendor result rows ────────────────────────────────────────────────────
def _level(malicious: int, total: int) -> str:
    if total and malicious > 0:
        return "malicious" if malicious >= 3 else "suspicious"
    return "clean"


def _vt_row(kind: str, indicator: str, key: str) -> dict:
    endpoint = {
        "ip": f"ip_addresses/{indicator}",
        "domain": f"domains/{indicator}",
        "hash": f"files/{indicator}",
        "url": "urls/" + base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("="),
    }[kind]
    gui = {
        "ip": f"https://www.virustotal.com/gui/ip-address/{indicator}",
        "domain": f"https://www.virustotal.com/gui/domain/{indicator}",
        "hash": f"https://www.virustotal.com/gui/file/{indicator}",
        "url": f"https://www.virustotal.com/gui/search/{indicator}",
    }[kind]
    st = _vt_stats(endpoint, key)
    if st is None:
        return {"vendor": "VirusTotal", "level": "error",
                "summary": "Lookup failed", "detail": "VirusTotal request error.", "link": gui}
    if not st.get("found"):
        return {"vendor": "VirusTotal", "level": "clean",
                "summary": "Not found", "detail": "No prior detections on VirusTotal.", "link": gui}
    mal, total = st.get("malicious", 0), st.get("total", 0)
    label = st.get("label") or ""
    detail = f"{mal}/{total} engines flagged it as malicious"
    if label:
        detail += f" — classified as {label}"
    return {"vendor": "VirusTotal", "level": _level(mal, total),
            "summary": f"{mal}/{total} malicious", "detail": detail + ".", "link": gui}


def _abuse_row(ip: str, key: str) -> dict:
    a = _abuseipdb(ip, key)
    link = f"https://www.abuseipdb.com/check/{ip}"
    if a is None:
        return {"vendor": "AbuseIPDB", "level": "error",
                "summary": "Lookup failed", "detail": "AbuseIPDB request error.", "link": link}
    score = a.get("score", 0)
    level = "malicious" if score >= 50 else "suspicious" if score > 0 else "clean"
    return {"vendor": "AbuseIPDB", "level": level,
            "summary": f"{score}% abuse confidence",
            "detail": f"{a.get('reports', 0)} report(s) · country {a.get('country') or 'n/a'}.",
            "link": link}


def _shodan_row(ip: str, key: str) -> dict:
    d = shodan_host(ip, key)
    link = f"https://www.shodan.io/host/{ip}"
    if not d:
        return {"vendor": "Shodan", "level": "clean",
                "summary": "No data", "detail": "Host not indexed by Shodan.", "link": link}
    ports = d.get("ports", []) or []
    vulns = d.get("vulns", []) or []
    level = "suspicious" if vulns else "info"
    detail = f"{len(ports)} open port(s): {', '.join(map(str, ports[:20])) or '—'}"
    if d.get("org"):
        detail += f" · org {d['org']}"
    if vulns:
        detail += f" · known vulns: {', '.join(vulns[:8])}"
    return {"vendor": "Shodan", "level": level,
            "summary": f"{len(ports)} ports, {len(vulns)} vuln(s)", "detail": detail + ".", "link": link}


def _hunter_row(domain: str, key: str) -> dict:
    emails = hunter_emails(domain, key)
    link = f"https://hunter.io/search/{domain}"
    return {"vendor": "Hunter.io", "level": "info",
            "summary": f"{len(emails)} email(s) found",
            "detail": (", ".join(emails[:25]) + ("…" if len(emails) > 25 else "")) or "No public emails found.",
            "link": link}


def _nvd_row(keyword: str, key: str) -> dict:
    res = nvd.search_by_keyword(keyword, min_cvss=7.0, limit=8, api_key=key)
    cves = res.get("cves", [])
    link = f"https://nvd.nist.gov/vuln/search/results?query={keyword}"
    if not cves:
        return {"vendor": "NVD", "level": "clean",
                "summary": "No high-severity CVEs",
                "detail": f"No CVEs with CVSS ≥ 7 matched '{keyword}'.", "link": link}
    top = ", ".join(f"{c['cve']} ({c['cvss']})" for c in cves[:6])
    return {"vendor": "NVD", "level": "suspicious",
            "summary": f"{len(cves)} CVE(s) ≥ CVSS 7",
            "detail": f"Top matches: {top}.", "link": link}


_HANDLERS = {
    "VT_API_KEY": lambda kind, ind, key: _vt_row("hash" if kind == "file" else kind, ind, key),
    "ABUSEIPDB_API_KEY": lambda kind, ind, key: _abuse_row(ind, key),
    "SHODAN_API_KEY": lambda kind, ind, key: _shodan_row(ind, key),
    "HUNTER_API_KEY": lambda kind, ind, key: _hunter_row(ind, key),
    "NVD_API_KEY": lambda kind, ind, key: _nvd_row(ind, key),
}


def analyze(api_key: str, indicator: str = "", file_path: str = "") -> dict:
    """Discover the vendor from the API key, then run the matching lookup.

    Returns {vendor, indicator, type, hashes, rows, notes} on success, or
    {error, ...} when the key is unrecognised or the indicator type doesn't fit
    the vendor."""
    env = discover_vendor(api_key)
    if not env:
        return {"error": "Couldn't match this API key to a supported vendor "
                "(VirusTotal, AbuseIPDB, Shodan, Hunter.io, or NVD). "
                "Check the key is correct and active, then try again."}

    label, supported = VENDOR_CAPS[env]
    hashes = None
    if file_path:
        hashes = file_hashes(file_path)
        kind, target, shown = "file", hashes["sha256"], f"{hashes['sha256']} (uploaded file)"
    else:
        kind, target, shown = detect_type(indicator), indicator.strip(), indicator.strip()

    effective = "hash" if kind == "file" and env == "VT_API_KEY" else kind
    if effective not in supported:
        sup = ", ".join(sorted(TYPE_LABEL[t] for t in supported if t != "file"))
        return {"vendor": label, "indicator": shown, "type": TYPE_LABEL.get(kind, kind),
                "error": f"This is a {label} key — it analyzes {sup}. "
                f"Your input looks like a {TYPE_LABEL[kind].lower()}; enter a matching indicator."}

    try:
        row = _HANDLERS[env](kind, target, api_key.strip())
    except Exception as err:  # noqa: BLE001
        log.info("%s lookup failed for %s: %s", label, target, err)
        return {"vendor": label, "indicator": shown, "type": TYPE_LABEL.get(kind, kind),
                "error": f"{label} lookup failed: {err}"}

    return {"vendor": label, "indicator": shown, "type": TYPE_LABEL.get(kind, kind),
            "hashes": hashes, "rows": [row] if row else [], "notes": []}
