"""Passive web security configuration grader — no external binary, no payloads.

Performs a single GET per endpoint and grades:
  • security response headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy),
  • cookie flags (Secure / HttpOnly / SameSite),
  • permissive CORS (Access-Control-Allow-Origin: *).

Read-only and safe to run broadly. Returns normalized findings; never raises."""
from __future__ import annotations

import logging

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("scan.headers")

UA = {"User-Agent": "threat-intel-briefing-agent/1.0 (security header check)"}

# header (lower-case) -> (display label, severity if missing)
_HEADERS = {
    "content-security-policy": ("Content-Security-Policy", "medium"),
    "strict-transport-security": ("Strict-Transport-Security (HSTS)", "medium"),
    "x-frame-options": ("X-Frame-Options", "medium"),
    "x-content-type-options": ("X-Content-Type-Options", "low"),
    "referrer-policy": ("Referrer-Policy", "low"),
    "permissions-policy": ("Permissions-Policy", "low"),
}


def grade(url: str, timeout: int = 15) -> list[dict]:
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, verify=False, headers=UA)
    except Exception as err:  # noqa: BLE001
        log.info("header check failed for %s: %s", url, err)
        return []

    h = {k.lower(): v for k, v in r.headers.items()}
    is_https = r.url.lower().startswith("https://")
    out: list[dict] = []

    for key, (label, sev) in _HEADERS.items():
        if key == "strict-transport-security" and not is_https:
            continue  # HSTS only meaningful over HTTPS
        if key not in h:
            out.append({"severity": sev, "check": label,
                        "issue": f"Missing {label} header", "url": r.url})

    if h.get("access-control-allow-origin", "").strip() == "*":
        out.append({"severity": "medium", "check": "CORS",
                    "issue": "Access-Control-Allow-Origin: * (any origin allowed)", "url": r.url})

    if "server" in h and any(c.isdigit() for c in h["server"]):
        out.append({"severity": "low", "check": "Server banner",
                    "issue": f"Server header leaks version: {h['server'][:60]}", "url": r.url})

    # Cookie flags (robust per-cookie inspection)
    for c in r.cookies:
        problems = []
        if is_https and not c.secure:
            problems.append("Secure")
        if not c.has_nonstandard_attr("HttpOnly") and not c.has_nonstandard_attr("httponly"):
            problems.append("HttpOnly")
        rest = {k.lower(): v for k, v in (c._rest or {}).items()}
        if "samesite" not in rest:
            problems.append("SameSite")
        if problems:
            out.append({"severity": "low", "check": "Cookie flags",
                        "issue": f"Cookie '{c.name}' missing {', '.join(problems)}", "url": r.url})

    return out


def grade_endpoints(urls: list[str], limit: int = 25) -> list[dict]:
    findings: list[dict] = []
    seen = set()
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        if len(seen) > limit:
            break
        findings += grade(u)
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: rank.get(f["severity"], 9))
    return findings
