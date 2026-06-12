"""Native web vulnerability checks — no external binary.

Detection only (it sends a small number of benign probe requests; it never
exploits, brute-forces, or attempts access):
  • reflective CORS misconfiguration,
  • open redirect on common redirect parameters (benign external value),
  • JWT exposure / alg=none,
  • exposed secrets (API keys, tokens, private keys) in the page body and
    linked JavaScript.

Returns normalized findings; never raises."""
from __future__ import annotations

import logging
import re

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("scan.webchecks")

UA = {"User-Agent": "threat-intel-briefing-agent/1.0 (web checks)"}
REDIRECT_PARAMS = ("next", "url", "redirect", "redirect_uri", "return", "returnUrl",
                   "dest", "destination", "continue", "r", "u")
_CANARY = "example-redirect-test.org"

# Exposed-secret signatures (regex, label, severity).
_SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID", "high"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API key", "high"),
    (r"xox[baprs]-[0-9A-Za-z\-]{10,48}", "Slack token", "high"),
    (r"gh[pousr]_[0-9A-Za-z]{36,}", "GitHub token", "high"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key", "critical"),
    (r"sk_live_[0-9A-Za-z]{24,}", "Stripe live secret key", "critical"),
    (r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", "JWT", "low"),
    (r"(?i)(?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
     "Hard-coded credential", "medium"),
]
_JS_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)


def _get(url, **kw):
    return requests.get(url, timeout=kw.pop("timeout", 15), allow_redirects=False,
                        verify=False, headers=UA, **kw)


def _cors(url: str) -> list[dict]:
    try:
        r = requests.get(url, timeout=15, verify=False,
                         headers={**UA, "Origin": "https://" + _CANARY})
    except Exception:
        return []
    h = {k.lower(): v for k, v in r.headers.items()}
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower() == "true"
    if acao == "https://" + _CANARY:
        return [{"severity": "high" if acac else "medium", "check": "CORS",
                 "name": f"Reflects arbitrary Origin in ACAO{' with credentials' if acac else ''}",
                 "host": url}]
    if acao == "*" and acac:
        return [{"severity": "high", "check": "CORS",
                 "name": "ACAO '*' with Allow-Credentials true", "host": url}]
    return []


def _open_redirect(url: str) -> list[dict]:
    sep = "&" if "?" in url else "?"
    for p in REDIRECT_PARAMS:
        try:
            r = _get(f"{url}{sep}{p}=https://{_CANARY}/")
        except Exception:
            continue
        loc = r.headers.get("Location", "").strip()
        # redirect whose target host is our external canary = open redirect
        if r.status_code in (301, 302, 303, 307, 308) and loc.startswith(
                ("http://", "https://", "//")) and _CANARY in loc:
            return [{"severity": "medium", "check": "Open redirect",
                     "name": f"Parameter '{p}' redirects off-site to an attacker-supplied URL",
                     "host": url}]
    return []


def _jwt_and_secrets(url: str) -> list[dict]:
    out = []
    try:
        r = requests.get(url, timeout=15, allow_redirects=True, verify=False, headers=UA)
    except Exception:
        return []
    body = r.text or ""

    # JWT in cookies / auth headers → alg=none is critical
    import base64
    for jwt in set(re.findall(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]*", body)):
        try:
            hdr = base64.urlsafe_b64decode(jwt.split(".")[0] + "===").decode("utf-8", "ignore")
            if '"alg"' in hdr and '"none"' in hdr.lower():
                out.append({"severity": "high", "check": "JWT",
                            "name": "JWT with alg=none accepted/exposed", "host": url})
                break
        except Exception:
            continue

    # Exposed secrets in body + a few linked JS files
    targets = [("page", body)]
    for src in _JS_SRC.findall(body)[:5]:
        js_url = src if src.startswith("http") else requests.compat.urljoin(r.url, src)
        try:
            targets.append((js_url, requests.get(js_url, timeout=12, verify=False, headers=UA).text))
        except Exception:
            continue
    seen = set()
    for where, text in targets:
        for pat, label, sev in _SECRET_PATTERNS:
            if re.search(pat, text or ""):
                key = (label, where)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"severity": sev, "check": "Exposed secret",
                            "name": f"{label} found in {where if where == 'page' else where.split('/')[-1]}",
                            "host": url})
    return out


def run(url: str) -> list[dict]:
    findings = []
    try:
        findings += _cors(url)
        findings += _open_redirect(url)
        findings += _jwt_and_secrets(url)
    except Exception as err:  # noqa: BLE001
        log.info("webchecks failed for %s: %s", url, err)
    return findings


def run_endpoints(urls: list[str], limit: int = 15) -> list[dict]:
    out, seen = [], set()
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        if len(seen) > limit:
            break
        out += run(u)
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out.sort(key=lambda f: rank.get(f["severity"], 9))
    return out
