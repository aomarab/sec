"""Map findings to the OWASP Top 10 (2021) via keyword rules.

Lightweight, deterministic categorisation so the Findings view and reports can
show OWASP coverage and a per-category breakdown. Best-effort — falls back to a
sensible default when nothing matches."""
from __future__ import annotations

import re

# OWASP Top 10 2021 codes -> title
OWASP = {
    "A01": "A01 Broken Access Control",
    "A02": "A02 Cryptographic Failures",
    "A03": "A03 Injection",
    "A04": "A04 Insecure Design",
    "A05": "A05 Security Misconfiguration",
    "A06": "A06 Vulnerable & Outdated Components",
    "A07": "A07 Identification & Authentication Failures",
    "A08": "A08 Software & Data Integrity Failures",
    "A09": "A09 Security Logging & Monitoring Failures",
    "A10": "A10 Server-Side Request Forgery (SSRF)",
}

# (regex over "title + source", OWASP code) — first match wins, in order.
_RULES = [
    (r"sql\s*inject|sqli|command inject|ldap inject|xss|cross.site script|template inject", "A03"),
    (r"ssrf|server.side request", "A10"),
    (r"cors|arbitrary origin|acao|open redirect|idor|directory traversal|path traversal|access control|forbidden|unauth", "A01"),
    (r"\btls\b|\bssl\b|cipher|certificate|cert |weak crypto|rc4|beast|heartbleed|secret|private key|api key|access key|exposed (?:key|secret|token)|password|token|hsts", "A02"),
    (r"cve-|outdated|vulnerable (?:js|library|component|version)|retire\.js|end.of.life|eol", "A06"),
    (r"mfa|authentication|login|credential|default password|jwt|session|user enumeration", "A07"),
    (r"missing .*header|x-frame|content-security|misconfig|directory listing|exposed (?:panel|config|\.git|\.env|backup)|debug|server-status|phpinfo|open port|rdp|telnet|ftp|smb|redis|database exposed", "A05"),
    (r"dependency|integrity|supply chain|unsigned", "A08"),
    (r"logging|monitoring|audit", "A09"),
]


def map_owasp(title: str, source: str = "") -> str:
    """Return an OWASP code (e.g. 'A05') for a finding."""
    hay = f"{title} {source}".lower()
    for pat, code in _RULES:
        if re.search(pat, hay):
            return code
    return "A05"  # default: security misconfiguration


def summarize(items: list[dict]) -> list[dict]:
    """Count findings per OWASP category. items: [{title, source?}]."""
    counts: dict[str, int] = {}
    for it in items:
        code = it.get("owasp") or map_owasp(it.get("title", ""), it.get("source", ""))
        counts[code] = counts.get(code, 0) + 1
    return [{"code": c, "title": OWASP[c], "count": counts.get(c, 0)} for c in OWASP if counts.get(c)]
