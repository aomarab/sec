"""Subdomain-takeover detection (passive fingerprints).

For each live host, fetch the page and match the response against well-known
'unclaimed service' fingerprints (GitHub Pages, S3, Heroku, Azure, etc.). A match
means the subdomain points at a service that no longer hosts it — a takeover
candidate. Detection only; never claims/registers anything."""
from __future__ import annotations

import logging

import requests

log = logging.getLogger("recon.takeover")

UA = {"User-Agent": "threat-intel-briefing-agent/1.0 (takeover check)"}

# service -> response fingerprints that indicate an unclaimed/danging target.
FINGERPRINTS = [
    ("GitHub Pages", ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"]),
    ("Amazon S3", ["NoSuchBucket", "The specified bucket does not exist"]),
    ("Heroku", ["No such app", "herokucdn.com/error-pages/no-such-app.html"]),
    ("Azure", ["404 Web Site not found", "Error 404 - Web app not found"]),
    ("Fastly", ["Fastly error: unknown domain"]),
    ("Shopify", ["Sorry, this shop is currently unavailable"]),
    ("Pantheon", ["The gods are wise, but do not know of the site which you seek"]),
    ("Bitbucket", ["Repository not found"]),
    ("Surge.sh", ["project not found"]),
    ("Tumblr", ["Whatever you were looking for doesn't currently exist at this address"]),
    ("Unbounce", ["The requested URL was not found on this server"]),
    ("Ghost", ["The thing you were looking for is no longer here"]),
    ("Cargo", ["404 Not Found", "If you're moving your domain away from Cargo"]),
    ("Webflow", ["The page you are looking for doesn't exist or has been moved"]),
    ("Wordpress", ["Do you want to register"]),
    ("Worksites", ["Hello! Sorry, but the website you're looking for doesn't exist"]),
]


def check_host(host: str, timeout: int = 12) -> dict | None:
    """Return a takeover finding for host, or None."""
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{host}", timeout=timeout, verify=False,
                             allow_redirects=True, headers=UA)
        except Exception:
            continue
        body = r.text or ""
        for service, sigs in FINGERPRINTS:
            if any(sig in body for sig in sigs):
                return {"host": host, "service": service, "severity": "high",
                        "title": f"Possible subdomain takeover — unclaimed {service} target"}
        return None  # got a response; no fingerprint matched
    return None


def scan_hosts(hosts: list[str], limit: int = 40, progress=None) -> list[dict]:
    out = []
    for i, h in enumerate(hosts[:limit]):
        f = check_host(h)
        if f:
            out.append(f)
        if progress:
            progress(i, min(len(hosts), limit))
    return out
