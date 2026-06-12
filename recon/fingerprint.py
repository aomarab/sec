"""Passive web-technology fingerprinting: fetch a host over HTTP/HTTPS and
identify server, CDN, CMS, framework, and analytics from headers + HTML. No
exploitation — a single GET to the homepage, like a browser."""
from __future__ import annotations

import logging
import re

import requests

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

log = logging.getLogger("recon.fingerprint")

_UA = {"User-Agent": "Mozilla/5.0 (compatible; recon-bot/1.0)"}

# (label, header-substring or None, body-regex or None)
_CDN = [
    ("Cloudflare", "cf-ray", r"cloudflare"),
    ("Akamai", "akamai", None),
    ("Fastly", "fastly", None),
    ("Amazon CloudFront", "x-amz-cf-id", None),
    ("Azure CDN/Front Door", "x-azure-ref", None),
    ("Sucuri", "x-sucuri-id", None),
    ("Imperva/Incapsula", "x-iinfo", None),
]
_TECH = [
    ("WordPress", r"wp-content|wp-includes|/wp-json"),
    ("Drupal", r"Drupal\.settings|sites/default/files|/sites/all/"),
    ("Joomla", r"/media/jui/|Joomla!"),
    ("Shopify", r"cdn\.shopify\.com|Shopify\.theme"),
    ("Wix", r"static\.wixstatic\.com|wix\.com"),
    ("Squarespace", r"squarespace"),
    ("Magento", r"Mage\.Cookies|/static/version\d"),
    ("Next.js", r"__NEXT_DATA__|/_next/static"),
    ("Nuxt.js", r"__NUXT__|/_nuxt/"),
    ("React", r"data-reactroot|react(?:-dom)?\.production"),
    ("Angular", r"ng-version|angular(?:\.min)?\.js"),
    ("Vue.js", r"data-v-[0-9a-f]{8}|vue(?:\.min)?\.js"),
    ("Laravel", r"laravel_session|/vendor/laravel"),
    ("Django", r"csrfmiddlewaretoken|__admin__"),
    ("ASP.NET", r"__VIEWSTATE|asp\.net"),
]
_ANALYTICS = [
    ("Google Analytics / GTM", r"googletagmanager\.com|google-analytics\.com|gtag\("),
    ("Facebook Pixel", r"connect\.facebook\.net|fbq\("),
    ("Hotjar", r"static\.hotjar\.com|hjid"),
    ("Segment", r"cdn\.segment\.com|analytics\.load"),
    ("Matomo/Piwik", r"matomo\.js|piwik\.js"),
]


def fetch_tech(host: str, timeout: int = 8) -> dict | None:
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{host}", timeout=timeout, allow_redirects=True,
                             headers=_UA, verify=False)
            return _analyze(host, r)
        except requests.RequestException:
            continue
    return None


def _analyze(host: str, r) -> dict:
    headers = {k.lower(): v for k, v in r.headers.items()}
    hdr_blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    body = (r.text or "")[:200000]

    cdn = next((label for label, hkey, brx in _CDN
                if (hkey and hkey in hdr_blob) or (brx and re.search(brx, hdr_blob))), "")
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")

    techs = [label for label, rx in _TECH if re.search(rx, body, re.I)]
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if gen:
        techs.append(gen.group(1).strip())
    analytics = [label for label, rx in _ANALYTICS if re.search(rx, body, re.I)]
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)

    return {
        "host": host, "status": r.status_code, "url": r.url,
        "title": (title.group(1).strip()[:80] if title else ""),
        "server": server, "powered_by": powered, "cdn": cdn,
        "tech": sorted(set(techs)), "analytics": sorted(set(analytics)),
    }
