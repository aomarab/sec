"""IP intelligence: ASN, ISP/hosting org, geolocation, and reverse DNS for a set
of IPs via the free ip-api.com batch endpoint (no key; rate-limited)."""
from __future__ import annotations

import logging

import requests

log = logging.getLogger("recon.ipintel")

_FIELDS = "query,as,isp,org,country,city,reverse,status"


def ip_intel(ips: list[str], timeout: int = 25) -> dict[str, dict]:
    out: dict[str, dict] = {}
    ips = list(dict.fromkeys(ips))  # de-dupe, keep order
    for i in range(0, len(ips), 100):  # batch endpoint allows up to 100 per call
        chunk = ips[i:i + 100]
        try:
            resp = requests.post(
                "http://ip-api.com/batch",
                params={"fields": _FIELDS},
                json=[{"query": ip} for ip in chunk],
                timeout=timeout)
            resp.raise_for_status()
            for item in resp.json():
                if item.get("status") == "success":
                    geo = ", ".join(p for p in (item.get("city"), item.get("country")) if p)
                    out[item["query"]] = {
                        "asn": item.get("as", ""), "isp": item.get("isp", ""),
                        "org": item.get("org", ""), "geo": geo,
                        "reverse": item.get("reverse", ""),
                    }
        except Exception as err:
            log.info("ip-api batch failed: %s", err)
    return out
