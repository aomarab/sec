"""Shared HTTP helper with a sane timeout, retries, and a descriptive UA."""
from __future__ import annotations

import time

import requests

_UA = "threat-intel-briefing-agent/1.0 (+https://github.com/)"
_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": _UA, "Accept": "application/json"})


def get_json(url: str, *, params: dict | None = None, headers: dict | None = None,
             timeout: int = 30, retries: int = 2) -> dict | list:
    last_err: Exception | None = None
    for attempt in range(retries + 1):
        try:
            resp = _SESSION.get(url, params=params, headers=headers, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as err:
            last_err = err
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"GET {url} failed after {retries + 1} attempts: {last_err}")
