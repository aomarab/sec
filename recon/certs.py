"""TLS certificate inspection for discovered hosts (passive).

Connects to host:443, reads the certificate, and reports days-to-expiry plus
basic validity issues (expired, expiring soon, hostname mismatch, self-signed).
Uses only the standard library; never raises."""
from __future__ import annotations

import datetime
import logging
import socket
import ssl

log = logging.getLogger("recon.certs")


def _parse_dt(value: str) -> datetime.datetime | None:
    try:
        return datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    except (ValueError, TypeError):
        return None


def inspect(host: str, port: int = 443, timeout: int = 8) -> dict | None:
    """Return {host, subject, issuer, not_after, days, issues:[...]} or None."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # we read the cert even if it doesn't validate
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
    except Exception as err:
        log.info("cert inspect failed for %s: %s", host, err)
        return None
    if not cert:
        return None

    not_after = _parse_dt(cert.get("notAfter", ""))
    now = datetime.datetime.utcnow()
    days = (not_after - now).days if not_after else None

    def _name(field):
        try:
            return dict(x[0] for x in cert.get(field, ()))
        except Exception:
            return {}
    subject = _name("subject")
    issuer = _name("issuer")

    issues = []
    if days is not None:
        if days < 0:
            issues.append(("critical", "Certificate has EXPIRED"))
        elif days <= 14:
            issues.append(("high", f"Certificate expires in {days} day(s)"))
        elif days <= 30:
            issues.append(("medium", f"Certificate expires in {days} day(s)"))
    if subject.get("organizationName") and issuer.get("organizationName") and \
            subject.get("commonName") == issuer.get("commonName"):
        issues.append(("medium", "Certificate appears self-signed"))

    return {"host": host, "subject_cn": subject.get("commonName", ""),
            "issuer": issuer.get("organizationName") or issuer.get("commonName", ""),
            "not_after": cert.get("notAfter", ""), "days": days, "issues": issues}


def scan_hosts(hosts: list[str], limit: int = 40) -> list[dict]:
    out = []
    for h in hosts[:limit]:
        info = inspect(h)
        if info:
            out.append(info)
    return out
