"""Lightweight, unauthenticated security checks run against discovered open
ports. No credentials, no exploitation — only safe protocol probes that a
defender would run against their own assets. Each check returns findings:
{host, port, severity, title, detail, remediation}."""
from __future__ import annotations

import logging
import socket
import ssl

log = logging.getLogger("scan.checks")

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_TLS_PORTS = {443, 8443, 993, 995, 465, 636, 990, 989, 5986, 9443}


def _finding(host, port, severity, title, detail, remediation):
    return {"host": host, "port": port, "severity": severity, "title": title,
            "detail": detail, "remediation": remediation}


def run_checks(results: list[dict], timeout: float = 4.0) -> list[dict]:
    findings: list[dict] = []
    for hostrec in results:
        host = hostrec["host"]
        for p in hostrec["open"]:
            port, svc = p["port"], p.get("service", "")
            try:
                if port in _TLS_PORTS or svc in ("https", "https-alt", "imaps", "pop3s", "smtps", "ldaps"):
                    findings += _tls_check(host, port, timeout)
                if port == 21 or svc == "ftp":
                    f = _ftp_anon(host, port, timeout)
                    if f:
                        findings.append(f)
                if port == 6379 or svc == "redis":
                    f = _redis_noauth(host, port, timeout)
                    if f:
                        findings.append(f)
                if port == 23 or svc == "telnet":
                    findings.append(_finding(host, port, "medium", "Telnet exposed (cleartext)",
                        "Telnet transmits credentials and data in plaintext.",
                        "Disable Telnet; use SSH instead."))
                if port in (445, 139):
                    findings.append(_finding(host, port, "medium", "SMB/NetBIOS exposed",
                        "SMB is reachable over the network.",
                        "Ensure SMBv1 is disabled, MS17-010 (EternalBlue) is patched, and SMB is "
                        "restricted to trusted networks. Consider nmap --script smb-vuln* to verify."))
                if port == 3389 or svc == "rdp":
                    findings.append(_finding(host, port, "medium", "RDP exposed",
                        "Remote Desktop is reachable over the network.",
                        "Require Network Level Authentication, restrict by firewall/VPN, and enforce MFA."))
                if port in (9200, 9300):
                    findings.append(_finding(host, port, "high", "Elasticsearch exposed",
                        "Elasticsearch is reachable; these are frequently left unauthenticated.",
                        "Enable authentication (X-Pack/Security) and bind to localhost or a trusted network."))
                if port == 11211:
                    findings.append(_finding(host, port, "high", "Memcached exposed",
                        "Memcached is reachable and is commonly unauthenticated (also a DDoS amplifier).",
                        "Bind to localhost, enable SASL auth, and block UDP/11211 at the firewall."))
                if port == 27017 or svc == "mongodb":
                    findings.append(_finding(host, port, "high", "MongoDB exposed",
                        "MongoDB is reachable; older/default deployments allow unauthenticated access.",
                        "Enable authorization, create admin users, and bind to a trusted interface."))
                if port in (3306, 5432, 1433):
                    findings.append(_finding(host, port, "medium", f"Database exposed ({svc or port})",
                        "A database service is reachable over the network.",
                        "Restrict to application hosts via firewall, enforce strong auth and TLS."))
            except Exception as err:
                log.info("check error %s:%s -> %s", host, port, err)
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f["severity"], 9), f["host"], f["port"]))
    return findings


def _tls_check(host: str, port: int, timeout: float) -> list[dict]:
    out: list[dict] = []
    # 1) Trust/expiry: verified handshake (hostname check off to avoid IP noise).
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
        not_after = cert.get("notAfter") if cert else None
        if not_after:
            import datetime
            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days = (exp - datetime.datetime.utcnow()).days
            if days < 0:
                out.append(_finding(host, port, "high", "Expired TLS certificate",
                    f"Certificate expired {abs(days)} day(s) ago ({not_after}).",
                    "Renew and deploy a valid certificate."))
            elif days < 30:
                out.append(_finding(host, port, "low", "TLS certificate expiring soon",
                    f"Certificate expires in {days} day(s) ({not_after}).",
                    "Renew the certificate before it expires."))
    except ssl.SSLCertVerificationError as err:
        out.append(_finding(host, port, "medium", "Untrusted / self-signed TLS certificate",
            f"Certificate did not validate: {getattr(err, 'reason', err)}.",
            "Install a certificate from a trusted CA; avoid self-signed certs in production."))
    except Exception as err:
        log.info("tls verify %s:%s -> %s", host, port, err)

    # 2) Weak protocol versions still enabled (TLS 1.0 / 1.1).
    for name, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        if _supports_protocol(host, port, ver, timeout):
            out.append(_finding(host, port, "medium", f"Weak TLS protocol enabled ({name})",
                f"The server negotiated {name}, which is deprecated and insecure.",
                "Disable TLS 1.0/1.1; require TLS 1.2 or higher."))
    return out


def _supports_protocol(host, port, version, timeout) -> bool:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                return True
    except Exception:
        return False


def _ftp_anon(host: str, port: int, timeout: float):
    import ftplib
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=timeout)
        ftp.login("anonymous", "anonymous@example.com")
        ftp.quit()
        return _finding(host, port, "high", "Anonymous FTP access allowed",
            "The FTP server accepted an anonymous login.",
            "Disable anonymous FTP, or replace FTP with SFTP/FTPS and require authentication.")
    except Exception:
        return None


def _redis_noauth(host: str, port: int, timeout: float):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"PING\r\n")
            resp = s.recv(64)
        if b"PONG" in resp:
            return _finding(host, port, "critical", "Redis accessible without authentication",
                "The Redis server responded to PING without requiring a password.",
                "Set 'requirepass', enable protected-mode, and bind to localhost / a trusted network.")
    except Exception:
        return None
    return None


def checks_table_markdown(findings: list[dict]) -> str:
    if not findings:
        return ("## Security Checks\n\n_No issues were flagged by the unauthenticated "
                "checks. This is not a guarantee of security — consider an authenticated scan._")
    out = ["## Security Checks", "",
           "| Host | Port | Severity | Finding | Remediation |",
           "|------|------|----------|---------|-------------|"]
    for f in findings:
        out.append(f"| `{f['host']}` | {f['port']} | {f['severity'].title()} | "
                   f"**{f['title']}** — {f['detail']} | {f['remediation']} |")
    return "\n".join(out)
