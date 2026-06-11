"""Network discovery: target expansion, threaded TCP connect scan, banner
grabbing, and an optional nmap wrapper. Pure-Python core (no dependencies);
nmap is used only when present and requested."""
from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET

log = logging.getLogger("scan.scanner")

# port -> service name
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    514: "syslog", 587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1025: "msrpc", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3306: "mysql",
    3389: "rdp", 4444: "metasploit", 5000: "http-alt", 5432: "postgresql",
    5601: "kibana", 5900: "vnc", 5985: "winrm", 5986: "winrm-tls", 6379: "redis",
    7001: "weblogic", 8000: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9200: "elasticsearch",
    9300: "elasticsearch", 11211: "memcached", 27017: "mongodb", 6443: "kubernetes",
}

# Basic mode: a curated set of high-signal ports.
TOP_BASIC = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 389, 443, 445,
             587, 993, 995, 1433, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 27017]

MAX_HOSTS = 256
MAX_PORTS = 2048


def expand_targets(target: str, max_hosts: int = MAX_HOSTS) -> list[str]:
    target = (target or "").strip()
    if not target:
        raise ValueError("No target supplied.")
    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
    else:
        try:
            ipaddress.ip_address(target)
            hosts = [target]
        except ValueError:
            hosts = [socket.gethostbyname(target)]  # resolve hostname
    if len(hosts) > max_hosts:
        raise ValueError(f"Target expands to {len(hosts)} hosts; the limit is "
                         f"{max_hosts}. Use a smaller range.")
    return hosts


def parse_ports(spec: str, default: list[int]) -> list[int]:
    if not spec or not spec.strip():
        return default
    out: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            if a.strip().isdigit() and b.strip().isdigit():
                out.update(range(int(a), int(b) + 1))
        elif part.isdigit():
            out.add(int(part))
    ports = sorted(p for p in out if 0 < p < 65536)
    if len(ports) > MAX_PORTS:
        raise ValueError(f"Too many ports ({len(ports)}); the limit is {MAX_PORTS}.")
    return ports or default


def _grab_banner(ip: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in (80, 8080, 8000, 8081, 8888, 3000, 5000, 9000):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            data = s.recv(256)
            text = data.decode("latin-1", "replace")
            # For HTTP, surface the Server header if present.
            m = re.search(r"(?im)^server:\s*(.+)$", text)
            if m:
                return m.group(1).strip()[:200]
            return text.strip().splitlines()[0][:200] if text.strip() else ""
    except Exception:
        return ""


def _scan_port(ip: str, port: int, timeout: float, grab: bool) -> dict | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            pass
    except Exception:
        return None
    banner = _grab_banner(ip, port, timeout) if grab else ""
    return {"port": port, "service": COMMON_PORTS.get(port, "unknown"), "banner": banner}


def tcp_scan(hosts: list[str], ports: list[int], timeout: float = 0.7,
             workers: int = 200, grab: bool = True, progress=None) -> list[dict]:
    tasks = [(h, p) for h in hosts for p in ports]
    open_by_host: dict[str, list[dict]] = {}
    done = 0
    total = len(tasks)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, 400)) as ex:
        futs = {ex.submit(_scan_port, h, p, timeout, grab): h for h, p in tasks}
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            r = fut.result()
            if r:
                open_by_host.setdefault(futs[fut], []).append(r)
            if progress and done % 250 == 0:
                progress(done, total)
    if progress:
        progress(total, total)
    return [{"host": h, "os": "", "open": sorted(open_by_host.get(h, []), key=lambda x: x["port"])}
            for h in hosts]


# ── nmap (optional) ──────────────────────────────────────────────────────────
def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def run_nmap(target: str, version: bool = True, vuln: bool = False,
             os_detect: bool = False, ports: str = "", top_ports: int = 100,
             timing: str = "4") -> tuple[list[dict], list[str], str]:
    """Return (results, vuln_findings, stderr). results mirror tcp_scan shape with
    added 'product'/'version'; vuln_findings are NSE 'vuln' script output lines."""
    if not nmap_available():
        raise RuntimeError("nmap is not installed on this host.")
    args = ["nmap", "-oX", "-", "-T" + str(timing), "-Pn"]
    if version:
        args.append("-sV")
    if os_detect:
        args.append("-O")
    if vuln:
        args += ["--script", "vuln"]
    if ports:
        args += ["-p", ports]
    else:
        args += ["--top-ports", str(top_ports)]
    args.append(target)
    log.info("Running nmap: %s", " ".join(args))
    proc = subprocess.run(args, capture_output=True, text=True, timeout=1800)
    try:
        results, findings = _parse_nmap_xml(proc.stdout)
    except ET.ParseError:
        results, findings = [], []
    return results, findings, proc.stderr.strip()


def _parse_nmap_xml(xml_text: str) -> tuple[list[dict], list[str]]:
    root = ET.fromstring(xml_text)
    results, findings = [], []
    for host in root.findall("host"):
        addr_el = host.find("address")
        ip = addr_el.get("addr") if addr_el is not None else "?"
        open_ports = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            service = svc.get("name") if svc is not None else "unknown"
            product = (svc.get("product", "") + " " + svc.get("version", "")).strip() if svc is not None else ""
            open_ports.append({"port": int(port.get("portid")), "service": service,
                               "banner": product})
            for script in port.findall("script"):
                out = (script.get("output") or "").strip()
                if out and script.get("id", "").lower() not in ("",):
                    findings.append(f"{ip}:{port.get('portid')} [{script.get('id')}] "
                                    + out.replace("\n", " ")[:300])
        for script in host.findall("./hostscript/script"):
            out = (script.get("output") or "").strip()
            if out:
                findings.append(f"{ip} [{script.get('id')}] " + out.replace("\n", " ")[:300])
        osmatch = host.find("./os/osmatch")
        os_name = osmatch.get("name") if osmatch is not None else ""
        results.append({"host": ip, "os": os_name,
                        "open": sorted(open_ports, key=lambda x: x["port"])})
    return results, findings


# ── product extraction for CVE correlation ───────────────────────────────────
_PROD_RE = re.compile(r"([A-Za-z][A-Za-z0-9 _.+-]{1,30}?)[ /]v?(\d+(?:\.\d+){1,3})")


def extract_products(results: list[dict]) -> list[str]:
    """Heuristically extract 'product version' strings from banners for CVE lookup."""
    seen: set[str] = set()
    out: list[str] = []
    for host in results:
        for p in host["open"]:
            banner = (p.get("banner") or "").strip()
            if not banner:
                continue
            m = _PROD_RE.search(banner)
            if m:
                cand = f"{m.group(1).strip()} {m.group(2)}".strip()
                key = cand.lower()
                if key not in seen:
                    seen.add(key)
                    out.append(cand)
    return out[:6]
