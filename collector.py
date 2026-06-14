"""Cross-platform host inventory collection (Linux + Windows), standard library
only. Every collector is defensive: failures degrade to an empty result rather
than raising, and every external command runs under a timeout so a slow host
can never hang the agent. Read-only — nothing here changes host state."""
from __future__ import annotations

import getpass
import json
import platform
import socket
import subprocess
import sys

# Hard caps so a single host can never produce an unbounded check-in payload.
MAX_PACKAGES = 5000
MAX_SERVICES = 2000
MAX_PORTS = 2000
_CMD_TIMEOUT = 25


def _run(cmd: list[str], timeout: int = _CMD_TIMEOUT) -> str:
    """Run a command and return stdout (empty string on any failure)."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return out.stdout or ""
    except Exception:
        return ""


def _ps(script: str, timeout: int = _CMD_TIMEOUT) -> str:
    """Run a PowerShell snippet (Windows) and return stdout."""
    return _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout)


def _is_windows() -> bool:
    return platform.system().lower().startswith("win")


# ── identity ─────────────────────────────────────────────────────────────────
def host_identity() -> dict:
    node = platform.node() or socket.gethostname()
    info = {
        "hostname": node,
        "fqdn": socket.getfqdn(),
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "current_user": _safe(getpass.getuser),
    }
    if not _is_windows():
        info["distro"] = _linux_distro()
    return info


def _safe(fn):
    try:
        return fn()
    except Exception:
        return ""


def _linux_distro() -> str:
    try:
        data = {}
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                if "=" in line:
                    k, v = line.rstrip().split("=", 1)
                    data[k] = v.strip().strip('"')
        return data.get("PRETTY_NAME") or data.get("NAME", "")
    except Exception:
        return ""


# ── network ──────────────────────────────────────────────────────────────────
def ip_addresses() -> list[str]:
    addrs = set()
    try:
        for res in socket.getaddrinfo(socket.gethostname(), None):
            ip = res[4][0]
            if not ip.startswith("127.") and ip != "::1":
                addrs.add(ip)
    except Exception:
        pass
    return sorted(addrs)


def listening_ports() -> list[dict]:
    ports = []
    if _is_windows():
        raw = _run(["netstat", "-ano", "-p", "TCP"])
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].upper() == "TCP" and parts[3].upper() == "LISTENING":
                local = parts[1]
                port = local.rsplit(":", 1)[-1]
                ports.append({"proto": "tcp", "local": local, "port": port,
                              "pid": parts[-1] if parts[-1].isdigit() else ""})
    else:
        raw = _run(["ss", "-tulnH"]) or _run(["netstat", "-tuln"])
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0].lower()
            if "tcp" not in proto and "udp" not in proto:
                continue
            local = parts[4] if "tcp" in proto or "udp" in proto else ""
            # ss column order: Netid State Recv-Q Send-Q Local Peer
            local = parts[4] if len(parts) >= 5 else ""
            port = local.rsplit(":", 1)[-1] if ":" in local else local
            ports.append({"proto": "tcp" if "tcp" in proto else "udp",
                          "local": local, "port": port, "pid": ""})
    # de-dup by (proto, port)
    seen, out = set(), []
    for p in ports:
        key = (p["proto"], p["port"])
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
        if len(out) >= MAX_PORTS:
            break
    return out


# ── installed packages ───────────────────────────────────────────────────────
def installed_packages() -> list[dict]:
    pkgs = []
    if _is_windows():
        script = (
            "Get-ItemProperty "
            "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, "
            "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
            "-ErrorAction SilentlyContinue | Where-Object DisplayName | "
            "Select-Object DisplayName,DisplayVersion | ConvertTo-Json -Compress"
        )
        for item in _parse_json_list(_ps(script)):
            name = item.get("DisplayName")
            if name:
                pkgs.append({"name": name, "version": item.get("DisplayVersion") or ""})
    else:
        raw = _run(["dpkg-query", "-W", "-f=${Package} ${Version}\n"])
        if raw:
            for line in raw.splitlines():
                bits = line.split(" ", 1)
                if bits and bits[0]:
                    pkgs.append({"name": bits[0], "version": bits[1] if len(bits) > 1 else ""})
        else:
            raw = _run(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"])
            for line in raw.splitlines():
                bits = line.split(" ", 1)
                if bits and bits[0]:
                    pkgs.append({"name": bits[0], "version": bits[1] if len(bits) > 1 else ""})
    return pkgs[:MAX_PACKAGES]


# ── running services ─────────────────────────────────────────────────────────
def running_services() -> list[dict]:
    svcs = []
    if _is_windows():
        script = ("Get-Service | Where-Object {$_.Status -eq 'Running'} | "
                  "Select-Object Name,DisplayName | ConvertTo-Json -Compress")
        for item in _parse_json_list(_ps(script)):
            if item.get("Name"):
                svcs.append({"name": item["Name"], "display": item.get("DisplayName") or ""})
    else:
        raw = _run(["systemctl", "list-units", "--type=service", "--state=running",
                    "--no-legend", "--no-pager", "--plain"])
        for line in raw.splitlines():
            parts = line.split()
            if parts and parts[0].endswith(".service"):
                svcs.append({"name": parts[0], "display": " ".join(parts[4:]) if len(parts) > 4 else ""})
        if not svcs:  # SysV / non-systemd fallback
            raw = _run(["service", "--status-all"])
            for line in raw.splitlines():
                if "[ + ]" in line:
                    svcs.append({"name": line.split("]", 1)[-1].strip(), "display": ""})
    return svcs[:MAX_SERVICES]


# ── local users ──────────────────────────────────────────────────────────────
def local_users() -> list[str]:
    users = []
    if _is_windows():
        for item in _parse_json_list(_ps(
                "Get-LocalUser | Select-Object Name,Enabled | ConvertTo-Json -Compress")):
            name = item.get("Name")
            if name:
                users.append(name + ("" if item.get("Enabled", True) else " (disabled)"))
        if not users:
            for line in _run(["net", "user"]).splitlines():
                users.extend(w for w in line.split() if w and not w.startswith("-"))
    else:
        try:
            with open("/etc/passwd", encoding="utf-8") as fh:
                for line in fh:
                    parts = line.split(":")
                    if len(parts) >= 7 and ("sh" in parts[6] or "bash" in parts[6]):
                        users.append(parts[0])
        except Exception:
            pass
    return users[:500]


# ── patches / hotfixes ───────────────────────────────────────────────────────
def patches() -> dict:
    if _is_windows():
        hot = []
        for item in _parse_json_list(_ps(
                "Get-HotFix | Select-Object HotFixID,InstalledOn | ConvertTo-Json -Compress")):
            if item.get("HotFixID"):
                hot.append({"id": item["HotFixID"], "installed": str(item.get("InstalledOn") or "")})
        return {"hotfixes": hot[:1000]}
    # Linux: count of available upgrades (best-effort, fast paths only)
    raw = _run(["apt-get", "-s", "upgrade"], timeout=30)
    if raw:
        n = sum(1 for ln in raw.splitlines() if ln.startswith("Inst "))
        return {"available_updates": n}
    raw = _run(["dnf", "-q", "check-update"], timeout=30)
    if raw:
        n = sum(1 for ln in raw.splitlines() if ln and not ln.startswith(("Last", "Obsoleting")))
        return {"available_updates": n}
    return {}


def _parse_json_list(text: str) -> list[dict]:
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except Exception:
        return []
    if isinstance(data, dict):
        return [data]
    return [d for d in data if isinstance(d, dict)]


# ── top-level ────────────────────────────────────────────────────────────────
def collect() -> dict:
    """Gather the full host inventory as a JSON-serialisable dict."""
    ident = host_identity()
    pkgs = installed_packages()
    svcs = running_services()
    ports = listening_ports()
    return {
        "schema": 1,
        "identity": ident,
        "ip_addresses": ip_addresses(),
        "listening_ports": ports,
        "packages": pkgs,
        "services": svcs,
        "users": local_users(),
        "patches": patches(),
        "summary": {
            "packages": len(pkgs),
            "services": len(svcs),
            "listening_ports": len(ports),
        },
    }


if __name__ == "__main__":
    json.dump(collect(), sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
