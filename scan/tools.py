"""Optional external assessment tools — detection/recon grade only.

Wrappers for masscan (fast port discovery), nuclei (template-based vulnerability
and misconfiguration DETECTION), and testssl.sh (TLS configuration assessment).
Every wrapper:
  • checks the binary is present (graceful no-op otherwise),
  • runs against the caller-supplied authorized target only,
  • enforces a timeout, and never raises — failures return an empty list.

These tools detect and report; they do NOT exploit, brute-force, or attack."""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile

log = logging.getLogger("scan.tools")


def _bin(*names: str) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def available() -> dict:
    return {"masscan": bool(_bin("masscan")),
            "nuclei": bool(_bin("nuclei")),
            "testssl": bool(_bin("testssl.sh", "testssl")),
            "nikto": bool(_bin("nikto")),
            "wapiti": bool(_bin("wapiti")),
            "subfinder": bool(_bin("subfinder")),
            "ffuf": bool(_bin("ffuf")),
            "wpscan": bool(_bin("wpscan")),
            "droopescan": bool(_bin("droopescan")),
            "sqlmap": bool(_bin("sqlmap")),
            "amass": bool(_bin("amass")),
            "dnsx": bool(_bin("dnsx")),
            "httpx": bool(_bin("httpx")),
            "gau": bool(_bin("gau", "waybackurls")),
            "zap": bool(os.getenv("ZAP_API_URL") or _bin("zap-baseline.py", "zap.sh")),
            "retire": bool(_bin("retire")),
            "trivy": bool(_bin("trivy")),
            "gitleaks": bool(_bin("gitleaks"))}


def _stdin_list_tool(exe_names, args, items, timeout):
    """Run a tool that reads newline-separated items on stdin; return stdout."""
    exe = _bin(*exe_names)
    if not exe or not items:
        return ""
    try:
        proc = subprocess.run([exe, *args], input="\n".join(items),
                              capture_output=True, text=True, timeout=timeout)
        return proc.stdout
    except (subprocess.TimeoutExpired, OSError) as err:
        log.info("%s failed: %s", exe_names[0], err)
        return ""


def run_dnsx(hosts: list[str], timeout: int = 240) -> list[dict]:
    """Fast bulk DNS resolution (passive). Returns [{host, ips}]."""
    out_text = _stdin_list_tool(["dnsx"], ["-silent", "-json", "-a"], hosts, timeout)
    rows = []
    for line in out_text.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        ips = d.get("a") or []
        if d.get("host") and ips:
            rows.append({"host": d["host"], "ips": ips})
    return rows


def run_httpx(hosts: list[str], timeout: int = 300) -> list[dict]:
    """Probe hosts for live web services (passive triage). Returns findings."""
    out_text = _stdin_list_tool(
        ["httpx"], ["-silent", "-json", "-title", "-web-server", "-tech-detect", "-status-code"],
        hosts, timeout)
    rows = []
    for line in out_text.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        rows.append({"url": d.get("url", ""), "status": d.get("status_code") or d.get("status-code"),
                     "title": (d.get("title") or "")[:80], "server": d.get("webserver", ""),
                     "tech": ", ".join(d.get("tech", []) or [])[:120]})
    rows.sort(key=lambda r: r.get("status") or 999)
    return rows


def run_urls(domain: str, timeout: int = 240, limit: int = 3000) -> list[str]:
    """Historical/known URLs for a domain (passive — gau or waybackurls)."""
    exe = _bin("gau")
    if exe:
        try:
            proc = subprocess.run([exe, "--subs", "--threads", "5", domain],
                                  capture_output=True, text=True, timeout=timeout)
            urls = proc.stdout
        except (subprocess.TimeoutExpired, OSError) as err:
            log.info("gau failed: %s", err)
            urls = ""
    else:
        urls = _stdin_list_tool(["waybackurls"], [], [domain], timeout)
    seen, out = set(), []
    for u in urls.splitlines():
        u = u.strip()
        if u and u not in seen:
            seen.add(u)
            out.append(u)
        if len(out) >= limit:
            break
    return out


def run_amass(domain: str, timeout: int = 600) -> list[str]:
    """Passive OSINT subdomain enumeration (amass enum -passive). No active
    probing of the target. Returns sorted subdomains; [] if unavailable."""
    import re
    exe = _bin("amass")
    if not exe or not domain:
        return []
    try:
        proc = subprocess.run([exe, "enum", "-passive", "-d", domain],
                              capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as err:
        log.info("amass failed: %s", err)
        return []
    # Version-robust: extract any token ending in the target domain from output.
    names = set(re.findall(r"[a-z0-9][a-z0-9.\-]*\." + re.escape(domain.lower()),
                           proc.stdout.lower()))
    return sorted(names)


# Small built-in wordlist for content discovery (no SecLists dependency).
DIR_WORDLIST = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "phpmyadmin",
    "config", "config.php", "configuration", ".env", ".git/HEAD", ".git/config",
    "backup", "backups", "backup.zip", "backup.sql", "db.sql", "dump.sql",
    "old", "test", "dev", "staging", "tmp", "temp", "uploads", "files",
    "api", "api/v1", "swagger", "swagger.json", "openapi.json", "graphql",
    "actuator", "actuator/health", "server-status", "phpinfo.php", "info.php",
    "robots.txt", ".htaccess", "web.config", "console", "debug", "status",
    "user", "users", "account", "dashboard", "portal", "private", "secret",
]


# ── masscan: fast port discovery ──────────────────────────────────────────────
def masscan_ports(target: str, ports: str = "1-1024", rate: str = "1000",
                  timeout: int = 300) -> list[dict]:
    """Return [{host, port}] of open TCP ports found by masscan. Needs raw-socket
    privileges (root / CAP_NET_RAW); returns [] if unavailable or on error."""
    exe = _bin("masscan")
    if not exe:
        return []
    args = [exe, "-p", ports or "1-1024", "--rate", str(rate or "1000"), "-oL", "-"]
    args += [t.strip() for t in target.split(",") if t.strip()]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as err:
        log.info("masscan failed: %s", err)
        return []
    found = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        # grepable list format: "open tcp 80 1.2.3.4 <timestamp>"
        if len(parts) >= 4 and parts[0] == "open" and parts[1] == "tcp":
            try:
                found.append({"host": parts[3], "port": int(parts[2])})
            except ValueError:
                continue
    return found


# ── nuclei: template-based detection ──────────────────────────────────────────
def run_nuclei(urls: list[str], severities: str = "critical,high,medium",
               timeout: int = 600, limit: int = 60) -> list[dict]:
    """Run nuclei against a list of URLs; return normalized findings. Detection
    only (no exploit/intrusive templates beyond nuclei defaults)."""
    exe = _bin("nuclei")
    if not exe or not urls:
        return []
    fd, listfile = tempfile.mkstemp(prefix="nuclei-", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(urls[:limit]))
        args = [exe, "-silent", "-jsonl", "-no-color", "-severity", severities, "-list", listfile]
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as err:
            log.info("nuclei failed: %s", err)
            return []
    finally:
        try:
            os.remove(listfile)
        except OSError:
            pass
    out = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        info = d.get("info", {}) or {}
        out.append({"name": info.get("name") or d.get("template-id", ""),
                    "severity": (info.get("severity") or "info").lower(),
                    "host": d.get("host") or d.get("matched-at", ""),
                    "matched": d.get("matched-at", ""),
                    "template": d.get("template-id", "")})
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out.sort(key=lambda r: sev_rank.get(r["severity"], 9))
    return out


# ── testssl.sh: TLS configuration assessment ──────────────────────────────────
def run_testssl(hostport: str, timeout: int = 300) -> list[dict]:
    """Assess TLS config of host:port; return findings rated MEDIUM+ severity."""
    exe = _bin("testssl.sh", "testssl")
    if not exe or not hostport:
        return []
    fd, jf = tempfile.mkstemp(prefix="testssl-", suffix=".json")
    os.close(fd)
    try:
        args = [exe, "--quiet", "--color", "0", "--jsonfile", jf, hostport]
        try:
            subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as err:
            log.info("testssl failed: %s", err)
            return []
        try:
            with open(jf, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return []
    finally:
        try:
            os.remove(jf)
        except OSError:
            pass
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    out = []
    for item in (data if isinstance(data, list) else []):
        sev = str(item.get("severity", "")).upper()
        if sev not in rank:
            continue
        out.append({"id": item.get("id", ""), "severity": sev.lower(),
                    "finding": (item.get("finding") or "")[:200],
                    "host": hostport})
    out.sort(key=lambda r: rank.get(r["severity"].upper(), 9))
    return out


# ── nikto: web server misconfig / dangerous files ─────────────────────────────
def run_nikto(url: str, timeout: int = 400) -> list[dict]:
    exe = _bin("nikto")
    if not exe or not url:
        return []
    fd, jf = tempfile.mkstemp(prefix="nikto-", suffix=".json")
    os.close(fd)
    try:
        args = [exe, "-h", url, "-Format", "json", "-output", jf,
                "-nointeractive", "-maxtime", str(max(60, timeout - 30)) + "s"]
        try:
            subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as err:
            log.info("nikto failed: %s", err)
            return []
        try:
            with open(jf, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return []
    finally:
        try:
            os.remove(jf)
        except OSError:
            pass
    vulns = []
    if isinstance(data, list):
        for host in data:
            vulns += host.get("vulnerabilities", []) if isinstance(host, dict) else []
    elif isinstance(data, dict):
        vulns = data.get("vulnerabilities", [])
    out = []
    for v in vulns:
        out.append({"name": (v.get("msg") or v.get("id") or "")[:200], "severity": "medium",
                    "host": v.get("url") or url, "id": v.get("id", "")})
    return out


# ── wapiti: web vulnerabilities (XSS, SQLi, file disclosure, etc.) ─────────────
def run_wapiti(url: str, timeout: int = 600) -> list[dict]:
    exe = _bin("wapiti")
    if not exe or not url:
        return []
    fd, jf = tempfile.mkstemp(prefix="wapiti-", suffix=".json")
    os.close(fd)
    try:
        args = [exe, "-u", url, "-f", "json", "-o", jf, "--flush-session",
                "--max-scan-time", str(max(1, (timeout - 60) // 60)), "--color", "0"]
        try:
            subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as err:
            log.info("wapiti failed: %s", err)
            return []
        try:
            with open(jf, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return []
    finally:
        try:
            os.remove(jf)
        except OSError:
            pass
    level_sev = {3: "high", 2: "medium", 1: "low"}
    out = []
    for category, items in (data.get("vulnerabilities", {}) or {}).items():
        for it in (items or []):
            out.append({"name": category, "severity": level_sev.get(it.get("level", 1), "low"),
                        "host": it.get("path") or url, "detail": (it.get("info") or "")[:160]})
    rank = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda r: rank.get(r["severity"], 9))
    return out


# ── subfinder: fast subdomain enumeration ─────────────────────────────────────
def run_subfinder(domain: str, timeout: int = 180) -> list[str]:
    exe = _bin("subfinder")
    if not exe or not domain:
        return []
    try:
        proc = subprocess.run([exe, "-d", domain, "-silent"],
                              capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as err:
        log.info("subfinder failed: %s", err)
        return []
    return sorted({ln.strip() for ln in proc.stdout.splitlines() if ln.strip()})


# ── ffuf: content / directory discovery ───────────────────────────────────────
def run_ffuf(base_url: str, timeout: int = 300, words: list[str] | None = None) -> list[dict]:
    exe = _bin("ffuf")
    if not exe or not base_url:
        return []
    base = base_url.rstrip("/")
    fdw, wl = tempfile.mkstemp(prefix="ffuf-wl-", suffix=".txt")
    fdo, of = tempfile.mkstemp(prefix="ffuf-out-", suffix=".json")
    os.close(fdo)
    try:
        with os.fdopen(fdw, "w", encoding="utf-8") as fh:
            fh.write("\n".join(words or DIR_WORDLIST))
        args = [exe, "-u", f"{base}/FUZZ", "-w", wl, "-mc", "200,204,301,302,307,401,403",
                "-of", "json", "-o", of, "-s", "-t", "40"]
        try:
            subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as err:
            log.info("ffuf failed: %s", err)
            return []
        try:
            with open(of, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return []
    finally:
        for p in (wl, of):
            try:
                os.remove(p)
            except OSError:
                pass
    out = []
    for r in data.get("results", []):
        out.append({"path": (r.get("input", {}) or {}).get("FUZZ", ""),
                    "status": r.get("status"), "url": r.get("url", ""),
                    "length": r.get("length")})
    out.sort(key=lambda r: (r.get("status") or 999))
    return out


# ── WPScan: WordPress assessment (detection/enumeration, no password attacks) ──
def run_wpscan(url: str, api_token: str = "", timeout: int = 600) -> list[dict]:
    exe = _bin("wpscan")
    if not exe or not url:
        return []
    args = [exe, "--url", url, "--format", "json", "--no-banner", "--random-user-agent",
            "--enumerate", "vp,t,u"]
    if api_token:
        args += ["--api-token", api_token]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as err:
        log.info("wpscan failed: %s", err)
        return []
    try:
        data = json.loads(proc.stdout or "{}")
    except ValueError:
        return []
    out = []
    for kind in ("plugins", "themes"):
        for name, info in (data.get(kind, {}) or {}).items():
            for v in (info.get("vulnerabilities", []) or []):
                out.append({"name": f"{name}: {v.get('title', 'vulnerability')}",
                            "severity": "high", "host": url, "kind": kind[:-1]})
    users = list((data.get("users", {}) or {}).keys())
    if users:
        out.append({"name": f"User enumeration: {', '.join(users[:10])}",
                    "severity": "low", "host": url, "kind": "users"})
    return out


# ── Droopescan: Drupal (and other CMS) assessment ─────────────────────────────
def run_droopescan(url: str, cms: str = "drupal", timeout: int = 400) -> list[dict]:
    exe = _bin("droopescan")
    if not exe or not url:
        return []
    try:
        proc = subprocess.run([exe, "scan", cms, "-u", url, "-o", "json"],
                              capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as err:
        log.info("droopescan failed: %s", err)
        return []
    try:
        data = json.loads((proc.stdout or "{}").splitlines()[-1])
    except (ValueError, IndexError):
        return []
    out = []
    ver = data.get("version", {}) or {}
    if ver.get("finalized"):
        out.append({"name": f"{cms} version: {', '.join(map(str, ver['finalized']))}",
                    "severity": "info", "host": url})
    for kind in ("plugins", "themes"):
        for item in (data.get(kind, {}) or {}).get("finalized", []) or []:
            out.append({"name": f"{cms} {kind[:-1]} found: {item}", "severity": "info", "host": url})
    return out


# ── sqlmap: SQL-injection DETECTION only (no data dumping/exploitation) ────────
def run_sqlmap_detect(url: str, timeout: int = 600) -> list[dict]:
    exe = _bin("sqlmap")
    if not exe or not url:
        return []
    # Detection-only: low level/risk, no --dump / --os-shell / --file-read etc.
    args = [exe, "-u", url, "--batch", "--level=1", "--risk=1", "--smart",
            "--disable-coloring", "--flush-session", "--answers=quit=N"]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as err:
        log.info("sqlmap failed: %s", err)
        return []
    text = proc.stdout or ""
    out = []
    if "is vulnerable" in text or "sqlmap identified the following injection point" in text:
        dbms = ""
        for ln in text.splitlines():
            if "back-end DBMS:" in ln:
                dbms = ln.split("back-end DBMS:", 1)[-1].strip()
                break
        out.append({"name": "SQL injection detected" + (f" — DBMS {dbms}" if dbms else ""),
                    "severity": "critical", "host": url})
    return out


# ── OWASP ZAP: DAST via daemon API (spider + passive alerts; no active attack) ─
def run_zap(url: str, timeout: int = 600) -> list[dict]:
    """Use a running ZAP daemon (set ZAP_API_URL, e.g. http://zap:8090). Spiders
    the target then returns passive-scan alerts. Active attack scan is not run."""
    import time as _t
    base = os.getenv("ZAP_API_URL")
    if not base or not url:
        return []
    key = os.getenv("ZAP_API_KEY", "")
    try:
        sid = requests.get(f"{base}/JSON/spider/action/scan/",
                           params={"url": url, "apikey": key}, timeout=30).json().get("scan")
        deadline = _t.time() + min(timeout, 180)
        while sid is not None and _t.time() < deadline:
            st = requests.get(f"{base}/JSON/spider/view/status/",
                              params={"scanId": sid, "apikey": key}, timeout=15).json().get("status", "100")
            if str(st).isdigit() and int(st) >= 100:
                break
            _t.sleep(3)
        _t.sleep(3)  # let passive scanner settle
        alerts = requests.get(f"{base}/JSON/core/view/alerts/",
                              params={"baseurl": url, "apikey": key, "start": 0, "count": 300},
                              timeout=30).json().get("alerts", [])
    except Exception as err:
        log.info("ZAP failed: %s", err)
        return []
    sevmap = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
    out, seen = [], set()
    for a in alerts:
        nm = a.get("alert") or a.get("name", "")
        if nm in seen:
            continue
        seen.add(nm)
        out.append({"name": nm, "severity": sevmap.get(a.get("risk"), "info"), "host": a.get("url", url)})
    rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    out.sort(key=lambda r: rank.get(r["severity"], 9))
    return out


# ── retire.js: known-vulnerable front-end JS libraries ────────────────────────
def run_retire(page_urls: list[str], timeout: int = 240) -> list[dict]:
    exe = _bin("retire")
    if not exe or not page_urls:
        return []
    import re as _re
    d = tempfile.mkdtemp(prefix="retire-")
    n = 0
    try:
        for page in page_urls[:5]:
            try:
                html = requests.get(page, timeout=12, verify=False).text
            except Exception:
                continue
            srcs = _re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, _re.I)
            for src in srcs[:10]:
                js_url = src if src.startswith("http") else requests.compat.urljoin(page, src)
                try:
                    js = requests.get(js_url, timeout=12, verify=False).text
                    with open(os.path.join(d, f"{n}.js"), "w", encoding="utf-8") as fh:
                        fh.write(js)
                    n += 1
                except Exception:
                    continue
        if not n:
            return []
        try:
            proc = subprocess.run([exe, "--path", d, "--outputformat", "json"],
                                  capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as err:
            log.info("retire failed: %s", err)
            return []
        try:
            data = json.loads(proc.stdout or "[]")
        except ValueError:
            return []
    finally:
        shutil.rmtree(d, ignore_errors=True)
    entries = data.get("data", data) if isinstance(data, dict) else data
    out = []
    for entry in (entries or []):
        for res in entry.get("results", []) if isinstance(entry, dict) else []:
            comp, ver = res.get("component", ""), res.get("version", "")
            for v in res.get("vulnerabilities", []) or []:
                ids = v.get("identifiers", {}) or {}
                title = ids.get("summary") or (ids.get("CVE") or [""])[0] or "known vulnerability"
                out.append({"name": f"{comp} {ver}: {title}",
                            "severity": (v.get("severity") or "medium").lower(), "host": ""})
    return out


# ── Trivy: dependency / container-image / IaC vulnerabilities (image|fs|repo) ──
def run_trivy(target: str, mode: str = "image", timeout: int = 600) -> list[dict]:
    exe = _bin("trivy")
    if not exe or not target:
        return []
    try:
        proc = subprocess.run([exe, mode, "-q", "-f", "json", target],
                              capture_output=True, text=True, timeout=timeout)
        data = json.loads(proc.stdout or "{}")
    except (subprocess.TimeoutExpired, OSError, ValueError) as err:
        log.info("trivy failed: %s", err)
        return []
    out = []
    for res in (data.get("Results") or []):
        for v in (res.get("Vulnerabilities") or []):
            out.append({"name": f"{v.get('PkgName','')} {v.get('InstalledVersion','')}: {v.get('VulnerabilityID','')}",
                        "severity": (v.get("Severity") or "unknown").lower(),
                        "host": res.get("Target", "")})
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    out.sort(key=lambda r: rank.get(r["severity"], 9))
    return out


# ── gitleaks: exposed secrets in a source repo / directory ────────────────────
def run_gitleaks(path: str, timeout: int = 300) -> list[dict]:
    exe = _bin("gitleaks")
    if not exe or not path:
        return []
    fd, rp = tempfile.mkstemp(prefix="gitleaks-", suffix=".json")
    os.close(fd)
    try:
        try:
            subprocess.run([exe, "detect", "-s", path, "--report-format", "json",
                            "--report-path", rp, "--no-banner", "--exit-code", "0"],
                           capture_output=True, text=True, timeout=timeout)
            with open(rp, encoding="utf-8") as fh:
                data = json.load(fh)
        except (subprocess.TimeoutExpired, OSError, ValueError) as err:
            log.info("gitleaks failed: %s", err)
            return []
    finally:
        try:
            os.remove(rp)
        except OSError:
            pass
    return [{"name": f"{f.get('RuleID', 'secret')}: {f.get('File', '')}",
             "severity": "high", "host": f.get("File", "")} for f in (data or [])]
