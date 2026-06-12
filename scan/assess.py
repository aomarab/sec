"""Run a network scan, correlate discovered services with known CVEs (grounded
in NVD/KEV), and assemble a Markdown vulnerability report."""
from __future__ import annotations

import datetime
import logging
import socket

import apikeys
from agent.llm import build_client
from collectors import kev, nvd
from config import CONFIG
from . import checks, headers, scanner, tools, webchecks

log = logging.getLogger("scan.assess")

_SYSTEM_TECH = """You are a network security analyst. You are given the results of an
authorized network scan (open ports, detected services/banners, security-check
findings, optionally nmap vulnerability-script findings) and a list of POTENTIAL
CVEs matched to detected service versions from NVD.

Write GitHub-flavoured Markdown with exactly two sections:

## Summary
3-6 sentences: what was scanned, the overall exposure (hosts/open ports), and the
most notable technical risks. Be factual; do not invent services or CVEs.

## Recommendations
Prioritised, concrete hardening actions based strictly on the findings (close or
firewall exposed ports, patch/upgrade specific services, disable legacy protocols,
restrict management interfaces, etc.).

Do NOT list the open ports or CVEs yourself — those are added as tables separately.
Only reference CVEs that appear in the provided potential-CVE list."""

_SYSTEM_EXEC = """You are a security advisor briefing leadership on an authorized
network scan. You are given open ports, security-check findings, and potential
CVEs from NVD.

Write GitHub-flavoured Markdown with exactly two sections, in plain business
language (minimal jargon):

## Executive Summary
3-5 sentences: the overall risk posture, what could happen if the top issues are
not addressed (business impact), and the single most urgent action. Lead with risk,
not technical detail. Do not invent findings.

## Priority Actions
A short, ranked list (max 5) of the most important actions, each one line, framed
as a business decision (what, why it matters, rough effort). No deep technical
detail — that lives in the tables below.

Do NOT list every open port or CVE — those are in the tables. Only reference CVEs
from the provided list."""


def _llm_narrative(cfg, context: str, style: str = "technical") -> str:
    system = _SYSTEM_EXEC if style == "executive" else _SYSTEM_TECH
    return _complete(cfg, system, context)


def _complete(cfg, system: str, context: str) -> str:
    client, model = build_client(cfg.llm)
    if cfg.llm.provider == "anthropic":
        kwargs = dict(model=model, max_tokens=2500,
                      system=[{"type": "text", "text": system,
                               "cache_control": {"type": "ephemeral"}}],
                      messages=[{"role": "user", "content": context}])
        if getattr(cfg.llm, "anthropic_thinking", False):
            kwargs["thinking"] = {"type": "adaptive"}
            kwargs["max_tokens"] = 6000
        resp = client.messages.create(**kwargs)
        return "".join(b.text for b in resp.content if b.type == "text")
    resp = client.chat.completions.create(
        model=model, temperature=0.2,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": context}])
    return resp.choices[0].message.content or ""


def _build_assets(results: list[dict], sec_findings: list[dict]) -> list[dict]:
    sev_by_host: dict[str, dict] = {}
    for f in sec_findings:
        sev_by_host.setdefault(f["host"], {}).setdefault(f["severity"], 0)
        sev_by_host[f["host"]][f["severity"]] += 1
    assets = []
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    for h in results:
        if not h["open"]:
            continue
        ip = h["host"]
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = ""
        counts = sev_by_host.get(ip, {})
        score, label = _risk_score({k: counts.get(k, 0) for k in
                                     ("critical", "high", "medium", "low")}, 0)
        assets.append({
            "ip": ip, "hostname": hostname, "os": h.get("os", ""),
            "ports": [p["port"] for p in h["open"]],
            "services": sorted({p["service"] for p in h["open"] if p["service"] != "unknown"}),
            "risk": score, "label": label, "last_scan": now,
        })
    return assets


def _risk_score(counts: dict, kev: int) -> tuple[int, str]:
    s = (counts.get("critical", 0) * 40 + counts.get("high", 0) * 20
         + counts.get("medium", 0) * 8 + counts.get("low", 0) * 3 + kev * 15)
    score = min(100, s)
    label = ("Critical" if score >= 80 else "High" if score >= 50
             else "Medium" if score >= 20 else "Low" if score > 0 else "Minimal")
    return score, label


def _ports_table(results: list[dict]) -> str:
    rows = []
    for host in results:
        for p in host["open"]:
            banner = (p.get("banner") or "").replace("|", "\\|")[:80] or "—"
            rows.append(f"| `{host['host']}` | {p['port']} | {p['service']} | {banner} |")
    if not rows:
        return "## Open Ports & Services\n\n_No open ports were found on the scanned target(s)._"
    return ("## Open Ports & Services\n\n| Host | Port | Service | Banner / Version |\n"
            "|------|------|---------|------------------|\n" + "\n".join(rows))


def _cve_table(cve_rows: list[dict]) -> str:
    if not cve_rows:
        return ("## Potential Vulnerabilities\n\n_No CVEs were correlated from the "
                "detected service versions. This does not mean the targets are secure — "
                "enable banner/version detection and review manually._")
    out = ["## Potential Vulnerabilities (verify before acting)", "",
           "| CVE | Matched service | CVSS | Severity | KEV | Summary |",
           "|-----|-----------------|------|----------|-----|---------|"]
    for r in cve_rows:
        kevf = "**Yes**" if r.get("kev") else "No"
        desc = (r.get("description") or "").replace("|", "\\|")[:160]
        out.append(f"| {r['cve']} | {r['product']} | {r['cvss']} | {r.get('severity','')} "
                   f"| {kevf} | {desc} |")
    return "\n".join(out)


def _correlate(products: list[str]) -> list[dict]:
    """Grounded CVE lookup: NVD keyword search per product + KEV flagging."""
    rows: list[dict] = []
    try:
        kev_ids = {v["cve"] for v in kev.fetch_kev(look_back_days=3650, limit=100000)
                   .get("vulnerabilities", [])}
    except Exception:
        kev_ids = set()
    for product in products:
        try:
            res = nvd.search_by_keyword(product, min_cvss=7.0, limit=5,
                                        api_key=apikeys.get("NVD_API_KEY"))
        except Exception as err:
            log.info("NVD lookup failed for %s: %s", product, err)
            continue
        for c in res.get("cves", []):
            c["kev"] = c["cve"] in kev_ids
            rows.append(c)
    rows.sort(key=lambda x: (not x["kev"], -x["cvss"]))
    return rows[:25]


def run_scan(opts: dict, cfg=CONFIG, progress=None) -> str:
    target = opts["target"]
    hosts = scanner.expand_targets(target)
    log.info("Scanning %d host(s): %s", len(hosts), target)

    advanced = opts.get("mode") == "advanced"
    use_nmap = advanced and opts.get("use_nmap") and scanner.nmap_available()
    findings: list[str] = []
    nmap_note = ""

    if use_nmap:
        log.info("Using nmap (version=%s vuln=%s)", True, opts.get("vuln_scripts"))
        results, findings, stderr = scanner.run_nmap(
            target, version=True, vuln=bool(opts.get("vuln_scripts")),
            os_detect=bool(opts.get("os_detect")), ports=opts.get("ports", ""),
            top_ports=200 if advanced else 100, timing=opts.get("timing", "4"))
        if stderr:
            nmap_note = stderr.splitlines()[0][:200]
            log.info("nmap stderr: %s", nmap_note)
    else:
        if advanced and opts.get("use_nmap"):
            log.info("nmap requested but not installed; using built-in TCP scanner.")
        default_ports = scanner.TOP_BASIC if not advanced else list(scanner.COMMON_PORTS)
        ports = scanner.parse_ports(opts.get("ports", ""), default_ports)
        grab = opts.get("grab_banner", True)
        results = scanner.tcp_scan(hosts, ports, grab=grab, progress=progress)

    # Optional fast port discovery with masscan (merged into results).
    if advanced and opts.get("use_masscan"):
        if tools.available()["masscan"]:
            log.info("Running masscan port discovery...")
            ms = tools.masscan_ports(target, ports=opts.get("ports") or "1-1024",
                                     rate=opts.get("masscan_rate", "1000"))
            by_host = {h["host"]: h for h in results}
            for r in ms:
                h = by_host.get(r["host"])
                if h is None:
                    h = {"host": r["host"], "open": []}
                    results.append(h)
                    by_host[r["host"]] = h
                if not any(p["port"] == r["port"] for p in h["open"]):
                    h["open"].append({"port": r["port"], "service": "unknown", "banner": ""})
            log.info("masscan: %d open port record(s)", len(ms))
        else:
            log.info("masscan requested but not installed; skipped.")

    open_count = sum(len(h["open"]) for h in results)
    hosts_up = sum(1 for h in results if h["open"])
    log.info("Scan complete: %d open port(s) across %d responsive host(s)", open_count, hosts_up)

    log.info("Running unauthenticated security checks...")
    sec_findings = checks.run_checks(results)
    if sec_findings:
        log.info("Security checks flagged %d issue(s)", len(sec_findings))

    cve_rows: list[dict] = []
    if opts.get("correlate_cves", True):
        products = scanner.extract_products(results)
        if products:
            log.info("Correlating CVEs for: %s", ", ".join(products))
            cve_rows = _correlate(products)

    # ── Optional web-app assessment + recon tools (advanced; authorized target) ──
    web_urls, tls_eps = [], []
    for h in results:
        for p in h["open"]:
            port, svc = p["port"], (p.get("service") or "").lower()
            if port in (443, 8443) or any(k in svc for k in ("https", "ssl", "tls")):
                web_urls.append(f"https://{h['host']}:{port}")
                tls_eps.append(f"{h['host']}:{port}")
            elif port in (80, 8080, 8000, 8888, 5000) or "http" in svc:
                web_urls.append(f"http://{h['host']}:{port}")
            elif port in (993, 995, 465, 636, 990, 5061):
                tls_eps.append(f"{h['host']}:{port}")
    web_urls = sorted(set(web_urls))
    tls_eps = sorted(set(tls_eps))

    nuclei_findings: list[dict] = []
    testssl_findings: list[dict] = []
    web_findings: list[dict] = []   # headers/nikto/wapiti/wpscan/droopescan/sqlmap
    content_findings: list[dict] = []
    subdomains: list[str] = []

    def _adv(opt):
        return advanced and opts.get(opt)

    if _adv("nuclei") and web_urls:
        log.info("Running nuclei against %d web endpoint(s)...", len(web_urls))
        nuclei_findings = tools.run_nuclei(web_urls)
    if _adv("testssl"):
        for ep in tls_eps[:5]:
            log.info("Running testssl on %s...", ep)
            testssl_findings += tools.run_testssl(ep)
    if _adv("headers") and web_urls:
        log.info("Grading security headers on %d endpoint(s)...", len(web_urls))
        for f in headers.grade_endpoints(web_urls):
            web_findings.append({**f, "source": "headers", "name": f["issue"]})
    if _adv("nikto"):
        for u in web_urls[:2]:
            log.info("Running nikto on %s...", u)
            for f in tools.run_nikto(u):
                web_findings.append({**f, "source": "nikto"})
    if _adv("wapiti"):
        for u in web_urls[:2]:
            log.info("Running wapiti on %s...", u)
            for f in tools.run_wapiti(u):
                web_findings.append({**f, "source": "wapiti"})
    if _adv("wpscan"):
        for u in web_urls[:2]:
            log.info("Running WPScan on %s...", u)
            for f in tools.run_wpscan(u, api_token=apikeys.get("WPSCAN_API_KEY")):
                web_findings.append({**f, "source": "wpscan"})
    if _adv("droopescan"):
        for u in web_urls[:2]:
            log.info("Running droopescan on %s...", u)
            for f in tools.run_droopescan(u):
                web_findings.append({**f, "source": "droopescan"})
    if _adv("sqlmap"):
        for u in web_urls[:2]:
            log.info("Running sqlmap (detection only) on %s...", u)
            for f in tools.run_sqlmap_detect(u):
                web_findings.append({**f, "source": "sqlmap"})
    if _adv("webchecks") and web_urls:
        log.info("Running native web checks (CORS/redirect/JWT/secrets)...")
        for f in webchecks.run_endpoints(web_urls):
            web_findings.append({**f, "source": "webchecks"})
    if _adv("zap"):
        for u in web_urls[:2]:
            log.info("Running OWASP ZAP (spider + passive) on %s...", u)
            for f in tools.run_zap(u):
                web_findings.append({**f, "source": "zap"})
    if _adv("retire") and web_urls:
        log.info("Checking for vulnerable JS libraries (retire.js)...")
        for f in tools.run_retire(web_urls):
            web_findings.append({**f, "source": "retire.js"})
    if _adv("ffuf"):
        for u in web_urls[:2]:
            log.info("Running ffuf content discovery on %s...", u)
            content_findings += tools.run_ffuf(u)
    if _adv("subfinder"):
        import re as _re
        dom = _re.sub(r"^https?://", "", target.split(",")[0]).split("/")[0].split(":")[0]
        if _re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", dom, _re.I) and not _re.match(r"^\d+\.\d+\.\d+\.\d+$", dom):
            log.info("Running subfinder on %s...", dom)
            subdomains = tools.run_subfinder(dom)
    log.info("Web tools: %d web finding(s), %d path(s), %d subdomain(s)",
             len(web_findings), len(content_findings), len(subdomains))

    # Build LLM context (compact)
    svc_lines = []
    for h in results:
        for p in h["open"]:
            svc_lines.append(f"{h['host']}:{p['port']} {p['service']} {p.get('banner','')}".strip())
    ctx = (f"Target: {target}\nHosts scanned: {len(hosts)} | responsive: {hosts_up} | "
           f"open ports: {open_count}\n\nOpen services:\n" + "\n".join(svc_lines[:200]))
    if sec_findings:
        ctx += "\n\nSecurity check findings:\n" + "\n".join(
            f"{f['host']}:{f['port']} [{f['severity']}] {f['title']}" for f in sec_findings)
    if cve_rows:
        ctx += "\n\nPotential CVEs (from NVD):\n" + "\n".join(
            f"{r['cve']} ({r['product']}, CVSS {r['cvss']}{', KEV' if r.get('kev') else ''})"
            for r in cve_rows)
    if findings:
        ctx += "\n\nnmap vuln-script findings:\n" + "\n".join(findings[:40])
    if nuclei_findings:
        ctx += "\n\nnuclei findings:\n" + "\n".join(
            f"[{f['severity']}] {f['name']} ({f['host']})" for f in nuclei_findings[:40])
    if testssl_findings:
        ctx += "\n\nTLS (testssl) findings:\n" + "\n".join(
            f"[{f['severity']}] {f['id']} ({f['host']})" for f in testssl_findings[:40])
    if web_findings:
        ctx += "\n\nWeb application findings:\n" + "\n".join(
            f"[{f['severity']}] ({f['source']}) {f['name']}" for f in web_findings[:40])
    if content_findings:
        ctx += "\n\nContent discovery (ffuf):\n" + "\n".join(
            f"{f['status']} {f['path']}" for f in content_findings[:40])
    if subdomains:
        ctx += f"\n\nSubdomains discovered: {len(subdomains)}"

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in sec_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    for r in cve_rows:
        sev = (r.get("severity") or "").lower()
        if sev in counts:
            counts[sev] += 1
    for f in nuclei_findings + testssl_findings + web_findings:
        sev = (f.get("severity") or "").lower()
        if sev in counts:
            counts[sev] += 1
    kev_count = sum(1 for r in cve_rows if r.get("kev"))
    score, label = _risk_score(counts, kev_count)
    stats = {"target": target, "hosts_up": hosts_up, "open_ports": open_count,
             "counts": counts, "cves": len(cve_rows), "kev": kev_count,
             "risk": score, "label": label}

    style = opts.get("report_style", "technical")
    try:
        narrative = _llm_narrative(cfg, ctx, style).strip()
    except Exception as err:
        log.info("LLM narrative unavailable: %s", err)
        es = str(err).lower()
        why = ("the AI engine isn't configured — add a valid LLM API key in Settings → API keys"
               if any(k in es for k in ("x-api-key", "authentication", "401", "api key", "unauthorized"))
               else "the AI engine was unavailable")
        narrative = (f"## Summary\nThe scan completed successfully; the AI-written summary was skipped "
                     f"because {why}. All findings below are complete.\n\n## Recommendations\n"
                     "- Review each open port and close or firewall those not required.\n"
                     "- Patch services flagged with potential CVEs and remediate the findings above.")

    risk_line = (f"**Risk score: {score}/100 ({label})** · {counts['critical']} critical, "
                 f"{counts['high']} high, {counts['medium']} medium findings · "
                 f"{len(cve_rows)} potential CVEs ({kev_count} in CISA KEV)")
    parts = [f"# Network Vulnerability Scan — {target}", "", risk_line, "", narrative, "", _ports_table(results)]
    parts += ["", checks.checks_table_markdown(sec_findings)]
    if findings:
        fl = "\n".join(f"- {f}" for f in findings[:40])
        parts += ["", "## nmap Vulnerability Findings", "", fl]
    if nuclei_findings:
        nrows = ["| Severity | Finding | Host | Template |", "|---|---|---|---|"]
        for f in nuclei_findings[:60]:
            nrows.append(f"| {f['severity'].title()} | {f['name']} | `{f['host']}` | {f.get('template','')} |")
        parts += ["", "## nuclei Findings (template-based detection)", ""] + nrows
    if testssl_findings:
        trows = ["| Severity | Check | Endpoint | Finding |", "|---|---|---|---|"]
        for f in testssl_findings[:60]:
            fnd = (f.get("finding") or "").replace("|", "\\|")
            trows.append(f"| {f['severity'].title()} | {f['id']} | `{f['host']}` | {fnd} |")
        parts += ["", "## TLS Assessment (testssl.sh)", ""] + trows
    if web_findings:
        wrows = ["| Severity | Source | Finding | Location |", "|---|---|---|---|"]
        for f in web_findings[:80]:
            nm = (f.get("name") or "").replace("|", "\\|")[:120]
            wrows.append(f"| {f['severity'].title()} | {f['source']} | {nm} | `{f.get('host','')}` |")
        parts += ["", "## Web Application Findings", "",
                  "_Header/cookie/CORS grading, Nikto, Wapiti, WPScan, Droopescan, and sqlmap "
                  "(detection only)._", ""] + wrows
    if content_findings:
        crows = ["| Status | Path | URL |", "|---|---|---|"]
        for f in content_findings[:80]:
            crows.append(f"| {f.get('status','')} | `{f.get('path','')}` | {f.get('url','')} |")
        parts += ["", "## Content Discovery (ffuf)", ""] + crows
    if subdomains:
        parts += ["", "## Subdomains (subfinder)", "",
                  f"_{len(subdomains)} discovered._", ""] + [f"- `{s}`" for s in subdomains[:100]]
    parts += ["", _cve_table(cve_rows)]
    if nmap_note:
        parts += ["", f"> nmap note: {nmap_note}"]
    engines = ["nmap" if use_nmap else "built-in TCP connect scanner"]
    if opts.get("use_masscan") and tools.available()["masscan"]:
        engines.append("masscan (discovery)")
    if nuclei_findings:
        engines.append("nuclei (detection)")
    if testssl_findings:
        engines.append("testssl.sh (TLS)")
    for opt, lbl in (("headers", "security headers"), ("nikto", "Nikto"), ("wapiti", "Wapiti"),
                     ("ffuf", "ffuf (content)"), ("subfinder", "subfinder"),
                     ("wpscan", "WPScan"), ("droopescan", "Droopescan"), ("sqlmap", "sqlmap (detect)"),
                     ("webchecks", "CORS/redirect/JWT/secrets"), ("zap", "OWASP ZAP"),
                     ("retire", "retire.js")):
        if opts.get(opt):
            engines.append(lbl)
    parts += ["", "## Scope & Method", "",
              f"- Scanned target: `{target}` ({hosts_up} responsive of {len(hosts)} host(s))",
              f"- Engines: {', '.join(engines)}",
              "- Detection/recon only — no exploitation, brute-force, or password attacks.",
              "- CVEs are *potential* matches from service banners via NVD — verify before acting."]
    return {"markdown": "\n".join(parts), "stats": stats,
            "assets": _build_assets(results, sec_findings)}
