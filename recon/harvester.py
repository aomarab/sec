"""Gather public footprint for a domain and assemble an OSINT recon report."""
from __future__ import annotations

import datetime
import logging
import os
import re
import socket

import requests

import apikeys
from agent.llm import build_client
from .fingerprint import fetch_tech
from .ipintel import ip_intel

log = logging.getLogger("recon.harvester")

UA = {"User-Agent": "threat-intel-briefing-agent/1.0", "Accept": "application/json"}
MAX_RESOLVE = int(os.getenv("RECON_MAX_RESOLVE", "150"))

_SYSTEM = """You are an attack-surface analyst. You are given OSINT recon results for
a domain (subdomains, DNS records, hosts/IPs, emails, optional Shodan data).
Write GitHub-flavoured Markdown with exactly two sections:

## Summary
3-6 sentences on the external attack surface: how exposed it looks, notable hosts
or services, and the most relevant risks. Be factual; don't invent hosts.

## Recommendations
Prioritised, concrete actions to reduce exposure (decommission stale subdomains,
close/firewall exposed services, fix DNS hygiene, monitor cert issuance, etc.).

Do not list every subdomain/record — those are in tables below."""


# ── sources ──────────────────────────────────────────────────────────────────
def crtsh_subdomains(domain: str) -> list[str]:
    """Subdomains from Certificate Transparency logs (crt.sh)."""
    try:
        resp = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                            headers=UA, timeout=40)
        resp.raise_for_status()
        rows = resp.json()
    except (requests.RequestException, ValueError) as err:
        log.info("crt.sh failed: %s", err)
        return []
    subs: set[str] = set()
    for row in rows:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(domain) and not name.startswith("@") and " " not in name:
                subs.add(name)
    subs.add(domain)
    return sorted(subs)


def doh(name: str, rtype: str) -> list[str]:
    """DNS-over-HTTPS query via Cloudflare (no key)."""
    try:
        resp = requests.get("https://cloudflare-dns.com/dns-query",
                            params={"name": name, "type": rtype},
                            headers={"Accept": "application/dns-json"}, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return []
    return [str(a.get("data", "")).strip('"') for a in data.get("Answer", []) if a.get("data")]


def resolve(host: str) -> list[str]:
    try:
        return sorted(set(socket.gethostbyname_ex(host)[2]))
    except Exception:
        return []


def shodan_host(ip: str, key: str) -> dict | None:
    try:
        resp = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                            params={"key": key}, timeout=20)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        d = resp.json()
        return {"ports": d.get("ports", []), "org": d.get("org", ""),
                "os": d.get("os") or "", "vulns": list(d.get("vulns", []) or [])}
    except Exception as err:
        log.info("shodan %s: %s", ip, err)
        return None


def hunter_emails(domain: str, key: str) -> list[str]:
    try:
        resp = requests.get("https://api.hunter.io/v2/domain-search",
                            params={"domain": domain, "api_key": key, "limit": 50}, timeout=25)
        resp.raise_for_status()
        return [e["value"] for e in resp.json().get("data", {}).get("emails", []) if e.get("value")]
    except Exception as err:
        log.info("hunter %s: %s", domain, err)
        return []


# ── report assembly ──────────────────────────────────────────────────────────
def _complete(cfg, context: str) -> str:
    client, model = build_client(cfg.llm)
    if cfg.llm.provider == "anthropic":
        kwargs = dict(model=model, max_tokens=2000,
                      system=[{"type": "text", "text": _SYSTEM,
                               "cache_control": {"type": "ephemeral"}}],
                      messages=[{"role": "user", "content": context}])
        if getattr(cfg.llm, "anthropic_thinking", False):
            kwargs["thinking"] = {"type": "adaptive"}
            kwargs["max_tokens"] = 5000
        resp = client.messages.create(**kwargs)
        return "".join(b.text for b in resp.content if b.type == "text")
    resp = client.chat.completions.create(
        model=model, temperature=0.2,
        messages=[{"role": "system", "content": _SYSTEM}, {"role": "user", "content": context}])
    return resp.choices[0].message.content or ""


def run_recon(domain: str, opts: dict, cfg, progress=None) -> dict:
    domain = re.sub(r"^https?://", "", (domain or "").strip()).strip("/").lower()
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        raise ValueError("Enter a valid domain, e.g. example.com")
    log.info("Recon for %s", domain)

    subs = crtsh_subdomains(domain)
    log.info("crt.sh: %d subdomains", len(subs))

    dns = {t: doh(domain, t) for t in ("A", "AAAA", "MX", "NS", "TXT", "CNAME")}

    host_rows = []
    ip_set: set[str] = set()
    for i, sub in enumerate(subs[:MAX_RESOLVE]):
        ips = resolve(sub)
        if ips:
            host_rows.append({"host": sub, "ips": ips})
            ip_set.update(ips)
        if progress and i % 25 == 0:
            progress(i, min(len(subs), MAX_RESOLVE))

    shodan_key = apikeys.get("SHODAN_API_KEY")
    shodan_data = {}
    if opts.get("use_shodan") and shodan_key:
        for ip in list(ip_set)[:25]:
            info = shodan_host(ip, shodan_key)
            if info:
                shodan_data[ip] = info

    emails = []
    hunter_key = apikeys.get("HUNTER_API_KEY")
    if opts.get("use_hunter") and hunter_key:
        emails = hunter_emails(domain, hunter_key)

    # Email-security records
    spf = [t for t in dns.get("TXT", []) if t.lower().startswith("v=spf1")]
    dmarc = [t for t in doh("_dmarc." + domain, "TXT") if "v=dmarc1" in t.lower()]

    # Web technology fingerprinting on live hosts
    tech = []
    if opts.get("fingerprint", True):
        for i, r in enumerate(host_rows[:25]):
            info = fetch_tech(r["host"])
            if info:
                tech.append(info)
            if progress:
                progress(len(host_rows) + i, len(host_rows) + 25)
        log.info("Fingerprinted %d host(s)", len(tech))

    # IP intelligence (ASN / ISP / geo / reverse DNS)
    ipdata = {}
    if opts.get("ip_intel", True) and ip_set:
        ipdata = ip_intel(list(ip_set)[:100])
        log.info("IP intel for %d address(es)", len(ipdata))

    # ── context for the LLM
    ctx = (f"Domain: {domain}\nSubdomains found: {len(subs)} | resolved hosts: "
           f"{len(host_rows)} | unique IPs: {len(ip_set)} | emails: {len(emails)}\n\n"
           "Sample subdomains:\n" + "\n".join(subs[:60]))
    if shodan_data:
        ctx += "\n\nShodan:\n" + "\n".join(
            f"{ip}: ports {d['ports']} org {d['org']} vulns {d['vulns'][:5]}"
            for ip, d in shodan_data.items())
    if emails:
        ctx += "\n\nEmails:\n" + "\n".join(emails[:40])
    ctx += f"\n\nEmail security: SPF={'yes' if spf else 'MISSING'}, DMARC={'yes' if dmarc else 'MISSING'}"
    if tech:
        ctx += "\n\nWeb technologies:\n" + "\n".join(
            f"{t['host']}: server={t['server']} cdn={t['cdn']} tech={','.join(t['tech'])}" for t in tech)
    if ipdata:
        ctx += "\n\nIP intel:\n" + "\n".join(
            f"{ip}: {d['asn']} {d['org'] or d['isp']} {d['geo']}" for ip, d in ipdata.items())
    try:
        narrative = _complete(cfg, ctx).strip()
    except Exception as err:
        log.exception("recon narrative failed")
        narrative = ("## Summary\nRecon completed; automated summary unavailable "
                     f"({err}). Review the tables below.\n\n## Recommendations\n"
                     "- Review each subdomain and decommission unused ones.\n"
                     "- Ensure exposed services are patched and firewalled.")

    parts = [f"# OSINT Recon — {domain}", "", narrative, ""]
    # Subdomains table
    parts += ["## Subdomains & Hosts", "", "| Host | Resolved IPs |", "|------|--------------|"]
    if host_rows:
        for r in host_rows:
            parts.append(f"| `{r['host']}` | {', '.join(r['ips'])} |")
    else:
        for s in subs[:200]:
            parts.append(f"| `{s}` | (no A record) |")
    # DNS table
    parts += ["", "## DNS Records", "", "| Type | Value |", "|------|-------|"]
    for t, vals in dns.items():
        for v in vals[:20]:
            parts.append(f"| {t} | `{v}` |")
    # Email security
    parts += ["", "## Email Security", "", "| Record | Status |", "|--------|--------|",
              f"| SPF | {'`' + spf[0][:120] + '`' if spf else '**Missing** — spoofing risk'} |",
              f"| DMARC | {'`' + dmarc[0][:120] + '`' if dmarc else '**Missing** — spoofing risk'} |"]
    # Web technologies
    if tech:
        parts += ["", "## Web Technologies", "",
                  "| Host | Status | Server | CDN | CMS / Framework | Analytics |",
                  "|------|--------|--------|-----|-----------------|-----------|"]
        for t in tech:
            parts.append(f"| `{t['host']}` | {t['status']} | {t['server'] or '—'} | {t['cdn'] or '—'} "
                         f"| {', '.join(t['tech']) or '—'} | {', '.join(t['analytics']) or '—'} |")
    # IP intelligence
    if ipdata:
        parts += ["", "## IP Intelligence", "",
                  "| IP | Reverse DNS | ASN | ISP / Org | Location |",
                  "|----|-------------|-----|-----------|----------|"]
        for ip, d in ipdata.items():
            parts.append(f"| `{ip}` | {d['reverse'] or '—'} | {d['asn'] or '—'} "
                         f"| {d['org'] or d['isp'] or '—'} | {d['geo'] or '—'} |")
    # Shodan
    if shodan_data:
        parts += ["", "## Exposed Hosts (Shodan)", "",
                  "| IP | Open ports | Org | Known vulns |", "|----|-----------|-----|-------------|"]
        for ip, d in shodan_data.items():
            vulns = ", ".join(d["vulns"][:6]) or "—"
            parts.append(f"| `{ip}` | {', '.join(map(str, d['ports']))} | {d['org']} | {vulns} |")
    # Emails
    if emails:
        parts += ["", "## Emails", ""] + [f"- {e}" for e in emails[:50]]
    parts += ["", "## Sources & Method", "",
              "- Subdomains: Certificate Transparency (crt.sh)",
              "- DNS: DNS-over-HTTPS (Cloudflare)",
              f"- Host resolution: built-in resolver ({len(host_rows)} resolved)",
              "- Optional: Shodan / Hunter.io (when an API key is configured)",
              "- Passive OSINT from public sources; verify before acting."]

    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    assets = [{"ip": ip, "hostname": next((r["host"] for r in host_rows if ip in r["ips"]), ""),
               "os": shodan_data.get(ip, {}).get("os", ""),
               "ports": shodan_data.get(ip, {}).get("ports", []),
               "services": [], "risk": 0, "label": "Minimal", "last_scan": now}
              for ip in sorted(ip_set)]

    return {"markdown": "\n".join(parts), "assets": assets,
            "counts": {"subdomains": len(subs), "ips": len(ip_set),
                       "emails": len(emails), "technologies": len(tech)}}
