"""On-demand threat-intelligence analysis: single-CVE deep dives, threat-actor
profiles, and threat-hunting query generation.

CVE analysis is grounded in live data (NVD record + CISA KEV status + FIRST EPSS
exploitation probability); the LLM writes the narrative around those facts.
Actor profiles and hunting queries are LLM-authored from public threat-intel
knowledge and are clearly marked for analyst verification."""
from __future__ import annotations

import logging
import re

from agent.llm import build_client
from collectors import epss, kev, nvd

log = logging.getLogger("intel.analyst")

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)


# ── shared LLM completion (mirrors the scan/recon narrative helpers) ──────────
def _complete(cfg, system: str, context: str, max_tokens: int = 2600) -> str:
    client, model = build_client(cfg.llm)
    if cfg.llm.provider == "anthropic":
        kwargs = dict(model=model, max_tokens=max_tokens,
                      system=[{"type": "text", "text": system,
                               "cache_control": {"type": "ephemeral"}}],
                      messages=[{"role": "user", "content": context}])
        if getattr(cfg.llm, "anthropic_thinking", False):
            kwargs["thinking"] = {"type": "adaptive"}
            kwargs["max_tokens"] = max(max_tokens, 6000)
        resp = client.messages.create(**kwargs)
        return "".join(b.text for b in resp.content if b.type == "text")
    resp = client.chat.completions.create(
        model=model, temperature=0.2,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": context}])
    return resp.choices[0].message.content or ""


# ── 1. CVE analysis ───────────────────────────────────────────────────────────
_CVE_SYSTEM = """You are a vulnerability analyst. You are given the authoritative
facts for a single CVE (NVD description, CVSS, CISA KEV status, FIRST EPSS
exploitation probability, affected products). Write GitHub-flavoured Markdown
with EXACTLY these sections and headings:

## Executive Summary
2-4 sentences for a CISO: what the flaw is, why it matters, and urgency. Lead
with business risk.

## Technical Analysis
What the vulnerability is, the affected component, attack vector and complexity,
and pre-conditions for exploitation.

## Risk Assessment
Combine CVSS (severity), EPSS (likelihood of exploitation), and KEV (confirmed
in-the-wild use) into a clear prioritisation verdict. If KEV-listed, say patch
immediately. Do not invent exploitation you weren't told about.

## MITRE ATT&CK Mapping
A short table | Tactic | Technique | ID | of the techniques an attacker would
plausibly use to exploit this. Only include techniques you are confident about.

## Mitigation & Remediation
Concrete, prioritised steps: patch/fixed version if known, workarounds,
detection, and compensating controls.

Be factual and grounded in the provided data. Never fabricate CVSS, dates, or a
fixed version you weren't given."""


def _kev_entry(cve_id: str) -> dict | None:
    try:
        data = kev.fetch_kev(look_back_days=36500, limit=1000000)
    except Exception as err:
        log.info("KEV fetch failed: %s", err)
        return None
    for v in data.get("vulnerabilities", []):
        if (v.get("cve") or "").upper() == cve_id.upper():
            return v
    return None


def _epss_row(cve_id: str) -> dict | None:
    try:
        scores = epss.fetch_epss([cve_id]).get("scores", [])
    except Exception as err:
        log.info("EPSS fetch failed: %s", err)
        return None
    return scores[0] if scores else None


def analyze_cve(cve_id: str, cfg) -> str:
    cve_id = (cve_id or "").strip().upper()
    if not CVE_RE.match(cve_id):
        raise ValueError("Enter a valid CVE ID, e.g. CVE-2024-3400")
    log.info("Analyzing %s", cve_id)

    import apikeys
    record = nvd.fetch_cve(cve_id, api_key=apikeys.get("NVD_API_KEY"))
    if not record:
        raise RuntimeError(f"{cve_id} was not found in the NVD. Check the ID and try again.")

    kev_entry = _kev_entry(cve_id)
    ep = _epss_row(cve_id)
    epss_pct = f"{ep['epss'] * 100:.1f}%" if ep else "n/a"
    epss_perc = f"{ep['percentile'] * 100:.0f}th pct" if ep else ""

    ctx = (f"CVE: {record['cve']}\n"
           f"Published: {record.get('published')}  Status: {record.get('status')}\n"
           f"CVSS base score: {record.get('cvss')} ({record.get('severity')})\n"
           f"CVSS vector: {record.get('vector')}\n"
           f"EPSS (30-day exploitation probability): {epss_pct} {epss_perc}\n"
           f"CISA KEV (known exploited): {'YES' if kev_entry else 'No'}\n")
    if kev_entry:
        ctx += (f"KEV ransomware use: {kev_entry.get('ransomware')}\n"
                f"KEV required action: {kev_entry.get('action')}\n"
                f"KEV due date: {kev_entry.get('due_date')}\n")
    if record.get("products"):
        ctx += "Affected products (CPE): " + ", ".join(record["products"]) + "\n"
    ctx += "\nNVD description:\n" + record.get("description", "")

    try:
        narrative = _complete(cfg, _CVE_SYSTEM, ctx).strip()
    except Exception as err:
        log.exception("CVE narrative failed")
        narrative = ("## Executive Summary\nAutomated analysis unavailable "
                     f"({err}). The grounded facts are in the table above.\n\n"
                     "## Mitigation & Remediation\n- Apply the vendor's latest patch.\n"
                     "- Restrict exposure of affected components until patched.")

    kev_cell = "**Yes**" + (" · ransomware-linked" if (kev_entry or {}).get("ransomware", "").lower() == "known" else "") if kev_entry else "No"
    facts = [
        f"# CVE Analysis — {record['cve']}", "",
        "| Attribute | Value |", "|-----------|-------|",
        f"| CVSS base score | {record.get('cvss')} ({record.get('severity') or 'n/a'}) |",
        f"| CVSS vector | `{record.get('vector') or 'n/a'}` |",
        f"| EPSS (30-day exploit prob.) | {epss_pct} {('· ' + epss_perc) if epss_perc else ''} |",
        f"| CISA KEV (actively exploited) | {kev_cell} |",
        f"| Published | {record.get('published') or 'n/a'} |",
        f"| NVD status | {record.get('status') or 'n/a'} |",
    ]
    if record.get("products"):
        facts.append(f"| Affected products | {', '.join(record['products'][:12])} |")
    parts = facts + ["", narrative]
    if record.get("references"):
        parts += ["", "## References", ""] + [f"- {u}" for u in record["references"]]
    parts += ["", "## Sources & Method", "",
              "- Vulnerability data: NVD (NIST)",
              "- Exploitation status: CISA KEV catalog",
              "- Exploitation probability: FIRST EPSS",
              "- Analysis & ATT&CK mapping: AI-assisted; verify before acting."]
    return "\n".join(parts)


# ── 2. Threat-actor profile ───────────────────────────────────────────────────
_ACTOR_SYSTEM = """You are a threat-intelligence analyst. Given a threat-actor or
malware/ransomware name, compile a structured profile from well-established
public threat intelligence. Write GitHub-flavoured Markdown with these sections:

## Overview
Who/what this is (APT group, ransomware operation, etc.), suspected origin, and
primary motivation (espionage, financial, destructive).

## Known Aliases
Comma-separated list of common aliases used by major vendors.

## Attribution Confidence
State attribution and your confidence (High/Medium/Low) and the basis. Be honest
about uncertainty.

## Target Industries & Regions
The sectors and geographies most associated with this actor.

## TTPs (MITRE ATT&CK)
A table | Tactic | Technique | ID | covering this actor's hallmark techniques
(use real ATT&CK technique IDs such as T1566). Group by tactic order.

## Notable Malware & Tools
Bullet list of associated malware families and tooling.

## Recent Campaigns
2-4 bullets on notable campaigns. CLEARLY mark recency as needing verification —
your knowledge has a cutoff and campaign activity changes constantly.

## Detection & Threat Hunting
3-5 starter hunting ideas tied to the TTPs above, with at least two example
Microsoft Sentinel / Defender KQL snippets in fenced ```kql blocks.

## Recommendations
Prioritised defensive actions tailored to this actor's TTPs.

Use real ATT&CK IDs you are confident about; never fabricate IDs. Separate
durable, well-established facts from time-sensitive claims that need
verification."""


def profile_actor(name: str, cfg) -> str:
    name = (name or "").strip()
    if not name:
        raise ValueError("Enter a threat-actor, group, or malware name (e.g. LockBit, APT29).")
    log.info("Profiling actor %s", name)
    ctx = (f"Produce a threat-actor intelligence profile for: {name}\n\n"
           "Compile from established public threat intelligence (MITRE ATT&CK "
           "Groups, vendor reporting). Mark any recent/time-sensitive claims as "
           "requiring verification.")
    try:
        body = _complete(cfg, _ACTOR_SYSTEM, ctx, max_tokens=3000).strip()
    except Exception as err:
        log.exception("Actor profile failed")
        raise RuntimeError(f"Could not generate the profile: {err}")
    note = ("> **Analyst note:** This profile is compiled from public threat "
            "intelligence and AI synthesis. Verify attribution and any recent "
            "campaign claims against primary sources (MITRE ATT&CK, CISA, vendor "
            "advisories) before operational use.")
    return f"# Threat Actor Profile — {name}\n\n{note}\n\n{body}"


# ── 3. Threat-hunting query generation ────────────────────────────────────────
_HUNT_SYSTEM = """You are a detection engineer. Given a threat (actor, malware,
technique, or behaviour) and a target query language, produce threat-hunting
content as GitHub-flavoured Markdown:

## Hunting Hypothesis
1-2 sentences on what malicious activity you're hunting for and why.

## Queries
3-6 queries in fenced code blocks in the requested language. Each query MUST be
preceded by a one-line description of what it surfaces. Keep queries syntactically
plausible and commented. Map each to a MITRE ATT&CK technique ID where relevant.

## Investigation Steps
A numbered triage workflow: what to check when a query returns hits, how to
confirm true positives, and escalation guidance.

CRITICAL: these queries are AI-generated starting points. Table/field names vary
by environment and must be validated. Do not invent product features."""

HUNT_LANGS = {
    "sentinel": "Microsoft Sentinel KQL (Log Analytics tables like SecurityEvent, DeviceProcessEvents, SigninLogs)",
    "defender": "Microsoft Defender XDR advanced hunting KQL (tables like DeviceProcessEvents, DeviceNetworkEvents, EmailEvents)",
    "splunk": "Splunk SPL",
    "sigma": "Sigma detection rules (YAML)",
}


def hunt_queries(subject: str, platform: str, cfg) -> str:
    subject = (subject or "").strip()
    if not subject:
        raise ValueError("Describe what to hunt for (e.g. 'LockBit ransomware', 'T1059 PowerShell abuse').")
    lang = HUNT_LANGS.get((platform or "sentinel").lower(), HUNT_LANGS["sentinel"])
    log.info("Generating hunt queries for %s (%s)", subject, platform)
    ctx = (f"Threat to hunt: {subject}\nTarget query language: {lang}\n\n"
           "Generate the hunting package in that language.")
    try:
        body = _complete(cfg, _HUNT_SYSTEM, ctx, max_tokens=2800).strip()
    except Exception as err:
        log.exception("Hunt generation failed")
        raise RuntimeError(f"Could not generate hunting queries: {err}")
    note = ("> **Validate before use:** These queries are AI-generated starting "
            "points. Confirm table and field names against your own schema and "
            "test in a non-production workspace first.")
    return f"# Threat Hunting — {subject}\n\n_Target: {lang}_\n\n{note}\n\n{body}"
