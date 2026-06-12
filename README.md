# Threat Intelligence Briefing Agent (self-hosted, Dockerized)

An open, self-hosted re-creation of the pattern behind the
[Microsoft Security Copilot Threat Intelligence Briefing Agent](https://learn.microsoft.com/en-us/copilot/security/threat-intel-briefing-agent):
an autonomous agent that gathers live threat-intel and vulnerability signals,
**dynamically decides its next step**, writes a leadership-ready briefing, and
emails it on a schedule.

This is **not** affiliated with Microsoft. It uses free, public threat feeds and
your own LLM backend (Anthropic Claude by default; also OpenAI, Azure OpenAI, or
a local model via Ollama).

## How it mirrors the Microsoft agent

| Microsoft agent | This project |
|---|---|
| Dynamically chooses next step based on previous outcome | LLM tool-calling loop in `agent/loop.py` |
| Threat Intelligence + Defender vulnerability signals | KEV, NVD, EPSS, ThreatFox collectors in `collectors/` |
| Input params (insights, look-back, region, industry, email) | `config.py` / `.env` |
| Scheduled or on-demand trigger | `RUN_MODE=schedule` (cron) or `once` |
| Briefing report with summary + technical analysis | `briefing/report.py` (Markdown + HTML) |

## Data sources (all free)

- **CISA KEV** — vulnerabilities confirmed exploited in the wild (no key)
- **NVD** — recent high-severity CVEs (optional API key raises rate limits)
- **FIRST EPSS** — exploit-probability scores for prioritization (no key)
- **abuse.ch ThreatFox** — recent IOCs (needs a free `ABUSECH_AUTH_KEY`)

## Quick start

```bash
cd threat-intel-briefing-agent
cp .env.example .env          # then edit .env
```

Set at minimum an LLM backend in `.env`. Default is Anthropic Claude:

```env
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-opus-4-7
```

The Claude backend uses the native tool-use loop with **adaptive thinking** and
**prompt caching** (the system prompt + tool definitions are cached and reused
across every step of the agent loop, cutting cost and latency). To use a
different provider instead, set `LLM_PROVIDER=openai` (or `azure` / `ollama`)
and the matching keys.

### Run with Docker (recommended)

The container runs the full web app (UI + scheduler + scanner, with `nmap`
pre-installed). One service, one persistent volume.

```bash
docker compose up -d --build
docker compose logs -f          # watch startup
```

Open **http://localhost:5000** and sign in (first run seeds an admin from
`ADMIN_USER` / `ADMIN_PASSWORD` in `.env`, default `admin` / `admin`).

All state — reports, users, schedules, assets, alerts, branding, the session
secret — is stored in **`./data/`** on the host (mounted at `/app/data`). Back up
that folder to preserve everything. Update with:

```bash
docker compose up -d --build    # rebuild after code changes
docker compose down             # stop
```

**Run a one-off briefing from the CLI** (no UI) using the same image:

```bash
docker compose run --rm web python main.py
```

**Scan your local network:** a bridged container can't see your LAN. On a Linux
host, switch to host networking — comment out the `ports:` line and uncomment
`network_mode: host` + `cap_add` in `docker-compose.yml`, then rebuild.

### Run without Docker

```bash
pip install -r requirements.txt
python webapp.py                # web app on http://localhost:5000
# or: python main.py            # one-off / cron briefing, no UI
```

The web UI is organised into tabs — **Generate**, **Analyze file**, **Network
scan**, **Assets**, **Schedule**, **History**, **Settings** (+ **Admin** for
admins) — plus a floating **AI assistant** chat bubble.

### Network vulnerability scan

The **Network scan** tab (requires the *Scan networks* privilege) discovers open
ports/services on an authorized target and correlates detected service versions
with known CVEs.

- **Basic** — fast threaded TCP connect scan of common ports with banner grab.
- **Advanced** — custom port ranges, banner/version detection, CVE correlation
  (NVD + CISA KEV), nmap timing, and — if `nmap` is installed on the host —
  service/version detection (`-sV`), OS detection (`-O`), and vuln NSE scripts
  (`--script vuln`).

Targets accept a host, IP, or CIDR (capped at 256 hosts). An **authorization
checkbox is required** before each scan — only scan systems you own or are
explicitly authorized to test. CVEs are *potential* matches (grounded in NVD),
labelled for verification. The pure-Python scanner needs no extra packages;
`nmap` is an optional external tool.

### AI security assistant

The **AI assistant** tab is a chat that answers security questions — "why is this
vulnerable?", "how do I remediate CVE-X?", "what's the business impact?" — and
generates remediation as PowerShell / Bash / Azure CLI. Optionally **ground the
chat in one of your reports** (a scan or analysis) so answers reference its actual
findings, hosts, and CVEs instead of generic advice.

### OSINT recon (theHarvester-style)

The **Recon** tab (requires the *Scan networks* privilege) maps a domain's public
footprint without scraping search engines:

- **Subdomains** from Certificate Transparency logs (crt.sh — free, no key)
- **DNS records** (A/AAAA/MX/NS/TXT/CNAME) via DNS-over-HTTPS (Cloudflare — free)
- **Hosts/IPs** by resolving discovered subdomains
- **Optional vendor enrichment** when a key is set in `.env`: **Shodan**
  (`SHODAN_API_KEY` — open ports, org, known vulns) and **Hunter.io**
  (`HUNTER_API_KEY` — emails)

It also **deeply inspects** what it finds:
- **Web technology fingerprinting** — fetches each live host and detects server,
  CDN, CMS, framework, and analytics (WordPress, Shopify, Drupal, Next.js, React,
  Cloudflare, etc.) from headers + HTML.
- **IP intelligence** — ASN, ISP/hosting org, geolocation, and reverse DNS for
  every discovered IP (via ip-api, free).
- **Email security** — SPF and DMARC presence (flags spoofing risk if missing).

Output is an AI attack-surface summary + tables, saved to History (and exportable
to CSV/Excel); discovered hosts are added to the **Assets** inventory. Requires an
authorization checkbox — only assess domains you own or are authorized to test.

### Assets, scheduled scans & alerts

- **Asset inventory** — every scan upserts discovered hosts (IP, hostname, OS,
  open ports, per-host risk, last scan) into an **Assets** tab.
- **Scheduled scans** — set a recurring scan of a target (daily/weekly/monthly,
  UTC) from the Network scan tab; reports land in History automatically.
- **Alerts** — admins configure (in Settings) email + Microsoft Teams + Slack +
  generic-webhook notifications that fire when a scan's findings meet a severity
  threshold (KEV CVEs always trigger). Includes a "Send test alert" button.

### Reports, exports & dashboard

Every report (briefing, analysis, scan) can be downloaded as **HTML, PDF,
Markdown, CSV, or Excel** from the History tab — CSV/Excel are built from the
report's tables (one Excel sheet per table). Network scans compute a **risk
score (0–100)** and severity breakdown, surfaced on the **Dashboard** ("Latest
network scan — risk"). Advanced scans can be written in a **Technical** (detailed)
or **Executive** (business-impact) report style.

### Login & user management

The web app requires sign-in. On first run an admin account is created from
`ADMIN_USER` / `ADMIN_PASSWORD` in `.env` (default `admin` / `admin` — **change
it after first login** via Settings → Change my password). Passwords are stored
salted+hashed (never plaintext) in `users.json`.

Admins get an **Admin** tab to create users and grant per-feature privileges:
**Generate briefings**, **Analyze files**, **Manage email schedule**, **Delete
history**, and **Administer users**. Tabs and actions are shown/enforced per the
signed-in user's privileges. The last administrator cannot be deleted or demoted.

> Self-hosted/internal use. Don't expose to the public internet without TLS and
> a hardened deployment. To persist logins across container rebuilds, mount
> `users.json` and `.flask_secret` as volumes.

### Analyze a threat document (upload)

On the **Analyze file** tab, upload a PDF or Excel/CSV threat report (e.g. a CISA
advisory). The agent extracts the text, pulls out indicators with regex, and the
model produces a structured report:

- **Summary of Threat**
- **Affected Products**
- **CVEs** (clickable, linked to NVD)
- **Indicators of Compromise** — IPs, domains, URLs, emails, MD5/SHA1/SHA256,
  each with a reputation lookup link (VirusTotal / AbuseIPDB). Set `VT_API_KEY`
  in `.env` to get live VirusTotal reputation scores inline.
- **Recommendations**

Indicators are extracted deterministically (defanged forms like `1.2.3[.]4` are
handled), so long hashes are never altered. Benign reporting/vendor domains
(cisa.gov, fbi.gov, etc.) are filtered out of the IOC table.

**Vendor-API enrichment** — when API keys are set in `.env`, each analysis also:
- computes the file's MD5/SHA1/SHA256 and looks the file up on **VirusTotal**
  (detection ratio + threat label) — useful when the upload is a suspected sample;
- enriches extracted IOCs via **VirusTotal** (IPs/domains/hashes) and **AbuseIPDB**
  (IP abuse score), shown with **source, verdict, and confidence**.

Vendor keys (VirusTotal, AbuseIPDB, Shodan, Hunter.io, NVD) are entered by an
admin in **Settings → Vendor API keys** — no `.env` editing needed. A stored key
overrides the matching `.env` variable if both are set; clearing it reverts to
`.env`. Without keys, the IOC table still shows clickable VT/AbuseIPDB lookup
links. Lookups are capped (`ENRICH_BUDGET`, default 12) to respect rate limits.

### Without Docker (CLI / scheduled)

```bash
pip install -r requirements.txt
python main.py
```

## Configuration (input parameters)

These mirror the Microsoft agent's inputs — set them in `.env`:

| Variable | Meaning | Default |
|---|---|---|
| `INSIGHTS_TO_RESEARCH` | Target number of prioritized vulnerabilities | `10` |
| `LOOK_BACK_DAYS` | How far back to research | `7` |
| `REGION` | Geographic focus | `Global` |
| `INDUSTRY` | Sector focus | `Technology` |
| `ASSET_KEYWORDS` | Comma-separated tech/vendor focus (e.g. `Fortinet,Exchange`) | empty |
| `EMAIL_ENABLED` + SMTP vars | Email delivery of the briefing | off |

## How it works

1. `main.py` loads config and starts the run (once or scheduled).
2. `agent/loop.py` gives the LLM a set of tools and lets it decide which feeds to
   query and in what order, prioritizing actively-exploited > high-EPSS > high-CVSS.
3. The agent stops calling tools when it has enough and writes the briefing as
   Markdown.
4. `briefing/report.py` renders Markdown → styled HTML; `delivery.py` emails it.

## Extending it

- **Add a feed**: drop a collector in `collectors/`, then register a tool spec +
  dispatch branch in `agent/tools.py`.
- **Internal signals**: to truly match the Microsoft agent, add a collector that
  reads *your* asset inventory or vuln-management export and have the agent
  correlate external threats against assets you actually run.
- **Other LLMs**: set `LLM_PROVIDER=openai`, `azure`, or `ollama` in `.env` (default is `anthropic`).

## Notes & limits

- The agent only reports what the feeds return; it is instructed not to invent
  CVEs, scores, or IOCs. Always verify critical findings before acting.
- NVD caps the publish-date window at 120 days; `LOOK_BACK_DAYS` is clamped.
- ThreatFox now requires a free auth key; without it that source is skipped
  gracefully and the agent continues with the others.
