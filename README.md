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

### Run a single briefing now

```bash
docker compose run --rm -e RUN_MODE=once threat-intel-agent
```

The briefing is written to `./reports/` as both `.md` and `.html`.

### Run on a schedule (default 07:00 UTC daily)

```bash
docker compose up -d        # RUN_MODE defaults to schedule in compose
docker compose logs -f
```

Change the cadence with `SCHEDULE_CRON` (standard cron, UTC), e.g. `0 6 * * 1-5`
for 06:00 on weekdays.

### Web UI (browser app)

Run the front end and drive it from a browser — set parameters, trigger a
briefing, watch the agent's progress live, and read past reports:

```bash
pip install -r requirements.txt
python webapp.py
```

Then open **http://localhost:5000**. With Docker: `docker compose up web` and
open the same URL. Reports are saved to `./reports/` and listed in the UI.

The web UI is organised into tabs: **Generate** (on-demand briefing), **Analyze
file**, **Schedule** (recurring emailed briefings), **History** (view / download
HTML, PDF, Markdown / preview / delete), **Dashboard**, and **Settings**.

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
