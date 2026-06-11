"""Browser front end for the Threat Intelligence Briefing Agent.

Run:  python webapp.py   ->  open http://localhost:5000
"""
from __future__ import annotations

import copy
import datetime as _dt
import glob
import io
import json
import logging
import os
import re
import threading
import uuid

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from flask import (Flask, abort, jsonify, render_template_string, request,
                   send_file)

from agent.loop import Cancelled, run_agent
from briefing import delivery, report
from config import CONFIG

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("webapp")

app = Flask(__name__)
JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()

SCHEDULE_FILE = os.getenv("SCHEDULE_FILE", "schedule.json")
_SCHED = BackgroundScheduler(timezone="UTC")
_JOB_ID = "email_briefing"

SEVERITY_CHOICES = [(9.0, "Critical only"), (7.0, "High and Critical"),
                    (4.0, "Medium and above"), (0.0, "All severities")]

# Preset key -> instruction snippet appended to the agent's system prompt.
PRESETS = {
    "ransomware": "Focus on vulnerabilities with known ransomware-campaign use and call them out explicitly.",
    "patch": "For each vulnerability, state patch or mitigation availability and the fixed version if known.",
    "mitre": "Map each major threat to relevant MITRE ATT&CK techniques, including technique IDs.",
    "exec": "Write in a concise executive tone for a CISO audience; lead with business impact.",
}
PRESET_LABELS = {
    "ransomware": "Ransomware-linked only",
    "patch": "Include patch / mitigation info",
    "mitre": "Map to MITRE ATT&CK",
    "exec": "Executive tone",
}


# ── helpers ─────────────────────────────────────────────────────────────────
class _ListHandler(logging.Handler):
    def __init__(self, buffer):
        super().__init__()
        self.buffer = buffer

    def emit(self, record):
        self.buffer.append(self.format(record))


def _build_instructions(form) -> str:
    parts = [PRESETS[k] for k in PRESETS if form.get("preset_" + k) == "on"]
    free = (form.get("extra_instructions") or "").strip()
    if free:
        parts.append(free)
    return "\n".join("- " + p for p in parts)


def _apply_params(cfg, p: dict):
    if p.get("region"):
        cfg.region = str(p["region"]).strip()
    if p.get("industry"):
        cfg.industry = str(p["industry"]).strip()
    try:
        cfg.look_back_days = int(p.get("look_back_days") or cfg.look_back_days)
    except (TypeError, ValueError):
        pass
    try:
        cfg.insights_to_research = int(p.get("insights") or cfg.insights_to_research)
    except (TypeError, ValueError):
        pass
    try:
        cfg.min_cvss = float(p.get("min_cvss"))
    except (TypeError, ValueError):
        pass
    kw = str(p.get("asset_keywords") or "").strip()
    if kw:
        cfg.asset_keywords = [k.strip() for k in kw.split(",") if k.strip()]
    if p.get("extra_instructions"):
        cfg.extra_instructions = str(p["extra_instructions"])
    return cfg


def _generate(cfg, email_to=None, cancel_event=None) -> dict:
    markdown = run_agent(cfg, cancel_event=cancel_event)
    if not markdown.strip():
        raise RuntimeError("Agent returned an empty briefing.")
    out = report.render(markdown)
    emailed = False
    if email_to:
        mail_cfg = copy.deepcopy(cfg.email)
        mail_cfg.enabled = True
        mail_cfg.to = email_to
        emailed = delivery.send_email(
            mail_cfg, subject=out["title"], html_body=out["html"], markdown_body=markdown,
        )
    return {"title": out["title"], "filename": os.path.basename(out["html_path"]),
            "emailed": emailed}


def _list_reports():
    paths = sorted(glob.glob(os.path.join(report.REPORTS_DIR, "*.html")),
                   key=os.path.getmtime, reverse=True)
    return [{"filename": os.path.basename(p)} for p in paths]


def _smtp_ready():
    e = CONFIG.email
    return bool(e.smtp_host and e.sender)


def _latest_stats():
    mds = sorted(glob.glob(os.path.join(report.REPORTS_DIR, "*.md")),
                 key=os.path.getmtime, reverse=True)
    total = len(glob.glob(os.path.join(report.REPORTS_DIR, "*.html")))
    if not mds:
        return {"total": total, "cves": 0, "when": None}
    with open(mds[0], encoding="utf-8") as fh:
        txt = fh.read()
    cves = len(set(re.findall(r"CVE-\d{4}-\d{4,7}", txt)))
    when = _dt.datetime.fromtimestamp(os.path.getmtime(mds[0])).strftime("%Y-%m-%d %H:%M")
    return {"total": total, "cves": cves, "when": when}


# ── on-demand job ───────────────────────────────────────────────────────────
def _run_job(job_id, cfg, email_to, cancel_event):
    job = JOBS[job_id]
    handler = _ListHandler(job["logs"])
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        job["report"] = _generate(cfg, email_to, cancel_event)
        job["status"] = "done"
        log.info("Briefing ready: %s", job["report"]["title"])
    except Cancelled:
        job["status"] = "stopped"
        job["error"] = "Stopped by user."
        log.info("Briefing stopped by user")
    except Exception as err:
        job["status"] = "error"
        job["error"] = str(err)
        log.exception("Briefing job failed")
    finally:
        root.removeHandler(handler)


# ── scheduled email job ─────────────────────────────────────────────────────
def _scheduled_run():
    sched = _load_schedule()
    if not sched or not sched.get("enabled"):
        return
    log.info("Running scheduled briefing -> %s", sched.get("email"))
    cfg = _apply_params(copy.deepcopy(CONFIG), sched)
    status = "ok"
    try:
        meta = _generate(cfg, email_to=sched.get("email"))
        status = "sent" if meta["emailed"] else "generated (not emailed)"
        log.info("Scheduled briefing done: %s (%s)", meta["title"], status)
    except Exception:
        status = "error"
        log.exception("Scheduled briefing failed")
    sched["last_run"] = _dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    sched["last_status"] = status
    _save_schedule(sched)


def _load_schedule():
    try:
        with open(SCHEDULE_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_schedule(data):
    with open(SCHEDULE_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def _register_schedule(sched):
    if _SCHED.get_job(_JOB_ID):
        _SCHED.remove_job(_JOB_ID)
    if not sched.get("enabled"):
        return
    hour, minute = (sched.get("time") or "07:00").split(":")
    kwargs = {"hour": int(hour), "minute": int(minute)}
    if sched.get("frequency") == "weekly":
        kwargs["day_of_week"] = sched.get("weekday", "mon")
    _SCHED.add_job(_scheduled_run, CronTrigger(timezone="UTC", **kwargs), id=_JOB_ID)
    log.info("Email schedule registered: %s", kwargs)


def _next_run():
    job = _SCHED.get_job(_JOB_ID)
    return job.next_run_time.strftime("%Y-%m-%d %H:%M UTC") if job and job.next_run_time else None


# ── routes ──────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template_string(
        _PAGE, cfg=CONFIG, reports=_list_reports(), provider=CONFIG.llm.provider,
        model=getattr(CONFIG.llm, f"{CONFIG.llm.provider}_model", ""),
        severities=SEVERITY_CHOICES, schedule=_load_schedule(), next_run=_next_run(),
        smtp_ready=_smtp_ready(), stats=_latest_stats(),
        presets=PRESET_LABELS,
    )


@app.route("/run", methods=["POST"])
def run():
    params = request.form.to_dict()
    params["extra_instructions"] = _build_instructions(request.form)
    cfg = _apply_params(copy.deepcopy(CONFIG), params)
    email_to = (request.form.get("email") or "").strip() or None
    job_id = uuid.uuid4().hex[:12]
    cancel = threading.Event()
    with _LOCK:
        JOBS[job_id] = {"status": "running", "logs": [], "report": None,
                        "error": None, "cancel": cancel}
    threading.Thread(target=_run_job, args=(job_id, cfg, email_to, cancel), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/status/<job_id>")
def status(job_id):
    job = JOBS.get(job_id)
    if not job:
        abort(404)
    return jsonify({k: v for k, v in job.items() if k != "cancel"})


@app.route("/stop/<job_id>", methods=["POST"])
def stop(job_id):
    job = JOBS.get(job_id)
    if not job:
        abort(404)
    if job.get("cancel"):
        job["cancel"].set()
    return jsonify({"ok": True})


@app.route("/schedule", methods=["POST"])
def save_schedule():
    f = request.form
    presets = [k for k in PRESETS if f.get("preset_" + k) == "on"]
    free = (f.get("extra_instructions") or "").strip()
    composed = "\n".join("- " + PRESETS[k] for k in presets)
    if free:
        composed += ("\n" if composed else "") + "- " + free
    sched = {
        "enabled": f.get("enabled") == "on",
        "frequency": f.get("frequency", "daily"),
        "weekday": f.get("weekday", "mon"),
        "time": f.get("time", "07:00"),
        "email": (f.get("email") or "").strip(),
        "region": f.get("region", CONFIG.region),
        "industry": f.get("industry", CONFIG.industry),
        "min_cvss": f.get("min_cvss", CONFIG.min_cvss),
        "look_back_days": f.get("look_back_days", CONFIG.look_back_days),
        "insights": f.get("insights", CONFIG.insights_to_research),
        "asset_keywords": f.get("asset_keywords", ""),
        "presets": presets,
        "extra_instructions_free": free,
        "extra_instructions": composed,
        "last_run": _load_schedule().get("last_run"),
        "last_status": _load_schedule().get("last_status"),
    }
    _save_schedule(sched)
    _register_schedule(sched)
    return jsonify({"ok": True, "next_run": _next_run(), "enabled": sched["enabled"]})


@app.route("/test-email", methods=["POST"])
def test_email():
    to = (request.form.get("email") or "").strip()
    if not to:
        return jsonify({"ok": False, "error": "Enter a recipient address first."})
    mail_cfg = copy.deepcopy(CONFIG.email)
    mail_cfg.enabled = True
    mail_cfg.to = to
    ok = delivery.send_email(
        mail_cfg, subject="Test - Threat Intelligence Briefing Agent",
        html_body="<p>This is a test message from your Threat Intelligence Briefing Agent. "
                  "If you received it, SMTP is configured correctly.</p>",
        markdown_body="Test message from your Threat Intelligence Briefing Agent. SMTP works.",
    )
    return jsonify({"ok": ok, "error": None if ok else "Send failed - check SMTP settings in .env."})


@app.route("/reports/<path:filename>")
def view_report(filename):
    safe = os.path.basename(filename)
    full = os.path.join(report.REPORTS_DIR, safe)
    if not os.path.isfile(full):
        abort(404)
    return send_file(os.path.abspath(full))


@app.route("/download/<path:filename>")
def download_report(filename):
    """Download a briefing as HTML (default), PDF (?fmt=pdf), or Markdown (?fmt=md)."""
    stem = os.path.splitext(os.path.basename(filename))[0]
    fmt = request.args.get("fmt", "html").lower()
    html_path = os.path.join(report.REPORTS_DIR, stem + ".html")
    md_path = os.path.join(report.REPORTS_DIR, stem + ".md")

    if fmt == "md":
        if not os.path.isfile(md_path):
            abort(404)
        return send_file(os.path.abspath(md_path), as_attachment=True,
                         download_name=stem + ".md")

    if not os.path.isfile(html_path):
        abort(404)

    if fmt == "pdf":
        try:
            from xhtml2pdf import pisa
        except ImportError:
            abort(501, "PDF export needs xhtml2pdf: pip install xhtml2pdf")
        with open(html_path, encoding="utf-8") as fh:
            html = fh.read()
        buf = io.BytesIO()
        result = pisa.CreatePDF(src=html, dest=buf)
        if result.err:
            abort(500, "PDF generation failed")
        buf.seek(0)
        return send_file(buf, mimetype="application/pdf", as_attachment=True,
                         download_name=stem + ".pdf")

    return send_file(os.path.abspath(html_path), as_attachment=True,
                     download_name=stem + ".html")


@app.route("/delete", methods=["POST"])
def delete_report():
    stem = os.path.splitext(os.path.basename(request.form.get("filename", "")))[0]
    if not stem:
        abort(400)
    removed = []
    for ext in (".html", ".md"):
        p = os.path.join(report.REPORTS_DIR, stem + ext)
        if os.path.isfile(p):
            os.remove(p)
            removed.append(os.path.basename(p))
    return jsonify({"ok": True, "removed": removed})


@app.route("/clear", methods=["POST"])
def clear_reports():
    count = 0
    for pattern in ("*.html", "*.md"):
        for p in glob.glob(os.path.join(report.REPORTS_DIR, pattern)):
            try:
                os.remove(p)
                count += 1
            except OSError:
                pass
    return jsonify({"ok": True, "deleted": count})


_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Threat Intelligence Briefing Agent</title>
<style>
  :root { --navy:#0f2a43; --line:#e2e5e9; --muted:#6b7280; --accent:#1d4671; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:'Segoe UI',-apple-system,Arial,sans-serif; background:#eef1f5; color:#1f2328; }
  header { background:linear-gradient(135deg,#0f2a43,#1d4671); color:#fff; padding:20px 28px; }
  header h1 { margin:0; font-size:20px; }
  .wrap { max-width:960px; margin:24px auto; padding:0 16px; display:grid; gap:20px; }
  .card { background:#fff; border:1px solid var(--line); border-radius:12px; padding:20px 22px; }
  .card h2 { margin:0 0 14px; font-size:15px; color:var(--navy); }
  .grid3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:14px; }
  label { display:block; font-size:12px; color:var(--muted); margin-bottom:4px; }
  input, select, textarea { width:100%; padding:9px 10px; border:1px solid var(--line); border-radius:6px; font-size:14px; background:#fff; font-family:inherit; }
  textarea { resize:vertical; min-height:60px; }
  button { background:var(--navy); color:#fff; border:0; padding:11px 20px; border-radius:6px; font-size:14px; cursor:pointer; margin-top:12px; }
  button:disabled { opacity:.5; cursor:not-allowed; }
  button.secondary { background:#eef1f4; color:var(--navy); border:1px solid var(--line); }
  .row { margin-top:14px; }
  .presets { display:flex; flex-wrap:wrap; gap:14px; margin-top:6px; }
  .presets label { display:flex; align-items:center; gap:6px; font-size:13px; color:#1f2328; margin:0; }
  .presets input { width:auto; }
  .check { display:flex; align-items:center; gap:8px; margin-top:6px; }
  .check input { width:auto; }
  .stats { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; }
  .stat { background:#f7f9fb; border:1px solid var(--line); border-radius:10px; padding:14px; }
  .stat .n { font-size:22px; font-weight:700; color:var(--navy); }
  .stat .l { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.05em; margin-top:4px; }
  .badge { font-size:11px; padding:2px 8px; border-radius:999px; }
  .badge.on { background:#dcfce7; color:#166534; } .badge.off { background:#f3f4f6; color:#6b7280; }
  .console { background:#0b1622; color:#cfe3f7; font-family:Consolas,monospace; font-size:12px; border-radius:8px; padding:14px; height:240px; overflow:auto; white-space:pre-wrap; display:none; margin-top:14px; }
  .pill { font-size:11px; padding:2px 8px; border-radius:999px; background:#eef1f4; color:var(--muted); margin-left:8px; }
  .ok { color:#1a7f37; } .err { color:#b42318; }
  .note { font-size:12px; color:var(--muted); margin-top:8px; }
  .warn { background:#fff7ed; border:1px solid #fed7aa; color:#9a3412; font-size:12px; padding:8px 10px; border-radius:6px; margin-top:10px; }
  ul.reports { list-style:none; margin:0; padding:0; }
  ul.reports li { padding:10px 0; border-bottom:1px solid var(--line); display:flex; justify-content:space-between; align-items:center; gap:10px; }
  ul.reports li:last-child { border-bottom:0; }
  ul.reports li .name { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  a { color:#1f6feb; text-decoration:none; } a:hover { text-decoration:underline; }
  .actions { display:flex; gap:6px; align-items:center; flex-shrink:0; }
  .dl, .pv { font-size:12px; border:1px solid var(--line); padding:4px 9px; border-radius:6px; color:#1f6feb; cursor:pointer; background:#fff; }
  .dl:hover, .pv:hover { background:#f4f8ff; text-decoration:none; }
  .del { background:#fff; color:#b42318; border:1px solid #f3c0b8; padding:4px 9px; border-radius:6px; font-size:12px; cursor:pointer; margin:0; }
  .del:hover { background:#fef2f2; }
  #stop-btn { background:#b42318; margin-left:8px; }
  #clear-btn { background:#b42318; font-size:13px; padding:8px 14px; }
  #search { margin-bottom:12px; }
  #preview { width:100%; height:520px; border:1px solid var(--line); border-radius:8px; margin-top:14px; display:none; background:#fff; }
</style></head>
<body>
<header><h1>Threat Intelligence Briefing Agent</h1></header>
<div class="wrap">

  <div class="card">
    <h2>Status</h2>
    <div class="stats">
      <div class="stat"><div class="n">{{ stats.total }}</div><div class="l">Saved briefings</div></div>
      <div class="stat"><div class="n">{{ stats.cves }}</div><div class="l">CVEs in latest</div></div>
      <div class="stat"><div class="n" style="font-size:14px">{% if smtp_ready %}<span class="badge on">Ready</span>{% else %}<span class="badge off">Not set</span>{% endif %}</div><div class="l">Email (SMTP)</div></div>
      <div class="stat"><div class="n" style="font-size:13px">{{ next_run or 'Off' }}</div><div class="l">Next scheduled run</div></div>
    </div>
    <div class="note">Engine: {{ provider }}{% if model %} &middot; {{ model }}{% endif %}{% if stats.when %} &middot; latest briefing {{ stats.when }}{% endif %}{% if schedule.last_run %} &middot; last scheduled run {{ schedule.last_run }} ({{ schedule.last_status }}){% endif %}</div>
  </div>

  <div class="card">
    <h2>Generate a briefing</h2>
    <form id="run-form">
      <div class="grid3">
        <div><label>Region focus</label><input name="region" value="{{ cfg.region }}"></div>
        <div><label>Industry focus</label><input name="industry" value="{{ cfg.industry }}"></div>
        <div><label>Minimum severity</label>
          <select name="min_cvss">
            {% for val,lbl in severities %}<option value="{{ val }}" {% if cfg.min_cvss == val %}selected{% endif %}>{{ lbl }}</option>{% endfor %}
          </select>
        </div>
        <div><label>Look-back (days)</label><input name="look_back_days" type="number" min="1" max="119" value="{{ cfg.look_back_days }}"></div>
        <div><label>Insights to research</label><input name="insights" type="number" min="1" max="50" value="{{ cfg.insights_to_research }}"></div>
        <div><label>Email this run to (optional, comma-separated)</label><input name="email" placeholder="you@company.com, team@company.com"></div>
      </div>
      <div class="row"><label>Asset / vendor keywords (comma-separated, optional)</label>
        <input name="asset_keywords" placeholder="Fortinet, Exchange, VMware" value="{{ cfg.asset_keywords|join(', ') }}"></div>
      <div class="row"><label>Focus presets</label>
        <div class="presets">
          {% for k,lbl in presets.items() %}<label><input type="checkbox" name="preset_{{ k }}"> {{ lbl }}</label>{% endfor %}
        </div>
      </div>
      <div class="row"><label>Extra instructions (optional)</label>
        <textarea name="extra_instructions" placeholder="e.g. emphasise OT/ICS impact; ignore browser CVEs"></textarea></div>
      <button id="run-btn" type="submit">Generate briefing</button>
      <button id="stop-btn" type="button" style="display:none">Stop</button>
      <span id="state" class="pill" style="display:none"></span>
    </form>
    <div id="console" class="console"></div>
  </div>

  <div class="card">
    <h2>Email schedule</h2>
    {% if not smtp_ready %}<div class="warn">SMTP isn't configured. Set SMTP_HOST, EMAIL_FROM (and login) in your .env, or scheduled briefings are generated but not emailed.</div>{% endif %}
    <form id="sched-form">
      <div class="check">
        <input type="checkbox" id="enabled" name="enabled" {% if schedule.enabled %}checked{% endif %}>
        <label for="enabled" style="margin:0">Enable recurring emailed briefings</label>
      </div>
      <div class="grid3" style="margin-top:12px">
        <div><label>Recipient(s) — comma-separated</label><input name="email" value="{{ schedule.email or '' }}" placeholder="ciso@company.com, soc@company.com"></div>
        <div><label>Frequency</label>
          <select name="frequency" id="freq">
            <option value="daily" {% if schedule.frequency != 'weekly' %}selected{% endif %}>Daily</option>
            <option value="weekly" {% if schedule.frequency == 'weekly' %}selected{% endif %}>Weekly</option>
          </select>
        </div>
        <div><label>Time (UTC)</label><input name="time" type="time" value="{{ schedule.time or '07:00' }}"></div>
        <div id="weekday-wrap"><label>Day of week</label>
          <select name="weekday">
            {% for d in ['mon','tue','wed','thu','fri','sat','sun'] %}<option value="{{ d }}" {% if schedule.weekday == d %}selected{% endif %}>{{ d|capitalize }}</option>{% endfor %}
          </select>
        </div>
        <div><label>Minimum severity</label>
          <select name="min_cvss">
            {% for val,lbl in severities %}<option value="{{ val }}" {% if (schedule.min_cvss|float if schedule.min_cvss else cfg.min_cvss) == val %}selected{% endif %}>{{ lbl }}</option>{% endfor %}
          </select>
        </div>
        <div><label>Region</label><input name="region" value="{{ schedule.region or cfg.region }}"></div>
        <div><label>Industry</label><input name="industry" value="{{ schedule.industry or cfg.industry }}"></div>
        <div><label>Look-back (days)</label><input name="look_back_days" type="number" min="1" max="119" value="{{ schedule.look_back_days or cfg.look_back_days }}"></div>
        <div><label>Insights</label><input name="insights" type="number" min="1" max="50" value="{{ schedule.insights or cfg.insights_to_research }}"></div>
      </div>
      <div class="row"><label>Focus presets</label>
        <div class="presets">
          {% for k,lbl in presets.items() %}<label><input type="checkbox" name="preset_{{ k }}" {% if k in (schedule.presets or []) %}checked{% endif %}> {{ lbl }}</label>{% endfor %}
        </div>
      </div>
      <div class="row"><label>Extra instructions (optional)</label>
        <textarea name="extra_instructions" placeholder="Steer the scheduled briefing...">{{ schedule.extra_instructions_free or '' }}</textarea></div>
      <button id="sched-btn" type="submit">Save schedule</button>
      <button id="test-btn" type="button" class="secondary">Send test email</button>
      <span id="sched-state" class="pill">{% if next_run %}Next run: {{ next_run }}{% else %}Not scheduled{% endif %}</span>
    </form>
    <div class="note">Times are UTC. The schedule runs only while this app is running.</div>
  </div>

  <div class="card">
    <h2>Past briefings</h2>
    <input id="search" type="search" placeholder="Filter briefings by name...">
    <ul class="reports" id="report-list">
      {% for r in reports %}
        <li data-file="{{ r.filename }}">
          <span class="name"><a href="/reports/{{ r.filename }}" target="_blank">{{ r.filename }}</a></span>
          <span class="actions">
            <button class="pv" type="button" data-file="{{ r.filename }}">Preview</button>
            <a class="dl" href="/download/{{ r.filename }}?fmt=html">HTML</a>
            <a class="dl" href="/download/{{ r.filename }}?fmt=pdf">PDF</a>
            <a class="dl" href="/download/{{ r.filename }}?fmt=md">MD</a>
            <button class="del" type="button" data-file="{{ r.filename }}">Delete</button>
          </span>
        </li>
      {% else %}
        <li style="color:#6b7280">No briefings yet - generate one above.</li>
      {% endfor %}
    </ul>
    {% if reports %}<button id="clear-btn" type="button">Clear all history</button>{% endif %}
    <iframe id="preview" title="Briefing preview"></iframe>
  </div>

</div>
<script>
const freq = document.getElementById('freq');
const wdWrap = document.getElementById('weekday-wrap');
function syncFreq(){ wdWrap.style.display = freq.value === 'weekly' ? 'block' : 'none'; }
freq.addEventListener('change', syncFreq); syncFreq();

const form = document.getElementById('run-form');
const btn = document.getElementById('run-btn');
const stopBtn = document.getElementById('stop-btn');
const con = document.getElementById('console');
const state = document.getElementById('state');
const list = document.getElementById('report-list');
const preview = document.getElementById('preview');
let currentJob = null;

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  btn.disabled = true; con.style.display = 'block'; con.textContent = '';
  state.style.display = 'inline'; state.textContent = 'running...'; state.className = 'pill';
  const res = await fetch('/run', { method:'POST', body: new FormData(form) });
  const { job_id } = await res.json();
  currentJob = job_id; stopBtn.style.display = 'inline-block'; stopBtn.disabled = false;
  poll(job_id);
});

stopBtn.addEventListener('click', async () => {
  if (!currentJob) return;
  stopBtn.disabled = true; state.textContent = 'stopping...';
  await fetch('/stop/' + currentJob, { method:'POST' });
});

function rowHtml(f) {
  return '<span class="name"><a href="/reports/' + f + '" target="_blank">' + f + '</a></span>' +
         '<span class="actions">' +
         '<button class="pv" type="button" data-file="' + f + '">Preview</button>' +
         '<a class="dl" href="/download/' + f + '?fmt=html">HTML</a>' +
         '<a class="dl" href="/download/' + f + '?fmt=pdf">PDF</a>' +
         '<a class="dl" href="/download/' + f + '?fmt=md">MD</a>' +
         '<button class="del" type="button" data-file="' + f + '">Delete</button></span>';
}
function addReportRow(f) {
  const empty = list.querySelector('li:not([data-file])');
  if (empty) empty.remove();
  const li = document.createElement('li');
  li.setAttribute('data-file', f);
  li.innerHTML = rowHtml(f);
  list.insertBefore(li, list.firstChild);
  if (!document.getElementById('clear-btn')) {
    const b = document.createElement('button');
    b.id = 'clear-btn'; b.type = 'button'; b.textContent = 'Clear all history';
    list.parentNode.insertBefore(b, preview);
  }
}

async function poll(jobId) {
  try {
    const r = await fetch('/status/' + jobId);
    const job = await r.json();
    con.textContent = (job.logs || []).join('\\n'); con.scrollTop = con.scrollHeight;
    if (job.status === 'running') { setTimeout(() => poll(jobId), 1200); return; }
    btn.disabled = false; stopBtn.style.display = 'none'; currentJob = null;
    if (job.status === 'done') {
      state.textContent = job.report.emailed ? 'done (emailed)' : 'done'; state.className = 'pill ok';
      con.textContent += '\\n\\nBriefing ready: ' + job.report.title;
      addReportRow(job.report.filename);
      window.open('/reports/' + job.report.filename, '_blank');
    } else if (job.status === 'stopped') {
      state.textContent = 'stopped'; state.className = 'pill';
      con.textContent += '\\n\\nStopped by user.';
    } else {
      state.textContent = 'error'; state.className = 'pill err';
      con.textContent += '\\n\\nError: ' + (job.error || 'unknown');
    }
  } catch (err) {
    btn.disabled = false; stopBtn.style.display = 'none'; state.textContent = 'error'; state.className = 'pill err';
    con.textContent += '\\n\\nError: ' + err;
  }
}

// preview + delete (event delegation)
list.addEventListener('click', async (e) => {
  if (e.target.classList.contains('pv')) {
    preview.src = '/reports/' + e.target.getAttribute('data-file');
    preview.style.display = 'block';
    preview.scrollIntoView({ behavior:'smooth' });
    return;
  }
  if (e.target.classList.contains('del')) {
    const f = e.target.getAttribute('data-file');
    if (!confirm('Delete ' + f + '?')) return;
    const fd = new FormData(); fd.append('filename', f);
    await fetch('/delete', { method:'POST', body: fd });
    const li = e.target.closest('li'); if (li) li.remove();
    if (!list.querySelector('li[data-file]')) {
      const cb = document.getElementById('clear-btn'); if (cb) cb.remove();
      list.innerHTML = '<li style="color:#6b7280">No briefings yet - generate one above.</li>';
    }
  }
});

// clear all
document.addEventListener('click', async (e) => {
  if (e.target.id !== 'clear-btn') return;
  if (!confirm('Delete ALL saved briefings? This cannot be undone.')) return;
  await fetch('/clear', { method:'POST' });
  e.target.remove(); preview.style.display = 'none';
  list.innerHTML = '<li style="color:#6b7280">No briefings yet - generate one above.</li>';
});

// search filter
document.getElementById('search').addEventListener('input', (e) => {
  const q = e.target.value.toLowerCase();
  list.querySelectorAll('li[data-file]').forEach(li => {
    li.style.display = li.getAttribute('data-file').toLowerCase().includes(q) ? 'flex' : 'none';
  });
});

// schedule save
const sform = document.getElementById('sched-form');
const sstate = document.getElementById('sched-state');
sform.addEventListener('submit', async (e) => {
  e.preventDefault();
  const res = await fetch('/schedule', { method:'POST', body: new FormData(sform) });
  const data = await res.json();
  if (data.enabled && data.next_run) { sstate.textContent = 'Saved - next run: ' + data.next_run; sstate.className = 'pill ok'; }
  else { sstate.textContent = 'Schedule disabled'; sstate.className = 'pill'; }
});

// test email
document.getElementById('test-btn').addEventListener('click', async () => {
  const fd = new FormData();
  fd.append('email', sform.querySelector('[name=email]').value);
  sstate.textContent = 'sending test...'; sstate.className = 'pill';
  const res = await fetch('/test-email', { method:'POST', body: fd });
  const data = await res.json();
  sstate.textContent = data.ok ? 'Test email sent' : ('Test failed: ' + data.error);
  sstate.className = data.ok ? 'pill ok' : 'pill err';
});
</script>
</body></html>"""


def _startup():
    _SCHED.start()
    saved = _load_schedule()
    if saved:
        _register_schedule(saved)


if __name__ == "__main__":
    _startup()
    port = int(os.getenv("WEB_PORT", "5000"))
    log.info("Threat Intel Briefing web UI on http://localhost:%d", port)
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
