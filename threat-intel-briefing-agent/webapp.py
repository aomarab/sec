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
from flask import (Flask, abort, jsonify, redirect, render_template_string,
                   request, send_file, session)
from werkzeug.utils import secure_filename

import auth
from agent.loop import Cancelled, run_agent
from analysis.analyze import analyze_document
from analysis.extract import SUPPORTED as ALLOWED_EXT
from briefing import delivery, report
from config import CONFIG

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("webapp")

app = Flask(__name__)
app.secret_key = auth.get_secret_key()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()

SCHEDULE_FILE = os.getenv("SCHEDULE_FILE", "schedule.json")
UPLOADS_DIR = os.getenv("UPLOADS_DIR", "uploads")
BRANDING_DIR = os.getenv("BRANDING_DIR", "branding")
LOGO_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"}
_SCHED = BackgroundScheduler(timezone="UTC")
_JOB_ID = "email_briefing"


def _logo_path():
    for p in sorted(glob.glob(os.path.join(BRANDING_DIR, "logo.*"))):
        return p
    return None


def _logo_ver():
    p = _logo_path()
    return int(os.path.getmtime(p)) if p else 0

SEVERITY_CHOICES = [(9.0, "Critical only"), (7.0, "High and Critical"),
                    (4.0, "Medium and above"), (0.0, "All severities")]

REGIONS = ["Global", "North America", "United States", "Canada", "Latin America",
           "Europe", "European Union", "United Kingdom", "EMEA", "Middle East",
           "Gulf / GCC", "Africa", "Asia-Pacific", "South Asia", "East Asia",
           "Southeast Asia", "Oceania"]

INDUSTRIES = ["Technology", "Software & SaaS", "Finance & Banking", "Insurance",
              "Healthcare", "Pharmaceutical", "Government / Public Sector",
              "Defense", "Critical Infrastructure", "Energy & Utilities",
              "Oil & Gas", "Manufacturing", "Automotive", "Retail & E-commerce",
              "Telecommunications", "Transportation & Logistics", "Aviation",
              "Education", "Media & Entertainment", "Legal", "Hospitality",
              "Non-profit / NGO"]


def _with_current(options: list[str], *current: str) -> list[str]:
    """Return options with any current selected values (comma-separated, possibly
    multiple) that aren't already in the list prepended, preserving order."""
    extra: list[str] = []
    for c in current:
        for v in (c or "").split(","):
            v = v.strip()
            if v and v not in options and v not in extra:
                extra.append(v)
    return extra + options

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


OWNERS_FILE = os.getenv("OWNERS_FILE", "report_owners.json")


def _load_owners():
    try:
        with open(OWNERS_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _set_owner(filename, owner):
    with _LOCK:
        owners = _load_owners()
        owners[filename] = owner or ""
        with open(OWNERS_FILE, "w", encoding="utf-8") as fh:
            json.dump(owners, fh, indent=2)


def _remove_owners(filenames):
    with _LOCK:
        owners = _load_owners()
        changed = False
        for f in filenames:
            if f in owners:
                del owners[f]
                changed = True
        if changed:
            with open(OWNERS_FILE, "w", encoding="utf-8") as fh:
                json.dump(owners, fh, indent=2)


def _list_reports():
    paths = sorted(glob.glob(os.path.join(report.REPORTS_DIR, "*.html")),
                   key=os.path.getmtime, reverse=True)
    owners = _load_owners()
    out = []
    for p in paths:
        name = os.path.basename(p)
        kind = "analysis" if name.startswith("analysis-") else "briefing"
        out.append({"filename": name, "kind": kind, "owner": owners.get(name, "")})
    return out


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
def _run_job(job_id, cfg, email_to, cancel_event, owner):
    job = JOBS[job_id]
    handler = _ListHandler(job["logs"])
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        meta = _generate(cfg, email_to, cancel_event)
        _set_owner(meta["filename"], owner)
        meta["owner"] = owner
        job["report"] = meta
        job["status"] = "done"
        log.info("Briefing ready: %s", meta["title"])
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
@app.route("/login", methods=["GET", "POST"])
def login():
    nxt = request.args.get("next", "/")
    logo, ver = bool(_logo_path()), _logo_ver()
    if request.method == "POST":
        if auth.verify(request.form.get("username", ""), request.form.get("password", "")):
            session["user"] = request.form.get("username", "").strip()
            return redirect(request.form.get("next") or "/")
        return render_template_string(_LOGIN, error="Invalid username or password.",
                                      next=nxt, logo=logo, logo_ver=ver)
    if auth.current_user():
        return redirect("/")
    return render_template_string(_LOGIN, error=None, next=nxt, logo=logo, logo_ver=ver)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/branding/logo")
def branding_logo():
    p = _logo_path()
    if not p:
        abort(404)
    return send_file(os.path.abspath(p))


@app.route("/admin/logo", methods=["POST"])
@auth.require_perm("admin")
def admin_logo():
    f = request.files.get("logo")
    if not f or not f.filename:
        return jsonify({"ok": False, "message": "Choose an image file."})
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in LOGO_EXTS:
        return jsonify({"ok": False, "message": "Use PNG, JPG, GIF, SVG, or WEBP."})
    os.makedirs(BRANDING_DIR, exist_ok=True)
    for old in glob.glob(os.path.join(BRANDING_DIR, "logo.*")):
        try:
            os.remove(old)
        except OSError:
            pass
    f.save(os.path.join(BRANDING_DIR, "logo" + ext))
    return jsonify({"ok": True, "message": "Logo updated."})


@app.route("/admin/logo/delete", methods=["POST"])
@auth.require_perm("admin")
def admin_logo_delete():
    for old in glob.glob(os.path.join(BRANDING_DIR, "logo.*")):
        try:
            os.remove(old)
        except OSError:
            pass
    return jsonify({"ok": True, "message": "Logo removed."})


@app.route("/")
@auth.login_required
def index():
    user = auth.current_user()
    perms = {p for p in auth.PRIV_KEYS if auth.has_perm(user, p)}
    active_tab = "tab-generate" if "generate" in perms else "tab-history"
    return render_template_string(
        _PAGE, cfg=CONFIG, reports=_list_reports(), provider=CONFIG.llm.provider,
        model=getattr(CONFIG.llm, f"{CONFIG.llm.provider}_model", ""),
        severities=SEVERITY_CHOICES, schedule=_load_schedule(), next_run=_next_run(),
        smtp_ready=_smtp_ready(), stats=_latest_stats(), presets=PRESET_LABELS,
        user=user, perms=perms, is_admin=auth.has_perm(user, "admin"),
        all_privileges=auth.PRIVILEGES, active_tab=active_tab,
        logo=bool(_logo_path()), logo_ver=_logo_ver(),
        password_rule=auth.PASSWORD_RULE,
        regions=_with_current(REGIONS, CONFIG.region, _load_schedule().get("region")),
        industries=_with_current(INDUSTRIES, CONFIG.industry, _load_schedule().get("industry")),
    )


# ── user administration (admin only) ─────────────────────────────────────────
@app.route("/admin/users")
@auth.require_perm("admin")
def admin_users():
    return jsonify({"users": auth.list_users(), "privileges": auth.PRIVILEGES})


@app.route("/admin/users/create", methods=["POST"])
@auth.require_perm("admin")
def admin_create():
    ok, msg = auth.create_user(request.form.get("username", ""),
                               request.form.get("password", ""),
                               request.form.getlist("privileges"))
    return jsonify({"ok": ok, "message": msg})


@app.route("/admin/users/update", methods=["POST"])
@auth.require_perm("admin")
def admin_update():
    ok, msg = auth.update_privileges(request.form.get("username", ""),
                                     request.form.getlist("privileges"))
    return jsonify({"ok": ok, "message": msg})


@app.route("/admin/users/password", methods=["POST"])
@auth.require_perm("admin")
def admin_password():
    ok, msg = auth.set_password(request.form.get("username", ""),
                                request.form.get("password", ""))
    return jsonify({"ok": ok, "message": msg})


@app.route("/admin/users/delete", methods=["POST"])
@auth.require_perm("admin")
def admin_delete():
    ok, msg = auth.delete_user(request.form.get("username", ""))
    return jsonify({"ok": ok, "message": msg})


@app.route("/account/password", methods=["POST"])
@auth.login_required
def account_password():
    user = auth.current_user()
    if not auth.verify(user["username"], request.form.get("current", "")):
        return jsonify({"ok": False, "message": "Current password is incorrect."})
    ok, msg = auth.set_password(user["username"], request.form.get("new", ""))
    return jsonify({"ok": ok, "message": msg})


@app.route("/run", methods=["POST"])
@auth.require_perm("generate")
def run():
    params = request.form.to_dict()
    regions = request.form.getlist("region")
    industries = request.form.getlist("industry")
    if regions:
        params["region"] = ", ".join(regions)
    if industries:
        params["industry"] = ", ".join(industries)
    params["extra_instructions"] = _build_instructions(request.form)
    cfg = _apply_params(copy.deepcopy(CONFIG), params)
    email_to = (request.form.get("email") or "").strip() or None
    owner = auth.current_user()["username"]
    job_id = uuid.uuid4().hex[:12]
    cancel = threading.Event()
    with _LOCK:
        JOBS[job_id] = {"status": "running", "logs": [], "report": None,
                        "error": None, "cancel": cancel}
    threading.Thread(target=_run_job, args=(job_id, cfg, email_to, cancel, owner), daemon=True).start()
    return jsonify({"job_id": job_id})


def _run_analyze_job(job_id, paths, email_to, owner):
    job = JOBS[job_id]
    handler = _ListHandler(job["logs"])
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        reports = []
        for p in paths:
            markdown = analyze_document(p, CONFIG)
            out = report.render(markdown, prefix="analysis")
            fname = os.path.basename(out["html_path"])
            _set_owner(fname, owner)
            emailed = False
            if email_to:
                mail_cfg = copy.deepcopy(CONFIG.email)
                mail_cfg.enabled = True
                mail_cfg.to = email_to
                emailed = delivery.send_email(
                    mail_cfg, subject=out["title"], html_body=out["html"], markdown_body=markdown,
                )
            reports.append({"title": out["title"], "filename": fname,
                            "emailed": emailed, "owner": owner})
            log.info("Analysis ready: %s", out["title"])
        job["reports"] = reports
        job["report"] = reports[-1] if reports else None
        job["status"] = "done"
    except Exception as err:
        job["status"] = "error"
        job["error"] = str(err)
        log.exception("Analysis job failed")
    finally:
        root.removeHandler(handler)


@app.route("/analyze", methods=["POST"])
@auth.require_perm("analyze")
def analyze():
    files = [f for f in request.files.getlist("files") if f and f.filename]
    if not files:
        return jsonify({"error": "No file uploaded."}), 400
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    paths = []
    for f in files:
        ext = os.path.splitext(f.filename)[1].lower()
        if ext not in ALLOWED_EXT:
            return jsonify({"error": f"Unsupported file type '{ext}'. "
                            f"Allowed: {', '.join(sorted(ALLOWED_EXT))}"}), 400
        safe = secure_filename(f.filename) or ("upload" + ext)
        dest = os.path.join(UPLOADS_DIR, uuid.uuid4().hex[:8] + "_" + safe)
        f.save(dest)
        paths.append(dest)
    email_to = (request.form.get("email") or "").strip() or None
    owner = auth.current_user()["username"]
    job_id = uuid.uuid4().hex[:12]
    with _LOCK:
        JOBS[job_id] = {"status": "running", "logs": [], "report": None,
                        "reports": None, "error": None}
    threading.Thread(target=_run_analyze_job, args=(job_id, paths, email_to, owner), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/status/<job_id>")
@auth.login_required
def status(job_id):
    job = JOBS.get(job_id)
    if not job:
        abort(404)
    return jsonify({k: v for k, v in job.items() if k != "cancel"})


@app.route("/stop/<job_id>", methods=["POST"])
@auth.require_perm("generate")
def stop(job_id):
    job = JOBS.get(job_id)
    if not job:
        abort(404)
    if job.get("cancel"):
        job["cancel"].set()
    return jsonify({"ok": True})


@app.route("/schedule", methods=["POST"])
@auth.require_perm("schedule")
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
        "region": ", ".join(f.getlist("region")) or CONFIG.region,
        "industry": ", ".join(f.getlist("industry")) or CONFIG.industry,
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
@auth.require_perm("schedule")
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
@auth.login_required
def view_report(filename):
    safe = os.path.basename(filename)
    full = os.path.join(report.REPORTS_DIR, safe)
    if not os.path.isfile(full):
        abort(404)
    return send_file(os.path.abspath(full))


@app.route("/download/<path:filename>")
@auth.login_required
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
@auth.require_perm("delete")
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
    _remove_owners([stem + ".html"])
    return jsonify({"ok": True, "removed": removed})


@app.route("/clear", methods=["POST"])
@auth.require_perm("delete")
def clear_reports():
    count = 0
    for pattern in ("*.html", "*.md"):
        for p in glob.glob(os.path.join(report.REPORTS_DIR, pattern)):
            try:
                os.remove(p)
                count += 1
            except OSError:
                pass
    with _LOCK:
        try:
            os.remove(OWNERS_FILE)
        except OSError:
            pass
    return jsonify({"ok": True, "deleted": count})


_LOGIN = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in — Threat Intelligence Briefing Agent</title>
<style>
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         font-family:'Segoe UI',-apple-system,Arial,sans-serif; background:linear-gradient(135deg,#0f2a43,#1d4671); }
  .box { background:#fff; padding:30px 28px; border-radius:12px; width:340px; max-width:92vw; box-shadow:0 10px 40px rgba(0,0,0,.25); }
  h1 { font-size:18px; color:#0f2a43; margin:0 0 4px; }
  p.sub { font-size:12px; color:#6b7280; margin:0 0 20px; }
  label { display:block; font-size:12px; color:#6b7280; margin:12px 0 4px; }
  input { width:100%; padding:11px 12px; border:1px solid #e2e5e9; border-radius:8px; font-size:16px; box-sizing:border-box; }
  button { width:100%; margin-top:18px; background:#0f2a43; color:#fff; border:0; padding:12px; border-radius:8px; font-size:15px; cursor:pointer; }
  .err { background:#fef2f2; color:#b42318; border:1px solid #f3c0b8; padding:9px 11px; border-radius:8px; font-size:13px; margin-bottom:8px; }
</style></head>
<body>
  <form class="box" method="post" action="/login">
    {% if logo %}<img src="/branding/logo?v={{ logo_ver }}" alt="Logo" style="max-height:72px;max-width:220px;display:block;margin:0 auto 16px;">{% endif %}
    <h1>Threat Intelligence Briefing Agent</h1>
    <p class="sub">Sign in to continue</p>
    {% if error %}<div class="err">{{ error }}</div>{% endif %}
    <input type="hidden" name="next" value="{{ next }}">
    <label>Username</label><input name="username" autofocus autocomplete="username">
    <label>Password</label><input name="password" type="password" autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
</body></html>"""


_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Threat Intelligence Briefing Agent</title>
<style>
  :root { --navy:#0f2a43; --line:#e2e5e9; --muted:#6b7280; --accent:#1d4671; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:'Segoe UI',-apple-system,Arial,sans-serif; background:#eef1f5; color:#1f2328; }
  header { background:linear-gradient(135deg,#0f2a43,#1d4671); color:#fff; padding:18px 28px; }
  header .hwrap { max-width:960px; margin:0 auto; display:flex; align-items:center; justify-content:space-between; gap:12px; }
  header h1 { margin:0; font-size:19px; }
  header .huser { font-size:13px; opacity:.9; display:flex; align-items:center; gap:12px; white-space:nowrap; }
  header .huser a { color:#fff; opacity:.85; }
  .tabbar { background:#fff; border-bottom:1px solid var(--line); position:sticky; top:0; z-index:10; }
  .tabbar .wrapbar { max-width:960px; margin:0 auto; display:flex; gap:2px; padding:0 16px; flex-wrap:wrap; }
  .tabbtn { background:none; border:0; padding:14px 16px; margin:0; color:var(--muted); font-size:14px; cursor:pointer; border-bottom:3px solid transparent; border-radius:0; }
  .tabbtn:hover { color:var(--navy); }
  .tabbtn.active { color:var(--navy); font-weight:600; border-bottom-color:var(--accent); }
  .tab { display:none; }
  .tab.active { display:flex; flex-direction:column; gap:20px; }
  input[readonly] { background:#f7f9fb; color:#6b7280; cursor:default; }
  .wrap { max-width:960px; margin:24px auto; padding:0 16px; }
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
  ul.reports li { padding:10px 0; border-bottom:1px solid var(--line); display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap; }
  ul.reports li:last-child { border-bottom:0; }
  ul.reports li .name { display:flex; align-items:center; gap:8px; min-width:0; flex:1 1 auto; }
  ul.reports li .name a { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .kind { font-size:10px; padding:2px 7px; border-radius:999px; font-weight:600; flex-shrink:0; letter-spacing:.02em; text-transform:uppercase; }
  .kind.briefing { background:#dbeafe; color:#1e40af; }
  .kind.analysis { background:#ede9fe; color:#6d28d9; }
  .by { color:#6b7280; font-size:12px; white-space:nowrap; }
  .ms { position:relative; }
  .ms-toggle { width:100%; margin-top:0; text-align:left; background:#fff; color:#1f2328; border:1px solid var(--line); padding:9px 10px; border-radius:6px; font-size:14px; cursor:pointer; display:flex; justify-content:space-between; align-items:center; gap:8px; }
  .ms-toggle .ms-arrow { color:#6b7280; }
  .ms-panel { position:absolute; z-index:30; left:0; right:0; top:calc(100% + 4px); background:#fff; border:1px solid var(--line); border-radius:8px; box-shadow:0 8px 24px rgba(0,0,0,.14); max-height:240px; overflow:auto; padding:6px; display:none; }
  .ms.open .ms-panel { display:block; }
  .ms-opt { display:flex; align-items:center; gap:8px; padding:6px 8px; font-size:13px; border-radius:6px; cursor:pointer; margin:0; white-space:nowrap; }
  .ms-opt:hover { background:#f4f8ff; }
  .ms-opt input { width:auto; margin:0; }
  a { color:#1f6feb; text-decoration:none; } a:hover { text-decoration:underline; }
  .actions { display:flex; gap:6px; align-items:center; flex-shrink:0; flex-wrap:wrap; }
  .dl, .pv { font-size:12px; border:1px solid var(--line); padding:4px 9px; border-radius:6px; color:#1f6feb; cursor:pointer; background:#fff; }
  .dl:hover, .pv:hover { background:#f4f8ff; text-decoration:none; }
  .del { background:#fff; color:#b42318; border:1px solid #f3c0b8; padding:4px 9px; border-radius:6px; font-size:12px; cursor:pointer; margin:0; }
  .del:hover { background:#fef2f2; }
  #stop-btn { background:#b42318; margin-left:8px; }
  #clear-btn { background:#b42318; font-size:13px; padding:8px 14px; }
  #search { margin-bottom:12px; }
  #preview { width:100%; height:520px; border:1px solid var(--line); border-radius:8px; margin-top:14px; display:none; background:#fff; }
  @media (max-width:680px) {
    .wrap { padding:0 10px; margin:16px auto; }
    .grid3 { grid-template-columns:1fr; }
    .stats { grid-template-columns:1fr 1fr; }
    .tabbar .wrapbar { overflow-x:auto; flex-wrap:nowrap; -webkit-overflow-scrolling:touch; }
    .tabbtn { padding:12px 12px; font-size:13px; white-space:nowrap; }
    header { padding:16px; } header h1 { font-size:17px; }
    .card { padding:16px; }
    ul.reports li .name { flex:1 1 100%; }
    .actions { flex:1 1 100%; }
    #preview { height:420px; }
    input, select, textarea { font-size:16px; }
  }
</style></head>
<body>
{% macro multiselect(name, options, selected) %}
<div class="ms" data-name="{{ name }}">
  <button type="button" class="ms-toggle"><span class="ms-label">Select…</span><span class="ms-arrow">▾</span></button>
  <div class="ms-panel">
    {% for o in options %}<label class="ms-opt"><input type="checkbox" name="{{ name }}" value="{{ o }}" {% if o in selected %}checked{% endif %}> {{ o }}</label>{% endfor %}
  </div>
</div>
{% endmacro %}
<header><div class="hwrap">
  <h1 style="display:flex;align-items:center;gap:10px;">{% if logo %}<img src="/branding/logo?v={{ logo_ver }}" alt="" style="height:30px;border-radius:4px;background:#fff;padding:2px;">{% endif %}Threat Intelligence Briefing Agent</h1>
  <div class="huser">{{ user.username }}{% if is_admin %} (admin){% endif %} &middot; <a href="/logout">Sign out</a></div>
</div></header>
<nav class="tabbar"><div class="wrapbar">
  {% if 'generate' in perms %}<button class="tabbtn {{ 'active' if active_tab=='tab-generate' }}" data-tab="tab-generate">Generate</button>{% endif %}
  {% if 'analyze' in perms %}<button class="tabbtn" data-tab="tab-analyze">Analyze file</button>{% endif %}
  {% if 'schedule' in perms %}<button class="tabbtn" data-tab="tab-schedule">Schedule</button>{% endif %}
  <button class="tabbtn {{ 'active' if active_tab=='tab-history' }}" data-tab="tab-history">History</button>
  <button class="tabbtn" data-tab="tab-dashboard">Dashboard</button>
  <button class="tabbtn" data-tab="tab-settings">Settings</button>
  {% if is_admin %}<button class="tabbtn" data-tab="tab-admin">Admin</button>{% endif %}
</div></nav>
<div class="wrap">

  <section class="tab" id="tab-dashboard">
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
  </section>

  {% if 'generate' in perms %}
  <section class="tab {{ 'active' if active_tab=='tab-generate' }}" id="tab-generate">
  <div class="card">
    <h2>Generate a briefing</h2>
    <form id="run-form">
      <div class="grid3">
        <div><label>Region focus</label>{{ multiselect('region', regions, cfg.region.split(', ')) }}</div>
        <div><label>Industry focus</label>{{ multiselect('industry', industries, cfg.industry.split(', ')) }}</div>
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
  </section>
  {% endif %}

  {% if 'analyze' in perms %}
  <section class="tab" id="tab-analyze">
  <div class="card">
    <h2>Analyze a threat document</h2>
    <p class="note">Upload a PDF or Excel/CSV threat report. You'll get a structured summary: threat overview, affected products, CVEs, an indicator (IOC) table with reputation lookups, and recommendations.</p>
    <form id="analyze-form">
      <div class="row"><label>File(s) — PDF, XLSX, CSV, TXT</label>
        <input id="analyze-files" name="files" type="file" multiple accept=".pdf,.xlsx,.xlsm,.csv,.tsv,.txt,.md,.json,.log"></div>
      <div class="row"><label>Email the result to (optional, comma-separated)</label>
        <input name="email" placeholder="you@company.com"></div>
      <button id="analyze-btn" type="submit">Analyze</button>
      <span id="a-state" class="pill" style="display:none"></span>
    </form>
    <div id="a-console" class="console"></div>
  </div>
  </section>
  {% endif %}

  {% if 'schedule' in perms %}
  <section class="tab" id="tab-schedule">
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
        <div><label>Region</label>{{ multiselect('region', regions, (schedule.region or cfg.region).split(', ')) }}</div>
        <div><label>Industry</label>{{ multiselect('industry', industries, (schedule.industry or cfg.industry).split(', ')) }}</div>
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
  </section>
  {% endif %}

  <section class="tab {{ 'active' if active_tab=='tab-history' }}" id="tab-history">
  <div class="card">
    <h2>Past briefings</h2>
    <input id="search" type="search" placeholder="Filter briefings by name...">
    <ul class="reports" id="report-list">
      {% for r in reports %}
        <li data-file="{{ r.filename }}">
          <span class="name"><span class="kind {{ r.kind }}">{{ 'Analysis' if r.kind == 'analysis' else 'Briefing' }}</span><a href="/reports/{{ r.filename }}" target="_blank">{{ r.filename }}</a>{% if r.owner %}<span class="by">by {{ r.owner }}</span>{% endif %}</span>
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
  </section>

  <section class="tab" id="tab-settings">
  <div class="card">
    <h2>Settings</h2>
    <p class="note">These come from your <code>.env</code> file and are shown for reference. Edit <code>.env</code> and restart the app to change them.</p>
    <div class="grid3" style="margin-top:14px">
      <div><label>LLM provider</label><input value="{{ provider }}" readonly></div>
      <div><label>Model</label><input value="{{ model or 'n/a' }}" readonly></div>
      <div><label>Email configured</label><input value="{{ 'Yes' if smtp_ready else 'No' }}" readonly></div>
      <div><label>Default region</label><input value="{{ cfg.region }}" readonly></div>
      <div><label>Default industry</label><input value="{{ cfg.industry }}" readonly></div>
      <div><label>Default min severity (CVSS)</label><input value="{{ cfg.min_cvss }}" readonly></div>
      <div><label>Default look-back (days)</label><input value="{{ cfg.look_back_days }}" readonly></div>
      <div><label>Default insights</label><input value="{{ cfg.insights_to_research }}" readonly></div>
      <div><label>Max agent steps</label><input value="{{ cfg.max_steps }}" readonly></div>
      <div><label>SMTP host</label><input value="{{ cfg.email.smtp_host or 'not set' }}" readonly></div>
      <div><label>Email from</label><input value="{{ cfg.email.sender or 'not set' }}" readonly></div>
      <div><label>SMTP port</label><input value="{{ cfg.email.smtp_port }}" readonly></div>
    </div>
  </div>
  {% if is_admin %}
  <div class="card">
    <h2>Company logo</h2>
    <p class="note">Appears on the login screen and in the header. PNG, JPG, GIF, SVG, or WEBP.</p>
    {% if logo %}<img src="/branding/logo?v={{ logo_ver }}" alt="Current logo" style="max-height:64px;max-width:220px;display:block;margin:8px 0 12px;border:1px solid var(--line);border-radius:6px;padding:6px;background:#fff;">{% endif %}
    <form id="logo-form">
      <input type="file" name="logo" accept=".png,.jpg,.jpeg,.gif,.svg,.webp">
      <div class="row">
        <button type="submit">Upload logo</button>
        {% if logo %}<button id="logo-del" type="button" class="secondary" style="margin-left:8px">Remove logo</button>{% endif %}
        <span id="logo-state" class="pill" style="display:none"></span>
      </div>
    </form>
  </div>
  {% endif %}
  <div class="card">
    <h2>Change my password</h2>
    <form id="pw-form">
      <div class="grid3">
        <div><label>Current password</label><input name="current" type="password" autocomplete="current-password"></div>
        <div><label>New password</label><input name="new" type="password" autocomplete="new-password"></div>
      </div>
      <div class="note">{{ password_rule }}</div>
      <button type="submit">Update password</button>
      <span id="pw-state" class="pill" style="display:none"></span>
    </form>
  </div>
  </section>

  {% if is_admin %}
  <section class="tab" id="tab-admin">
  <div class="card">
    <h2>User management</h2>
    <p class="note">Create users and grant per-feature privileges. Admins have every privilege.</p>
    <table style="width:100%;border-collapse:collapse;margin-top:8px" id="user-table"></table>
  </div>
  <div class="card">
    <h2>Create user</h2>
    <form id="newuser-form">
      <div class="grid3">
        <div><label>Username</label><input name="username" autocomplete="off"></div>
        <div><label>Password</label><input name="password" type="password" autocomplete="new-password"></div>
      </div>
      <div class="note">{{ password_rule }}</div>
      <div class="row"><label>Privileges</label>
        <div class="presets">
          {% for k,lbl in all_privileges %}<label><input type="checkbox" name="privileges" value="{{ k }}"> {{ lbl }}</label>{% endfor %}
        </div>
      </div>
      <button type="submit">Create user</button>
      <span id="nu-state" class="pill" style="display:none"></span>
    </form>
  </div>
  </section>
  {% endif %}

</div>
<script>
window.__ALL_PRIVS = [{% for k,lbl in all_privileges %}["{{ k }}","{{ lbl }}"]{% if not loop.last %},{% endif %}{% endfor %}];
const _fetch = window.fetch;
window.fetch = async (...a) => { const r = await _fetch(...a); if (r.status === 401) { location.href = '/login'; } return r; };
</script>
<script>
document.querySelectorAll('.tabbtn').forEach(b => b.addEventListener('click', () => {
  document.querySelectorAll('.tabbtn').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  document.getElementById(b.dataset.tab).classList.add('active');
}));

// checkbox dropdowns (multi-select)
document.querySelectorAll('.ms').forEach(ms => {
  const toggle = ms.querySelector('.ms-toggle');
  const label = ms.querySelector('.ms-label');
  const panel = ms.querySelector('.ms-panel');
  const boxes = ms.querySelectorAll('input[type=checkbox]');
  const summary = () => {
    const sel = [...boxes].filter(b => b.checked).map(b => b.value);
    label.textContent = sel.length === 0 ? 'Select…' : (sel.length <= 2 ? sel.join(', ') : sel.length + ' selected');
  };
  toggle.addEventListener('click', (e) => {
    e.stopPropagation();
    document.querySelectorAll('.ms.open').forEach(o => { if (o !== ms) o.classList.remove('open'); });
    ms.classList.toggle('open');
  });
  panel.addEventListener('click', (e) => e.stopPropagation());
  boxes.forEach(b => b.addEventListener('change', summary));
  summary();
});
document.addEventListener('click', () => document.querySelectorAll('.ms.open').forEach(o => o.classList.remove('open')));
</script>
<script>
const freq = document.getElementById('freq');
const wdWrap = document.getElementById('weekday-wrap');
if (freq && wdWrap) {
  const syncFreq = () => { wdWrap.style.display = freq.value === 'weekly' ? 'block' : 'none'; };
  freq.addEventListener('change', syncFreq); syncFreq();
}

const form = document.getElementById('run-form');
const btn = document.getElementById('run-btn');
const stopBtn = document.getElementById('stop-btn');
const con = document.getElementById('console');
const state = document.getElementById('state');
const list = document.getElementById('report-list');
const preview = document.getElementById('preview');
let currentJob = null;

if (form) form.addEventListener('submit', async (e) => {
  e.preventDefault();
  btn.disabled = true; con.style.display = 'block'; con.textContent = '';
  state.style.display = 'inline'; state.textContent = 'running...'; state.className = 'pill';
  const res = await fetch('/run', { method:'POST', body: new FormData(form) });
  const { job_id } = await res.json();
  currentJob = job_id; stopBtn.style.display = 'inline-block'; stopBtn.disabled = false;
  poll(job_id);
});

if (stopBtn) stopBtn.addEventListener('click', async () => {
  if (!currentJob) return;
  stopBtn.disabled = true; state.textContent = 'stopping...';
  await fetch('/stop/' + currentJob, { method:'POST' });
});

function rowHtml(f, owner) {
  const kind = f.indexOf('analysis-') === 0 ? 'analysis' : 'briefing';
  const label = kind === 'analysis' ? 'Analysis' : 'Briefing';
  const by = owner ? '<span class="by">by ' + owner + '</span>' : '';
  return '<span class="name"><span class="kind ' + kind + '">' + label + '</span>' +
         '<a href="/reports/' + f + '" target="_blank">' + f + '</a>' + by + '</span>' +
         '<span class="actions">' +
         '<button class="pv" type="button" data-file="' + f + '">Preview</button>' +
         '<a class="dl" href="/download/' + f + '?fmt=html">HTML</a>' +
         '<a class="dl" href="/download/' + f + '?fmt=pdf">PDF</a>' +
         '<a class="dl" href="/download/' + f + '?fmt=md">MD</a>' +
         '<button class="del" type="button" data-file="' + f + '">Delete</button></span>';
}
function addReportRow(f, owner) {
  const empty = list.querySelector('li:not([data-file])');
  if (empty) empty.remove();
  const li = document.createElement('li');
  li.setAttribute('data-file', f);
  li.innerHTML = rowHtml(f, owner);
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
      addReportRow(job.report.filename, job.report.owner);
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
if (sform) {
  sform.addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await fetch('/schedule', { method:'POST', body: new FormData(sform) });
    const data = await res.json();
    if (data.enabled && data.next_run) { sstate.textContent = 'Saved - next run: ' + data.next_run; sstate.className = 'pill ok'; }
    else { sstate.textContent = 'Schedule disabled'; sstate.className = 'pill'; }
  });
  document.getElementById('test-btn').addEventListener('click', async () => {
    const fd = new FormData();
    fd.append('email', sform.querySelector('[name=email]').value);
    sstate.textContent = 'sending test...'; sstate.className = 'pill';
    const res = await fetch('/test-email', { method:'POST', body: fd });
    const data = await res.json();
    sstate.textContent = data.ok ? 'Test email sent' : ('Test failed: ' + data.error);
    sstate.className = data.ok ? 'pill ok' : 'pill err';
  });
}

// analyze file upload
const aform = document.getElementById('analyze-form');
const abtn = document.getElementById('analyze-btn');
const acon = document.getElementById('a-console');
const astate = document.getElementById('a-state');
if (aform) aform.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!document.getElementById('analyze-files').files.length) { alert('Choose a file to analyze.'); return; }
  abtn.disabled = true; acon.style.display = 'block'; acon.textContent = '';
  astate.style.display = 'inline'; astate.textContent = 'analyzing...'; astate.className = 'pill';
  const res = await fetch('/analyze', { method:'POST', body: new FormData(aform) });
  if (!res.ok) {
    let msg = 'upload failed'; try { msg = (await res.json()).error || msg; } catch (e) {}
    astate.textContent = 'error'; astate.className = 'pill err'; acon.textContent = msg; abtn.disabled = false; return;
  }
  pollAnalyze((await res.json()).job_id);
});
async function pollAnalyze(jobId) {
  try {
    const r = await fetch('/status/' + jobId);
    const job = await r.json();
    acon.textContent = (job.logs || []).join('\\n'); acon.scrollTop = acon.scrollHeight;
    if (job.status === 'running') { setTimeout(() => pollAnalyze(jobId), 1200); return; }
    abtn.disabled = false;
    if (job.status === 'done') {
      const reps = job.reports || (job.report ? [job.report] : []);
      astate.textContent = 'done (' + reps.length + ')'; astate.className = 'pill ok';
      acon.textContent += '\\n\\nAnalysis complete: ' + reps.length + ' report(s).';
      reps.forEach(rp => addReportRow(rp.filename, rp.owner));
      if (reps[0]) window.open('/reports/' + reps[0].filename, '_blank');
    } else {
      astate.textContent = 'error'; astate.className = 'pill err';
      acon.textContent += '\\n\\nError: ' + (job.error || 'unknown');
    }
  } catch (err) {
    abtn.disabled = false; astate.textContent = 'error'; astate.className = 'pill err';
    acon.textContent += '\\n\\nError: ' + err;
  }
}

// change my password
const pwf = document.getElementById('pw-form');
if (pwf) pwf.addEventListener('submit', async (e) => {
  e.preventDefault();
  const r = await fetch('/account/password', { method:'POST', body: new FormData(pwf) });
  const d = await r.json();
  const s = document.getElementById('pw-state');
  s.style.display = 'inline'; s.textContent = d.message; s.className = 'pill ' + (d.ok ? 'ok' : 'err');
  if (d.ok) pwf.reset();
});

// admin: user management
const userTable = document.getElementById('user-table');
if (userTable) {
  const privs = window.__ALL_PRIVS;
  async function loadUsers() {
    const d = await (await fetch('/admin/users')).json();
    let html = '<tr style="text-align:left;border-bottom:2px solid #e2e5e9">' +
               '<th style="padding:8px">User</th><th style="padding:8px">Privileges</th><th style="padding:8px">Actions</th></tr>';
    d.users.forEach(u => {
      const checks = '<div style="display:flex;flex-wrap:wrap;gap:6px 16px">' + privs.map(p =>
        '<label style="display:inline-flex;align-items:center;gap:5px;white-space:nowrap;font-size:12px;margin:0">' +
        '<input type="checkbox" data-user="' + u.username + '" value="' + p[0] + '" ' +
        (u.privileges.indexOf(p[0]) >= 0 ? 'checked' : '') + '>' + p[1] + '</label>').join('') + '</div>';
      html += '<tr style="border-bottom:1px solid #eef1f4">' +
        '<td style="padding:8px;font-weight:600">' + u.username + '</td>' +
        '<td style="padding:8px">' + checks + '</td>' +
        '<td style="padding:8px;white-space:nowrap">' +
        '<button class="dl" type="button" data-act="save" data-user="' + u.username + '">Save</button> ' +
        '<button class="dl" type="button" data-act="pw" data-user="' + u.username + '">Reset PW</button> ' +
        '<button class="del" type="button" data-act="del" data-user="' + u.username + '">Delete</button></td></tr>';
    });
    userTable.innerHTML = html;
  }
  userTable.addEventListener('click', async (e) => {
    const act = e.target.getAttribute('data-act'); if (!act) return;
    const user = e.target.getAttribute('data-user');
    const fd = new FormData(); fd.append('username', user);
    if (act === 'save') {
      userTable.querySelectorAll('input[type=checkbox][data-user="' + user + '"]:checked').forEach(c => fd.append('privileges', c.value));
      const d = await (await fetch('/admin/users/update', { method:'POST', body: fd })).json(); alert(d.message);
    } else if (act === 'pw') {
      const pw = prompt('New password for ' + user); if (!pw) return;
      fd.append('password', pw);
      const d = await (await fetch('/admin/users/password', { method:'POST', body: fd })).json(); alert(d.message);
    } else if (act === 'del') {
      if (!confirm('Delete user ' + user + '?')) return;
      const d = await (await fetch('/admin/users/delete', { method:'POST', body: fd })).json();
      alert(d.message); loadUsers();
    }
  });
  document.getElementById('newuser-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const d = await (await fetch('/admin/users/create', { method:'POST', body: new FormData(e.target) })).json();
    const s = document.getElementById('nu-state');
    s.style.display = 'inline'; s.textContent = d.message; s.className = 'pill ' + (d.ok ? 'ok' : 'err');
    if (d.ok) { e.target.reset(); loadUsers(); }
  });
  loadUsers();

  // company logo
  const logoForm = document.getElementById('logo-form');
  if (logoForm) {
    logoForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const d = await (await fetch('/admin/logo', { method:'POST', body: new FormData(logoForm) })).json();
      const s = document.getElementById('logo-state');
      s.style.display = 'inline'; s.textContent = d.message; s.className = 'pill ' + (d.ok ? 'ok' : 'err');
      if (d.ok) setTimeout(() => location.reload(), 700);
    });
    const del = document.getElementById('logo-del');
    if (del) del.addEventListener('click', async () => {
      if (!confirm('Remove the company logo?')) return;
      const d = await (await fetch('/admin/logo/delete', { method:'POST' })).json();
      if (d.ok) location.reload();
    });
  }
}
</script>
</body></html>"""


def _startup():
    auth.ensure_admin()
    _SCHED.start()
    saved = _load_schedule()
    if saved:
        _register_schedule(saved)


if __name__ == "__main__":
    _startup()
    port = int(os.getenv("WEB_PORT", "5000"))
    log.info("Threat Intel Briefing web UI on http://localhost:%d", port)
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
