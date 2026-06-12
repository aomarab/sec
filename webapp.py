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
import time
import uuid

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from flask import (Flask, abort, jsonify, redirect, render_template_string,
                   request, send_file, session)
from werkzeug.utils import secure_filename

import alerts
import apikeys
import assistant
import audit
import auth
from agent.loop import Cancelled, run_agent
from analysis.analyze import analyze_document
from analysis.extract import SUPPORTED as ALLOWED_EXT
from analysis import vendor as vendor_analysis
from intel import analyst
from briefing import delivery, export, report
from collectors import kev, nvd
from config import CONFIG
from scan import scanner as scan_scanner
from scan import tools as scan_tools
from scan.assess import run_scan
from recon.harvester import run_recon
from cloud import azure as azure_cloud
from cloud import vendor as cloud_vendor

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("webapp")
audit.install_handler()  # capture app activity into the Logs tab


def _audit(category, action, level="info", detail="", username=None):
    """Record a user action in the activity log (resolves the current user)."""
    try:
        if username is None:
            u = auth.current_user()
            username = u["username"] if u else ""
    except Exception:
        username = username or ""
    audit.record(category, action, user=username or "", level=level, detail=detail)


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


SCAN_STATS_FILE = os.getenv("SCAN_STATS_FILE", "scan_stats.json")


def _load_scan_stats():
    try:
        with open(SCAN_STATS_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _set_scan_stats(filename, stats):
    with _LOCK:
        data = _load_scan_stats()
        data[filename] = stats
        with open(SCAN_STATS_FILE, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)


def _latest_scan_stats():
    data = _load_scan_stats()
    scans = sorted(glob.glob(os.path.join(report.REPORTS_DIR, "scan-*.html")),
                   key=os.path.getmtime, reverse=True)
    for p in scans:
        st = data.get(os.path.basename(p))
        if st:
            return st
    return None


# ── asset inventory ──────────────────────────────────────────────────────────
ASSETS_FILE = os.getenv("ASSETS_FILE", "assets.json")


def _load_assets():
    try:
        with open(ASSETS_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _upsert_assets(assets):
    with _LOCK:
        data = _load_assets()
        for a in assets:
            data[a["ip"]] = a
        with open(ASSETS_FILE, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)


def _list_assets():
    return sorted(_load_assets().values(), key=lambda a: a.get("risk", 0), reverse=True)


# ── scheduled scans ──────────────────────────────────────────────────────────
SCAN_SCHED_FILE = os.getenv("SCAN_SCHED_FILE", "scan_schedule.json")
_SCAN_JOB_ID = "network_scan"


def _load_scan_sched():
    try:
        with open(SCAN_SCHED_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_scan_sched(data):
    with open(SCAN_SCHED_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def _register_scan_sched(sched):
    if _SCHED.get_job(_SCAN_JOB_ID):
        _SCHED.remove_job(_SCAN_JOB_ID)
    if not sched.get("enabled"):
        return
    hour, minute = (sched.get("time") or "03:00").split(":")
    kwargs = {"hour": int(hour), "minute": int(minute)}
    if sched.get("frequency") == "weekly":
        kwargs["day_of_week"] = sched.get("weekday", "mon")
    elif sched.get("frequency") == "monthly":
        kwargs["day"] = "1"
    _SCHED.add_job(_scheduled_scan_run, CronTrigger(timezone="UTC", **kwargs), id=_SCAN_JOB_ID)
    log.info("Network scan schedule registered: %s", kwargs)


def _next_scan_run():
    job = _SCHED.get_job(_SCAN_JOB_ID)
    return job.next_run_time.strftime("%Y-%m-%d %H:%M UTC") if job and job.next_run_time else None


def _do_scan(opts, owner):
    """Run a scan, persist report + stats + assets, and fire alerts. Shared by
    the on-demand job and the scheduler."""
    result = run_scan(opts, CONFIG)
    out = report.render(result["markdown"], prefix="scan")
    fname = os.path.basename(out["html_path"])
    _set_owner(fname, owner)
    _set_scan_stats(fname, result["stats"])
    _upsert_assets(result.get("assets", []))
    try:
        alerts.dispatch(result["stats"], opts["target"], fname)
    except Exception:
        log.exception("Alert dispatch failed")
    return out, result


def _scheduled_scan_run():
    sched = _load_scan_sched()
    if not sched or not sched.get("enabled") or not sched.get("target"):
        return
    log.info("Running scheduled network scan of %s", sched["target"])
    opts = {"target": sched["target"], "mode": sched.get("mode", "advanced"),
            "ports": sched.get("ports", ""), "grab_banner": True, "correlate_cves": True,
            "use_nmap": bool(sched.get("use_nmap")), "vuln_scripts": bool(sched.get("vuln_scripts")),
            "os_detect": bool(sched.get("os_detect")), "timing": sched.get("timing", "4"),
            "report_style": sched.get("report_style", "technical")}
    try:
        _do_scan(opts, "scheduler")
        sched["last_run"] = _dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        sched["last_status"] = "ok"
    except Exception:
        sched["last_status"] = "error"
        log.exception("Scheduled scan failed")
    _save_scan_sched(sched)


def _list_reports():
    paths = sorted(glob.glob(os.path.join(report.REPORTS_DIR, "*.html")),
                   key=os.path.getmtime, reverse=True)
    owners = _load_owners()
    out = []
    for p in paths:
        name = os.path.basename(p)
        if name.startswith("analysis-"):
            kind = "analysis"
        elif name.startswith("scan-"):
            kind = "scan"
        elif name.startswith("recon-"):
            kind = "recon"
        elif name.startswith("cve-"):
            kind = "cve"
        elif name.startswith("actor-"):
            kind = "actor"
        elif name.startswith("hunt-"):
            kind = "hunt"
        elif name.startswith(("cloud-", "azure-", "aws-", "gcp-")):
            kind = "cloud"
        else:
            kind = "briefing"
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
        uname = request.form.get("username", "").strip()
        if auth.verify(request.form.get("username", ""), request.form.get("password", "")):
            session["user"] = uname
            audit.record("auth", "Sign in", user=uname, level="success")
            return redirect(request.form.get("next") or "/")
        audit.record("auth", "Failed sign-in attempt", user=uname, level="warning")
        return render_template_string(_LOGIN, error="Invalid username or password.",
                                      next=nxt, logo=logo, logo_ver=ver)
    if auth.current_user():
        return redirect("/")
    return render_template_string(_LOGIN, error=None, next=nxt, logo=logo, logo_ver=ver)


@app.route("/logout")
def logout():
    _audit("auth", "Sign out")
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
    active_tab = "tab-dashboard"
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
        nmap_ok=scan_scanner.nmap_available(),
        tools_ok=scan_tools.available(),
        scan_stats=_latest_scan_stats(),
        assets=_list_assets() if "scan" in perms else [],
        scan_sched=_load_scan_sched(), next_scan_run=_next_scan_run(),
        alert_cfg=alerts.load_config() if auth.has_perm(user, "admin") else {},
        vendor_sections=[(k, v[0]) for k, v in cloud_vendor.SECTIONS.items()],
        api_keys=apikeys.status() if auth.has_perm(user, "admin") else [],
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
    if ok:
        _audit("admin", "Create user", detail=request.form.get("username", ""))
    return jsonify({"ok": ok, "message": msg})


@app.route("/admin/users/update", methods=["POST"])
@auth.require_perm("admin")
def admin_update():
    ok, msg = auth.update_privileges(request.form.get("username", ""),
                                     request.form.getlist("privileges"))
    if ok:
        _audit("admin", "Update user privileges",
               detail=f"{request.form.get('username','')}: {', '.join(request.form.getlist('privileges'))}")
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
    if ok:
        _audit("admin", "Delete user", level="warning", detail=request.form.get("username", ""))
    return jsonify({"ok": ok, "message": msg})


@app.route("/apikeys/save", methods=["POST"])
@auth.require_perm("admin")
def apikeys_save():
    apikeys.save_form(request.form)
    _audit("admin", "Update API keys", level="info")
    return jsonify({"ok": True})


@app.route("/admin/logs")
@auth.require_perm("admin")
def admin_logs():
    try:
        limit = max(1, min(int(request.args.get("limit", 300)), 2000))
    except (TypeError, ValueError):
        limit = 300
    events = audit.read(category=request.args.get("category", "").strip(),
                        level=request.args.get("level", "").strip(),
                        user=request.args.get("user", "").strip(),
                        query=request.args.get("q", "").strip(), limit=limit)
    return jsonify({"events": events, "count": len(events),
                    "categories": audit.CATEGORIES, "levels": audit.LEVELS,
                    "stats": audit.stats()})


@app.route("/admin/logs/clear", methods=["POST"])
@auth.require_perm("admin")
def admin_logs_clear():
    audit.clear()
    _audit("admin", "Cleared activity log", level="warning")
    return jsonify({"ok": True})


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
    _audit("briefing", "Generate briefing", detail=f"region={cfg.region}; industry={cfg.industry}")
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
    _audit("analysis", "Analyze file(s)", detail=", ".join(os.path.basename(p) for p in paths)[:300])
    threading.Thread(target=_run_analyze_job, args=(job_id, paths, email_to, owner), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/vendor-analyze", methods=["POST"])
@auth.require_perm("analyze")
def vendor_analyze():
    """Discover the vendor from a pasted API key, then look up one indicator or
    an uploaded file against that vendor."""
    api_key = (request.form.get("api_key") or "").strip()
    indicator = (request.form.get("indicator") or "").strip()
    f = request.files.get("file")
    file_path = None
    if f and f.filename:
        os.makedirs(UPLOADS_DIR, exist_ok=True)
        safe = secure_filename(f.filename) or "upload"
        file_path = os.path.join(UPLOADS_DIR, uuid.uuid4().hex[:8] + "_" + safe)
        f.save(file_path)
    if not api_key:
        return jsonify({"error": "Enter a vendor API key."}), 400
    if not file_path and not indicator:
        return jsonify({"error": "Enter an indicator or choose a file to analyze."}), 400
    try:
        result = vendor_analysis.analyze(api_key=api_key, indicator=indicator, file_path=file_path)
    except Exception as err:
        log.exception("Vendor analysis failed")
        return jsonify({"error": f"Analysis error: {err}"}), 500
    return jsonify(result)


def _save_intel(markdown, prefix, owner):
    out = report.render(markdown, prefix=prefix)
    fname = os.path.basename(out["html_path"])
    _set_owner(fname, owner)
    heading = next((ln[2:].strip() for ln in markdown.splitlines() if ln.startswith("# ")), out["title"])
    return {"ok": True, "filename": fname, "title": heading, "owner": owner}


@app.route("/cve-analyze", methods=["POST"])
@auth.require_perm("generate")
def cve_analyze():
    cve_id = (request.form.get("cve") or "").strip()
    try:
        md = analyst.analyze_cve(cve_id, CONFIG)
    except ValueError as err:
        return jsonify({"error": str(err)}), 400
    except Exception as err:
        log.exception("CVE analysis failed")
        return jsonify({"error": str(err)}), 500
    _audit("intel", "CVE analysis", detail=cve_id)
    return jsonify(_save_intel(md, "cve", auth.current_user()["username"]))


@app.route("/actor-profile", methods=["POST"])
@auth.require_perm("generate")
def actor_profile():
    name = (request.form.get("name") or "").strip()
    try:
        md = analyst.profile_actor(name, CONFIG)
    except ValueError as err:
        return jsonify({"error": str(err)}), 400
    except Exception as err:
        log.exception("Actor profile failed")
        return jsonify({"error": str(err)}), 500
    _audit("intel", "Threat actor profile", detail=name)
    return jsonify(_save_intel(md, "actor", auth.current_user()["username"]))


@app.route("/hunt-generate", methods=["POST"])
@auth.require_perm("generate")
def hunt_generate():
    subject = (request.form.get("subject") or "").strip()
    platform = (request.form.get("platform") or "sentinel").strip()
    try:
        md = analyst.hunt_queries(subject, platform, CONFIG)
    except ValueError as err:
        return jsonify({"error": str(err)}), 400
    except Exception as err:
        log.exception("Hunt generation failed")
        return jsonify({"error": str(err)}), 500
    _audit("intel", "Threat hunting queries", detail=f"{subject} ({platform})")
    return jsonify(_save_intel(md, "hunt", auth.current_user()["username"]))


# ── latest CVE feed (NVD recent + KEV flag, cached) ───────────────────────────
_CVE_CACHE: dict = {"ts": 0.0, "items": []}
_CVE_TTL = int(os.getenv("LATEST_CVE_TTL", "900"))  # 15 minutes


def _fetch_latest_cves(limit: int = 30) -> list[dict]:
    now = time.time()
    with _LOCK:
        if _CVE_CACHE["items"] and now - _CVE_CACHE["ts"] < _CVE_TTL:
            return _CVE_CACHE["items"][:limit]
    try:
        res = nvd.fetch_recent_cves(look_back_days=7, min_cvss=0.0, limit=300)
        cves = res.get("cves", [])
    except Exception as err:
        log.info("Latest-CVE NVD fetch failed: %s", err)
        cves = []
    try:
        kev_ids = {v["cve"] for v in
                   kev.fetch_kev(look_back_days=36500, limit=1000000).get("vulnerabilities", [])}
    except Exception:
        kev_ids = set()
    items = []
    for c in cves:
        items.append({
            "cve": c.get("cve"),
            "cvss": c.get("cvss"),
            "severity": c.get("severity") or "",
            "published": (c.get("published") or "")[:10],
            "description": (c.get("description") or "")[:240],
            "kev": c.get("cve") in kev_ids,
        })
    items.sort(key=lambda x: x.get("published", ""), reverse=True)
    if items:
        with _LOCK:
            _CVE_CACHE["items"] = items
            _CVE_CACHE["ts"] = now
    return items[:limit]


@app.route("/api/latest-cves")
@auth.login_required
def api_latest_cves():
    try:
        limit = max(1, min(int(request.args.get("limit", 30)), 100))
    except (TypeError, ValueError):
        limit = 30
    items = _fetch_latest_cves(limit)
    return jsonify({"cves": items, "count": len(items),
                    "fetched": _dt.datetime.utcfromtimestamp(_CVE_CACHE["ts"]).strftime("%Y-%m-%d %H:%M UTC")
                    if _CVE_CACHE["ts"] else None})


def _run_scan_job(job_id, opts, email_to, owner):
    job = JOBS[job_id]
    handler = _ListHandler(job["logs"])
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        out, result = _do_scan(opts, owner)
        fname = os.path.basename(out["html_path"])
        emailed = False
        if email_to:
            mail_cfg = copy.deepcopy(CONFIG.email)
            mail_cfg.enabled = True
            mail_cfg.to = email_to
            emailed = delivery.send_email(
                mail_cfg, subject=out["title"], html_body=out["html"], markdown_body=result["markdown"])
        job["report"] = {"title": out["title"], "filename": fname,
                         "emailed": emailed, "owner": owner}
        job["status"] = "done"
        log.info("Scan report ready: %s", out["title"])
    except Exception as err:
        job["status"] = "error"
        job["error"] = str(err)
        log.exception("Scan job failed")
    finally:
        root.removeHandler(handler)


@app.route("/scan", methods=["POST"])
@auth.require_perm("scan")
def scan_route():
    f = request.form
    if f.get("authorized") != "on":
        return jsonify({"error": "You must confirm you are authorized to scan this target."}), 400
    target = (f.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Enter a target host, IP, or CIDR range."}), 400
    try:
        scan_scanner.expand_targets(target)
    except Exception as err:
        return jsonify({"error": str(err)}), 400
    advanced = f.get("mode") == "advanced"
    opts = {
        "target": target,
        "mode": "advanced" if advanced else "basic",
        "ports": (f.get("ports") or "").strip() if advanced else "",
        "grab_banner": (f.get("grab_banner") == "on") if advanced else True,
        "correlate_cves": (f.get("correlate_cves") == "on") if advanced else True,
        "use_nmap": (f.get("use_nmap") == "on") if advanced else False,
        "vuln_scripts": (f.get("vuln_scripts") == "on") if advanced else False,
        "os_detect": (f.get("os_detect") == "on") if advanced else False,
        "use_masscan": (f.get("use_masscan") == "on") if advanced else False,
        "nuclei": (f.get("nuclei") == "on") if advanced else False,
        "testssl": (f.get("testssl") == "on") if advanced else False,
        "headers": (f.get("headers") == "on") if advanced else False,
        "nikto": (f.get("nikto") == "on") if advanced else False,
        "wapiti": (f.get("wapiti") == "on") if advanced else False,
        "ffuf": (f.get("ffuf") == "on") if advanced else False,
        "subfinder": (f.get("subfinder") == "on") if advanced else False,
        "wpscan": (f.get("wpscan") == "on") if advanced else False,
        "droopescan": (f.get("droopescan") == "on") if advanced else False,
        "sqlmap": (f.get("sqlmap") == "on") if advanced else False,
        "webchecks": (f.get("webchecks") == "on") if advanced else False,
        "zap": (f.get("zap") == "on") if advanced else False,
        "retire": (f.get("retire") == "on") if advanced else False,
        "timing": f.get("timing", "4") if advanced else "4",
        "report_style": f.get("report_style", "technical") if advanced else "technical",
    }
    owner = auth.current_user()["username"]
    email_to = (f.get("email") or "").strip() or None
    job_id = uuid.uuid4().hex[:12]
    with _LOCK:
        JOBS[job_id] = {"status": "running", "logs": [], "report": None, "error": None}
    _audit("scan", "Network scan", detail=f"target={target}; mode={opts['mode']}")
    threading.Thread(target=_run_scan_job, args=(job_id, opts, email_to, owner), daemon=True).start()
    return jsonify({"job_id": job_id})


def _run_recon_job(job_id, domain, opts, owner):
    job = JOBS[job_id]
    handler = _ListHandler(job["logs"])
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        def progress(done, total):
            log.info("Resolved %d / %d hosts", done, total)
        result = run_recon(domain, opts, CONFIG, progress)
        out = report.render(result["markdown"], prefix="recon")
        fname = os.path.basename(out["html_path"])
        _set_owner(fname, owner)
        assets = result.get("assets", [])
        _upsert_assets(assets)
        targets = sorted({a["ip"] for a in assets if a.get("ip")})[:64]
        job["report"] = {"title": out["title"], "filename": fname,
                         "emailed": False, "owner": owner,
                         "targets": ", ".join(targets), "target_count": len(targets)}
        job["status"] = "done"
        log.info("Recon report ready: %s", out["title"])
    except Exception as err:
        job["status"] = "error"
        job["error"] = str(err)
        log.exception("Recon job failed")
    finally:
        root.removeHandler(handler)


@app.route("/recon", methods=["POST"])
@auth.require_perm("scan")
def recon_route():
    f = request.form
    if f.get("authorized") != "on":
        return jsonify({"error": "You must confirm you are authorized to assess this domain."}), 400
    domain = (f.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "Enter a domain, e.g. example.com"}), 400
    opts = {"use_shodan": f.get("use_shodan") == "on", "use_hunter": f.get("use_hunter") == "on",
            "fingerprint": f.get("fingerprint", "on") == "on",
            "ip_intel": f.get("ip_intel", "on") == "on",
            "use_subfinder": f.get("use_subfinder", "on") == "on",
            "use_amass": f.get("use_amass") == "on",
            "use_dnsx": f.get("use_dnsx", "on") == "on",
            "use_httpx": f.get("use_httpx") == "on",
            "use_urls": f.get("use_urls") == "on"}
    owner = auth.current_user()["username"]
    job_id = uuid.uuid4().hex[:12]
    with _LOCK:
        JOBS[job_id] = {"status": "running", "logs": [], "report": None, "error": None}
    _audit("recon", "OSINT recon", detail=f"domain={domain}")
    threading.Thread(target=_run_recon_job, args=(job_id, domain, opts, owner), daemon=True).start()
    return jsonify({"job_id": job_id})


def _run_cloud_job(job_id, creds, owner, token=None, sections=None):
    """One Azure assessment = tenant posture (CSPM) + optional vendor (provider)
    assessment, merged into a single report. Each part is captured independently
    so one failing doesn't lose the other."""
    job = JOBS[job_id]
    handler = _ListHandler(job["logs"])
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        parts, ok = [], False
        try:
            result = azure_cloud.assess_azure(creds, CONFIG, progress=lambda m: log.info("%s", m), token=token)
            parts.append(result["markdown"]); ok = True
        except Exception as err:
            log.info("Tenant posture failed: %s", err)
            parts.append(f"# Azure Cloud Security Posture\n\n> Tenant posture assessment could not run: {err}")
        if sections:
            try:
                log.info("Running Azure vendor security assessment…")
                parts.append(cloud_vendor.assess_vendor("azure", CONFIG, sections=sections)); ok = True
            except Exception as err:
                log.info("Vendor assessment failed: %s", err)
                parts.append(f"# Vendor Security Assessment\n\n> Vendor assessment could not run: {err}")
        if not ok:
            raise RuntimeError(parts[0].split("> ", 1)[-1] if parts else "Assessment failed.")
        out = report.render("\n\n---\n\n".join(parts), prefix="azure")
        fname = os.path.basename(out["html_path"])
        _set_owner(fname, owner)
        job["report"] = {"title": out["title"], "filename": fname, "emailed": False, "owner": owner}
        job["status"] = "done"
        log.info("Azure assessment report ready: %s", out["title"])
    except Exception as err:
        job["status"] = "error"
        job["error"] = str(err)
        log.exception("Cloud assessment failed")
    finally:
        root.removeHandler(handler)


@app.route("/cloud/azure", methods=["POST"])
@auth.require_perm("scan")
def cloud_azure():
    f = request.form
    if f.get("authorized") != "on":
        return jsonify({"error": "You must confirm you are authorized to assess this Azure tenant."}), 400
    creds = {"tenant": (f.get("tenant") or "").strip(),
             "client_id": (f.get("client_id") or "").strip(),
             "secret": f.get("secret") or "",
             "subscription": (f.get("subscription") or "").strip()}
    if not (creds["tenant"] and creds["client_id"] and creds["secret"]):
        return jsonify({"error": "Enter the tenant ID, client ID, and client secret."}), 400
    sections = f.getlist("sections")
    owner = auth.current_user()["username"]
    job_id = uuid.uuid4().hex[:12]
    with _LOCK:
        JOBS[job_id] = {"status": "running", "logs": [], "report": None, "error": None}
    threading.Thread(target=_run_cloud_job, args=(job_id, creds, owner),
                     kwargs={"sections": sections}, daemon=True).start()
    _audit("cloud", "Azure assessment (service principal)", detail=f"tenant={creds['tenant']}")
    return jsonify({"job_id": job_id})


@app.route("/cloud/azure/device/start", methods=["POST"])
@auth.require_perm("scan")
def cloud_azure_device_start():
    f = request.form
    if f.get("authorized") != "on":
        return jsonify({"error": "You must confirm you are authorized to assess this Azure tenant."}), 400
    tenant = (f.get("tenant") or "organizations").strip() or "organizations"
    try:
        d = azure_cloud.start_device_code(tenant)
    except Exception as err:
        log.exception("Device-code start failed")
        return jsonify({"error": f"Couldn't start sign-in: {err}"}), 500
    return jsonify({"device_code": d.get("device_code"), "user_code": d.get("user_code"),
                    "verification_uri": d.get("verification_uri") or d.get("verification_url"),
                    "interval": d.get("interval", 5), "expires_in": d.get("expires_in", 900),
                    "message": d.get("message", "")})


@app.route("/cloud/azure/device/poll", methods=["POST"])
@auth.require_perm("scan")
def cloud_azure_device_poll():
    f = request.form
    tenant = (f.get("tenant") or "organizations").strip() or "organizations"
    device_code = f.get("device_code") or ""
    if not device_code:
        return jsonify({"status": "error", "error": "Missing device code."}), 400
    res = azure_cloud.poll_token(tenant, device_code)
    if res["status"] == "pending":
        return jsonify({"status": "pending"})
    if res["status"] != "ok":
        return jsonify({"status": res["status"], "error": res.get("message", "Sign-in not completed.")})
    creds = {"tenant": "" if tenant in ("organizations", "common") else tenant,
             "subscription": (f.get("subscription") or "").strip()}
    owner = auth.current_user()["username"]
    job_id = uuid.uuid4().hex[:12]
    with _LOCK:
        JOBS[job_id] = {"status": "running", "logs": [], "report": None, "error": None}
    threading.Thread(target=_run_cloud_job, args=(job_id, creds, owner),
                     kwargs={"token": res["access_token"], "sections": f.getlist("sections")},
                     daemon=True).start()
    _audit("cloud", "Azure assessment (signed-in)", detail=f"tenant={tenant}")
    return jsonify({"status": "ok", "job_id": job_id})


def _run_vendor_job(job_id, provider, sections, owner):
    job = JOBS[job_id]
    handler = _ListHandler(job["logs"])
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        log.info("Running %s vendor security assessment…", provider)
        md = cloud_vendor.assess_vendor(provider, CONFIG, sections=sections)
        out = report.render(md, prefix=provider)
        fname = os.path.basename(out["html_path"])
        _set_owner(fname, owner)
        job["report"] = {"title": out["title"], "filename": fname, "emailed": False, "owner": owner}
        job["status"] = "done"
        log.info("Vendor assessment ready: %s", out["title"])
    except Exception as err:
        job["status"] = "error"
        job["error"] = str(err)
        log.exception("Vendor assessment failed")
    finally:
        root.removeHandler(handler)


@app.route("/cloud/vendor-assess", methods=["POST"])
@auth.require_perm("scan")
def cloud_vendor_assess():
    provider = (request.form.get("provider") or "").strip().lower()
    if provider not in cloud_vendor.PROVIDERS:
        return jsonify({"error": "Choose a supported provider: azure, aws, or gcp."}), 400
    sections = request.form.getlist("sections")
    owner = auth.current_user()["username"]
    job_id = uuid.uuid4().hex[:12]
    with _LOCK:
        JOBS[job_id] = {"status": "running", "logs": [], "report": None, "error": None}
    _audit("cloud", "Vendor security assessment", detail=provider)
    threading.Thread(target=_run_vendor_job, args=(job_id, provider, sections, owner), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/scan/schedule", methods=["POST"])
@auth.require_perm("scan")
def save_scan_schedule():
    f = request.form
    target = (f.get("target") or "").strip()
    if f.get("enabled") == "on" and target:
        try:
            scan_scanner.expand_targets(target)
        except Exception as err:
            return jsonify({"ok": False, "message": str(err)})
    prev = _load_scan_sched()
    sched = {
        "enabled": f.get("enabled") == "on",
        "target": target,
        "frequency": f.get("frequency", "weekly"),
        "weekday": f.get("weekday", "mon"),
        "time": f.get("time", "03:00"),
        "mode": f.get("mode", "advanced"),
        "ports": (f.get("ports") or "").strip(),
        "use_nmap": f.get("use_nmap") == "on",
        "vuln_scripts": f.get("vuln_scripts") == "on",
        "report_style": f.get("report_style", "technical"),
        "last_run": prev.get("last_run"),
        "last_status": prev.get("last_status"),
    }
    _save_scan_sched(sched)
    _register_scan_sched(sched)
    return jsonify({"ok": True, "enabled": sched["enabled"], "next_run": _next_scan_run()})


@app.route("/assets")
@auth.require_perm("scan")
def assets_list():
    return jsonify({"assets": _list_assets()})


def _assets_markdown():
    assets = _list_assets()
    lines = ["# Asset Inventory", "",
             f"_{len(assets)} host(s) · generated "
             f"{_dt.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}_", "",
             "## Assets", "",
             "| IP | Hostname | OS | Open ports | Services | Risk | Last scan |",
             "|----|----------|----|-----------|----------|------|-----------|"]
    for a in assets:
        ports = ", ".join(str(p) for p in a.get("ports", [])) or "—"
        svcs = ", ".join(a.get("services", [])) or "—"
        lines.append(f"| `{a.get('ip','')}` | {a.get('hostname') or '—'} | {a.get('os') or '—'} "
                     f"| {ports} | {svcs} | {a.get('risk',0)} {a.get('label','')} "
                     f"| {a.get('last_scan','')} |")
    if not assets:
        lines.append("| _no assets_ | | | | | | |")
    return "\n".join(lines)


@app.route("/assets/export")
@auth.require_perm("scan")
def assets_export():
    fmt = request.args.get("fmt", "html").lower()
    md = _assets_markdown()
    stamp = _dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    if fmt == "csv":
        return send_file(io.BytesIO(export.to_csv(export.extract_tables(md)).encode("utf-8-sig")),
                         mimetype="text/csv", as_attachment=True, download_name=f"assets-{stamp}.csv")
    if fmt == "xlsx":
        return send_file(io.BytesIO(export.to_xlsx_bytes(export.extract_tables(md))),
                         mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                         as_attachment=True, download_name=f"assets-{stamp}.xlsx")
    html = report.to_html(md, title="Asset Inventory", heading="Asset Inventory")
    return send_file(io.BytesIO(html.encode("utf-8")), mimetype="text/html",
                     as_attachment=True, download_name=f"assets-{stamp}.html")


@app.route("/assets/clear", methods=["POST"])
@auth.require_perm("scan")
def assets_clear():
    with _LOCK:
        try:
            os.remove(ASSETS_FILE)
        except OSError:
            pass
    return jsonify({"ok": True})


@app.route("/alerts", methods=["GET"])
@auth.require_perm("admin")
def alerts_get():
    return jsonify(alerts.load_config())


@app.route("/alerts/save", methods=["POST"])
@auth.require_perm("admin")
def alerts_save():
    f = request.form
    cfg = {
        "enabled": f.get("enabled") == "on",
        "min_severity": f.get("min_severity", "high"),
        "email_to": (f.get("email_to") or "").strip(),
        "teams_webhook": (f.get("teams_webhook") or "").strip(),
        "slack_webhook": (f.get("slack_webhook") or "").strip(),
        "webhook_url": (f.get("webhook_url") or "").strip(),
    }
    alerts.save_config(cfg)
    return jsonify({"ok": True})


@app.route("/alerts/test", methods=["POST"])
@auth.require_perm("admin")
def alerts_test():
    f = request.form
    cfg = {"enabled": True, "min_severity": f.get("min_severity", "high"),
           "email_to": (f.get("email_to") or "").strip(),
           "teams_webhook": (f.get("teams_webhook") or "").strip(),
           "slack_webhook": (f.get("slack_webhook") or "").strip(),
           "webhook_url": (f.get("webhook_url") or "").strip()}
    result = alerts.send_test(cfg)
    msg = ("Sent via: " + ", ".join(result["sent"])) if result["sent"] else "No channels sent."
    if result["errors"]:
        msg += " · errors: " + "; ".join(result["errors"])
    return jsonify({"ok": bool(result["sent"]), "message": msg})


@app.route("/assistant", methods=["POST"])
@auth.login_required
def assistant_route():
    data = request.get_json(silent=True) or {}
    clean = []
    for m in (data.get("messages") or [])[-20:]:
        role, content = m.get("role"), str(m.get("content", ""))[:6000]
        if role in ("user", "assistant") and content.strip():
            clean.append({"role": role, "content": content})
    if not clean or clean[-1]["role"] != "user":
        return jsonify({"error": "No question provided."}), 400
    context = ""
    rep = os.path.basename(data.get("report", "") or "")
    if rep:
        md = os.path.join(report.REPORTS_DIR, os.path.splitext(rep)[0] + ".md")
        if os.path.isfile(md):
            with open(md, encoding="utf-8") as fh:
                context = fh.read()
    try:
        reply = assistant.answer(clean, context, CONFIG)
    except Exception as err:
        log.exception("Assistant failed")
        return jsonify({"error": f"Assistant error: {err}"}), 500
    return jsonify({"reply": reply})


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

    if fmt in ("csv", "xlsx"):
        if not os.path.isfile(md_path):
            abort(404)
        with open(md_path, encoding="utf-8") as fh:
            tables = export.extract_tables(fh.read())
        if fmt == "csv":
            return send_file(io.BytesIO(export.to_csv(tables).encode("utf-8-sig")),
                             mimetype="text/csv", as_attachment=True,
                             download_name=stem + ".csv")
        return send_file(io.BytesIO(export.to_xlsx_bytes(tables)),
                         mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                         as_attachment=True, download_name=stem + ".xlsx")

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
    _audit("admin", "Delete report", level="warning", detail=stem)
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
    _audit("admin", "Clear all reports", level="warning", detail=f"{count} file(s) removed")
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
  :root { --bg:#0F172A; --panel:#0B1220; --card:#1E293B; --line:#334155; --muted:#94A3B8; --text:#F8FAFC; --primary:#3B82F6; --primary-d:#2563EB; --field:#0F172A; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:'Segoe UI',-apple-system,Inter,Arial,sans-serif; background:var(--bg); color:var(--text); -webkit-font-smoothing:antialiased; }
  .app { display:flex; min-height:100vh; }
  .sidebar { width:236px; flex-shrink:0; background:var(--panel); border-right:1px solid var(--line); padding:16px 12px; position:sticky; top:0; height:100vh; overflow:auto; display:flex; flex-direction:column; gap:3px; }
  .brand { display:flex; align-items:center; gap:10px; color:#fff; font-weight:700; font-size:15px; padding:6px 8px 12px; letter-spacing:.02em; }
  .brand .dot { width:9px; height:9px; border-radius:50%; background:var(--primary); box-shadow:0 0 10px var(--primary); flex-shrink:0; }
  .nav-group { font-size:10px; text-transform:uppercase; letter-spacing:.09em; color:#64748b; margin:12px 8px 4px; }
  .tabbtn { display:flex; align-items:center; gap:10px; width:100%; text-align:left; background:none; border:0; color:var(--muted); font-size:13.5px; padding:9px 11px; border-radius:8px; cursor:pointer; margin:0; }
  .tabbtn:hover { background:rgba(148,163,184,.10); color:var(--text); }
  .tabbtn.active { background:rgba(59,130,246,.16); color:#fff; box-shadow:inset 2px 0 0 var(--primary); }
  .content { flex:1; min-width:0; display:flex; flex-direction:column; }
  .topbar { display:flex; align-items:center; justify-content:space-between; gap:16px; padding:18px 30px; border-bottom:1px solid var(--line); position:sticky; top:0; z-index:20; background:rgba(15,23,42,.85); backdrop-filter:blur(8px); }
  .topclock { font-variant-numeric:tabular-nums; font-size:12.5px; color:var(--muted); background:var(--field); border:1px solid var(--line); border-radius:999px; padding:4px 11px; white-space:nowrap; }
  .quick { display:flex; flex-wrap:wrap; gap:10px; }
  .quick .dash-jump { margin-top:0; }
  .topbar h1 { margin:0; font-size:15px; font-weight:600; color:#fff; display:flex; align-items:center; gap:10px; min-width:0; }
  .topbar h1 { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .topbar-logo { height:26px; max-width:120px; border-radius:4px; background:#fff; padding:2px; flex-shrink:0; }
  .topbar .huser { font-size:13px; color:var(--muted); display:flex; gap:12px; align-items:center; white-space:nowrap; }
  .topbar .huser a { color:var(--primary); }
  .menu-toggle { display:none; background:transparent; border:1px solid var(--line); color:var(--text); font-size:18px; line-height:1; padding:7px 11px; border-radius:8px; cursor:pointer; margin:0; flex-shrink:0; }
  .menu-toggle:hover { background:rgba(148,163,184,.10); }
  .scrim { display:none; }
  .acc-head { cursor:pointer; display:flex; justify-content:space-between; align-items:center; gap:10px; user-select:none; }
  .acc-arrow { color:var(--muted); font-size:13px; transition:transform .2s; flex-shrink:0; }
  .card.collapsed .acc-arrow { transform:rotate(-90deg); }
  .card.collapsed .acc-body { display:none; }
  .card.collapsed h2 { margin-bottom:0; }
  .wrap { max-width:1200px; width:100%; margin:0 auto; padding:24px; }
  .tab { display:none; }
  .tab.active { display:flex; flex-direction:column; gap:20px; }
  .subtabs { display:flex; gap:4px; border-bottom:1px solid var(--line); flex-wrap:wrap; }
  .subtabbtn { background:none; border:0; border-bottom:2px solid transparent; color:var(--muted); font-size:13.5px; font-weight:600; padding:8px 16px; margin:0; border-radius:0; cursor:pointer; }
  .subtabbtn:hover { color:var(--text); }
  .subtabbtn.active { color:#fff; border-bottom-color:var(--primary); }
  .subtab { display:none; flex-direction:column; gap:20px; }
  .subtab.active { display:flex; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:20px 22px; box-shadow:0 1px 2px rgba(0,0,0,.25); }
  .card h2 { margin:0 0 14px; font-size:15px; color:#fff; }
  .grid3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:14px; }
  label { display:block; font-size:12px; color:var(--muted); margin-bottom:4px; }
  input, select, textarea { width:100%; padding:9px 10px; border:1px solid var(--line); border-radius:6px; font-size:14px; background:var(--field); color:var(--text); font-family:inherit; }
  input::placeholder, textarea::placeholder { color:#64748b; }
  input[readonly] { background:#0b1220; color:var(--muted); cursor:default; }
  textarea { resize:vertical; min-height:60px; }
  button { background:var(--primary); color:#fff; border:0; padding:11px 20px; border-radius:6px; font-size:14px; cursor:pointer; margin-top:12px; }
  button:hover { background:var(--primary-d); }
  button:disabled { opacity:.5; cursor:not-allowed; }
  button.secondary { background:transparent; color:var(--text); border:1px solid var(--line); }
  button.secondary:hover { background:rgba(148,163,184,.10); }
  .row { margin-top:14px; }
  .presets { display:flex; flex-wrap:wrap; gap:14px; margin-top:6px; }
  .presets label { display:flex; align-items:center; gap:6px; font-size:13px; color:var(--text); margin:0; }
  .presets input { width:auto; }
  .check { display:flex; align-items:center; gap:8px; margin-top:6px; }
  .check input { width:auto; }
  .stats { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; }
  .stat { background:var(--field); border:1px solid var(--line); border-radius:10px; padding:14px; }
  .stat .n { font-size:22px; font-weight:700; color:#fff; }
  .stat .l { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.05em; margin-top:4px; }
  .risk-critical { color:#f87171; } .risk-high { color:#fb923c; } .risk-medium { color:#fbbf24; }
  .risk-low { color:#4ade80; } .risk-minimal { color:#4ade80; }
  .badge { font-size:11px; padding:2px 8px; border-radius:999px; }
  .badge.on { background:rgba(34,197,94,.18); color:#4ade80; } .badge.off { background:rgba(148,163,184,.15); color:#94a3b8; }
  .console { background:#060c16; color:#9fd0f5; font-family:Consolas,monospace; font-size:12px; border:1px solid var(--line); border-radius:8px; padding:14px; height:240px; overflow:auto; white-space:pre-wrap; display:none; margin-top:14px; }
  .pill { font-size:11px; padding:2px 8px; border-radius:999px; background:rgba(148,163,184,.15); color:var(--muted); margin-left:8px; }
  .ok { color:#4ade80; } .err { color:#f87171; }
  .note { font-size:12px; color:var(--muted); margin-top:8px; }
  .warn { background:rgba(245,158,11,.12); border:1px solid rgba(245,158,11,.45); color:#fbbf24; font-size:12px; padding:8px 10px; border-radius:6px; margin-top:10px; }
  ul.reports { list-style:none; margin:0; padding:0; }
  ul.reports li { padding:10px 0; border-bottom:1px solid var(--line); display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap; }
  ul.reports li:last-child { border-bottom:0; }
  ul.reports li .name { display:flex; align-items:center; gap:8px; min-width:0; flex:1 1 auto; }
  ul.reports li .name a { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .kind { font-size:10px; padding:2px 7px; border-radius:999px; font-weight:600; flex-shrink:0; letter-spacing:.02em; text-transform:uppercase; }
  .kind.briefing { background:rgba(59,130,246,.18); color:#93c5fd; }
  .kind.analysis { background:rgba(139,92,246,.18); color:#c4b5fd; }
  .kind.scan { background:rgba(20,184,166,.20); color:#5eead4; }
  .kind.recon { background:rgba(245,158,11,.18); color:#fcd34d; }
  .kind.cve { background:rgba(239,68,68,.18); color:#fca5a5; }
  .kind.actor { background:rgba(168,85,247,.20); color:#d8b4fe; }
  .kind.hunt { background:rgba(16,185,129,.18); color:#6ee7b7; }
  .kind.cloud { background:rgba(56,189,248,.18); color:#7dd3fc; }
  .by { color:var(--muted); font-size:12px; white-space:nowrap; }
  .ms { position:relative; }
  .ms-toggle { width:100%; margin-top:0; text-align:left; background:var(--field); color:var(--text); border:1px solid var(--line); padding:9px 10px; border-radius:6px; font-size:14px; cursor:pointer; display:flex; justify-content:space-between; align-items:center; gap:8px; }
  .ms-toggle .ms-arrow { color:var(--muted); }
  .ms-panel { position:absolute; z-index:30; left:0; right:0; top:calc(100% + 4px); background:var(--card); border:1px solid var(--line); border-radius:8px; box-shadow:0 8px 24px rgba(0,0,0,.5); max-height:240px; overflow:auto; padding:6px; display:none; }
  .ms.open .ms-panel { display:block; }
  .ms-opt { display:flex; align-items:center; gap:8px; padding:6px 8px; font-size:13px; border-radius:6px; cursor:pointer; margin:0; white-space:nowrap; color:var(--text); }
  .ms-opt:hover { background:rgba(59,130,246,.14); }
  .ms-opt input { width:auto; margin:0; }
  a { color:#60a5fa; text-decoration:none; } a:hover { text-decoration:underline; }
  .actions { display:flex; gap:6px; align-items:center; flex-shrink:0; flex-wrap:wrap; }
  .dl, .pv { font-size:12px; border:1px solid var(--line); padding:4px 9px; border-radius:6px; color:#93c5fd; cursor:pointer; background:transparent; }
  .dl:hover, .pv:hover { background:rgba(59,130,246,.14); text-decoration:none; }
  .del { background:transparent; color:#f87171; border:1px solid rgba(239,68,68,.45); padding:4px 9px; border-radius:6px; font-size:12px; cursor:pointer; margin:0; }
  .del:hover { background:rgba(239,68,68,.14); }
  #stop-btn { background:#ef4444; margin-left:8px; } #stop-btn:hover { background:#dc2626; }
  #clear-btn { background:#ef4444; font-size:13px; padding:8px 14px; } #clear-btn:hover { background:#dc2626; }
  #search { margin-bottom:12px; }
  #preview { width:100%; height:520px; border:1px solid var(--line); border-radius:8px; margin-top:14px; display:none; background:#fff; }
  .card table { max-width:100%; }
  .card table th, .card table td { border-color:var(--line) !important; color:var(--text); }
  .aichat { border:1px solid var(--line); border-radius:8px; padding:12px; height:380px; overflow:auto; background:#060c16; display:flex; flex-direction:column; gap:10px; margin-top:6px; }
  .msg { max-width:88%; padding:10px 12px; border-radius:10px; font-size:14px; line-height:1.5; white-space:pre-wrap; word-break:break-word; }
  .msg.user { align-self:flex-end; background:var(--primary); color:#fff; }
  .msg.bot { align-self:flex-start; background:var(--field); color:#e2e8f0; border:1px solid var(--line); font-family:Consolas,Menlo,monospace; }
  #ai-fab { position:fixed; right:22px; bottom:22px; width:56px; height:56px; border-radius:50%; background:var(--primary); color:#fff; border:0; font-size:24px; cursor:pointer; box-shadow:0 6px 24px rgba(59,130,246,.5); z-index:1000; margin:0; display:flex; align-items:center; justify-content:center; }
  #ai-fab:hover { background:var(--primary-d); }
  #ai-widget { position:fixed; right:22px; bottom:88px; width:380px; max-width:92vw; height:520px; max-height:78vh; background:var(--card); border:1px solid var(--line); border-radius:14px; box-shadow:0 16px 48px rgba(0,0,0,.55); display:none; flex-direction:column; overflow:hidden; z-index:1000; }
  #ai-widget.open { display:flex; }
  .ai-head { background:linear-gradient(135deg,#0f2a43,#1d4671); color:#fff; padding:12px 14px; display:flex; justify-content:space-between; align-items:center; font-size:14px; font-weight:600; }
  .ai-head button { background:none; border:0; color:#fff; font-size:22px; line-height:1; cursor:pointer; margin:0; padding:0; }
  .ai-body { display:flex; flex-direction:column; gap:8px; padding:10px; flex:1; min-height:0; }
  .ai-body .aichat { flex:1; height:auto; margin-top:0; }
  .ai-body form { display:flex; gap:8px; }
  .ai-body #ai-input { flex:1; }
  .ai-body #ai-send { margin-top:0; }
  @media (max-width:860px) {
    .menu-toggle { display:flex; }
    .sidebar { position:fixed; top:0; left:0; height:100vh; width:248px; flex-direction:column;
               transform:translateX(-100%); transition:transform .22s ease; z-index:60; overflow:auto;
               border-right:1px solid var(--line); }
    .sidebar.open { transform:translateX(0); box-shadow:6px 0 28px rgba(0,0,0,.5); }
    .scrim.open { display:block; position:fixed; inset:0; background:rgba(0,0,0,.5); z-index:55; }
    .tabbtn { white-space:nowrap; }
    .topbar { padding:14px 18px; gap:10px; }
    .topbar h1 { font-size:14px; }
    .topclock { display:none; }
    .quick .dash-jump { flex:1 1 100%; }
    .wrap { padding:16px; }
    .grid3 { grid-template-columns:1fr; }
    .stats { grid-template-columns:1fr 1fr; }
    .card { padding:16px; }
    .card table { display:block; overflow-x:auto; white-space:nowrap; -webkit-overflow-scrolling:touch; }
    ul.reports li { flex-direction:column; align-items:flex-start; }
    ul.reports li .name { flex:1 1 100%; width:100%; }
    .actions { flex:1 1 100%; flex-wrap:wrap; }
    .console { height:200px; }
    #preview { height:420px; }
    input, select, textarea { font-size:16px; }
    .presets { gap:10px 14px; }
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
{% macro vendor_card(provider, label, sections) %}
<div class="card">
  <h2>Vendor security assessment</h2>
  <p class="note">Provider-level review of {{ label }} — choose which checks to include below, then run. No credentials needed. The result is AI-compiled from public information; verify against the provider's trust center.</p>
  <div class="row"><label>Checks to include</label>
    <div class="presets">
      {% for k, lbl in sections %}<label><input type="checkbox" name="sections" value="{{ k }}" checked> {{ lbl }}</label>{% endfor %}
    </div>
  </div>
  <button class="vendor-btn" type="button" data-provider="{{ provider }}">Run vendor assessment</button>
  <span class="pill vendor-state" style="display:none"></span>
  <div class="vendor-console console" style="display:none"></div>
</div>
{% endmacro %}
<div class="app">
<aside class="sidebar">
  <div class="brand">{% if logo %}<img src="/branding/logo?v={{ logo_ver }}" alt="" style="height:24px;border-radius:4px;background:#fff;padding:2px;">{% else %}<span class="dot"></span>{% endif %}Threat Intel</div>
  <button class="tabbtn {{ 'active' if active_tab=='tab-dashboard' }}" data-tab="tab-dashboard">Dashboard</button>
  <button class="tabbtn" data-tab="tab-latest-cves">Latest CVEs</button>
  {% if 'generate' in perms or 'analyze' in perms %}<div class="nav-group">Intelligence</div>{% endif %}
  {% if 'generate' in perms %}<button class="tabbtn {{ 'active' if active_tab=='tab-generate' }}" data-tab="tab-generate">Briefings</button>{% endif %}
  {% if 'analyze' in perms %}<button class="tabbtn" data-tab="tab-analyze">Analyze</button>{% endif %}
  {% if 'generate' in perms %}<button class="tabbtn" data-tab="tab-intel">Threat Intel</button>{% endif %}
  {% if 'scan' in perms %}<div class="nav-group">Attack Surface</div>
  <button class="tabbtn" data-tab="tab-scan">Network Scan</button>
  <button class="tabbtn" data-tab="tab-recon">OSINT Recon</button>
  <button class="tabbtn" data-tab="tab-cloud">Cloud Posture</button>
  <button class="tabbtn" data-tab="tab-assets">Assets</button>{% endif %}
  <div class="nav-group">Operations</div>
  {% if 'schedule' in perms %}<button class="tabbtn" data-tab="tab-schedule">Schedule</button>{% endif %}
  <button class="tabbtn {{ 'active' if active_tab=='tab-history' }}" data-tab="tab-history">History</button>
  <div class="nav-group">System</div>
  <button class="tabbtn" data-tab="tab-settings">Settings</button>
  {% if is_admin %}<button class="tabbtn" data-tab="tab-admin">Admin</button>{% endif %}
  {% if is_admin %}<button class="tabbtn" data-tab="tab-logs">Logs</button>{% endif %}
</aside>
<div id="nav-scrim" class="scrim"></div>
<div class="content">
<header class="topbar">
  <button id="menu-toggle" class="menu-toggle" type="button" aria-label="Open menu">&#9776;</button>
  <h1>{% if logo %}<img src="/branding/logo?v={{ logo_ver }}" alt="" class="topbar-logo">{% endif %}Threat Intelligence Briefing Agent</h1>
  <div class="huser"><span id="clock" class="topclock"></span>{{ user.username }}{% if is_admin %} (admin){% endif %} &middot; <a href="/logout">Sign out</a></div>
</header>
<div class="wrap">

  <section class="tab {{ 'active' if active_tab=='tab-dashboard' }}" id="tab-dashboard">
  <div class="card">
    <h2>Overview</h2>
    <div class="stats">
      <div class="stat"><div class="n">{{ stats.total }}</div><div class="l">Saved reports</div></div>
      <div class="stat"><div class="n">{{ stats.cves }}</div><div class="l">CVEs in latest briefing</div></div>
      <div class="stat"><div class="n">{{ assets|length }}</div><div class="l">Assets tracked</div></div>
      <div class="stat"><div class="n" style="font-size:14px">{% if smtp_ready %}<span class="badge on">Ready</span>{% else %}<span class="badge off">Not set</span>{% endif %}</div><div class="l">Email (SMTP)</div></div>
    </div>
    <div class="note">Engine: {{ provider }}{% if model %} &middot; {{ model }}{% endif %}{% if stats.when %} &middot; latest briefing {{ stats.when }}{% endif %} &middot; next scheduled briefing {{ next_run or 'off' }}{% if next_scan_run %} &middot; next scan {{ next_scan_run }}{% endif %}{% if schedule.last_run %} &middot; last run {{ schedule.last_run }} ({{ schedule.last_status }}){% endif %}</div>
  </div>

  <div class="card">
    <h2>Quick actions</h2>
    <div class="quick">
      {% if 'generate' in perms %}<button type="button" class="dash-jump" data-tab="tab-generate">New briefing</button>{% endif %}
      {% if 'analyze' in perms %}<button type="button" class="dash-jump secondary" data-tab="tab-analyze">Analyze a file</button>{% endif %}
      {% if 'generate' in perms %}<button type="button" class="dash-jump secondary" data-tab="tab-intel">CVE / actor lookup</button>{% endif %}
      {% if 'scan' in perms %}<button type="button" class="dash-jump secondary" data-tab="tab-scan">Network scan</button>{% endif %}
      <button type="button" class="dash-jump secondary" data-tab="tab-history">View history</button>
    </div>
  </div>

  {% if scan_stats %}
  <div class="card">
    <h2>Latest network scan — risk</h2>
    <div class="stats">
      <div class="stat"><div class="n risk-{{ scan_stats.label|lower }}">{{ scan_stats.risk }}/100</div><div class="l">Risk · {{ scan_stats.label }}</div></div>
      <div class="stat"><div class="n risk-critical">{{ scan_stats.counts.critical }}</div><div class="l">Critical</div></div>
      <div class="stat"><div class="n risk-high">{{ scan_stats.counts.high }}</div><div class="l">High</div></div>
      <div class="stat"><div class="n risk-medium">{{ scan_stats.counts.medium }}</div><div class="l">Medium</div></div>
    </div>
    <div class="note">Target {{ scan_stats.target }} &middot; {{ scan_stats.hosts_up }} responsive host(s) &middot; {{ scan_stats.open_ports }} open ports &middot; {{ scan_stats.cves }} potential CVEs ({{ scan_stats.kev }} in CISA KEV)</div>
  </div>
  {% endif %}

  {% if assets %}
  <div class="card">
    <h2>Top assets by risk</h2>
    <ul class="reports">
      {% for a in assets[:5] %}
      <li><span class="name"><span class="risk-{{ a.label|lower }}" style="font-weight:600">{{ a.risk }} · {{ a.label }}</span> <span style="color:var(--muted)">{{ a.ip }}{% if a.hostname %} ({{ a.hostname }}){% endif %}</span></span>
      <span class="by">{{ a.ports|length }} open port(s)</span></li>
      {% endfor %}
    </ul>
  </div>
  {% endif %}

  <div class="card">
    <h2>Latest CVEs <span id="dash-cve-meta" class="pill" style="display:none"></span></h2>
    <p class="note">Newly published vulnerabilities from the NVD feed. <a href="#" class="dash-jump" data-tab="tab-latest-cves">See all →</a></p>
    <div id="dash-cves"><p class="note">Loading latest CVEs…</p></div>
  </div>

  <div class="card">
    <h2>Recent reports</h2>
    {% if reports %}
    <ul class="reports">
      {% for r in reports[:6] %}
      <li><span class="name"><span class="kind {{ r.kind }}">{{ {'analysis':'Analysis','scan':'Scan','recon':'Recon','briefing':'Briefing','cve':'CVE','actor':'Actor','hunt':'Hunt','cloud':'Cloud'}[r.kind] }}</span><a href="/reports/{{ r.filename }}" target="_blank">{{ r.filename }}</a>{% if r.owner %}<span class="by">by {{ r.owner }}</span>{% endif %}</span></li>
      {% endfor %}
    </ul>
    {% else %}
    <p class="note">No reports yet — generate a briefing or run a scan to get started.</p>
    {% endif %}
  </div>
  </section>

  <section class="tab" id="tab-latest-cves">
  <div class="card">
    <h2>Latest CVEs <span id="cve-feed-meta" class="pill" style="display:none"></span></h2>
    <p class="note">Recently published vulnerabilities from the NVD, flagged when listed in the CISA Known Exploited Vulnerabilities (KEV) catalog. {% if 'generate' in perms %}Use <b>Analyze</b> for a full grounded deep-dive.{% endif %}</p>
    <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
      <button id="cve-refresh" type="button" class="secondary" style="margin-top:0">Refresh</button>
      <span id="cve-feed-state" class="pill" style="display:none"></span>
    </div>
    <div id="cve-feed"><p class="note">Loading latest CVEs…</p></div>
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
  <div class="card">
    <h2>Vendor lookup</h2>
    <p class="note">Paste a vendor API key and an indicator (IP, domain, URL, or file hash) — or choose a file. The app detects which vendor the key belongs to (VirusTotal, AbuseIPDB, Shodan, Hunter.io, or NVD) and runs the lookup. Keys are used for this request only and never stored.</p>
    <form id="vendor-form">
      <div class="row"><label>Vendor API key</label>
        <input id="vendor-key" name="api_key" type="password" autocomplete="off" placeholder="Paste your VirusTotal / AbuseIPDB / Shodan / Hunter.io / NVD key"></div>
      <div class="grid3">
        <div style="grid-column:span 2"><label>Indicator (IP, domain, URL, or file hash)</label>
          <input id="vendor-indicator" name="indicator" placeholder="8.8.8.8 · evil-domain.com · https://… · a1b2c3… hash"></div>
        <div><label>…or a file</label><input id="vendor-file" name="file" type="file"></div>
      </div>
      <button id="vendor-btn" type="submit">Analyze</button>
      <span id="v-state" class="pill" style="display:none"></span>
    </form>
    <div id="vendor-result" style="margin-top:14px"></div>
  </div>
  </section>
  {% endif %}

  {% if 'generate' in perms %}
  <section class="tab" id="tab-intel">
  <div class="card">
    <h2>CVE analysis</h2>
    <p class="note">Enter a CVE ID for a grounded deep-dive — live CVSS (NVD), exploitation probability (EPSS), CISA KEV status, MITRE ATT&CK mapping, and prioritised remediation. Saved to History.</p>
    <form id="cve-form">
      <div class="grid3">
        <div style="grid-column:span 2"><label>CVE ID</label><input id="cve-id" name="cve" placeholder="CVE-2024-3400"></div>
        <div style="display:flex;align-items:flex-end"><button id="cve-btn" type="submit" style="margin:0;width:100%">Analyze CVE</button></div>
      </div>
      <span id="cve-state" class="pill" style="display:none"></span>
    </form>
  </div>
  <div class="card">
    <h2>Threat actor intelligence</h2>
    <p class="note">Profile a threat actor, APT group, or ransomware operation — aliases, TTPs mapped to MITRE ATT&CK, associated malware, target sectors, attribution confidence, and hunting starters. AI-compiled from public intel; verify recent claims before operational use.</p>
    <form id="actor-form">
      <div class="grid3">
        <div style="grid-column:span 2"><label>Actor / group / malware name</label><input id="actor-name" name="name" placeholder="LockBit · APT29 · Lazarus Group"></div>
        <div style="display:flex;align-items:flex-end"><button id="actor-btn" type="submit" style="margin:0;width:100%">Build profile</button></div>
      </div>
      <span id="actor-state" class="pill" style="display:none"></span>
    </form>
  </div>
  <div class="card">
    <h2>Threat hunting queries</h2>
    <p class="note">Generate hunting queries plus an investigation workflow for a threat or technique, in your platform's language. Queries are AI-generated starting points — validate table/field names against your environment before use.</p>
    <form id="hunt-form">
      <div class="grid3">
        <div><label>Hunt for</label><input id="hunt-subject" name="subject" placeholder="LockBit ransomware · T1059 PowerShell"></div>
        <div><label>Platform</label><select name="platform">
          <option value="sentinel">Microsoft Sentinel (KQL)</option>
          <option value="defender">Microsoft Defender XDR (KQL)</option>
          <option value="splunk">Splunk (SPL)</option>
          <option value="sigma">Sigma (YAML)</option>
        </select></div>
        <div style="display:flex;align-items:flex-end"><button id="hunt-btn" type="submit" style="margin:0;width:100%">Generate queries</button></div>
      </div>
      <span id="hunt-state" class="pill" style="display:none"></span>
    </form>
  </div>
  </section>
  {% endif %}

  {% if 'scan' in perms %}
  <section class="tab" id="tab-scan">
  <div class="card">
    <h2>Scan a network for vulnerabilities</h2>
    <p class="note">Discovers open ports and services, then correlates detected versions with known CVEs (from NVD/KEV). Results are saved to History.</p>
    <div class="warn">Only scan systems you own or are explicitly authorized to test. Unauthorized scanning may be illegal.</div>
    <form id="scan-form">
      <div class="grid3">
        <div><label>Target (host, IP, or CIDR)</label><input name="target" placeholder="192.168.1.10 or 10.0.0.0/28 or host.example.com"></div>
        <div><label>Mode</label>
          <select name="mode" id="scan-mode">
            <option value="basic">Basic — common ports, fast</option>
            <option value="advanced">Advanced — custom ports, CVE correlation, nmap</option>
          </select>
        </div>
        <div><label>Email result to (optional)</label><input name="email" placeholder="you@company.com"></div>
      </div>
      <div id="scan-adv" style="display:none">
        <div class="grid3" style="margin-top:6px">
          <div><label>Ports (e.g. 1-1024 or 22,80,443) — blank = common set</label><input name="ports" placeholder="1-1024"></div>
          <div><label>nmap timing (0 slow – 5 fast)</label>
            <select name="timing"><option>3</option><option selected>4</option><option>5</option><option>2</option><option>1</option><option>0</option></select>
          </div>
          <div><label>Report style</label>
            <select name="report_style"><option value="technical">Technical (detailed)</option><option value="executive">Executive (business)</option></select>
          </div>
        </div>
        <div class="row"><label>Options</label>
          <div class="presets">
            <label><input type="checkbox" name="grab_banner" checked> Banner / version detection</label>
            <label><input type="checkbox" name="correlate_cves" checked> Correlate CVEs (NVD/KEV)</label>
            <label><input type="checkbox" name="use_nmap"> Use nmap if installed {% if not nmap_ok %}(not detected){% endif %}</label>
            <label><input type="checkbox" name="vuln_scripts"> nmap vuln scripts</label>
            <label><input type="checkbox" name="os_detect"> OS detection (nmap)</label>
            <label><input type="checkbox" name="use_masscan"> Fast discovery (masscan){% if not tools_ok.masscan %} (not detected){% endif %}</label>
            <label><input type="checkbox" name="nuclei"> Template detection (nuclei){% if not tools_ok.nuclei %} (not detected){% endif %}</label>
            <label><input type="checkbox" name="testssl"> TLS assessment (testssl.sh){% if not tools_ok.testssl %} (not detected){% endif %}</label>
          </div>
          {% if not nmap_ok %}<div class="note">nmap isn't installed on the server, so nmap options are ignored — the built-in scanner is used. Install nmap for service/version detection and vuln scripts.</div>{% endif %}
        </div>
        <div class="row"><label>Web application assessment (active — sends test requests to web services found)</label>
          <div class="presets">
            <label><input type="checkbox" name="headers" checked> Security headers / cookies / CORS</label>
            <label><input type="checkbox" name="webchecks"> Deep checks: CORS / open-redirect / JWT / exposed secrets</label>
            <label><input type="checkbox" name="zap"> OWASP ZAP (DAST){% if not tools_ok.zap %} (set ZAP_API_URL){% endif %}</label>
            <label><input type="checkbox" name="retire"> Vulnerable JS libs (retire.js){% if not tools_ok.retire %} (not detected){% endif %}</label>
            <label><input type="checkbox" name="nikto"> Nikto (misconfig / dangerous files){% if not tools_ok.nikto %} (not detected){% endif %}</label>
            <label><input type="checkbox" name="wapiti"> Wapiti (XSS / SQLi / disclosure){% if not tools_ok.wapiti %} (not detected){% endif %}</label>
            <label><input type="checkbox" name="ffuf"> Content discovery (ffuf){% if not tools_ok.ffuf %} (not detected){% endif %}</label>
            <label><input type="checkbox" name="subfinder"> Subdomain enum (subfinder){% if not tools_ok.subfinder %} (not detected){% endif %}</label>
            <label><input type="checkbox" name="wpscan"> WordPress (WPScan){% if not tools_ok.wpscan %} (not detected){% endif %}</label>
            <label><input type="checkbox" name="droopescan"> Drupal (Droopescan){% if not tools_ok.droopescan %} (not detected){% endif %}</label>
            <label><input type="checkbox" name="sqlmap"> SQLi detection (sqlmap){% if not tools_ok.sqlmap %} (not detected){% endif %}</label>
          </div>
          <div class="note">Tools not detected are skipped automatically (they ship in the Docker image). The web-app checks send test requests to discovered HTTP(S) services — run only against systems you own or are authorized to test, ideally non-production. Detection only: sqlmap confirms injectable parameters but does not dump data; no brute-force or password attacks.</div>
        </div>
      </div>
      <div class="check"><input type="checkbox" id="scan-auth" name="authorized"><label for="scan-auth" style="margin:0">I am authorized to scan this target.</label></div>
      <button id="scan-btn" type="submit">Start scan</button>
      <span id="s-state" class="pill" style="display:none"></span>
    </form>
    <div id="s-console" class="console"></div>
  </div>
  <div class="card">
    <h2>Scheduled scans</h2>
    <p class="note">Recurring scan of a target; alerts fire on findings (configure in Settings). Runs only while the app is running; times are UTC.</p>
    <form id="scan-sched-form">
      <div class="check"><input type="checkbox" id="ss-enabled" name="enabled" {% if scan_sched.enabled %}checked{% endif %}><label for="ss-enabled" style="margin:0">Enable scheduled scan</label></div>
      <div class="grid3" style="margin-top:12px">
        <div><label>Target (host/IP/CIDR)</label><input name="target" value="{{ scan_sched.target or '' }}" placeholder="10.0.0.0/28"></div>
        <div><label>Frequency</label><select name="frequency"><option value="daily" {% if scan_sched.frequency=='daily' %}selected{% endif %}>Daily</option><option value="weekly" {% if scan_sched.frequency not in ['daily','monthly'] %}selected{% endif %}>Weekly</option><option value="monthly" {% if scan_sched.frequency=='monthly' %}selected{% endif %}>Monthly (1st)</option></select></div>
        <div><label>Time (UTC)</label><input name="time" type="time" value="{{ scan_sched.time or '03:00' }}"></div>
        <div><label>Day of week (weekly)</label><select name="weekday">{% for d in ['mon','tue','wed','thu','fri','sat','sun'] %}<option value="{{ d }}" {% if scan_sched.weekday==d %}selected{% endif %}>{{ d|capitalize }}</option>{% endfor %}</select></div>
        <div><label>Mode</label><select name="mode"><option value="basic" {% if scan_sched.mode=='basic' %}selected{% endif %}>Basic</option><option value="advanced" {% if scan_sched.mode!='basic' %}selected{% endif %}>Advanced</option></select></div>
        <div><label>Ports (advanced)</label><input name="ports" value="{{ scan_sched.ports or '' }}" placeholder="1-1024"></div>
      </div>
      <div class="presets" style="margin-top:10px">
        <label><input type="checkbox" name="use_nmap" {% if scan_sched.use_nmap %}checked{% endif %}> Use nmap</label>
        <label><input type="checkbox" name="vuln_scripts" {% if scan_sched.vuln_scripts %}checked{% endif %}> nmap vuln scripts</label>
      </div>
      <button type="submit">Save scheduled scan</button>
      <span id="ss-state" class="pill">{% if next_scan_run %}Next run: {{ next_scan_run }}{% else %}Not scheduled{% endif %}{% if scan_sched.last_run %} · last: {{ scan_sched.last_run }} ({{ scan_sched.last_status }}){% endif %}</span>
    </form>
  </div>
  </section>
  {% endif %}

  {% if 'scan' in perms %}
  <section class="tab" id="tab-assets">
  <div class="card">
    <h2>Asset inventory</h2>
    <p class="note">Hosts discovered by scans with their highest observed risk — updated automatically after each scan.</p>
    {% if assets %}
    <table style="width:100%;border-collapse:collapse;margin-top:8px">
      <tr style="text-align:left;border-bottom:2px solid #e2e5e9"><th style="padding:8px">IP</th><th style="padding:8px">Hostname</th><th style="padding:8px">OS</th><th style="padding:8px">Open ports</th><th style="padding:8px">Risk</th><th style="padding:8px">Last scan</th></tr>
      {% for a in assets %}
      <tr style="border-bottom:1px solid #eef1f4">
        <td style="padding:8px;font-weight:600">{{ a.ip }}</td>
        <td style="padding:8px">{{ a.hostname or '—' }}</td>
        <td style="padding:8px">{{ a.os or '—' }}</td>
        <td style="padding:8px">{{ a.ports|length }}{% if a.services %} ({{ a.services|join(', ') }}){% endif %}</td>
        <td style="padding:8px"><span class="risk-{{ a.label|lower }}" style="font-weight:600">{{ a.risk }} · {{ a.label }}</span></td>
        <td style="padding:8px;color:#6b7280">{{ a.last_scan }}</td>
      </tr>
      {% endfor %}
    </table>
    <div style="margin-top:12px; display:flex; gap:8px; flex-wrap:wrap; align-items:center">
      <a class="dl" href="/assets/export?fmt=html">Download HTML</a>
      <a class="dl" href="/assets/export?fmt=csv">CSV</a>
      <a class="dl" href="/assets/export?fmt=xlsx">XLSX</a>
      <button id="assets-clear" type="button" class="secondary" style="margin-top:0">Clear inventory</button>
    </div>
    {% else %}
    <p style="color:#6b7280">No assets yet — run a network scan.</p>
    {% endif %}
  </div>
  </section>
  {% endif %}

  {% if 'scan' in perms %}
  <section class="tab" id="tab-recon">
  <div class="card">
    <h2>OSINT recon (theHarvester-style)</h2>
    <p class="note">Maps a domain's public footprint — subdomains (Certificate Transparency), DNS records, resolved hosts/IPs, and optionally Shodan/Hunter.io enrichment. Discovered hosts are added to the Assets inventory.</p>
    <div class="warn">Only enumerate domains you own or are explicitly authorized to assess.</div>
    <form id="recon-form">
      <div class="grid3">
        <div><label>Domain</label><input name="domain" placeholder="example.com"></div>
        <div></div>
        <div></div>
      </div>
      <div class="row"><label>Subdomain sources (passive OSINT)</label>
        <div class="presets">
          <label><input type="checkbox" checked disabled> Certificate Transparency (crt.sh)</label>
          <label><input type="checkbox" name="use_subfinder" checked> subfinder (multi-source){% if not tools_ok.subfinder %} (not detected){% endif %}</label>
          <label><input type="checkbox" name="use_amass"> amass passive (deeper){% if not tools_ok.amass %} (not detected){% endif %}</label>
        </div>
      </div>
      <div class="row"><label>Depth</label>
        <div class="presets">
          <label><input type="checkbox" name="fingerprint" checked> Web technology fingerprinting</label>
          <label><input type="checkbox" name="ip_intel" checked> IP intelligence (ASN / geo / rDNS)</label>
          <label><input type="checkbox" name="use_dnsx" checked> Fast resolution (dnsx){% if not tools_ok.dnsx %} (not detected){% endif %}</label>
          <label><input type="checkbox" name="use_httpx"> Live web triage (httpx){% if not tools_ok.httpx %} (not detected){% endif %}</label>
          <label><input type="checkbox" name="use_urls"> Historical URLs (gau / Wayback){% if not tools_ok.gau %} (not detected){% endif %}</label>
        </div>
      </div>
      <div class="row"><label>Optional vendor enrichment (needs API key in .env)</label>
        <div class="presets">
          <label><input type="checkbox" name="use_shodan"> Shodan (host/port/vulns)</label>
          <label><input type="checkbox" name="use_hunter"> Hunter.io (emails)</label>
        </div>
      </div>
      <div class="check"><input type="checkbox" id="recon-auth" name="authorized"><label for="recon-auth" style="margin:0">I am authorized to assess this domain.</label></div>
      <button id="recon-btn" type="submit">Start recon</button>
      <span id="rc-state" class="pill" style="display:none"></span>
    </form>
    <div id="rc-console" class="console"></div>
    <div id="rc-actions" style="margin-top:10px"></div>
  </div>
  </section>
  {% endif %}

  {% if 'scan' in perms %}
  <section class="tab" id="tab-cloud">
  <div class="subtabs">
    <button type="button" class="subtabbtn active" data-subtab="cloud-azure">Azure</button>
    <button type="button" class="subtabbtn" data-subtab="cloud-aws">AWS</button>
    <button type="button" class="subtabbtn" data-subtab="cloud-gcp">GCP</button>
  </div>

  <div class="subtab active" id="cloud-azure">
  <div class="card">
    <h2>Azure security posture</h2>
    <p class="note">Read-only assessment of an Azure tenant: resource inventory (Azure Resource Graph) plus Microsoft Defender for Cloud secure score and failing security recommendations. Results are saved to History.</p>
    <div class="warn">Use a service principal with <b>Reader</b> + <b>Security Reader</b> roles. Only assess tenants you own or are authorized to review. Credentials are used for this run only and are never stored.</div>
    <details class="hint" style="margin:10px 0 4px">
      <summary style="cursor:pointer;color:#60a5fa;font-size:13px">How do I create the service principal and roles? (step-by-step)</summary>
      <ol style="margin:8px 0 0;padding-left:20px;color:var(--muted);font-size:13px;line-height:1.75">
        <li><b>Register an app.</b> In the <a href="https://entra.microsoft.com" target="_blank">Microsoft Entra admin center</a> go to <b>Entra ID → App registrations → New registration</b>. Name it (e.g. <code>threat-intel-cspm</code>), choose <i>single tenant</i>, and Register. On the Overview page copy the <b>Directory (tenant) ID</b> and <b>Application (client) ID</b>. <a href="https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app" target="_blank">Docs ↗</a></li>
        <li><b>Create a client secret.</b> In the app, open <b>Certificates &amp; secrets → New client secret</b>, set an expiry, and copy the secret <b>Value</b> immediately (it's shown only once). <a href="https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal" target="_blank">Docs ↗</a></li>
        <li><b>Assign read roles.</b> In the <a href="https://portal.azure.com" target="_blank">Azure portal</a> open your <b>Subscription</b> (or management group) → <b>Access control (IAM) → Add → Add role assignment</b>. Assign <b>Reader</b>, then repeat and assign <b>Security Reader</b>. On the Members tab pick <i>User, group, or service principal</i> and search for your app by name. <a href="https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal" target="_blank">Docs ↗</a> · <a href="https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles" target="_blank">Built-in roles ↗</a></li>
        <li><b>Enable Defender for Cloud</b> on the subscription so a secure score and recommendations are available. <a href="https://learn.microsoft.com/en-us/azure/defender-for-cloud/connect-azure-subscription" target="_blank">Docs ↗</a></li>
        <li>Paste the tenant ID, client ID, and secret below and run. Leave subscription blank to assess all that the principal can read.</li>
      </ol>
    </details>
    <form id="cloud-form">
      <div class="row"><label>Authentication</label>
        <div class="presets">
          <label><input type="radio" name="method" value="login" checked> Sign in with my Azure account <span class="note" style="margin:0">(no app registration)</span></label>
          <label><input type="radio" name="method" value="sp"> Service principal (client ID + secret)</label>
        </div>
      </div>
      <div class="grid3">
        <div><label>Directory (tenant) ID <span class="note" style="margin:0">(optional for sign-in)</span></label><input name="tenant" placeholder="contoso.onmicrosoft.com or GUID"></div>
        <div class="sp-field" style="display:none"><label>Application (client) ID</label><input name="client_id" placeholder="app registration GUID"></div>
        <div class="sp-field" style="display:none"><label>Client secret</label><input name="secret" type="password" autocomplete="off" placeholder="service principal secret"></div>
        <div style="grid-column:span 2"><label>Subscription (optional — name or ID; blank = all accessible)</label><input name="subscription" placeholder="leave blank to assess all subscriptions"></div>
      </div>
      <div class="row"><label>Vendor (provider-level) assessment to include — uncheck all to run tenant posture only</label>
        <div class="presets">
          {% for k, lbl in vendor_sections %}<label><input type="checkbox" name="sections" value="{{ k }}" checked> {{ lbl }}</label>{% endfor %}
        </div>
      </div>
      <div class="check"><input type="checkbox" id="cloud-auth" name="authorized"><label for="cloud-auth" style="margin:0">I am authorized to assess this Azure tenant.</label></div>
      <button id="cloud-btn" type="submit">Run Azure assessment</button>
      <span id="cl-state" class="pill" style="display:none"></span>
    </form>
    <div id="cloud-device" class="warn" style="display:none"></div>
    <div id="cl-console" class="console"></div>
  </div>
  <div class="card">
    <h2>Azure assessment history</h2>
    <ul class="reports" id="azure-reports">
      {% for r in reports if r.filename.startswith('azure-') %}
      <li data-file="{{ r.filename }}"><span class="name"><span class="kind cloud">Cloud</span><a href="/reports/{{ r.filename }}" target="_blank">{{ r.filename }}</a>{% if r.owner %}<span class="by">by {{ r.owner }}</span>{% endif %}</span>
        <span class="actions"><a class="dl" href="/download/{{ r.filename }}?fmt=html">HTML</a><a class="dl" href="/download/{{ r.filename }}?fmt=pdf">PDF</a><a class="dl" href="/download/{{ r.filename }}?fmt=md">MD</a></span></li>
      {% else %}
      <li style="color:var(--muted)">No Azure assessments yet — run one above.</li>
      {% endfor %}
    </ul>
  </div>
  </div>

  <div class="subtab" id="cloud-aws">
  <div class="card">
    <h2>AWS security posture</h2>
    <p class="note">Read-only assessment of an AWS account: resource inventory plus AWS Security Hub findings (CIS benchmark, foundational best practices) and GuardDuty.</p>
    <div class="warn">Planned — not yet connected. It will use a read-only IAM role/keys with the managed <b>SecurityAudit</b> policy and pull findings from AWS Security Hub. No credentials are stored.</div>
    <p class="note">Tell the assistant "build AWS" to enable this provider. The flow mirrors Azure: enter read-only credentials (or assume-role), discover resources, pull native posture findings, and save a report here.</p>
  </div>
  {{ vendor_card('aws', 'Amazon Web Services (AWS)', vendor_sections) }}
  <div class="card">
    <h2>AWS assessment history</h2>
    <ul class="reports" id="aws-reports">
      {% for r in reports if r.filename.startswith('aws-') %}
      <li data-file="{{ r.filename }}"><span class="name"><span class="kind cloud">Cloud</span><a href="/reports/{{ r.filename }}" target="_blank">{{ r.filename }}</a>{% if r.owner %}<span class="by">by {{ r.owner }}</span>{% endif %}</span>
        <span class="actions"><a class="dl" href="/download/{{ r.filename }}?fmt=html">HTML</a><a class="dl" href="/download/{{ r.filename }}?fmt=pdf">PDF</a><a class="dl" href="/download/{{ r.filename }}?fmt=md">MD</a></span></li>
      {% else %}
      <li style="color:var(--muted)">No AWS assessments yet.</li>
      {% endfor %}
    </ul>
  </div>
  </div>

  <div class="subtab" id="cloud-gcp">
  <div class="card">
    <h2>GCP security posture</h2>
    <p class="note">Read-only assessment of a GCP project/organization: Cloud Asset Inventory plus Security Command Center findings.</p>
    <div class="warn">Planned — not yet connected. It will use a read-only service-account key (viewer / securityReviewer) and pull findings from Security Command Center. No credentials are stored.</div>
    <p class="note">Tell the assistant "build GCP" to enable this provider. The flow mirrors Azure: authenticate read-only, enumerate assets, pull native posture findings, and save a report here.</p>
  </div>
  {{ vendor_card('gcp', 'Google Cloud Platform (GCP)', vendor_sections) }}
  <div class="card">
    <h2>GCP assessment history</h2>
    <ul class="reports" id="gcp-reports">
      {% for r in reports if r.filename.startswith('gcp-') %}
      <li data-file="{{ r.filename }}"><span class="name"><span class="kind cloud">Cloud</span><a href="/reports/{{ r.filename }}" target="_blank">{{ r.filename }}</a>{% if r.owner %}<span class="by">by {{ r.owner }}</span>{% endif %}</span>
        <span class="actions"><a class="dl" href="/download/{{ r.filename }}?fmt=html">HTML</a><a class="dl" href="/download/{{ r.filename }}?fmt=pdf">PDF</a><a class="dl" href="/download/{{ r.filename }}?fmt=md">MD</a></span></li>
      {% else %}
      <li style="color:var(--muted)">No GCP assessments yet.</li>
      {% endfor %}
    </ul>
  </div>
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
          <span class="name"><span class="kind {{ r.kind }}">{{ {'analysis':'Analysis','scan':'Scan','recon':'Recon','briefing':'Briefing','cve':'CVE','actor':'Actor','hunt':'Hunt','cloud':'Cloud'}[r.kind] }}</span><a href="/reports/{{ r.filename }}" target="_blank">{{ r.filename }}</a>{% if r.owner %}<span class="by">by {{ r.owner }}</span>{% endif %}</span>
          <span class="actions">
            <button class="pv" type="button" data-file="{{ r.filename }}">Preview</button>
            <a class="dl" href="/download/{{ r.filename }}?fmt=html">HTML</a>
            <a class="dl" href="/download/{{ r.filename }}?fmt=pdf">PDF</a>
            <a class="dl" href="/download/{{ r.filename }}?fmt=md">MD</a>
            <a class="dl" href="/download/{{ r.filename }}?fmt=csv">CSV</a>
            <a class="dl" href="/download/{{ r.filename }}?fmt=xlsx">XLSX</a>
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
    <h2>Configuration</h2>
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
  {% if is_admin %}
  <div class="card">
    <h2>API keys</h2>
    <p class="note">Store keys here instead of editing <code>.env</code> — they take effect immediately, no restart needed. Includes the LLM engine key (Anthropic/OpenAI) and vendor keys. Stored keys override <code>.env</code>. Leave a field blank to keep the current value; tick Clear to remove it. Keys are write-only (shown masked).</p>
    <form id="keys-form">
      {% for k in api_keys %}
      <div class="row">
        <label>{{ k.label }} — <span style="color:var(--muted)">{{ k.desc }}</span>{% if k.configured %} · <span class="ok">configured{% if k.hint %} ({{ k.hint }}){% endif %}</span>{% else %} · <span style="color:#f87171">not set</span>{% endif %}</label>
        <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap">
          <input name="{{ k.key }}" type="password" autocomplete="off" placeholder="{% if k.configured %}enter to replace{% else %}paste API key{% endif %}" style="flex:1; min-width:240px">
          {% if k.configured %}<label style="display:flex; align-items:center; gap:6px; font-size:12px; margin:0"><input type="checkbox" name="clear_{{ k.key }}" style="width:auto"> Clear</label>{% endif %}
        </div>
      </div>
      {% endfor %}
      <button type="submit">Save API keys</button>
      <span id="keys-state" class="pill" style="display:none"></span>
    </form>
  </div>
  <div class="card">
    <h2>Alerts</h2>
    <p class="note">Notify when a scan's findings meet the severity threshold. Webhook URLs come from Teams/Slack "Incoming Webhook" connectors.</p>
    <form id="alerts-form">
      <div class="check"><input type="checkbox" id="al-en" name="enabled" {% if alert_cfg.enabled %}checked{% endif %}><label for="al-en" style="margin:0">Enable alerts</label></div>
      <div class="grid3" style="margin-top:12px">
        <div><label>Trigger at severity</label><select name="min_severity">{% for s in ['critical','high','medium','low'] %}<option value="{{ s }}" {% if alert_cfg.min_severity==s %}selected{% endif %}>{{ s|capitalize }} and above</option>{% endfor %}</select></div>
        <div><label>Email to (comma-separated)</label><input name="email_to" value="{{ alert_cfg.email_to or '' }}"></div>
        <div></div>
        <div><label>Microsoft Teams webhook</label><input name="teams_webhook" value="{{ alert_cfg.teams_webhook or '' }}" placeholder="https://outlook.office.com/webhook/..."></div>
        <div><label>Slack webhook</label><input name="slack_webhook" value="{{ alert_cfg.slack_webhook or '' }}" placeholder="https://hooks.slack.com/services/..."></div>
        <div><label>Generic webhook (JSON POST)</label><input name="webhook_url" value="{{ alert_cfg.webhook_url or '' }}"></div>
      </div>
      <button type="submit">Save alerts</button>
      <button id="al-test" type="button" class="secondary" style="margin-left:8px">Send test alert</button>
      <span id="al-state" class="pill" style="display:none"></span>
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

  {% if is_admin %}
  <section class="tab" id="tab-logs">
  <div class="card">
    <h2>Activity log <span id="logs-meta" class="pill" style="display:none"></span></h2>
    <p class="note">Everything that happens in the application — sign-ins, scans, recon, cloud and vendor assessments, briefings, deletions, and admin changes — plus the app's own system events. Newest first.</p>
    <div class="grid3">
      <div><label>Category</label><select id="logf-category"><option value="">All categories</option></select></div>
      <div><label>Level</label><select id="logf-level"><option value="">All levels</option></select></div>
      <div><label>User</label><input id="logf-user" placeholder="filter by user"></div>
      <div style="grid-column:span 2"><label>Search</label><input id="logf-q" placeholder="search action / detail"></div>
      <div style="display:flex;align-items:flex-end;gap:8px">
        <button id="logs-refresh" type="button" style="margin:0">Refresh</button>
        <button id="logs-clear" type="button" class="secondary" style="margin:0">Clear log</button>
      </div>
    </div>
    <div id="logs-table" style="margin-top:14px"><p class="note">Loading…</p></div>
  </div>
  </section>
  {% endif %}

</div>
</div>
</div>

<button id="ai-fab" type="button" title="AI security assistant" aria-label="AI security assistant">&#128172;</button>
<div id="ai-widget" role="dialog" aria-label="AI security assistant">
  <div class="ai-head"><span>AI security assistant</span><button id="ai-close" type="button" aria-label="Close">&times;</button></div>
  <div class="ai-body">
    <select id="ai-report"><option value="">Ground in a report (optional)</option>{% for r in reports %}<option value="{{ r.filename }}">{{ r.filename }}</option>{% endfor %}</select>
    <div id="ai-chat" class="aichat"></div>
    <form id="ai-form"><input id="ai-input" placeholder="Ask about a vuln or remediation…"><button id="ai-send" type="submit">Send</button></form>
  </div>
</div>

<script>
window.__ALL_PRIVS = [{% for k,lbl in all_privileges %}["{{ k }}","{{ lbl }}"]{% if not loop.last %},{% endif %}{% endfor %}];
const _fetch = window.fetch;
window.fetch = async (...a) => { const r = await _fetch(...a); if (r.status === 401) { location.href = '/login'; } return r; };
</script>
<script>
// mobile slide-out menu
const sidebarEl = document.querySelector('.sidebar');
const navScrim = document.getElementById('nav-scrim');
const menuToggle = document.getElementById('menu-toggle');
function closeNav() { if (sidebarEl) sidebarEl.classList.remove('open'); if (navScrim) navScrim.classList.remove('open'); }
if (menuToggle && sidebarEl) menuToggle.addEventListener('click', () => {
  const open = sidebarEl.classList.toggle('open');
  if (navScrim) navScrim.classList.toggle('open', open);
});
if (navScrim) navScrim.addEventListener('click', closeNav);

// live UTC clock in the top bar
const clockEl = document.getElementById('clock');
if (clockEl) {
  const tick = () => {
    clockEl.textContent = new Date().toISOString().slice(0, 19).replace('T', ' ') + ' UTC';
  };
  tick(); setInterval(tick, 1000);
}

// central tab switcher — used by sidebar nav and dashboard quick actions
function activateTab(tabId, remember) {
  const sec = document.getElementById(tabId);
  if (!sec) return;
  document.querySelectorAll('.tabbtn').forEach(x => x.classList.toggle('active', x.dataset.tab === tabId));
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  sec.classList.add('active');
  if (remember !== false) { try { localStorage.setItem('tiba_tab', tabId); } catch (e) {} }
  closeNav();
  window.scrollTo({ top: 0 });
}
// restore the last-viewed tab across reloads
try {
  const saved = localStorage.getItem('tiba_tab');
  if (saved && document.getElementById(saved)) activateTab(saved, false);
} catch (e) {}
// event delegation so any current or future .tabbtn / .dash-jump works
document.addEventListener('click', (e) => {
  const nav = e.target.closest('.tabbtn, .dash-jump');
  if (nav && nav.dataset.tab) { e.preventDefault(); activateTab(nav.dataset.tab); }
  // provider sub-tabs (Cloud Posture: Azure / AWS / GCP)
  const sub = e.target.closest('.subtabbtn');
  if (sub && sub.dataset.subtab) {
    const scope = sub.closest('section') || document;
    scope.querySelectorAll('.subtabbtn').forEach(x => x.classList.toggle('active', x === sub));
    scope.querySelectorAll('.subtab').forEach(x => x.classList.remove('active'));
    const panel = document.getElementById(sub.dataset.subtab);
    if (panel) panel.classList.add('active');
  }
});

// Settings: collapsible sections (accordion)
document.querySelectorAll('#tab-settings > .card').forEach((card, i) => {
  const h = card.querySelector('h2');
  if (!h) return;
  const body = document.createElement('div');
  body.className = 'acc-body';
  while (h.nextSibling) body.appendChild(h.nextSibling);
  card.appendChild(body);
  h.classList.add('acc-head');
  h.insertAdjacentHTML('beforeend', '<span class="acc-arrow">&#9662;</span>');
  if (i !== 0) card.classList.add('collapsed');
  h.addEventListener('click', () => card.classList.toggle('collapsed'));
});

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

// AI assistant popup toggle
const aiFab = document.getElementById('ai-fab');
const aiWidget = document.getElementById('ai-widget');
if (aiFab && aiWidget) {
  aiFab.addEventListener('click', () => {
    aiWidget.classList.toggle('open');
    if (aiWidget.classList.contains('open')) document.getElementById('ai-input').focus();
  });
  document.getElementById('ai-close').addEventListener('click', () => aiWidget.classList.remove('open'));
}
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
  const KINDS = [['analysis-','analysis','Analysis'],['scan-','scan','Scan'],['recon-','recon','Recon'],
                 ['cve-','cve','CVE'],['actor-','actor','Actor'],['hunt-','hunt','Hunt'],
                 ['cloud-','cloud','Cloud'],['azure-','cloud','Cloud'],['aws-','cloud','Cloud'],['gcp-','cloud','Cloud']];
  const m = KINDS.find(k => f.indexOf(k[0]) === 0) || ['','briefing','Briefing'];
  const kind = m[1], label = m[2];
  const by = owner ? '<span class="by">by ' + owner + '</span>' : '';
  return '<span class="name"><span class="kind ' + kind + '">' + label + '</span>' +
         '<a href="/reports/' + f + '" target="_blank">' + f + '</a>' + by + '</span>' +
         '<span class="actions">' +
         '<button class="pv" type="button" data-file="' + f + '">Preview</button>' +
         '<a class="dl" href="/download/' + f + '?fmt=html">HTML</a>' +
         '<a class="dl" href="/download/' + f + '?fmt=pdf">PDF</a>' +
         '<a class="dl" href="/download/' + f + '?fmt=md">MD</a>' +
         '<a class="dl" href="/download/' + f + '?fmt=csv">CSV</a>' +
         '<a class="dl" href="/download/' + f + '?fmt=xlsx">XLSX</a>' +
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

// vendor lookup (key discovery)
const vform = document.getElementById('vendor-form');
if (vform) {
  const vbtn = document.getElementById('vendor-btn');
  const vstate = document.getElementById('v-state');
  const vres = document.getElementById('vendor-result');
  const VLEVEL = {
    malicious: ['#7f1d1d', '#fca5a5', 'Malicious'], suspicious: ['#78350f', '#fcd34d', 'Suspicious'],
    info: ['#1e3a5f', '#93c5fd', 'Info'], clean: ['#14432a', '#86efac', 'Clean'],
    error: ['#3f1d1d', '#f87171', 'Error']
  };
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  vform.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!document.getElementById('vendor-key').value.trim()) { alert('Paste a vendor API key.'); return; }
    const hasInd = document.getElementById('vendor-indicator').value.trim();
    const hasFile = document.getElementById('vendor-file').files.length;
    if (!hasInd && !hasFile) { alert('Enter an indicator or choose a file.'); return; }
    vbtn.disabled = true; vres.innerHTML = '';
    vstate.style.display = 'inline'; vstate.textContent = 'detecting vendor…'; vstate.className = 'pill';
    let d;
    try {
      const res = await fetch('/vendor-analyze', { method:'POST', body: new FormData(vform) });
      d = await res.json();
      if (!res.ok && !d.vendor) { vstate.textContent = 'error'; vstate.className = 'pill err'; vres.innerHTML = '<p class="err">' + esc(d.error || 'Analysis failed.') + '</p>'; vbtn.disabled = false; return; }
    } catch (err) {
      vstate.textContent = 'error'; vstate.className = 'pill err'; vres.innerHTML = '<p class="err">Error: ' + esc(err) + '</p>'; vbtn.disabled = false; return;
    }
    let html = '';
    if (d.vendor) html += '<div class="note" style="margin-bottom:8px">Detected vendor: <b>' + esc(d.vendor) + '</b>'
                        + (d.indicator ? ' · target <code>' + esc(d.indicator) + '</code>' : '')
                        + (d.type ? ' · ' + esc(d.type) : '') + '</div>';
    if (d.error) {
      vstate.textContent = d.vendor ? 'vendor mismatch' : 'not recognized'; vstate.className = 'pill err';
      html += '<p class="err">' + esc(d.error) + '</p>';
      vres.innerHTML = html; vbtn.disabled = false; return;
    }
    vstate.textContent = 'done'; vstate.className = 'pill ok';
    if (d.hashes) html += '<div class="note" style="margin-bottom:8px">SHA256 <code>' + esc(d.hashes.sha256) + '</code></div>';
    if (d.rows && d.rows.length) {
      html += '<table style="width:100%;border-collapse:collapse"><tr style="text-align:left;border-bottom:2px solid var(--line)">' +
              '<th style="padding:8px">Vendor</th><th style="padding:8px">Verdict</th><th style="padding:8px">Details</th><th style="padding:8px"></th></tr>';
      d.rows.forEach(r => {
        const lv = VLEVEL[r.level] || VLEVEL.info;
        const link = r.link ? '<a href="' + esc(r.link) + '" target="_blank">Open</a>' : '';
        html += '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:8px;font-weight:600">' + esc(r.vendor) + '</td>' +
          '<td style="padding:8px"><span class="badge" style="background:' + lv[0] + ';color:' + lv[1] + '">' + lv[2] + '</span> ' + esc(r.summary) + '</td>' +
          '<td style="padding:8px;color:var(--muted)">' + esc(r.detail) + '</td>' +
          '<td style="padding:8px">' + link + '</td></tr>';
      });
      html += '</table>';
    } else {
      html += '<p class="note">No result returned for this indicator.</p>';
    }
    vres.innerHTML = html;
    vbtn.disabled = false;
  });
}

// threat intel: CVE analysis / actor profile / hunt queries
function wireIntel(formId, btnId, stateId, url, busyText) {
  const f = document.getElementById(formId);
  if (!f) return;
  const btn = document.getElementById(btnId);
  const st = document.getElementById(stateId);
  f.addEventListener('submit', async (e) => {
    e.preventDefault();
    btn.disabled = true; st.style.display = 'inline'; st.textContent = busyText; st.className = 'pill';
    let d;
    try {
      const res = await fetch(url, { method:'POST', body: new FormData(f) });
      d = await res.json();
      if (!res.ok || !d.ok) { st.textContent = (d && d.error) ? d.error : 'error'; st.className = 'pill err'; btn.disabled = false; return; }
    } catch (err) { st.textContent = 'Error: ' + err; st.className = 'pill err'; btn.disabled = false; return; }
    st.textContent = 'done'; st.className = 'pill ok';
    addReportRow(d.filename, d.owner);
    window.open('/reports/' + d.filename, '_blank');
    btn.disabled = false;
  });
}
wireIntel('cve-form', 'cve-btn', 'cve-state', '/cve-analyze', 'analyzing…');
wireIntel('actor-form', 'actor-btn', 'actor-state', '/actor-profile', 'profiling…');
wireIntel('hunt-form', 'hunt-btn', 'hunt-state', '/hunt-generate', 'generating…');

// ── Latest CVEs feed (dashboard card + dedicated tab) ──
const cveEsc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const cveSev = (s) => { s = (s || '').toLowerCase(); return s.indexOf('crit')===0 ? 'risk-critical' : s.indexOf('high')===0 ? 'risk-high' : s.indexOf('med')===0 ? 'risk-medium' : 'risk-low'; };
function cveTable(cves, withAnalyze) {
  if (!cves || !cves.length) return '<p class="note">No recent CVEs returned — try Refresh in a moment.</p>';
  let h = '<table style="width:100%;border-collapse:collapse"><tr style="text-align:left;border-bottom:2px solid var(--line)">'
        + '<th style="padding:8px">CVE</th><th style="padding:8px">CVSS</th><th style="padding:8px">Published</th><th style="padding:8px">Summary</th>'
        + (withAnalyze ? '<th style="padding:8px"></th>' : '') + '</tr>';
  cves.forEach(c => {
    const kev = c.kev ? ' <span class="badge" style="background:#7f1d1d;color:#fca5a5">KEV</span>' : '';
    const sev = (c.cvss != null) ? '<span class="' + cveSev(c.severity) + '" style="font-weight:600">' + cveEsc(c.cvss) + '</span> ' + cveEsc(c.severity) : '—';
    const act = withAnalyze ? '<td style="padding:8px"><button type="button" class="dl cve-analyze" data-cve="' + cveEsc(c.cve) + '">Analyze</button></td>' : '';
    h += '<tr style="border-bottom:1px solid var(--line)">'
      + '<td style="padding:8px;white-space:nowrap"><a href="https://nvd.nist.gov/vuln/detail/' + cveEsc(c.cve) + '" target="_blank">' + cveEsc(c.cve) + '</a>' + kev + '</td>'
      + '<td style="padding:8px;white-space:nowrap">' + sev + '</td>'
      + '<td style="padding:8px;white-space:nowrap;color:var(--muted)">' + cveEsc(c.published) + '</td>'
      + '<td style="padding:8px;color:var(--muted)">' + cveEsc(c.description) + '</td>'
      + act + '</tr>';
  });
  return h + '</table>';
}
async function loadCves(targetId, limit, withAnalyze, metaId, stateId) {
  const el = document.getElementById(targetId);
  if (!el) return;
  const st = stateId ? document.getElementById(stateId) : null;
  if (st) { st.style.display = 'inline'; st.textContent = 'loading…'; st.className = 'pill'; }
  try {
    const d = await (await fetch('/api/latest-cves?limit=' + limit)).json();
    el.innerHTML = cveTable(d.cves || [], withAnalyze);
    if (metaId && d.fetched) { const m = document.getElementById(metaId); if (m) { m.style.display = 'inline'; m.textContent = 'updated ' + d.fetched; } }
    if (st) st.style.display = 'none';
  } catch (err) {
    el.innerHTML = '<p class="err">Couldn\\'t load CVEs right now.</p>';
    if (st) { st.textContent = 'error'; st.className = 'pill err'; }
  }
}
loadCves('dash-cves', 10, false, 'dash-cve-meta', null);   // dashboard card on page load
let cveTabLoaded = false;
document.addEventListener('click', (e) => {
  if (e.target.closest('[data-tab="tab-latest-cves"]') && !cveTabLoaded) {
    cveTabLoaded = true;
    loadCves('cve-feed', 50, true, 'cve-feed-meta', 'cve-feed-state');
  }
});
const cveRefresh = document.getElementById('cve-refresh');
if (cveRefresh) cveRefresh.addEventListener('click', () => loadCves('cve-feed', 50, true, 'cve-feed-meta', 'cve-feed-state'));
// "Analyze" on a CVE row -> jump to Threat Intel, prefill + run (or open NVD if no access)
document.addEventListener('click', (e) => {
  const a = e.target.closest('.cve-analyze');
  if (!a) return;
  const input = document.getElementById('cve-id');
  if (input) {
    activateTab('tab-intel');
    input.value = a.dataset.cve;
    const f = document.getElementById('cve-form');
    if (f) f.requestSubmit();
  } else {
    window.open('https://nvd.nist.gov/vuln/detail/' + a.dataset.cve, '_blank');
  }
});

// add a finished cloud report into the matching provider sub-tab history list
function prependCloudReport(filename, owner) {
  const provider = filename.indexOf('aws-') === 0 ? 'aws' : (filename.indexOf('gcp-') === 0 ? 'gcp' : 'azure');
  const ul = document.getElementById(provider + '-reports');
  if (!ul) return;
  const empty = ul.querySelector('li:not([data-file])'); if (empty) empty.remove();
  const by = owner ? '<span class="by">by ' + owner + '</span>' : '';
  const li = document.createElement('li');
  li.setAttribute('data-file', filename);
  li.innerHTML = '<span class="name"><span class="kind cloud">Cloud</span>' +
    '<a href="/reports/' + filename + '" target="_blank">' + filename + '</a>' + by + '</span>' +
    '<span class="actions"><a class="dl" href="/download/' + filename + '?fmt=html">HTML</a>' +
    '<a class="dl" href="/download/' + filename + '?fmt=pdf">PDF</a>' +
    '<a class="dl" href="/download/' + filename + '?fmt=md">MD</a></span>';
  ul.insertBefore(li, ul.firstChild);
}

// vendor security assessment (provider-level; no credentials needed)
document.addEventListener('click', async (e) => {
  const b = e.target.closest('.vendor-btn');
  if (!b) return;
  const card = b.closest('.card');
  const st = card.querySelector('.vendor-state');
  const con = card.querySelector('.vendor-console');
  b.disabled = true;
  st.style.display = 'inline'; st.textContent = 'assessing…'; st.className = 'pill vendor-state';
  con.style.display = 'block'; con.textContent = '';
  const fd = new FormData(); fd.append('provider', b.dataset.provider);
  const picked = card.querySelectorAll('input[name=sections]:checked');
  if (!picked.length) { st.textContent='pick a check'; st.className='pill vendor-state err'; con.style.display='none'; b.disabled=false; return; }
  picked.forEach(c => fd.append('sections', c.value));
  let r;
  try { r = await (await fetch('/cloud/vendor-assess', { method:'POST', body: fd })).json(); }
  catch (err) { st.textContent='error'; st.className='pill vendor-state err'; con.textContent='Error: '+err; b.disabled=false; return; }
  if (!r.job_id) { st.textContent='error'; st.className='pill vendor-state err'; con.textContent=r.error||'failed'; b.disabled=false; return; }
  (function poll() {
    fetch('/status/' + r.job_id).then(x => x.json()).then(job => {
      con.textContent = (job.logs || []).join('\\n'); con.scrollTop = con.scrollHeight;
      if (job.status === 'running') { setTimeout(poll, 1500); return; }
      b.disabled = false;
      if (job.status === 'done') {
        st.textContent = 'done'; st.className = 'pill vendor-state ok';
        con.textContent += '\\n\\nVendor assessment ready: ' + job.report.title;
        prependCloudReport(job.report.filename, job.report.owner);
        addReportRow(job.report.filename, job.report.owner);
        window.open('/reports/' + job.report.filename, '_blank');
      } else {
        st.textContent = 'error'; st.className = 'pill vendor-state err';
        con.textContent += '\\n\\nError: ' + (job.error || 'unknown');
      }
    }).catch(() => { b.disabled = false; st.textContent='error'; st.className='pill vendor-state err'; });
  })();
});

// cloud posture (Azure)
const cloudForm = document.getElementById('cloud-form');
if (cloudForm) {
  const clBtn = document.getElementById('cloud-btn');
  const clCon = document.getElementById('cl-console');
  const clState = document.getElementById('cl-state');
  const clDevice = document.getElementById('cloud-device');
  // show/hide service-principal fields based on the chosen method
  const syncMethod = () => {
    const sp = cloudForm.querySelector('[name=method]:checked').value === 'sp';
    cloudForm.querySelectorAll('.sp-field').forEach(el => el.style.display = sp ? 'block' : 'none');
    clBtn.textContent = sp ? 'Run Azure assessment' : 'Sign in & run assessment';
  };
  cloudForm.querySelectorAll('[name=method]').forEach(r => r.addEventListener('change', syncMethod));
  syncMethod();

  cloudForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!document.getElementById('cloud-auth').checked) { alert('Please confirm you are authorized to assess this Azure tenant.'); return; }
    const method = cloudForm.querySelector('[name=method]:checked').value;
    clBtn.disabled = true; clCon.style.display = 'block'; clCon.textContent = '';
    clDevice.style.display = 'none'; clDevice.innerHTML = '';
    clState.style.display = 'inline'; clState.className = 'pill';
    if (method === 'sp') {
      clState.textContent = 'assessing…';
      const res = await fetch('/cloud/azure', { method:'POST', body: new FormData(cloudForm) });
      if (!res.ok) { let m='failed'; try { m=(await res.json()).error||m; } catch(e){} clState.textContent='error'; clState.className='pill err'; clCon.textContent=m; clBtn.disabled=false; return; }
      pollCloud((await res.json()).job_id);
    } else {
      clState.textContent = 'starting sign-in…';
      const res = await fetch('/cloud/azure/device/start', { method:'POST', body: new FormData(cloudForm) });
      const d = await res.json();
      if (!res.ok) { clState.textContent='error'; clState.className='pill err'; clCon.textContent=d.error||'sign-in failed'; clBtn.disabled=false; return; }
      const link = '<a href="' + d.verification_uri + '" target="_blank">' + d.verification_uri + '</a>';
      clDevice.style.display = 'block';
      clDevice.innerHTML = 'To sign in, open ' + link + ' and enter code <b style="font-size:16px;letter-spacing:2px">' + d.user_code + '</b> — then approve. Waiting…';
      clState.textContent = 'waiting for sign-in…';
      pollDevice(d.device_code, (d.interval || 5) * 1000);
    }
  });

  async function pollDevice(deviceCode, intervalMs) {
    const fd = new FormData(cloudForm);
    fd.set('device_code', deviceCode);
    let d;
    try { d = await (await fetch('/cloud/azure/device/poll', { method:'POST', body: fd })).json(); }
    catch (err) { clState.textContent='error'; clState.className='pill err'; clCon.textContent='Error: '+err; clBtn.disabled=false; return; }
    if (d.status === 'pending') { setTimeout(() => pollDevice(deviceCode, intervalMs), intervalMs); return; }
    if (d.status === 'ok') {
      clDevice.style.display = 'none';
      clState.textContent = 'assessing…';
      pollCloud(d.job_id);
    } else {
      clState.textContent = d.status === 'expired' ? 'sign-in expired' : 'error';
      clState.className = 'pill err';
      clCon.textContent = d.error || 'Sign-in was not completed.';
      clBtn.disabled = false;
    }
  }

  async function pollCloud(jobId) {
    try {
      const job = await (await fetch('/status/' + jobId)).json();
      clCon.textContent = (job.logs || []).join('\\n'); clCon.scrollTop = clCon.scrollHeight;
      if (job.status === 'running') { setTimeout(() => pollCloud(jobId), 1500); return; }
      clBtn.disabled = false;
      if (job.status === 'done') {
        clState.textContent = 'done'; clState.className = 'pill ok';
        clCon.textContent += '\\n\\nCloud posture report ready: ' + job.report.title;
        prependCloudReport(job.report.filename, job.report.owner);
        addReportRow(job.report.filename, job.report.owner);
        window.open('/reports/' + job.report.filename, '_blank');
      } else {
        clState.textContent = 'error'; clState.className = 'pill err';
        clCon.textContent += '\\n\\nError: ' + (job.error || 'unknown');
      }
    } catch (err) {
      clBtn.disabled = false; clState.textContent = 'error'; clState.className = 'pill err';
      clCon.textContent += '\\n\\nError: ' + err;
    }
  }
}

// network scan
const scanForm = document.getElementById('scan-form');
if (scanForm) {
  const scanMode = document.getElementById('scan-mode');
  const scanAdv = document.getElementById('scan-adv');
  const syncMode = () => { scanAdv.style.display = scanMode.value === 'advanced' ? 'block' : 'none'; };
  scanMode.addEventListener('change', syncMode); syncMode();
  const sbtn = document.getElementById('scan-btn');
  const scon = document.getElementById('s-console');
  const sstate2 = document.getElementById('s-state');
  scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!document.getElementById('scan-auth').checked) { alert('Please confirm you are authorized to scan this target.'); return; }
    sbtn.disabled = true; scon.style.display = 'block'; scon.textContent = '';
    sstate2.style.display = 'inline'; sstate2.textContent = 'scanning...'; sstate2.className = 'pill';
    const res = await fetch('/scan', { method:'POST', body: new FormData(scanForm) });
    if (!res.ok) { let m='scan failed'; try { m=(await res.json()).error||m; } catch(e){} sstate2.textContent='error'; sstate2.className='pill err'; scon.textContent=m; sbtn.disabled=false; return; }
    pollScan((await res.json()).job_id);
  });
  async function pollScan(jobId) {
    try {
      const job = await (await fetch('/status/' + jobId)).json();
      scon.textContent = (job.logs || []).join('\\n'); scon.scrollTop = scon.scrollHeight;
      if (job.status === 'running') { setTimeout(() => pollScan(jobId), 1200); return; }
      sbtn.disabled = false;
      if (job.status === 'done') {
        sstate2.textContent = 'done'; sstate2.className = 'pill ok';
        scon.textContent += '\\n\\nScan report ready: ' + job.report.title;
        addReportRow(job.report.filename, job.report.owner);
        window.open('/reports/' + job.report.filename, '_blank');
      } else {
        sstate2.textContent = 'error'; sstate2.className = 'pill err';
        scon.textContent += '\\n\\nError: ' + (job.error || 'unknown');
      }
    } catch (err) {
      sbtn.disabled = false; sstate2.textContent = 'error'; sstate2.className = 'pill err';
      scon.textContent += '\\n\\nError: ' + err;
    }
  }
}

// AI assistant chat
const aiForm = document.getElementById('ai-form');
if (aiForm) {
  const chat = document.getElementById('ai-chat');
  const input = document.getElementById('ai-input');
  const sendBtn = document.getElementById('ai-send');
  const reportSel = document.getElementById('ai-report');
  let history = [];
  function bubble(role, text) {
    const d = document.createElement('div');
    d.className = 'msg ' + (role === 'user' ? 'user' : 'bot');
    d.textContent = text;
    chat.appendChild(d); chat.scrollTop = chat.scrollHeight;
    return d;
  }
  aiForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const q = input.value.trim();
    if (!q) return;
    input.value = ''; sendBtn.disabled = true;
    bubble('user', q);
    history.push({ role: 'user', content: q });
    if (history.length > 20) history = history.slice(-20);
    const pending = bubble('bot', '…');
    try {
      const res = await fetch('/assistant', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages: history, report: reportSel.value })
      });
      const d = await res.json();
      pending.textContent = d.reply || d.error || '(no response)';
      if (d.reply) history.push({ role: 'assistant', content: d.reply });
    } catch (err) {
      pending.textContent = 'Error: ' + err;
    }
    sendBtn.disabled = false; input.focus();
  });
}

// One-click: scan the hosts discovered by a recon run (prefills the Network scan form)
function scanDiscovered(targets, count) {
  if (!confirm('Start a network scan of ' + count + ' discovered host(s)? '
      + 'Only proceed if you are authorized to scan these systems.')) return;
  const btn = document.querySelector('.tabbtn[data-tab="tab-scan"]');
  const sf = document.getElementById('scan-form');
  if (!btn || !sf) { alert('Network scan is not available for your account.'); return; }
  btn.click();  // switch to the Network scan tab
  sf.querySelector('[name=target]').value = targets;
  const mode = document.getElementById('scan-mode');
  mode.value = 'advanced'; mode.dispatchEvent(new Event('change'));
  const corr = sf.querySelector('[name=correlate_cves]'); if (corr) corr.checked = true;
  document.getElementById('scan-auth').checked = true;
  sf.requestSubmit();
}

// OSINT recon
const reconForm = document.getElementById('recon-form');
if (reconForm) {
  const rbtn = document.getElementById('recon-btn');
  const rcon = document.getElementById('rc-console');
  const rstate = document.getElementById('rc-state');
  reconForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!document.getElementById('recon-auth').checked) { alert('Please confirm you are authorized to assess this domain.'); return; }
    rbtn.disabled = true; rcon.style.display = 'block'; rcon.textContent = '';
    rstate.style.display = 'inline'; rstate.textContent = 'running...'; rstate.className = 'pill';
    const res = await fetch('/recon', { method:'POST', body: new FormData(reconForm) });
    if (!res.ok) { let m='recon failed'; try { m=(await res.json()).error||m; } catch(e){} rstate.textContent='error'; rstate.className='pill err'; rcon.textContent=m; rbtn.disabled=false; return; }
    pollRecon((await res.json()).job_id);
  });
  async function pollRecon(jobId) {
    try {
      const job = await (await fetch('/status/' + jobId)).json();
      rcon.textContent = (job.logs || []).join('\\n'); rcon.scrollTop = rcon.scrollHeight;
      if (job.status === 'running') { setTimeout(() => pollRecon(jobId), 1200); return; }
      rbtn.disabled = false;
      if (job.status === 'done') {
        rstate.textContent = 'done'; rstate.className = 'pill ok';
        rcon.textContent += '\\n\\nRecon report ready: ' + job.report.title;
        addReportRow(job.report.filename, job.report.owner);
        window.open('/reports/' + job.report.filename, '_blank');
        const acts = document.getElementById('rc-actions');
        acts.innerHTML = '';
        if (job.report.targets && job.report.target_count > 0) {
          const b = document.createElement('button');
          b.type = 'button'; b.textContent = 'Scan ' + job.report.target_count + ' discovered host(s)';
          b.onclick = () => scanDiscovered(job.report.targets, job.report.target_count);
          acts.appendChild(b);
        }
      } else {
        rstate.textContent = 'error'; rstate.className = 'pill err';
        rcon.textContent += '\\n\\nError: ' + (job.error || 'unknown');
      }
    } catch (err) {
      rbtn.disabled = false; rstate.textContent = 'error'; rstate.className = 'pill err';
      rcon.textContent += '\\n\\nError: ' + err;
    }
  }
}

// scheduled scan
const ssForm = document.getElementById('scan-sched-form');
if (ssForm) ssForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const d = await (await fetch('/scan/schedule', { method:'POST', body: new FormData(ssForm) })).json();
  const s = document.getElementById('ss-state');
  if (d.ok) { s.textContent = (d.enabled && d.next_run) ? ('Saved · next run: ' + d.next_run) : 'Scheduled scan disabled'; s.className = 'pill ok'; }
  else { s.textContent = d.message || 'error'; s.className = 'pill err'; }
});

// asset inventory clear
const assetsClear = document.getElementById('assets-clear');
if (assetsClear) assetsClear.addEventListener('click', async () => {
  if (!confirm('Clear the asset inventory?')) return;
  await fetch('/assets/clear', { method:'POST' });
  location.reload();
});

// API keys
const keysForm = document.getElementById('keys-form');
if (keysForm) keysForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  await fetch('/apikeys/save', { method:'POST', body: new FormData(keysForm) });
  const s = document.getElementById('keys-state');
  s.style.display = 'inline'; s.textContent = 'Saved'; s.className = 'pill ok';
  setTimeout(() => location.reload(), 700);
});

// alerts config
const alForm = document.getElementById('alerts-form');
if (alForm) {
  alForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    await fetch('/alerts/save', { method:'POST', body: new FormData(alForm) });
    const s = document.getElementById('al-state'); s.style.display = 'inline';
    s.textContent = 'Saved'; s.className = 'pill ok';
  });
  document.getElementById('al-test').addEventListener('click', async () => {
    const s = document.getElementById('al-state'); s.style.display = 'inline';
    s.textContent = 'sending...'; s.className = 'pill';
    const d = await (await fetch('/alerts/test', { method:'POST', body: new FormData(alForm) })).json();
    s.textContent = d.message; s.className = 'pill ' + (d.ok ? 'ok' : 'err');
  });
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

  // ── Activity log (admin) ──
  const logsTable = document.getElementById('logs-table');
  if (logsTable) {
    const LVL = { error:['#7f1d1d','#fca5a5'], warning:['#78350f','#fcd34d'],
                  success:['#14432a','#86efac'], info:['#1e3a5f','#93c5fd'] };
    const esc = (s) => String(s==null?'':s).replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
    const fcat = document.getElementById('logf-category');
    const flvl = document.getElementById('logf-level');
    const fuser = document.getElementById('logf-user');
    const fq = document.getElementById('logf-q');
    const meta = document.getElementById('logs-meta');
    let filled = false;
    async function loadLogs() {
      logsTable.innerHTML = '<p class="note">Loading…</p>';
      const qs = new URLSearchParams({ category:fcat.value, level:flvl.value, user:fuser.value, q:fq.value, limit:'500' });
      let d;
      try { d = await (await fetch('/admin/logs?' + qs)).json(); }
      catch (e) { logsTable.innerHTML = '<p class="err">Couldn\\'t load the log.</p>'; return; }
      if (!filled) {
        (d.categories||[]).forEach(c => fcat.insertAdjacentHTML('beforeend', '<option value="'+c+'">'+c+'</option>'));
        (d.levels||[]).forEach(l => flvl.insertAdjacentHTML('beforeend', '<option value="'+l+'">'+l+'</option>'));
        filled = true;
      }
      meta.style.display='inline'; meta.textContent = d.count + ' event(s)';
      const ev = d.events || [];
      if (!ev.length) { logsTable.innerHTML = '<p class="note">No matching events.</p>'; return; }
      let h = '<table style="width:100%;border-collapse:collapse"><tr style="text-align:left;border-bottom:2px solid var(--line)">' +
              '<th style="padding:8px">Time (UTC)</th><th style="padding:8px">Category</th><th style="padding:8px">Level</th>' +
              '<th style="padding:8px">User</th><th style="padding:8px">Action</th><th style="padding:8px">Detail</th></tr>';
      ev.forEach(e => {
        const lv = LVL[e.level] || LVL.info;
        h += '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:8px;white-space:nowrap;color:var(--muted)">' + esc(e.ts) + '</td>' +
          '<td style="padding:8px"><span class="kind cloud">' + esc(e.category) + '</span></td>' +
          '<td style="padding:8px"><span class="badge" style="background:'+lv[0]+';color:'+lv[1]+'">' + esc(e.level) + '</span></td>' +
          '<td style="padding:8px">' + (esc(e.user) || '—') + '</td>' +
          '<td style="padding:8px">' + esc(e.action) + '</td>' +
          '<td style="padding:8px;color:var(--muted)">' + esc(e.detail) + '</td></tr>';
      });
      logsTable.innerHTML = h + '</table>';
    }
    document.addEventListener('click', (e) => { if (e.target.closest('[data-tab="tab-logs"]')) loadLogs(); });
    document.getElementById('logs-refresh').addEventListener('click', loadLogs);
    [fcat, flvl].forEach(el => el.addEventListener('change', loadLogs));
    let t; [fuser, fq].forEach(el => el.addEventListener('input', () => { clearTimeout(t); t = setTimeout(loadLogs, 400); }));
    document.getElementById('logs-clear').addEventListener('click', async () => {
      if (!confirm('Clear the entire activity log? This cannot be undone.')) return;
      await fetch('/admin/logs/clear', { method:'POST' });
      loadLogs();
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
    scan_sched = _load_scan_sched()
    if scan_sched:
        _register_scan_sched(scan_sched)


if __name__ == "__main__":
    _startup()
    port = int(os.getenv("WEB_PORT", "5000"))
    log.info("Threat Intel Briefing web UI on http://localhost:%d", port)
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
