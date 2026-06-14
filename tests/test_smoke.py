"""Smoke tests for the pure-Python modules (no Flask, no network).

Runnable with `pytest` or directly with `python tests/test_smoke.py`. Tests stub
out subprocess/requests and point file-backed stores at temp files."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── audit log ────────────────────────────────────────────────────────────────
def test_audit_record_filter_and_handler():
    import logging
    import audit
    audit.LOG_FILE = tempfile.mktemp(suffix=".jsonl")
    logging.basicConfig(level=logging.INFO)
    audit.install_handler()
    audit.record("auth", "Sign in", user="abdul", level="success")
    audit.record("scan", "Network scan", user="abdul", detail="target 10.0.0.0/28")
    logging.getLogger("werkzeug").info("GET /status 200")   # must be skipped
    events = audit.read(limit=50)
    assert any(e["category"] == "auth" and e["user"] == "abdul" for e in events)
    assert not any("GET /status" in e["action"] for e in events)
    assert len(audit.read(category="scan")) >= 1


# ── change detection ─────────────────────────────────────────────────────────
def test_monitor_diff():
    import monitor
    monitor.SNAP_FILE = tempfile.mktemp(suffix=".json")
    first = monitor.record("scan", "t", {"open ports": ["a:80"]}, {"risk score": 10})
    assert first["diff"]["baseline"] is True
    second = monitor.record("scan", "t", {"open ports": ["a:443"]}, {"risk score": 30})
    assert second["diff"]["changed"] is True
    assert "a:443" in second["diff"]["categories"]["open ports"]["added"]
    assert "a:80" in second["diff"]["categories"]["open ports"]["removed"]
    assert second["diff"]["metrics"]["risk score"] == {"from": 10, "to": 30}


# ── findings register ────────────────────────────────────────────────────────
def test_findings_dedup_and_lifecycle():
    import findings
    findings.FINDINGS_FILE = tempfile.mktemp(suffix=".json")
    new, upd = findings.ingest("10.0.0.5", "scan", [
        {"severity": "high", "title": "Open RDP", "host": "10.0.0.5"},
        {"severity": "medium", "title": "Missing CSP", "host": "https://10.0.0.5"},
    ])
    assert (new, upd) == (2, 0)
    new, upd = findings.ingest("10.0.0.5", "scan", [{"severity": "high", "title": "Open RDP", "host": "10.0.0.5"}])
    assert (new, upd) == (0, 1)                       # deduped
    top = findings.list_findings()[0]
    assert top["severity"] == "high" and top["count"] == 2
    assert findings.update(top["id"], status="fixed", owner="abdul")
    # reappears after being fixed -> auto-reopens
    findings.ingest("10.0.0.5", "scan", [{"severity": "high", "title": "Open RDP", "host": "10.0.0.5"}])
    assert findings.list_findings(severity="high")[0]["status"] == "open"
    assert findings.stats()["total"] == 2


# ── scan tool parsers ────────────────────────────────────────────────────────
def test_tools_parsers():
    from scan import tools

    class P:
        def __init__(self, out=""):
            self.stdout = out
    orig_which, orig_run = tools.shutil.which, tools.subprocess.run
    tools.shutil.which = lambda *n: "/usr/bin/x"
    try:
        tools.subprocess.run = lambda a, **k: P("open tcp 443 1.2.3.4 1620000000\n")
        assert tools.masscan_ports("1.2.3.4") == [{"host": "1.2.3.4", "port": 443}]
        tools.subprocess.run = lambda a, **k: P(json.dumps(
            {"template-id": "x", "info": {"name": "Exposed panel", "severity": "high"},
             "host": "h", "matched-at": "h/admin"}) + "\n")
        rows = tools.run_nuclei(["http://h"])
        assert rows and rows[0]["severity"] == "high"
    finally:
        tools.shutil.which, tools.subprocess.run = orig_which, orig_run


# ── native headers grader ────────────────────────────────────────────────────
def test_headers_grader():
    from scan import headers

    class R:
        url = "https://x/"
        headers = {"Server": "nginx/1.18.0"}
        cookies = []
    orig = headers.requests.get
    headers.requests.get = lambda *a, **k: R()
    try:
        f = headers.grade("https://x")
        names = {x["check"] for x in f}
        assert "Content-Security-Policy" in names and "Strict-Transport-Security (HSTS)" in names
    finally:
        headers.requests.get = orig


# ── native web checks ────────────────────────────────────────────────────────
def test_webchecks_cors_and_secrets():
    from scan import webchecks

    class R:
        def __init__(self, headers=None, text="", status=200, url="https://x/"):
            self.headers = headers or {}
            self.text = text
            self.status_code = status
            self.url = url
    orig = webchecks.requests.get
    webchecks.requests.get = lambda u, **k: R(headers={
        "Access-Control-Allow-Origin": "https://example-redirect-test.org",
        "Access-Control-Allow-Credentials": "true"})
    try:
        cors = webchecks._cors("https://x")
        assert cors and cors[0]["severity"] == "high"
    finally:
        webchecks.requests.get = orig


# ── IOC extraction ───────────────────────────────────────────────────────────
def test_ioc_extraction():
    from analysis import iocs
    text = iocs.refang("Contact evil[.]com from 8.8.8.8 hash d41d8cd98f00b204e9800998ecf8427e")
    found = iocs.extract_iocs(text)
    assert "8.8.8.8" in found.get("ipv4", [])
    assert "evil.com" in found.get("domain", [])
    assert "d41d8cd98f00b204e9800998ecf8427e" in found.get("md5", [])


# ── table export ─────────────────────────────────────────────────────────────
def test_export_tables():
    from briefing import export
    md = "| CVE | CVSS |\n|---|---|\n| CVE-2024-1 | 9.8 |\n| CVE-2024-2 | 7.5 |"
    tables = export.extract_tables(md)
    assert tables and len(tables[0]["rows"]) == 2
    csv = export.to_csv(tables)
    assert "CVE-2024-1" in csv and "9.8" in csv


# ── vendor assessment section selection ──────────────────────────────────────
def test_vendor_section_selection():
    from cloud import vendor
    captured = {}
    orig = vendor._complete
    vendor._complete = lambda cfg, system, context, max_tokens=3800: captured.setdefault("sys", system) or "ok"
    try:
        vendor.assess_vendor("aws", cfg=None, sections=["certifications", "score"])
        assert "Security Certifications" in captured["sys"]
        assert "Compliance Coverage" not in captured["sys"]
    finally:
        vendor._complete = orig


# ── api key store ────────────────────────────────────────────────────────────
def test_apikeys_store():
    import apikeys

    class Form(dict):
        def get(self, k, d=None):
            return dict.get(self, k, d)
    apikeys.KEYS_FILE = tempfile.mktemp(suffix=".json")
    apikeys.save_form(Form({"VT_API_KEY": "abcd1234"}))
    assert apikeys.get("VT_API_KEY") == "abcd1234"
    statuses = {s["key"]: s["configured"] for s in apikeys.status()}
    assert statuses["VT_API_KEY"] is True
    assert "ANTHROPIC_API_KEY" in statuses


# ── compliance (OWASP) mapping ───────────────────────────────────────────────
def test_compliance_mapping():
    import compliance
    assert compliance.map_owasp("SQL injection detected", "sqlmap") == "A03"
    assert compliance.map_owasp("CVE-2024-3400 — Palo Alto", "cve") == "A06"
    assert compliance.map_owasp("Reflects arbitrary Origin", "webchecks") == "A01"
    assert compliance.map_owasp("RC4 ciphers offered", "testssl") == "A02"
    summary = compliance.summarize([{"title": "XSS", "source": "wapiti"},
                                    {"title": "Missing CSP header", "source": "headers"}])
    codes = {s["code"] for s in summary}
    assert "A03" in codes and "A05" in codes


# ── subdomain takeover fingerprint ───────────────────────────────────────────
def test_takeover_fingerprint():
    from recon import takeover

    class R:
        def __init__(self, text):
            self.text = text
            self.status_code = 200
    orig = takeover.requests.get
    takeover.requests.get = lambda u, **k: R("<p>There isn't a GitHub Pages site here</p>")
    try:
        f = takeover.check_host("sub.example.com")
        assert f and f["service"] == "GitHub Pages" and f["severity"] == "high"
    finally:
        takeover.requests.get = orig


if __name__ == "__main__":
    funcs = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in funcs:
        try:
            fn()
            print(f"PASS {fn.__name__}")
            passed += 1
        except Exception as err:
            print(f"FAIL {fn.__name__}: {err!r}")
    print(f"\n{passed}/{len(funcs)} passed")
    sys.exit(0 if passed == len(funcs) else 1)
