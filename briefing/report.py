"""Render the agent's Markdown briefing to a styled, email-safe HTML document
and persist both to the reports/ directory."""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone

REPORTS_DIR = os.getenv("REPORTS_DIR", "reports")

_SEVERITY_COLORS = {
    "critical": ("#7f1d1d", "#fee2e2"),
    "high": ("#9a3412", "#ffedd5"),
    "medium": ("#854d0e", "#fef9c3"),
    "low": ("#374151", "#f3f4f6"),
}

_HTML_SHELL = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title></head>
<body style="margin:0;background:#eef1f5;font-family:'Segoe UI',-apple-system,Arial,sans-serif;color:#1f2328;-webkit-font-smoothing:antialiased;">
<div style="max-width:860px;margin:0 auto;padding:28px 16px;">
  <div style="background:linear-gradient(135deg,#0f2a43,#1d4671);color:#fff;padding:26px 30px;border-radius:12px 12px 0 0;">
    <div style="font-size:12px;letter-spacing:.14em;opacity:.8;text-transform:uppercase;">Threat Intelligence Briefing</div>
    <div style="font-size:22px;font-weight:600;margin-top:6px;">{heading}</div>
    <div style="font-size:13px;opacity:.7;margin-top:8px;">Generated {generated} UTC &middot; Automated &mdash; verify critical findings before acting</div>
  </div>
  <div style="background:#fff;padding:28px 30px;border-radius:0 0 12px 12px;border:1px solid #e2e5e9;border-top:none;line-height:1.6;font-size:15px;">
{body}
  </div>
  <div style="text-align:center;color:#9aa1ab;font-size:12px;padding:18px;">
    Sources: CISA KEV &middot; NVD &middot; FIRST EPSS &middot; abuse.ch ThreatFox
  </div>
</div></body></html>"""


def _md_to_html(md: str) -> str:
    lines = md.splitlines()
    html: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        if not line.strip():
            i += 1
            continue

        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            level = len(m.group(1))
            html.append(_heading(level, m.group(2)))
            i += 1
            continue

        if "|" in line and i + 1 < len(lines) and re.match(r"^\s*\|?[\s:|-]+\|?\s*$", lines[i + 1]):
            header = [c.strip() for c in line.strip().strip("|").split("|")]
            i += 2
            rows = []
            while i < len(lines) and "|" in lines[i]:
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            html.append(_table(header, rows))
            continue

        if re.match(r"^\s*[-*]\s+", line):
            items = []
            while i < len(lines) and re.match(r"^\s*[-*]\s+", lines[i]):
                items.append(re.sub(r"^\s*[-*]\s+", "", lines[i]).strip())
                i += 1
            lis = "".join(f"<li style='margin:6px 0;'>{_inline(it)}</li>" for it in items)
            html.append(f"<ul style='margin:10px 0;padding-left:22px;'>{lis}</ul>")
            continue

        html.append(f"<p style='margin:10px 0;'>{_inline(line)}</p>")
        i += 1

    return "\n".join(html)


def _heading(level: int, text: str) -> str:
    text = _inline(text)
    if level == 1:
        return (f"<h1 style='font-size:21px;color:#0f2a43;margin:22px 0 10px;'>{text}</h1>")
    if level == 2:
        return ("<h2 style='font-size:17px;color:#0f2a43;margin:24px 0 10px;"
                "padding-left:11px;border-left:4px solid #1d4671;'>" + text + "</h2>")
    return f"<h3 style='font-size:15px;color:#3a4250;margin:18px 0 6px;'>{text}</h3>"


def _table(header: list[str], rows: list[list[str]]) -> str:
    th = "".join(
        "<th style='text-align:left;padding:10px 12px;background:#0f2a43;color:#fff;"
        f"font-size:12px;letter-spacing:.03em;text-transform:uppercase;'>{_inline(h)}</th>"
        for h in header
    )
    body = []
    for r_idx, row in enumerate(rows):
        bg = "#ffffff" if r_idx % 2 == 0 else "#f7f9fb"
        tds = "".join(
            "<td style='padding:9px 12px;border-bottom:1px solid #e8ebef;"
            f"font-size:13px;vertical-align:top;'>{_cell(c)}</td>" for c in row
        )
        body.append(f"<tr style='background:{bg};'>{tds}</tr>")
    return ("<table style='border-collapse:collapse;width:100%;margin:14px 0;"
            "border:1px solid #e2e5e9;border-radius:8px;overflow:hidden;'>"
            f"<thead><tr>{th}</tr></thead><tbody>{''.join(body)}</tbody></table>")


def _badge(text: str, fg: str, bg: str) -> str:
    return (f"<span style='display:inline-block;padding:2px 9px;border-radius:999px;"
            f"font-size:12px;font-weight:600;color:{fg};background:{bg};'>{text}</span>")


def _cell(text: str) -> str:
    raw = text.strip()
    low = raw.lower()

    if low in _SEVERITY_COLORS:
        fg, bg = _SEVERITY_COLORS[low]
        return _badge(raw, fg, bg)
    if low in {"yes", "exploited", "active"}:
        return _badge(raw, "#7f1d1d", "#fee2e2")
    if low in {"no", "not exploited"}:
        return _badge(raw, "#374151", "#f3f4f6")

    # CVSS-style numbers (1.0–10.0) get color-coded; EPSS decimals (<1) stay plain.
    if re.fullmatch(r"\d{1,2}(\.\d+)?", raw):
        try:
            val = float(raw)
        except ValueError:
            val = -1
        if 1.0 <= val <= 10.0:
            if val >= 9:
                fg, bg = _SEVERITY_COLORS["critical"]
            elif val >= 7:
                fg, bg = _SEVERITY_COLORS["high"]
            elif val >= 4:
                fg, bg = _SEVERITY_COLORS["medium"]
            else:
                fg, bg = _SEVERITY_COLORS["low"]
            return _badge(raw, fg, bg)
    return _inline(raw)


def _inline(text: str) -> str:
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`(.+?)`", r"<code style='background:#eef1f4;padding:1px 5px;"
                  r"border-radius:4px;font-size:.92em;'>\1</code>", text)
    text = re.sub(
        r"\b(CVE-\d{4}-\d{4,7})\b",
        r"<a href='https://nvd.nist.gov/vuln/detail/\1' target='_blank' "
        r"style='color:#1f6feb;font-weight:600;'>\1</a>",
        text,
    )
    return text


def to_html(markdown: str, title: str = "Report", heading: str | None = None) -> str:
    """Render markdown to a standalone, styled HTML string (no file written)."""
    now = datetime.now(timezone.utc)
    return _HTML_SHELL.format(
        title=title, heading=heading or title,
        generated=now.strftime("%Y-%m-%d %H:%M"), body=_md_to_html(markdown))


def render(markdown: str, prefix: str = "briefing") -> dict:
    """Persist markdown + HTML; return paths and the rendered HTML.
    `prefix` distinguishes report types in the filename (briefing | analysis)."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%d-%H%M%S")
    title = f"Threat Intelligence Briefing {now.strftime('%Y-%m-%d')}"

    # Use the first markdown H1 as the banner heading when present.
    heading = next((re.sub(r"^#\s+", "", ln).strip()
                    for ln in markdown.splitlines() if ln.startswith("# ")), title)

    md_path = os.path.join(REPORTS_DIR, f"{prefix}-{stamp}.md")
    html_path = os.path.join(REPORTS_DIR, f"{prefix}-{stamp}.html")

    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(markdown)

    html = to_html(markdown, title=title, heading=heading)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return {"title": title, "markdown_path": md_path, "html_path": html_path, "html": html}
