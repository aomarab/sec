"""Analyze an uploaded threat document: extract text + IOCs, ask the LLM for a
structured summary, and assemble a Markdown report (rendered to HTML elsewhere)."""
from __future__ import annotations

import logging
import os

from agent.llm import build_client
from .extract import extract_text
from .iocs import extract_iocs, ioc_table_markdown, refang

log = logging.getLogger("analysis.analyze")

MAX_CHARS = int(os.getenv("ANALYZE_MAX_CHARS", "40000"))

_SYSTEM = """You are a senior cyber threat-intelligence analyst. You are given the
text of a threat report, advisory, or data export uploaded by a security engineer.
Produce a clear, accurate analysis grounded ONLY in the provided text. Do not
invent CVEs, products, or facts that are not supported by the document. If a
section has no information, say so briefly.

Output GitHub-flavoured Markdown with exactly these sections, in this order:

## Summary of Threat
3-6 sentences: what the threat is (actor/malware/campaign), how it operates, and
who/what it targets.

## Affected Products
Bullet list of affected software, systems, or platforms named in the document.

## CVEs
Bullet list of every CVE mentioned (just the IDs, one per line, e.g. "- CVE-2021-34527").
If none, write "None referenced."

[[IOCS]]

## Recommendations
Prioritised, concrete defensive actions drawn from the document's mitigation
guidance (patching, hardening, detection, response).

Do NOT include an IOC list yourself — the line [[IOCS]] is a placeholder that will
be replaced with an extracted indicator table. Keep [[IOCS]] on its own line."""


def _complete(cfg, system: str, user: str) -> str:
    client, model = build_client(cfg.llm)
    if cfg.llm.provider == "anthropic":
        kwargs = dict(model=model, max_tokens=4000,
                      system=[{"type": "text", "text": system,
                               "cache_control": {"type": "ephemeral"}}],
                      messages=[{"role": "user", "content": user}])
        if getattr(cfg.llm, "anthropic_thinking", False):
            kwargs["thinking"] = {"type": "adaptive"}
            kwargs["max_tokens"] = 8000
        resp = client.messages.create(**kwargs)
        return "".join(b.text for b in resp.content if b.type == "text")
    # OpenAI-compatible
    resp = client.chat.completions.create(
        model=model, temperature=0.2,
        messages=[{"role": "system", "content": system},
                  {"role": "user", "content": user}],
    )
    return resp.choices[0].message.content or ""


def analyze_document(path: str, cfg) -> str:
    """Return a Markdown threat-analysis report for the uploaded file."""
    name = os.path.basename(path)
    log.info("Extracting %s", name)
    raw = extract_text(path)
    text = refang(raw)
    if not text.strip():
        raise RuntimeError(f"No readable text found in {name} (it may be a scanned image).")

    iocs = extract_iocs(text)
    ioc_counts = ", ".join(f"{len(v)} {k}" for k, v in iocs.items()) or "none"
    log.info("Extracted IOCs: %s", ioc_counts)

    snippet = text[:MAX_CHARS]
    truncated = len(text) > MAX_CHARS
    user = (f"Document filename: {name}\n"
            f"{'(NOTE: text truncated to first %d characters)' % MAX_CHARS if truncated else ''}\n\n"
            f"--- DOCUMENT TEXT ---\n{snippet}")

    log.info("Analyzing %s with the model", name)
    body = _complete(cfg, _SYSTEM, user).strip()

    ioc_md = ioc_table_markdown(iocs)
    if "[[IOCS]]" in body:
        body = body.replace("[[IOCS]]", ioc_md)
    else:
        body += "\n\n" + ioc_md

    header = f"# Threat Analysis — {name}\n\n"
    return header + body
