"""AI security assistant: answers questions about vulnerabilities, impact, and
remediation, optionally grounded in one of the user's saved reports."""
from __future__ import annotations

import logging

from agent.llm import build_client

log = logging.getLogger("assistant")

SYSTEM = """You are a senior cybersecurity assistant helping a security engineer.
Answer questions about vulnerabilities, exploitation, business impact, and
remediation clearly and practically.

- When asked to remediate, produce concrete steps and, where useful, ready-to-run
  scripts in fenced code blocks — PowerShell, Bash, or Azure CLI as appropriate.
- Explain *why* something is risky and the realistic business impact when asked.
- Be accurate. If you are not certain of a specific CVE's details, say so rather
  than inventing specifics — recommend verifying against NVD/vendor advisories.
- Keep answers focused; prefer prioritised, actionable guidance over long prose."""

MAX_CONTEXT_CHARS = 12000


def answer(history: list[dict], context: str, cfg) -> str:
    """history: list of {role: 'user'|'assistant', content: str}; context: optional
    grounding text (a report's markdown). Returns the assistant's reply text."""
    client, model = build_client(cfg.llm)
    system = SYSTEM
    if context:
        system += ("\n\nThe user has grounded this conversation in the following report. "
                   "Base any specifics about 'this scan/report/host/finding' on it; quote "
                   "indicators/CVEs from it rather than inventing them:\n\n"
                   + context[:MAX_CONTEXT_CHARS])

    if cfg.llm.provider == "anthropic":
        kwargs = dict(model=model, max_tokens=2500,
                      system=[{"type": "text", "text": system,
                               "cache_control": {"type": "ephemeral"}}],
                      messages=history)
        if getattr(cfg.llm, "anthropic_thinking", False):
            kwargs["thinking"] = {"type": "adaptive"}
            kwargs["max_tokens"] = 6000
        resp = client.messages.create(**kwargs)
        return "".join(b.text for b in resp.content if b.type == "text")

    resp = client.chat.completions.create(
        model=model, temperature=0.3,
        messages=[{"role": "system", "content": system}, *history])
    return resp.choices[0].message.content or ""
