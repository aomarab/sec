"""The agentic loop. Like the Microsoft Threat Intelligence Briefing Agent, it
dynamically chooses the next step based on the outcome of the previous step:
the LLM is given tools and decides which to call, in what order, and when it has
enough information to write the briefing.

Two backends are supported behind one entrypoint:
  - Anthropic Claude (native messages.create tool-use loop, with prompt caching
    and adaptive thinking) — the default.
  - OpenAI-compatible (OpenAI, Azure OpenAI, Ollama) via chat.completions.
"""
from __future__ import annotations

import json
import logging

from config import AgentConfig
from .llm import build_client
from .tools import TOOL_SPECS, anthropic_tool_specs, dispatch

log = logging.getLogger("agent.loop")

SYSTEM_PROMPT = """You are a senior cyber threat-intelligence analyst agent.
Your job is to produce a concise, decision-ready Threat Intelligence Briefing
for a security leadership audience (CISO, security managers, analysts).

Operating parameters for this run:
- Region focus: {region}
- Industry focus: {industry}
- Look-back window: {look_back_days} days
- Insights to research (target number of prioritized vulnerabilities): {insights}
- Minimum severity: only include vulnerabilities with CVSS >= {min_cvss} ({severity}).
  When calling fetch_recent_cves, pass min_cvss={min_cvss}. Exclude anything below this floor.
- Asset/exposure keywords of interest: {assets}

How to work:
1. Use the available tools to gather current threat data. Decide dynamically
   which tool to call next based on what previous results reveal. For example,
   start with actively exploited vulns (KEV), pull recent high-severity CVEs,
   then use EPSS to prioritize the most exploit-likely ones, and pull IOCs for
   active campaigns when relevant.
2. Prioritize ruthlessly: actively exploited > high EPSS > high CVSS. Tie the
   findings back to the region/industry/asset focus where the data allows.
3. Do not invent CVEs, scores, vendors, or IOCs. Use only tool results. If a
   tool errors or returns nothing, note the gap rather than filling it.
4. When you have enough to brief on ~{insights} prioritized items, STOP calling
   tools and write the final briefing as Markdown.

Final briefing format (Markdown):
# Threat Intelligence Briefing — {region} / {industry}
## Executive Summary        (3-5 sentences, plain language for leadership)
## Top Threats This Period  (table: CVE | Product | CVSS | EPSS | Exploited? | Why it matters)
## Active Exploitation & Campaigns   (KEV items, ransomware use, notable IOCs)
## Recommended Actions      (prioritized, concrete: patch X, hunt for Y)
## Sources & Method         (which feeds were used; note any gaps)
"""

_KICKOFF = "Generate today's threat intelligence briefing."
_FORCE_FINAL = "Stop researching now and write the final briefing from the data gathered."


def _severity_label(min_cvss: float) -> str:
    if min_cvss >= 9:
        return "Critical only"
    if min_cvss >= 7:
        return "High and Critical"
    if min_cvss >= 4:
        return "Medium and above"
    return "all severities"


class Cancelled(RuntimeError):
    """Raised when a run is stopped by the user."""


def _check_cancel(cancel_event) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise Cancelled("Briefing cancelled by user.")


def run_agent(cfg: AgentConfig, cancel_event=None) -> str:
    client, model = build_client(cfg.llm)
    system = SYSTEM_PROMPT.format(
        region=cfg.region,
        industry=cfg.industry,
        look_back_days=cfg.look_back_days,
        insights=cfg.insights_to_research,
        min_cvss=cfg.min_cvss,
        severity=_severity_label(cfg.min_cvss),
        assets=", ".join(cfg.asset_keywords) or "none specified",
    )
    extra = getattr(cfg, "extra_instructions", "").strip()
    if extra:
        system += "\n\nAdditional instructions from the user (follow these closely):\n" + extra
    if cfg.llm.provider == "anthropic":
        return _run_anthropic(cfg, client, model, system, cancel_event)
    return _run_openai_compatible(cfg, client, model, system, cancel_event)


# ── Anthropic Claude backend ────────────────────────────────────────────────
def _run_anthropic(cfg: AgentConfig, client, model: str, system: str, cancel_event=None) -> str:
    tools = anthropic_tool_specs()
    # Cache the system prompt: tools render before system, so a cache breakpoint
    # on the system block caches the tools + system prefix. It's reused on every
    # step of the loop, so each subsequent step reads it instead of reprocessing.
    system_blocks = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
    thinking = {"type": "adaptive"} if cfg.llm.anthropic_thinking else {"type": "disabled"}
    messages: list[dict] = [{"role": "user", "content": _KICKOFF}]

    def call(msgs: list[dict], with_tools: bool):
        kwargs = dict(model=model, max_tokens=16000, system=system_blocks,
                      thinking=thinking, messages=msgs)
        if with_tools:
            kwargs["tools"] = tools
        return client.messages.create(**kwargs)

    for step in range(1, cfg.max_steps + 1):
        _check_cancel(cancel_event)
        log.info("Agent step %d/%d", step, cfg.max_steps)
        response = call(messages, with_tools=True)

        if response.stop_reason != "tool_use":
            log.info("Agent produced final briefing at step %d", step)
            return _anthropic_text(response)

        # Append the full assistant turn verbatim — this preserves thinking and
        # tool_use blocks, which the API requires when continuing the loop.
        messages.append({"role": "assistant", "content": response.content})

        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                log.info("  -> tool %s args=%s", block.name, block.input)
                result = dispatch(block.name, dict(block.input), cfg)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result,
                })
        # Rolling cache breakpoint on the newest turn so the growing transcript
        # is cached too (system breakpoint + this one = 2 of the 4 allowed).
        if tool_results:
            tool_results[-1]["cache_control"] = {"type": "ephemeral"}
        messages.append({"role": "user", "content": tool_results})

    log.warning("Max steps reached; forcing final briefing.")
    messages.append({"role": "user", "content": _FORCE_FINAL})
    return _anthropic_text(call(messages, with_tools=False))


def _anthropic_text(response) -> str:
    return "".join(b.text for b in response.content if b.type == "text")


# ── OpenAI-compatible backend (OpenAI / Azure / Ollama) ──────────────────────
def _run_openai_compatible(cfg: AgentConfig, client, model: str, system: str, cancel_event=None) -> str:
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": _KICKOFF},
    ]

    for step in range(1, cfg.max_steps + 1):
        _check_cancel(cancel_event)
        log.info("Agent step %d/%d", step, cfg.max_steps)
        response = client.chat.completions.create(
            model=model, messages=messages, tools=TOOL_SPECS,
            tool_choice="auto", temperature=0.2,
        )
        msg = response.choices[0].message

        if not msg.tool_calls:
            log.info("Agent produced final briefing at step %d", step)
            return msg.content or ""

        messages.append({
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in msg.tool_calls
            ],
        })

        for tc in msg.tool_calls:
            name = tc.function.name
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            log.info("  -> tool %s args=%s", name, args)
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "name": name,
                "content": dispatch(name, args, cfg),
            })

    log.warning("Max steps reached; forcing final briefing.")
    messages.append({"role": "user", "content": _FORCE_FINAL})
    response = client.chat.completions.create(
        model=model, messages=messages, temperature=0.2,
    )
    return response.choices[0].message.content or ""
