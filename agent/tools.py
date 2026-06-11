"""Tool registry exposed to the agent. Each tool maps to a collector function.
The agent decides which tools to call and in what order — this is what makes the
briefing dynamic rather than a fixed pipeline."""
from __future__ import annotations

import json

from collectors import epss, kev, nvd, threatfox
from config import AgentConfig

TOOL_SPECS = [
    {
        "type": "function",
        "function": {
            "name": "fetch_kev",
            "description": "Get CISA Known Exploited Vulnerabilities (KEV) added recently. "
                           "These are confirmed exploited in the wild — top priority.",
            "parameters": {
                "type": "object",
                "properties": {
                    "look_back_days": {"type": "integer", "description": "How many days back to look."},
                    "limit": {"type": "integer", "description": "Max entries to return (default 25)."},
                    "keywords": {
                        "type": "array", "items": {"type": "string"},
                        "description": "Optional vendor/product filters, e.g. ['Fortinet','Exchange'].",
                    },
                },
                "required": ["look_back_days"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_recent_cves",
            "description": "Get recently published high-severity CVEs from NVD, filtered by CVSS.",
            "parameters": {
                "type": "object",
                "properties": {
                    "look_back_days": {"type": "integer"},
                    "min_cvss": {"type": "number", "description": "Minimum CVSS base score (default 7.0)."},
                    "limit": {"type": "integer"},
                    "keyword": {"type": "string", "description": "Optional keyword to scope the search."},
                },
                "required": ["look_back_days"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "score_epss",
            "description": "Get EPSS exploit-probability scores for specific CVE IDs to prioritize them.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cves": {"type": "array", "items": {"type": "string"},
                             "description": "CVE IDs, e.g. ['CVE-2024-1234']."},
                },
                "required": ["cves"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_recent_iocs",
            "description": "Get recent indicators of compromise (IOCs) from abuse.ch ThreatFox, "
                           "tied to active malware/threat-actor campaigns.",
            "parameters": {
                "type": "object",
                "properties": {
                    "days": {"type": "integer", "description": "Days back, 1-7."},
                    "limit": {"type": "integer"},
                },
            },
        },
    },
]


def anthropic_tool_specs() -> list[dict]:
    """Convert the OpenAI-style TOOL_SPECS to Anthropic's tool format
    ({name, description, input_schema}) so the same tools work on both backends."""
    specs = []
    for spec in TOOL_SPECS:
        fn = spec["function"]
        specs.append({
            "name": fn["name"],
            "description": fn["description"],
            "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
        })
    return specs


def dispatch(name: str, args: dict, cfg: AgentConfig) -> str:
    """Execute a tool by name and return a JSON string for the model."""
    try:
        if name == "fetch_kev":
            result = kev.fetch_kev(
                look_back_days=args.get("look_back_days", cfg.look_back_days),
                limit=args.get("limit", 25),
                keywords=args.get("keywords") or cfg.asset_keywords or None,
            )
        elif name == "fetch_recent_cves":
            result = nvd.fetch_recent_cves(
                look_back_days=args.get("look_back_days", cfg.look_back_days),
                min_cvss=args.get("min_cvss", 7.0),
                limit=args.get("limit", 25),
                keyword=args.get("keyword"),
                api_key=cfg.nvd_api_key,
            )
        elif name == "score_epss":
            result = epss.fetch_epss(cves=args.get("cves", []))
        elif name == "fetch_recent_iocs":
            result = threatfox.fetch_recent_iocs(
                days=args.get("days", 1), limit=args.get("limit", 25),
            )
        else:
            result = {"error": f"unknown tool: {name}"}
    except Exception as err:  # surface failures to the model so it can adapt
        result = {"error": f"{type(err).__name__}: {err}"}

    return json.dumps(result, default=str)
