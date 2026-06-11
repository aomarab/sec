"""Environment-driven configuration. Mirrors the input parameters of the
Microsoft Threat Intelligence Briefing Agent (insights, look-back, region,
industry, email)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _list(name: str) -> list[str]:
    raw = os.getenv(name, "").strip()
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass
class LLMConfig:
    provider: str = field(default_factory=lambda: os.getenv("LLM_PROVIDER", "anthropic").lower())
    anthropic_api_key: str = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", ""))
    anthropic_model: str = field(default_factory=lambda: os.getenv("ANTHROPIC_MODEL", "claude-opus-4-7"))
    anthropic_thinking: bool = field(default_factory=lambda: _bool("ANTHROPIC_THINKING", True))
    openai_api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    openai_model: str = field(default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o"))
    azure_api_key: str = field(default_factory=lambda: os.getenv("AZURE_OPENAI_API_KEY", ""))
    azure_endpoint: str = field(default_factory=lambda: os.getenv("AZURE_OPENAI_ENDPOINT", ""))
    azure_deployment: str = field(default_factory=lambda: os.getenv("AZURE_OPENAI_DEPLOYMENT", ""))
    azure_api_version: str = field(
        default_factory=lambda: os.getenv("AZURE_OPENAI_API_VERSION", "2024-08-01-preview")
    )
    ollama_base_url: str = field(
        default_factory=lambda: os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434/v1")
    )
    ollama_model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3.1"))


@dataclass
class EmailConfig:
    enabled: bool = field(default_factory=lambda: _bool("EMAIL_ENABLED"))
    to: str = field(default_factory=lambda: os.getenv("EMAIL_TO", ""))
    sender: str = field(default_factory=lambda: os.getenv("EMAIL_FROM", ""))
    smtp_host: str = field(default_factory=lambda: os.getenv("SMTP_HOST", ""))
    smtp_port: int = field(default_factory=lambda: _int("SMTP_PORT", 587))
    smtp_username: str = field(default_factory=lambda: os.getenv("SMTP_USERNAME", ""))
    smtp_password: str = field(default_factory=lambda: os.getenv("SMTP_PASSWORD", ""))
    use_tls: bool = field(default_factory=lambda: _bool("SMTP_USE_TLS", True))


@dataclass
class AgentConfig:
    # Input parameters (mirror the MS agent)
    insights_to_research: int = field(default_factory=lambda: _int("INSIGHTS_TO_RESEARCH", 10))
    look_back_days: int = field(default_factory=lambda: _int("LOOK_BACK_DAYS", 7))
    region: str = field(default_factory=lambda: os.getenv("REGION", "Global"))
    industry: str = field(default_factory=lambda: os.getenv("INDUSTRY", "Technology"))
    # Minimum CVSS to include: 9.0 Critical, 7.0 High, 4.0 Medium, 0.0 all
    min_cvss: float = field(default_factory=lambda: _float("MIN_CVSS", 7.0))
    asset_keywords: list[str] = field(default_factory=lambda: _list("ASSET_KEYWORDS"))
    # Free-text steering appended to the system prompt (set per-run by the web UI)
    extra_instructions: str = field(default_factory=lambda: os.getenv("EXTRA_INSTRUCTIONS", ""))

    nvd_api_key: str = field(default_factory=lambda: os.getenv("NVD_API_KEY", ""))

    run_mode: str = field(default_factory=lambda: os.getenv("RUN_MODE", "once").lower())
    schedule_cron: str = field(default_factory=lambda: os.getenv("SCHEDULE_CRON", "0 7 * * *"))
    max_steps: int = field(default_factory=lambda: _int("MAX_AGENT_STEPS", 12))

    llm: LLMConfig = field(default_factory=LLMConfig)
    email: EmailConfig = field(default_factory=EmailConfig)


CONFIG = AgentConfig()
