"""Provider-agnostic chat client. Returns an OpenAI-compatible client plus the
model/deployment name. Works with OpenAI, Azure OpenAI, and any OpenAI-compatible
endpoint (e.g. Ollama)."""
from __future__ import annotations

import apikeys
from config import LLMConfig


def build_client(cfg: LLMConfig):
    """Return (client, model_name). The client exposes the OpenAI v1
    `chat.completions.create` interface in all cases. Keys come from config
    (.env) or, if blank, the UI-managed key store (Settings → API keys)."""
    provider = cfg.provider

    if provider == "anthropic":
        import anthropic
        key = cfg.anthropic_api_key or apikeys.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("Anthropic provider requires ANTHROPIC_API_KEY "
                               "(set it in Settings → API keys, or .env)")
        client = anthropic.Anthropic(api_key=key)
        return client, cfg.anthropic_model

    if provider == "azure":
        from openai import AzureOpenAI
        if not (cfg.azure_api_key and cfg.azure_endpoint and cfg.azure_deployment):
            raise RuntimeError("Azure provider requires AZURE_OPENAI_API_KEY, "
                               "AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_DEPLOYMENT")
        client = AzureOpenAI(
            api_key=cfg.azure_api_key,
            azure_endpoint=cfg.azure_endpoint,
            api_version=cfg.azure_api_version,
        )
        return client, cfg.azure_deployment

    if provider == "ollama":
        from openai import OpenAI
        client = OpenAI(base_url=cfg.ollama_base_url, api_key="ollama")
        return client, cfg.ollama_model

    # default: openai
    from openai import OpenAI
    key = cfg.openai_api_key or apikeys.get("OPENAI_API_KEY")
    if not key:
        raise RuntimeError("OpenAI provider requires OPENAI_API_KEY "
                           "(set it in Settings → API keys, or .env)")
    client = OpenAI(api_key=key)
    return client, cfg.openai_model
