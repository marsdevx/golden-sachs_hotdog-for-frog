"""Ollama adapter, using its OpenAI-compatible /v1 endpoint.

Keep Ollama-specific translations here if the protocol needs to diverge later.
"""
from firewall_app.providers.openai_compatible import OpenAICompatibleAdapter


class OllamaAdapter(OpenAICompatibleAdapter):
    """Shares the compatible wire protocol; base_url must include /v1."""
