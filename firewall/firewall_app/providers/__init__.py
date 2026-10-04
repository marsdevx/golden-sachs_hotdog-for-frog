"""Built-in provider modules. Register additional adapters here."""
from firewall_app.providers.anthropic import AnthropicAdapter
from firewall_app.providers.mock import MockAdapter
from firewall_app.providers.ollama import OllamaAdapter
from firewall_app.providers.openai_compatible import OpenAICompatibleAdapter
from firewall_app.providers.registry import ProviderRegistry

registry = ProviderRegistry()
registry.register("ollama", OllamaAdapter)
registry.register("openai_compatible", OpenAICompatibleAdapter)
registry.register("mock", MockAdapter)
registry.register("anthropic", AnthropicAdapter)
