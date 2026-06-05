"""
Provider factory.
Returns the correct provider instance based on the --provider flag.
"""

from .openai_provider    import OpenAIProvider
from .anthropic_provider import AnthropicProvider
from .gemini_provider    import GeminiProvider
from .ollama_provider    import OllamaProvider


PROVIDERS = {
    "openai":    OpenAIProvider,
    "anthropic": AnthropicProvider,
    "gemini":    GeminiProvider,
    "ollama":    OllamaProvider,
}


def get_provider(provider_name, api_url, api_key, model):
    provider_class = PROVIDERS.get(provider_name.lower())

    if not provider_class:
        raise ValueError(
            f"Unknown provider '{provider_name}'. "
            f"Valid options: {', '.join(PROVIDERS.keys())}"
        )

    return provider_class(api_url, api_key, model)
