"""
OpenAI-compatible provider.
Works with: Groq, OpenAI, Together AI, Fireworks, Mistral, Anyscale,
and any API that speaks the OpenAI /v1/chat/completions format.
"""

import requests
from .base import BaseProvider


class OpenAIProvider(BaseProvider):
    def call(self, messages, timeout=30):
        response = requests.post(
            self.api_url,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model":    self.model,
                "messages": messages,
            },
            timeout=timeout,
        )

        result = response.json()

        if "choices" not in result:
            raise ValueError(f"Unexpected response format: {result}")

        return result["choices"][0]["message"]["content"]
