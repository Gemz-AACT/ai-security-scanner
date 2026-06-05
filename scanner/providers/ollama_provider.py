"""
Ollama local model provider.
Endpoint : http://localhost:11434/api/chat
Auth     : none required
"""

import requests
from .base import BaseProvider


class OllamaProvider(BaseProvider):

    def call(self, messages, timeout=60):
        payload = {
            "model":    self.model,
            "messages": messages,
            "stream":   False,
        }

        response = requests.post(
            self.api_url,
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=timeout,
        )

        result = response.json()

        if "error" in result:
            raise ValueError(f"Ollama error: {result['error']}")

        if "message" not in result:
            raise ValueError(f"Unexpected response format: {result}")

        return result["message"]["content"]
