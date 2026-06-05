"""
Anthropic Claude provider.
Endpoint : https://api.anthropic.com/v1/messages
Auth     : x-api-key header
"""

import requests
from .base import BaseProvider


class AnthropicProvider(BaseProvider):

    ANTHROPIC_VERSION = "2023-06-01"
    DEFAULT_MAX_TOKENS = 1024

    def call(self, messages, timeout=30):
        system_content = None
        filtered_messages = []

        for msg in messages:
            if msg["role"] == "system":
                system_content = msg["content"]
            else:
                filtered_messages.append({
                    "role":    msg["role"],
                    "content": msg["content"],
                })

        payload = {
            "model":      self.model,
            "max_tokens": self.DEFAULT_MAX_TOKENS,
            "messages":   filtered_messages,
        }

        if system_content:
            payload["system"] = system_content

        headers = {
            "x-api-key":         self.api_key,
            "anthropic-version": self.ANTHROPIC_VERSION,
            "Content-Type":      "application/json",
        }

        response = requests.post(
            self.api_url,
            headers=headers,
            json=payload,
            timeout=timeout,
        )

        result = response.json()

        if "error" in result:
            raise ValueError(f"Anthropic API error: {result['error']}")

        if "content" not in result or not result["content"]:
            raise ValueError(f"Unexpected response format: {result}")

        for block in result["content"]:
            if block.get("type") == "text":
                return block["text"]

        raise ValueError("No text block found in Anthropic response")
