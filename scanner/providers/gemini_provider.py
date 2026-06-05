"""
Google Gemini provider.
Endpoint : https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent
Auth     : ?key= query parameter
"""

import requests
from .base import BaseProvider


class GeminiProvider(BaseProvider):

    def call(self, messages, timeout=30):
        gemini_contents = []
        system_prefix = None

        for msg in messages:
            role = msg["role"]
            text = msg["content"]

            if role == "system":
                system_prefix = text
                continue
            elif role == "assistant":
                role = "model"

            gemini_contents.append({
                "role":  role,
                "parts": [{"text": text}],
            })

        if system_prefix and gemini_contents:
            first = gemini_contents[0]
            if first["role"] == "user":
                first["parts"][0]["text"] = f"{system_prefix}\n\n{first['parts'][0]['text']}"

        payload = {"contents": gemini_contents}
        url = f"{self.api_url}?key={self.api_key}"

        response = requests.post(
            url,
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=timeout,
        )

        result = response.json()

        if "error" in result:
            raise ValueError(f"Gemini API error: {result['error']}")

        if "candidates" not in result or not result["candidates"]:
            raise ValueError(f"Unexpected response format: {result}")

        try:
            return result["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError) as e:
            raise ValueError(f"Could not parse Gemini response: {result}") from e
