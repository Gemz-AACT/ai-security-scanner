"""
Base provider interface.
Every provider adapter must implement call() and returns a plain string (the model's reply)
or raises an exception on failure.
"""

class BaseProvider:
    def __init__(self, api_url, api_key, model):
        self.api_url = api_url
        self.api_key = api_key
        self.model   = model

    def call(self, messages, timeout=30):
        """
        Send messages to the model and return the reply as a plain string.
        messages = list of {"role": "user"|"assistant"|"system", "content": "..."}
        """
        raise NotImplementedError
