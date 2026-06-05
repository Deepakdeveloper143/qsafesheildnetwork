import time
import httpx
from typing import Optional, Dict, Any


class GroqClient:
    def __init__(self, api_key: Optional[str] = None, base_url: str = "https://api.groq.com"):
        self.api_key = api_key
        self.base_url = base_url
        self._client = httpx.Client(timeout=30.0)

    def call_model(self, model: str, prompt: str, timeout: int = 15) -> Dict[str, Any]:
        # Lightweight stub: in production use official SDK and streaming
        if not self.api_key:
            raise RuntimeError("Groq API key not configured")
        tries = 0
        while tries < 3:
            try:
                # Example request (replace with real Groq call)
                r = self._client.post(f"{self.base_url}/v1/models/{model}/predict", json={"prompt": prompt}, timeout=timeout)
                r.raise_for_status()
                return r.json()
            except Exception:
                tries += 1
                time.sleep(1 + tries)
        raise RuntimeError("Groq request failed after retries")
