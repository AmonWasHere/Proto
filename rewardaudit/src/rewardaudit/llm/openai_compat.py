"""OpenAI-compatible chat backend (cloud APIs and local OpenAI-compatible servers).

Standard library only. Point it at any endpoint that speaks
`POST {base_url}/chat/completions`:

    cloud:  base_url=https://api.openai.com/v1, api_key=$OPENAI_API_KEY
    local:  base_url=http://localhost:11434/v1 (ollama), api_key="ollama"
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request

from .base import LLMError, LLMRequest, LLMResponse

_RETRY_CODES = {429, 500, 502, 503, 504}


class OpenAICompatibleBackend:
    name = "openai_compat"

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str | None = None,
        name: str | None = None,
        timeout: float = 120.0,
        retries: int = 10,
        backoff_base: float = 1.5,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.retries = max(1, retries)
        self.backoff_base = backoff_base
        if name:
            self.name = name

    @classmethod
    def from_env(cls) -> "OpenAICompatibleBackend":
        return cls(
            base_url=os.environ.get("REWARDAUDIT_LLM_BASE_URL", "https://api.openai.com/v1"),
            model=os.environ.get("REWARDAUDIT_LLM_MODEL", "gpt-4o-mini"),
            api_key=os.environ.get("REWARDAUDIT_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY"),
        )

    def _delay(self, attempt: int, detail: str, headers) -> float:
        delay = self.backoff_base * (2**attempt)
        if headers is not None:
            retry_after = headers.get("Retry-After")
            if retry_after and str(retry_after).isdigit():
                delay = max(delay, int(retry_after))
        match = re.search(r"try again in ([0-9.]+)s", detail or "")
        if match:
            delay = max(delay, float(match.group(1)) + 0.5)
        return min(delay, 60.0)

    def complete(self, request: LLMRequest) -> LLMResponse:
        body: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": request.system},
                {"role": "user", "content": request.user},
            ],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if request.json_mode:
            body["response_format"] = {"type": "json_object"}

        data = json.dumps(body).encode()
        headers = {
            "Content-Type": "application/json",
            # Some providers sit behind Cloudflare, which rejects the default
            # python-urllib User-Agent outright (error 1010).
            "User-Agent": "rewardaudit/0.0.1 (OpenAI-compatible client)",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        req = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=data, headers=headers, method="POST"
        )
        payload: dict | None = None
        last_error = ""
        for attempt in range(self.retries):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    payload = json.loads(resp.read().decode())
                break
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", "replace")[:300]
                last_error = f"HTTP {exc.code}: {detail}"
                if exc.code in _RETRY_CODES and attempt < self.retries - 1:
                    time.sleep(self._delay(attempt, detail, exc.headers))
                    continue
                raise LLMError(f"{self.name} {last_error}") from exc
            except OSError as exc:  # pragma: no cover - network path
                last_error = str(exc)
                if attempt < self.retries - 1:
                    time.sleep(self._delay(attempt, "", None))
                    continue
                raise LLMError(f"{self.name} request failed: {exc}") from exc
        if payload is None:
            raise LLMError(f"{self.name} exhausted retries: {last_error}")

        try:
            text = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"{self.name} malformed response: {str(payload)[:200]}") from exc
        usage = payload.get("usage", {}) or {}
        return LLMResponse(
            text=text or "",
            backend=self.name,
            model=payload.get("model", self.model),
            tokens_in=int(usage.get("prompt_tokens", 0)),
            tokens_out=int(usage.get("completion_tokens", 0)),
        )
