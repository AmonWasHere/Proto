"""Local LLM backend for ollama / llama.cpp / vLLM OpenAI-compatible servers."""

from __future__ import annotations

import os

from .openai_compat import OpenAICompatibleBackend


class LocalBackend(OpenAICompatibleBackend):
    name = "local"

    def __init__(
        self,
        *,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float = 300.0,
    ) -> None:
        super().__init__(
            base_url=base_url or os.environ.get("REWARDAUDIT_LOCAL_BASE_URL", "http://localhost:11434/v1"),
            model=model or os.environ.get("REWARDAUDIT_LOCAL_MODEL", "qwen2.5-coder:7b"),
            api_key=os.environ.get("REWARDAUDIT_LOCAL_API_KEY", "local"),
            timeout=timeout,
        )
