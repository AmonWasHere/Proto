"""Local LLM backend for ollama / llama.cpp / vLLM / LM Studio OpenAI-compatible servers.

Auto-recognition: if no model is configured (or the model is the literal string
``auto``), the backend asks the server which models it serves and uses the first
one. Discovery is layered so it does the right thing on LM Studio and stays
generic elsewhere:

1. LM Studio's native ``GET /api/v0/models`` — prefer a model whose ``state`` is
   ``loaded`` and whose ``type`` is ``llm`` (skip embedders).
2. The OpenAI-standard ``GET /v1/models`` — take the first non-embedding id.

The endpoint is resolved from the first of `REWARDAUDIT_LOCAL_BASE_URL`,
`REWARDAUDIT_LLM_BASE_URL`, then the ollama default, and is normalized to end in
``/v1``.

Local servers commonly reject OpenAI's ``response_format: json_object`` (LM Studio
does), so JSON mode is off by default; re-enable it with
``REWARDAUDIT_LOCAL_JSON_MODE=1`` for servers that support it.
"""

from __future__ import annotations

import json
import os
import urllib.request

from .openai_compat import OpenAICompatibleBackend

_DEFAULT_BASE = "http://localhost:11434/v1"
_DEFAULT_MODEL = "qwen2.5-coder:7b"


def normalize_base_url(base: str) -> str:
    """Ensure an OpenAI-compatible base URL ends in ``/v1``."""
    base = base.rstrip("/")
    if "/v1" not in base:
        base = base + "/v1"
    return base


def _get_json(url: str, headers: dict) -> dict:
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=10.0) as resp:
        return json.loads(resp.read().decode())


def discover_models(base_url: str, api_key: str | None = None, timeout: float = 10.0) -> list[str]:
    """Return candidate model ids for a local endpoint, loaded-LLM first."""
    base = normalize_base_url(base_url)
    host = base[:-3] if base.endswith("/v1") else base
    headers = {"User-Agent": "rewardaudit/0.0.1 (OpenAI-compatible client)"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    # 1. LM Studio native API: prefer a loaded, non-embedding LLM.
    try:
        data = _get_json(f"{host}/api/v0/models", headers)
        entries = data.get("data", [])
        loaded = [m["id"] for m in entries
                  if m.get("state") == "loaded" and m.get("type") == "llm"]
        rest = [m["id"] for m in entries
                if m.get("id") not in loaded and m.get("type") == "llm"
                and "embed" not in m.get("id", "").lower()]
        if loaded or rest:
            return loaded + rest
    except Exception:  # noqa: BLE001 - not LM Studio, or endpoint down
        pass

    # 2. Generic OpenAI-compatible /v1/models.
    try:
        data = _get_json(f"{base}/models", headers)
        return [m["id"] for m in data.get("data", [])
                if m.get("id") and "embed" not in m["id"].lower()]
    except Exception:  # noqa: BLE001 - discovery must never be fatal
        return []


class LocalBackend(OpenAICompatibleBackend):
    name = "local"

    def __init__(
        self,
        *,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float = 300.0,
        extra_body: dict | None = None,
    ) -> None:
        extra = dict(extra_body or {})
        raw = os.environ.get("REWARDAUDIT_LLM_EXTRA_JSON")
        if raw:
            extra.update(json.loads(raw))

        resolved_base = normalize_base_url(
            base_url
            or os.environ.get("REWARDAUDIT_LOCAL_BASE_URL")
            or os.environ.get("REWARDAUDIT_LLM_BASE_URL")
            or _DEFAULT_BASE
        )
        resolved_model = (
            model
            or os.environ.get("REWARDAUDIT_LOCAL_MODEL")
            or os.environ.get("REWARDAUDIT_LLM_MODEL")
            or ""
        )
        json_ok = os.environ.get("REWARDAUDIT_LOCAL_JSON_MODE", "").lower() in ("1", "true", "yes")

        super().__init__(
            base_url=resolved_base,
            model=resolved_model or "auto",
            api_key=os.environ.get("REWARDAUDIT_LOCAL_API_KEY") or "local",
            timeout=timeout,
            extra_body=extra,
            json_mode_supported=json_ok,
        )

        # Auto-recognize the served model when none was given.
        if not resolved_model or resolved_model.lower() == "auto":
            discovered = self.list_models()
            self.model = discovered[0] if discovered else _DEFAULT_MODEL

    def list_models(self) -> list[str]:
        """Auto-recognized model ids for this endpoint (loaded LLM first)."""
        return discover_models(self.base_url, self.api_key, timeout=min(self.timeout, 15.0))
