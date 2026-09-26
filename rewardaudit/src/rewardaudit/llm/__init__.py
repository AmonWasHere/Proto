from __future__ import annotations

import os

from .. import config
from .base import LLMBackend, LLMError, LLMRequest, LLMResponse
from .cache import CachedBackend, unwrap
from .local import LocalBackend
from .mock import MockBackend
from .openai_compat import OpenAICompatibleBackend
from .scripted import ScriptedBackend


def _cache_path() -> str | None:
    """Cache location, or None to disable.

    Unset -> default on (`runs/llm_cache.jsonl`). `off`/`0`/`false` -> disabled.
    Any other value -> treated as the file path.
    """
    raw = os.environ.get("REWARDAUDIT_LLM_CACHE")
    if raw is None:
        return str(config.RUNS_DIR / "llm_cache.jsonl")
    if raw.lower() in ("", "off", "0", "false", "no"):
        return None
    return raw


def build_backend(kind: str, *, cache: bool = True, no_thinking: bool = False):
    """Factory: 'mock' | 'scripted' | 'local' | 'cloud'.

    Cloud/local backends are wrapped in a content-addressed verdict cache by
    default (see `REWARDAUDIT_LLM_CACHE`). `no_thinking` disables provider
    thinking mode where supported (DeepSeek: `thinking.type=disabled`).
    """
    kind = kind.lower()
    if kind == "mock":
        return MockBackend()
    if kind == "scripted":
        return ScriptedBackend()
    if kind == "local":
        backend: LLMBackend = LocalBackend()
    elif kind in ("cloud", "api", "openai"):
        backend = OpenAICompatibleBackend.from_env(no_thinking=no_thinking)
    else:
        raise ValueError(f"unknown backend: {kind!r}")

    path = _cache_path() if cache else None
    if path:
        return CachedBackend(backend, path)
    return backend


__all__ = [
    "LLMBackend",
    "LLMError",
    "LLMRequest",
    "LLMResponse",
    "CachedBackend",
    "LocalBackend",
    "MockBackend",
    "OpenAICompatibleBackend",
    "ScriptedBackend",
    "build_backend",
    "unwrap",
]
