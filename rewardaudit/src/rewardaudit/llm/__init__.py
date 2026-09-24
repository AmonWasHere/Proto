from .base import LLMBackend, LLMError, LLMRequest, LLMResponse
from .local import LocalBackend
from .mock import MockBackend
from .openai_compat import OpenAICompatibleBackend


def build_backend(kind: str):
    """Factory used by the harness: 'mock' | 'local' | 'cloud'."""
    kind = kind.lower()
    if kind == "mock":
        return MockBackend()
    if kind == "local":
        return LocalBackend()
    if kind in ("cloud", "api", "openai"):
        return OpenAICompatibleBackend.from_env()
    raise ValueError(f"unknown backend: {kind!r}")


__all__ = [
    "LLMBackend",
    "LLMError",
    "LLMRequest",
    "LLMResponse",
    "LocalBackend",
    "MockBackend",
    "OpenAICompatibleBackend",
    "build_backend",
]
