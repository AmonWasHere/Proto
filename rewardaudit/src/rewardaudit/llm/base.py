"""Backend-agnostic LLM interface.

The same `LLMRequest` goes to a cloud API, a local server, or a mock, so results
are backend-independent and reproducible. Implementations use only the standard
library, so there is nothing to install to talk to either.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class LLMError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class LLMRequest:
    system: str
    user: str
    max_tokens: int = 1024
    temperature: float = 0.0
    json_mode: bool = True


@dataclass(frozen=True, slots=True)
class LLMResponse:
    text: str
    backend: str
    model: str = ""
    tokens_in: int = 0
    tokens_out: int = 0


class LLMBackend(Protocol):
    name: str

    def complete(self, request: LLMRequest) -> LLMResponse: ...
