"""Deterministic mock backend for tests and offline development."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from .base import LLMRequest, LLMResponse

Responder = Callable[[LLMRequest], str]


class MockBackend:
    name = "mock"

    def __init__(
        self,
        responses: Sequence[str] | None = None,
        responder: Responder | None = None,
        default: str = '{"disposition": "unknown_risk", "confidence": 0.0, "rationale": "mock default"}',
    ) -> None:
        self._responses = list(responses or [])
        self._responder = responder
        self._default = default
        self.requests: list[LLMRequest] = []

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        if self._responder is not None:
            text = self._responder(request)
        elif self._responses:
            text = self._responses.pop(0)
        else:
            text = self._default
        return LLMResponse(text=text, backend=self.name, model="mock")
