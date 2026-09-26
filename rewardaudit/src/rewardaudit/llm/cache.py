"""Content-addressed verdict cache.

Wraps any backend and reuses responses for identical requests. The key includes
the model, system prompt, user prompt, temperature, JSON mode, and token budget —
so any change to the question, the code slice, the prompt version, or the model
produces a different key and cannot return a stale verdict.

Why this matters for cost: it is the cheapest large saving available. A CI scan
that changes 2% of files re-verifies 2% of candidates; the rest are cache hits
that cost zero tokens.

Storage is append-only JSONL (safe under concurrent writers via O_APPEND), loaded
into memory on construction.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .base import LLMBackend, LLMRequest, LLMResponse


class CachedBackend:
    name = "cached"

    def __init__(self, inner: LLMBackend, path: str | Path) -> None:
        self.inner = inner
        self.path = Path(path)
        self.hits = 0
        self.misses = 0
        self.saved_tokens_in = 0
        self.saved_tokens_out = 0
        self._store: dict[str, dict] = {}
        self._load()

    # -- key / storage -----------------------------------------------------
    def _key(self, request: LLMRequest) -> str:
        payload = json.dumps(
            {
                "inner": getattr(self.inner, "name", "?"),
                "model": getattr(self.inner, "model", ""),
                "extra": getattr(self.inner, "extra_body", {}),
                "system": request.system,
                "user": request.user,
                "temperature": request.temperature,
                "json_mode": request.json_mode,
                "max_tokens": request.max_tokens,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        with open(self.path) as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self._store[record["key"]] = record

    def _append(self, key: str, response: LLMResponse) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "key": key,
            "text": response.text,
            "model": response.model,
            "tokens_in": response.tokens_in,
            "tokens_out": response.tokens_out,
        }
        line = json.dumps(record) + "\n"
        # O_APPEND keeps concurrent writers from interleaving partial lines.
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            os.write(fd, line.encode())
        finally:
            os.close(fd)
        self._store[key] = record

    # -- backend interface -------------------------------------------------
    def complete(self, request: LLMRequest) -> LLMResponse:
        key = self._key(request)
        cached = self._store.get(key)
        if cached is not None:
            self.hits += 1
            self.saved_tokens_in += int(cached.get("tokens_in", 0))
            self.saved_tokens_out += int(cached.get("tokens_out", 0))
            return LLMResponse(
                text=cached["text"],
                backend=getattr(self.inner, "name", "cached"),
                model=cached.get("model", ""),
                tokens_in=0,
                tokens_out=0,
            )
        response = self.inner.complete(request)
        self.misses += 1
        self._append(key, response)
        return response

    def stats(self) -> dict:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "saved_tokens_in": self.saved_tokens_in,
            "saved_tokens_out": self.saved_tokens_out,
        }


def unwrap(backend: LLMBackend) -> LLMBackend:
    """The underlying backend, if `backend` is a cache wrapper."""
    return backend.inner if isinstance(backend, CachedBackend) else backend
