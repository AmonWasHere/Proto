import json

from rewardaudit.llm.base import LLMRequest, LLMResponse
from rewardaudit.llm.cache import CachedBackend
from rewardaudit.llm.mock import MockBackend


class TokenBackend:
    name = "token"
    model = "m"

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.calls += 1
        return LLMResponse(text=f"resp:{request.user}", backend=self.name, model="m",
                           tokens_in=100, tokens_out=200)


def test_cache_miss_then_hit(tmp_path):
    inner = TokenBackend()
    backend = CachedBackend(inner, tmp_path / "c.jsonl")
    request = LLMRequest(system="s", user="u")

    first = backend.complete(request)
    assert inner.calls == 1
    assert backend.misses == 1 and backend.hits == 0

    second = backend.complete(request)
    assert inner.calls == 1  # no new API call
    assert backend.hits == 1
    assert second.text == first.text
    assert backend.stats()["saved_tokens_out"] == 200


def test_cache_key_separates_different_questions(tmp_path):
    inner = TokenBackend()
    backend = CachedBackend(inner, tmp_path / "c.jsonl")
    backend.complete(LLMRequest(system="s", user="a"))
    backend.complete(LLMRequest(system="s", user="b"))
    assert inner.calls == 2
    assert backend.misses == 2


def test_cache_key_includes_extra_body(tmp_path):
    a = CachedBackend(TokenBackend(), tmp_path / "c.jsonl")
    a.inner.extra_body = {"thinking": {"type": "disabled"}}
    a.complete(LLMRequest(system="s", user="u"))
    b = CachedBackend(TokenBackend(), tmp_path / "c.jsonl")
    b.inner.extra_body = {}
    b.complete(LLMRequest(system="s", user="u"))
    assert b.hits == 0  # different provider configuration -> not reused


def test_cache_persists_across_instances(tmp_path):
    path = tmp_path / "c.jsonl"
    first = CachedBackend(TokenBackend(), path)
    first.complete(LLMRequest(system="s", user="u"))

    inner = TokenBackend()
    second = CachedBackend(inner, path)
    second.complete(LLMRequest(system="s", user="u"))
    assert second.hits == 1
    assert inner.calls == 0


def test_cache_file_is_jsonl(tmp_path):
    path = tmp_path / "c.jsonl"
    CachedBackend(TokenBackend(), path).complete(LLMRequest(system="s", user="u"))
    record = json.loads(path.read_text().strip())
    assert {"key", "text", "tokens_in", "tokens_out"} <= set(record)
