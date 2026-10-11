"""Local backend: endpoint/model auto-recognition and JSON-mode behavior."""

from rewardaudit.llm.base import LLMRequest
from rewardaudit.llm.local import LocalBackend, normalize_base_url


def test_normalize_base_url_appends_v1():
    assert normalize_base_url("http://localhost:1234") == "http://localhost:1234/v1"
    assert normalize_base_url("http://localhost:1234/v1") == "http://localhost:1234/v1"
    assert normalize_base_url("http://localhost:11434/v1/") == "http://localhost:11434/v1"


def test_local_falls_back_to_generic_env(monkeypatch):
    monkeypatch.delenv("REWARDAUDIT_LOCAL_BASE_URL", raising=False)
    monkeypatch.delenv("REWARDAUDIT_LOCAL_MODEL", raising=False)
    monkeypatch.setenv("REWARDAUDIT_LLM_BASE_URL", "http://localhost:1234")
    monkeypatch.setenv("REWARDAUDIT_LLM_MODEL", "some-model")
    backend = LocalBackend()
    assert backend.base_url == "http://localhost:1234/v1"
    assert backend.model == "some-model"


def test_local_auto_model_uses_discovery(monkeypatch):
    monkeypatch.delenv("REWARDAUDIT_LOCAL_MODEL", raising=False)
    monkeypatch.delenv("REWARDAUDIT_LLM_MODEL", raising=False)
    monkeypatch.setattr(LocalBackend, "list_models", lambda self: ["m1", "m2"])
    backend = LocalBackend(base_url="http://localhost:1234/v1", model="auto")
    assert backend.model == "m1"


def test_local_auto_model_falls_back_when_none_served(monkeypatch):
    monkeypatch.delenv("REWARDAUDIT_LOCAL_MODEL", raising=False)
    monkeypatch.delenv("REWARDAUDIT_LLM_MODEL", raising=False)
    monkeypatch.setattr(LocalBackend, "list_models", lambda self: [])
    backend = LocalBackend(base_url="http://localhost:1234/v1", model="auto")
    assert backend.model == "qwen2.5-coder:7b"


def test_local_omits_response_format_by_default(monkeypatch):
    monkeypatch.delenv("REWARDAUDIT_LOCAL_JSON_MODE", raising=False)
    backend = LocalBackend(base_url="http://localhost:1234/v1", model="m")
    body = backend._body(LLMRequest(system="s", user="u", json_mode=True))
    assert "response_format" not in body


def test_local_json_mode_can_be_enabled(monkeypatch):
    monkeypatch.setenv("REWARDAUDIT_LOCAL_JSON_MODE", "1")
    backend = LocalBackend(base_url="http://localhost:1234/v1", model="m")
    body = backend._body(LLMRequest(system="s", user="u", json_mode=True))
    assert body["response_format"] == {"type": "json_object"}
