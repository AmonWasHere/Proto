from rewardaudit.llm.base import LLMRequest
from rewardaudit.llm.openai_compat import OpenAICompatibleBackend


def test_body_includes_extra_and_omits_temperature_when_thinking_disabled():
    backend = OpenAICompatibleBackend(
        base_url="https://x/v1",
        model="deepseek-flash",
        extra_body={"thinking": {"type": "disabled"}},
    )
    body = backend._body(LLMRequest(system="s", user="u", temperature=0.3, json_mode=True))
    assert body["thinking"] == {"type": "disabled"}
    assert "temperature" not in body  # thinking-mode providers ignore it
    assert body["response_format"] == {"type": "json_object"}
    assert body["model"] == "deepseek-flash"


def test_body_keeps_temperature_without_thinking_toggle():
    backend = OpenAICompatibleBackend(base_url="https://x/v1", model="m")
    body = backend._body(LLMRequest(system="s", user="u", temperature=0.3, json_mode=False))
    assert body["temperature"] == 0.3
    assert "response_format" not in body


def test_from_env_no_thinking(monkeypatch):
    monkeypatch.setenv("REWARDAUDIT_NO_THINKING", "1")
    backend = OpenAICompatibleBackend.from_env()
    assert backend.extra_body["thinking"]["type"] == "disabled"


def test_from_env_extra_json(monkeypatch):
    monkeypatch.setenv("REWARDAUDIT_LLM_EXTRA_JSON", '{"reasoning_effort": "low"}')
    backend = OpenAICompatibleBackend.from_env()
    assert backend.extra_body["reasoning_effort"] == "low"
