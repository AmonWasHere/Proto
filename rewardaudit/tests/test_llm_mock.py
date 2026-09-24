import json

from rewardaudit.llm.mock import MockBackend
from rewardaudit.llm.base import LLMRequest


def test_mock_returns_scripted_responses():
    backend = MockBackend(responses=["a", "b"])
    assert backend.complete(LLMRequest(system="", user="1")).text == "a"
    assert backend.complete(LLMRequest(system="", user="2")).text == "b"
    # exhausted -> default
    assert "unknown_risk" in backend.complete(LLMRequest(system="", user="3")).text


def test_mock_responder_callable():
    backend = MockBackend(responder=lambda req: f"echo:{req.user}")
    assert backend.complete(LLMRequest(system="", user="hi")).text == "echo:hi"
    assert backend.requests[0].user == "hi"


def test_mock_default_is_valid_json():
    backend = MockBackend()
    payload = json.loads(backend.complete(LLMRequest(system="", user="1")).text)
    assert payload["disposition"] == "unknown_risk"
