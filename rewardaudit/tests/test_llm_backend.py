from rewardaudit.llm.openai_compat import OpenAICompatibleBackend


def test_retry_delay_honours_retry_after_header():
    backend = OpenAICompatibleBackend(base_url="http://x/v1", model="m", backoff_base=1.0)
    assert backend._delay(0, "", {"Retry-After": "7"}) == 7
    assert backend._delay(0, "", {"Retry-After": "abc"}) == 1


def test_retry_delay_parses_detail_hint():
    backend = OpenAICompatibleBackend(base_url="http://x/v1", model="m", backoff_base=1.0)
    # "3.525s" -> 4.025, within the cap
    assert 3.9 <= backend._delay(0, "try again in 3.525s", None) <= 4.1


def test_retry_delay_is_capped():
    backend = OpenAICompatibleBackend(base_url="http://x/v1", model="m", backoff_base=10.0)
    assert backend._delay(5, "", None) == 60.0


def test_backend_constructs_from_env(monkeypatch):
    monkeypatch.setenv("REWARDAUDIT_LLM_BASE_URL", "https://api.example/v1")
    monkeypatch.setenv("REWARDAUDIT_LLM_MODEL", "some-model")
    monkeypatch.setenv("REWARDAUDIT_LLM_API_KEY", "secret")
    backend = OpenAICompatibleBackend.from_env()
    assert backend.base_url == "https://api.example/v1"
    assert backend.model == "some-model"
    assert backend.api_key == "secret"
