from types import SimpleNamespace

import pytest

from tools.llm_client import (
    LLMClient, LLMResponse, _GLOBAL_PROVIDER_COOLDOWNS, _GLOBAL_RATE_WINDOWS,
    _bearer_token,
)


@pytest.fixture(autouse=True)
def reset_process_wide_llm_state():
    """Keep shared limiter/circuit state from leaking between unit tests."""
    _GLOBAL_RATE_WINDOWS.clear()
    _GLOBAL_PROVIDER_COOLDOWNS.clear()
    yield
    _GLOBAL_RATE_WINDOWS.clear()
    _GLOBAL_PROVIDER_COOLDOWNS.clear()


def _config():
    llm = SimpleNamespace(
        provider="openai_compat",
        model="Qwen/Qwen2.5-32B-Instruct-AWQ",
        api_key_env="",
        api_key="",
        base_url="http://gpu:8000",
        verify_ssl=True,
        max_tokens=1024,
        temperature=0.1,
        analysis_model="qwen3:8b",
        report_model="Qwen/Qwen2.5-32B-Instruct-AWQ",
        review_model="llama3.2",
        enabled=True,
        allow_fallbacks=True,
        fallback_providers=[
            {"provider": "ollama", "model": "qwen3:8b", "base_url": "http://mac:11434"},
            {
                "provider": "http_basic_chat", "model": "llama3.2",
                "base_url": "https://cpu:8443", "api_key": "user:test", "verify_ssl": False,
            },
        ],
    )
    return SimpleNamespace(llm=llm)


def test_bearer_token_accepts_raw_or_prefixed_keys():
    assert _bearer_token(" nvapi-test ") == "nvapi-test"
    assert _bearer_token("Bearer nvapi-test") == "nvapi-test"


def test_rate_limit_is_shared_and_reserves_failed_attempts():
    first = LLMClient(_config())
    second = LLMClient(_config())
    key = "openai_compat:https://integrate.api.nvidia.com"
    assert first._reserve_rate_limit(key, 2) is True
    assert second._reserve_rate_limit(key, 2) is True
    assert first._reserve_rate_limit(key, 2) is False


@pytest.mark.asyncio
async def test_auth_failure_opens_shared_provider_circuit(monkeypatch):
    monkeypatch.setattr("core.runtime_config.apply_runtime_llm_overlay", lambda config: config)
    client = LLMClient(_config())
    calls = 0

    async def unauthorized(**kwargs):
        nonlocal calls
        calls += 1
        return LLMResponse(content="", provider="openai_compat", model="m", error="HTTP 401: Unauthorized")

    client._call_provider = unauthorized
    await client.complete("first auth failure", use_fallback=False)
    await client.complete("second call is blocked", use_fallback=False)
    assert calls == 1


@pytest.mark.asyncio
async def test_each_role_uses_endpoint_that_serves_its_model(monkeypatch):
    monkeypatch.setattr("core.runtime_config.apply_runtime_llm_overlay", lambda config: config)
    client = LLMClient(_config())
    calls = []

    async def fake_call(**kwargs):
        pc = kwargs["pc"]
        calls.append((pc.provider.value, kwargs["model"]))
        return LLMResponse(content='{"ok": true}', provider=pc.provider.value, model=kwargs["model"])

    client._call_provider = fake_call
    await client.complete("triage", task="triage")
    await client.complete("write report", task="report")
    await client.complete("challenge evidence", task="dual_review")

    assert calls == [
        ("ollama", "qwen3:8b"),
        ("openai_compat", "Qwen/Qwen2.5-32B-Instruct-AWQ"),
        ("http_basic_chat", "llama3.2"),
    ]


@pytest.mark.asyncio
async def test_failed_role_endpoint_falls_back_with_provider_native_model(monkeypatch):
    monkeypatch.setattr("core.runtime_config.apply_runtime_llm_overlay", lambda config: config)
    client = LLMClient(_config())
    calls = []

    async def fake_call(**kwargs):
        pc = kwargs["pc"]
        calls.append((pc.provider.value, kwargs["model"]))
        if pc.provider.value == "ollama":
            return LLMResponse(content="", provider="ollama", model=kwargs["model"], error="offline")
        return LLMResponse(content="ok", provider=pc.provider.value, model=kwargs["model"])

    client._call_provider = fake_call
    result = await client.complete("triage unique fallback", task="triage")

    assert result.provider == "openai_compat"
    assert calls[:2] == [
        ("ollama", "qwen3:8b"),
        ("openai_compat", "Qwen/Qwen2.5-32B-Instruct-AWQ"),
    ]
