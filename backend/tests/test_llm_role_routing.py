from types import SimpleNamespace

import pytest

from tools.llm_client import LLMClient, LLMResponse


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
