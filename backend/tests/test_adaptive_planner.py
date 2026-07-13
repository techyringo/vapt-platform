from types import SimpleNamespace

import pytest

from core.adaptive_planner import AdaptivePlanner
from tools.llm_client import LLMResponse


def config():
    return SimpleNamespace(llm=SimpleNamespace(
        provider="openai_compat", model="planner", api_key_env="", api_key="",
        base_url="http://model", verify_ssl=True, max_tokens=512, max_rpm=40,
        temperature=0.1, analysis_model="planner", report_model="planner",
        review_model="planner", enabled=False, allow_fallbacks=False,
        fallback_providers=[],
    ))


@pytest.mark.asyncio
async def test_wordpress_evidence_makes_wordpress_capability_eligible(monkeypatch):
    monkeypatch.setattr("core.runtime_config.apply_runtime_llm_overlay", lambda value: value)
    planner = AdaptivePlanner(config())
    decision = await planner.plan(
        scan_id="scan-1",
        phase="vuln_scanning",
        evidence_tokens={"live_url", "tech_wordpress"},
        already_run=set(),
    )
    selected = {item["tool"] for item in decision["selected"]}
    assert "wpscan" in selected
    assert decision["policy"]["arbitrary_commands_allowed"] is False
    assert decision["policy"]["decision_authority"] == "deterministic_engagement_policy"
    assert decision["execution"]["automatically_executed"] is False
    assert decision["status"] == "recommended"


@pytest.mark.asyncio
async def test_model_cannot_introduce_unapproved_tool(monkeypatch):
    monkeypatch.setattr("core.runtime_config.apply_runtime_llm_overlay", lambda value: value)
    planner = AdaptivePlanner(config())

    class FakeLLM:
        def get_available_providers(self):
            return ["fake"]

        async def complete(self, *args, **kwargs):
            return LLMResponse(
                content='{"selected":[{"tool":"evil-installer","reason":"download it"},{"tool":"wpscan","reason":"WordPress evidence"}]}',
                provider="fake", model="fake",
            )

    planner._llm = FakeLLM()
    decision = await planner.plan(
        scan_id="scan-1",
        phase="vuln_scanning",
        evidence_tokens={"live_url", "tech_wordpress"},
        already_run=set(),
    )
    assert [item["tool"] for item in decision["selected"]] == ["wpscan"]
