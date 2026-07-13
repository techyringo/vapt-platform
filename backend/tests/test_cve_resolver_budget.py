from types import SimpleNamespace

import pytest

from core.models import AgentType, Finding, Severity, Target
from tools.cve_resolver import CVEResolver


class FakeLLM:
    def __init__(self):
        self.calls = 0

    def get_available_providers(self):
        return ["nvidia"]

    async def analyze(self, *args, **kwargs):
        self.calls += 1
        return {"proposals": [{"identifier": "CWE-79", "kind": "cwe"}]}


def finding():
    return Finding(
        title="Missing header",
        description="Header proof",
        severity=Severity.LOW,
        agent_source=AgentType.VULN_SCANNER,
        target=Target(host="example.test"),
        evidence="HTTP response header evidence",
    )


@pytest.mark.asyncio
async def test_per_finding_llm_cve_proposals_are_disabled_by_default(monkeypatch):
    monkeypatch.delenv("VAPT_CVE_LLM_PROPOSALS", raising=False)
    llm = FakeLLM()
    nvd = SimpleNamespace()
    resolver = CVEResolver(llm, nvd)
    await resolver.enrich(finding())
    assert llm.calls == 0


@pytest.mark.asyncio
async def test_llm_cve_proposals_can_be_explicitly_enabled(monkeypatch):
    monkeypatch.setenv("VAPT_CVE_LLM_PROPOSALS", "true")
    llm = FakeLLM()
    resolver = CVEResolver(llm, SimpleNamespace())
    item = finding()
    await resolver.enrich(item)
    assert llm.calls == 1
    assert item.cwe_ids == ["CWE-79"]
