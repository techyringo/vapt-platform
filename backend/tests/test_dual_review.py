from types import SimpleNamespace

import pytest

from core.dual_review import DISAGREE_TAG, dual_review


class FakeResponse:
    model = "reviewer"

    def json_content(self):
        return {
            "verdicts": [
                {"id": 0, "valid": True, "confidence": "high", "reasoning": "Replay proof supports it."},
                {"id": 1, "valid": False, "confidence": "low", "reasoning": "No response proof."},
                {"id": 0, "valid": "false", "confidence": "high", "reasoning": "Wrong type."},
                {"id": 999, "valid": True, "confidence": "high", "reasoning": "Invented id."},
            ],
        }


class FakeLLM:
    def __init__(self):
        self.calls = 0

    async def complete(self, **kwargs):
        self.calls += 1
        assert kwargs["task"] == "dual_review"
        return FakeResponse()


class FakeFinding:
    def __init__(self, title: str):
        self.title = title
        self.severity = SimpleNamespace(value="high")
        self.tags = []
        self.confidence = "high"
        self.llm_reasoning = {}

    def to_report_dict(self):
        return {
            "title": self.title,
            "severity": "high",
            "description": "Description",
            "evidence": "Evidence",
            "request_proof": "GET /",
            "response_proof": "HTTP/1.1 200 OK",
            "cve_ids": [],
        }


@pytest.mark.asyncio
async def test_dual_review_batches_findings_and_rejects_unknown_ids(monkeypatch):
    monkeypatch.setenv("VAPT_LLM_REVIEW_BATCH_SIZE", "8")
    findings = [FakeFinding("one"), FakeFinding("two")]
    llm = FakeLLM()

    result = await dual_review(findings, llm)

    assert llm.calls == 1
    assert result == {"reviewed": 2, "disagreed": 1}
    assert DISAGREE_TAG not in findings[0].tags
    assert DISAGREE_TAG in findings[1].tags
    assert findings[1].confidence == "low"
