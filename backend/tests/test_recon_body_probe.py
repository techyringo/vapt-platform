import httpx
import pytest

from agents.recon import ReconAgent
from core.config import AppConfig
from tools.runner import ToolResult


class _Scope:
    @staticmethod
    def is_in_scope(_url: str) -> bool:
        return True


class _Client:
    is_closed = False

    async def get(self, url: str, **_kwargs):
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            request=request,
            headers={"content-type": "text/html", "server": "unit-test"},
            text="<html><title>Juice Shop</title><app-root></app-root></html>",
        )


@pytest.mark.asyncio
async def test_direct_probe_keeps_successful_body_evidence(monkeypatch):
    agent = ReconAgent(_Scope(), AppConfig())

    async def client():
        return _Client()

    monkeypatch.setattr(agent, "_get_http_client", client)
    technologies = {}
    results = await agent._direct_http_probe(["http://juice-shop:3000"], technologies)

    assert len(results) == 1
    assert results[0]["scheme"] == "http"
    assert results[0]["body_verified"] is True
    assert results[0]["body_usable"] is True
    assert results[0]["content_length"] > 0
    assert results[0]["body_sha256"]


@pytest.mark.asyncio
async def test_katana_runs_one_compatible_plain_output_crawl():
    agent = ReconAgent(_Scope(), AppConfig())
    calls = []

    class Runner:
        async def run(self, **kwargs):
            calls.append(kwargs)
            return ToolResult("katana", 0, "https://example.test/a\n", "", 1.0)

    agent._runner = Runner()
    urls = await agent._run_katana([{"url": "https://example.test"}])

    assert urls == ["https://example.test/a"]
    assert len(calls) == 1
    assert "-jsonl" not in calls[0]["args"]


@pytest.mark.asyncio
async def test_gau_retries_once_at_lower_concurrency_and_keeps_partial_urls():
    agent = ReconAgent(_Scope(), AppConfig())
    calls = []

    class Runner:
        async def run(self, **kwargs):
            calls.append(kwargs)
            if len(calls) == 1:
                return ToolResult("gau", 1, "", "temporary provider failure", 1.0)
            return ToolResult(
                "gau", 1, "https://example.test/from-archive\n",
                "one provider still unavailable", 1.0,
            )

    agent._runner = Runner()
    urls = await agent._run_gau("example.test")

    assert urls == ["https://example.test/from-archive"]
    assert len(calls) == 2
    first_threads = calls[0]["args"].index("--threads") + 1
    retry_threads = calls[1]["args"].index("--threads") + 1
    assert calls[0]["args"][first_threads] == "5"
    assert calls[1]["args"][retry_threads] == "2"
    assert [run["outcome"] for run in agent.get_tool_runs()] == ["failed", "partial"]
