import httpx
import pytest

from agents.recon import ReconAgent
from core.config import AppConfig


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
