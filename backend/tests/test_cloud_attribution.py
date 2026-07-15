from types import SimpleNamespace

import pytest

from agents.cloud_agent import CloudAgent


def test_s3_bucket_extraction_requires_observed_aws_hostname():
    assert CloudAgent._observed_s3_bucket("customer-assets.s3.amazonaws.com") == "customer-assets"
    assert CloudAgent._observed_s3_bucket("customer-assets.s3.ap-south-1.amazonaws.com") == "customer-assets"
    assert CloudAgent._observed_s3_bucket("public-www") is None
    assert CloudAgent._observed_s3_bucket("customer-assets.example.test") is None


@pytest.mark.asyncio
async def test_generic_or_domain_guessed_bucket_is_never_requested(monkeypatch):
    agent = object.__new__(CloudAgent)
    agent._findings = []
    requested: list[str] = []

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url):
            requested.append(url)
            return SimpleNamespace(status_code=200, text="<ListBucketResult />")

    monkeypatch.setattr("agents.cloud_agent.httpx_client.AsyncClient", lambda **_kwargs: FakeClient())
    checked = await agent._check_cloud_storage(
        "www.example.test",
        ["assets.example.test"],
        [{"url": "https://www.example.test/app.js"}],
    )

    assert checked == 0
    assert requested == []
    assert agent._findings == []

