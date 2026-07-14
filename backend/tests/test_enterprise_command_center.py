from types import SimpleNamespace

import pytest

from core.adaptive_planner import AdaptivePlanner
from core.asset_graph import AssetGraphBuilder, canonical_graph_projection, normalize_url
from core.assurance_coverage import build_assurance_coverage


def _config():
    return SimpleNamespace(llm=SimpleNamespace(
        provider="", model="", api_key_env="", api_key="", base_url="",
        verify_ssl=True, max_tokens=512, max_rpm=40, temperature=0.1,
        analysis_model="", report_model="", review_model="", enabled=False,
        allow_fallbacks=False, fallback_providers=[],
    ))


def test_endpoint_identity_removes_values_tracking_and_dynamic_ids():
    first = normalize_url("https://EXAMPLE.test:443/api/users/12345?utm_source=x&role=admin#fragment")
    second = normalize_url("https://example.test/api/users/67890?role=user")

    assert first == "https://example.test/api/users/{id}?role=%7Bvalue%7D"
    assert first == second
    assert normalize_url("https://example.test/\\bad") == ""


def test_legacy_asset_projection_collapses_crawler_variants():
    builder = AssetGraphBuilder("scan")
    builder.add_url("https://example.test/product/10000?color=red", "katana")
    assets, edges = builder.records()
    url_asset = next(item for item in assets if item["asset_type"] == "url")
    legacy = {
        **url_asset,
        "asset_key": "legacy",
        "value": "https://example.test/product/99999?color=blue&utm_source=x",
    }
    projected, _ = canonical_graph_projection([*assets, legacy], edges)
    urls = [item for item in projected if item["asset_type"] == "url"]

    assert len(urls) == 1
    assert urls[0]["metadata"]["observation_count"] >= 2


@pytest.mark.asyncio
async def test_planner_never_recommends_runtime_blocked_registry_tool():
    planner = AdaptivePlanner(_config())
    decision = await planner.plan(
        scan_id="scan", phase="enumeration", evidence_tokens={"live_url"},
        already_run=set(), available_tools={"whatweb"},
    )

    assert {item["tool"] for item in decision["selected"]} == {"whatweb"}
    assert decision["policy"]["runtime_intersection_applied"] is True


def test_wstg_projection_separates_observed_from_tested():
    result = build_assurance_coverage(
        scan={"targets": ["example.test"]},
        assets=[{"asset_type": "url"}, {"asset_type": "parameter"}],
        actions=[{"tool": "httpx", "status": "completed"}],
        findings=[],
    )
    statuses = {item["category_id"]: item["status"] for item in result["categories"]}

    assert statuses["WSTG-INFO"] == "tested"
    assert statuses["WSTG-INPV"] == "observed"
    assert statuses["WSTG-BUSL"] == "not_tested"
    assert result["claim"] == "testing_coverage_only"
