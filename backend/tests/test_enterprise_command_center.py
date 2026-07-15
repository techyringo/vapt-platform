from types import SimpleNamespace

import pytest

from core.adaptive_planner import AdaptivePlanner
from core.asset_graph import AssetGraphBuilder, canonical_graph_projection, normalize_url
from core.assurance_coverage import build_assurance_coverage
from core.models import ScanPhase
from core.orchestrator import Orchestrator


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


def test_enum_ports_preserve_nmap_service_product_and_version():
    builder = AssetGraphBuilder("scan")
    builder.ingest_task_result(
        {
            "ports": {
                "example.test": [{
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "OpenSSH 9.2p1",
                }],
            },
        },
        "enum",
        "example.test",
    )
    assets, _ = builder.records()
    service = next(item for item in assets if item["asset_type"] == "service")

    assert service["value"] == "example.test:22/tcp"
    assert service["metadata"]["product"] == "OpenSSH"
    assert service["metadata"]["version"] == "OpenSSH 9.2p1"


def test_service_identity_merges_unknown_and_enriched_observations():
    builder = AssetGraphBuilder("scan")
    builder.add_asset("service", "example.test:22", "finding", metadata={"port": 22})
    builder.add_asset(
        "service", "example.test:22/ssh", "enum", "high",
        {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH"},
    )

    assets, _ = builder.records()
    services = [item for item in assets if item["asset_type"] == "service"]
    assert len(services) == 1
    assert services[0]["value"] == "example.test:22/tcp"
    assert services[0]["metadata"]["service"] == "ssh"


def test_nmap_port_evidence_activates_service_specific_planning_tokens():
    orchestrator = object.__new__(Orchestrator)
    orchestrator._phase_context = {
        "enum_data": {
            "ports": {
                "example.test": [{"port": 22, "service": "ssh"}],
            },
        },
    }
    orchestrator._evidence = set()

    orchestrator._ingest_evidence_from_phase_context(ScanPhase.ENUMERATION)

    assert "open_port" in orchestrator._evidence
    assert "service_banner" in orchestrator._evidence
    assert "ssh_open" in orchestrator._evidence


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


def test_wstg_projection_counts_typed_validator_execution():
    result = build_assurance_coverage(
        scan={"targets": ["example.test"]},
        assets=[{"asset_type": "parameter"}],
        actions=[],
        findings=[],
        validation_summary={
            "hypotheses_planned": 4,
            "hypotheses_tested": 2,
            "proofs_confirmed": 0,
            "validator_summary": {"sqli_error_boolean": {"not_confirmed": 2}},
            "validation_attempts": [],
        },
    )

    category = next(item for item in result["categories"] if item["category_id"] == "WSTG-INPV")
    assert category["status"] == "tested"
    assert category["executed_validators"] == ["sqli_error_boolean"]
    assert result["dynamic_validation"]["hypotheses_tested"] == 2
