from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from core.dast_planner import DASTHypothesis, DASTPlanner, InputCandidate
from core.dast_validators import DASTValidator


def test_planner_adds_resource_and_response_hypotheses():
    planner = DASTPlanner()
    candidates = planner.collect_candidates(
        recon_data={
            "live_urls": [{"url": "https://example.com/"}],
            "crawled_urls": ["https://example.com/static/app.js"],
        }
    )

    hypotheses = planner.build_hypotheses(candidates)
    validators = {item.validator for item in hypotheses}

    assert "sourcemap_exposure" in validators
    assert "jwt_alg_none" in validators


def test_planner_turns_arjun_and_js_discovery_into_testable_inputs():
    planner = DASTPlanner()
    candidates = planner.collect_candidates(
        recon_data={"live_urls": [{"url": "https://example.com/app"}]},
        enum_data={
            "parameters": [{"url": "https://example.com/search", "parameters": ["q", "page"]}],
            "js_endpoints": ["/api/users"],
        },
    )

    by_parameter = {item.parameter: item for item in candidates}
    assert by_parameter["q"].source == "parameter_discovery"
    assert "q=vapt-baseline" in by_parameter["q"].url
    assert any(item.url == "https://example.com/api/users" for item in candidates)


def test_large_crawl_cannot_starve_discovered_input_validators():
    planner = DASTPlanner()
    candidates = planner.collect_candidates(
        recon_data={
            "live_urls": [{"url": "https://example.com/"}],
            "crawled_urls": [
                *[f"https://example.com/content/{index}" for index in range(250)],
                "https://example.com/search?q=needle&id=7",
            ],
        },
        enum_data={
            "parameters": [{"url": "https://example.com/fetch", "parameters": ["url"]}],
        },
    )
    hypotheses = planner.build_hypotheses(candidates)
    validators = {(item.validator, item.candidate.parameter) for item in hypotheses}

    assert ("sqli_error_boolean", "q") in validators
    assert ("sqli_error_boolean", "id") in validators
    assert ("ssrf_http_oob", "url") in validators
    assert sum(1 for item in candidates if item.parameter == "__response__") <= 12


def test_jwt_header_decoder_detects_alg_none_header():
    token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ."

    header = DASTValidator._decode_jwt_header(token)

    assert header == {"alg": "none", "typ": "JWT"}


def test_planner_selects_oob_ssrf_for_url_inputs():
    planner = DASTPlanner()
    candidates = planner.collect_candidates(
        recon_data={"live_urls": [{"url": "https://example.com/fetch?url=https://example.org"}]},
    )

    hypotheses = planner.build_hypotheses(candidates)

    assert any(item.validator == "ssrf_http_oob" and item.candidate.parameter == "url" for item in hypotheses)


@pytest.mark.asyncio
async def test_sqli_validator_requires_paired_boolean_negative_control(monkeypatch):
    validator = DASTValidator()
    hypothesis = DASTHypothesis(
        id="hyp_0001",
        vuln_type="sqli",
        validator="sqli_error_boolean",
        candidate=InputCandidate(
            id="inp_0001",
            url="https://example.test/items?id=1",
            method="GET",
            parameter="id",
            value="1",
            source="parameter_discovery",
        ),
        reason="ID parameter may reach SQL query logic.",
    )

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def get(self, url):
            value = parse_qs(urlparse(url).query).get("id", [""])[0]
            if "AND '1'='2" in value:
                body = "No matching inventory records"
            else:
                body = "Inventory record 1: widget available"
            return httpx.Response(200, request=httpx.Request("GET", url), text=body)

    monkeypatch.setattr(validator, "_client", lambda **_kwargs: Client())
    proof = await validator._validate_sqli(hypothesis)

    assert proof is not None
    assert proof.confirmed is True
    assert "boolean-differential" in proof.tags
    assert "NEGATIVE CONTROL" in proof.request_proof


def test_response_similarity_is_bounded_and_whitespace_stable():
    assert DASTValidator._response_similarity("hello   world", "hello\nworld") == 1.0
    assert DASTValidator._response_similarity("allow", "deny") < 0.72


@pytest.mark.asyncio
async def test_validation_ledger_keeps_negative_and_skipped_outcomes(monkeypatch):
    validator = DASTValidator()
    hypotheses = [
        DASTHypothesis(
            id="hyp_sqli", vuln_type="sqli", validator="sqli_error_boolean",
            candidate=InputCandidate(
                id="inp_sqli", url="https://example.test/items?id=1", method="GET",
                parameter="id", value="1", source="parameter_discovery",
            ),
            reason="Test SQL handling.",
        ),
        DASTHypothesis(
            id="hyp_ssrf", vuln_type="ssrf", validator="ssrf_http_oob",
            candidate=InputCandidate(
                id="inp_ssrf", url="https://example.test/fetch?url=https://example.org", method="GET",
                parameter="url", value="https://example.org", source="crawler",
            ),
            reason="Test server-side fetch behavior.",
        ),
    ]

    async def no_proof(_hypothesis):
        return None

    monkeypatch.setattr(validator, "validate", no_proof)
    proofs = await validator.validate_many(hypotheses, max_checks=2, concurrency=2)

    assert proofs == []
    outcomes = {item["hypothesis_id"]: item for item in validator.attempts}
    assert outcomes["hyp_sqli"]["status"] == "not_confirmed"
    assert outcomes["hyp_ssrf"]["status"] == "skipped"
    assert "OOB callback" in outcomes["hyp_ssrf"]["reason"]
