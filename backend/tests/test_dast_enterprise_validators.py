from core.dast_planner import DASTPlanner
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
