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


def test_jwt_header_decoder_detects_alg_none_header():
    token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ."

    header = DASTValidator._decode_jwt_header(token)

    assert header == {"alg": "none", "typ": "JWT"}
