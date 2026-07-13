from types import SimpleNamespace

from core.http_evidence import (
    equivalent_to_baseline,
    fingerprint_response,
    validate_api_response,
    validate_sensitive_response,
)


def response(body: bytes, content_type: str = "text/html", status: int = 200):
    return SimpleNamespace(
        content=body,
        text=body.decode("utf-8", errors="replace"),
        status_code=status,
        headers={"content-type": content_type},
    )


def test_spa_fallback_is_rejected_for_sensitive_file():
    shell = response(b"<html><app-root></app-root><script src='main.js'></script></html>")
    baseline = fingerprint_response(shell)
    outcome = validate_sensitive_response(".env", shell, baseline)
    assert outcome.confirmed is False
    assert outcome.category == "soft_404"


def test_real_env_requires_distinct_non_html_body():
    baseline = fingerprint_response(response(b"<html>not found</html>"))
    env = response(b"NODE_ENV=production\nDATABASE_URL=postgres://db\n", "text/plain")
    outcome = validate_sensitive_response(".env", env, baseline)
    assert outcome.confirmed is True
    assert outcome.category == "environment"


def test_api_version_rejects_spa_and_accepts_json():
    baseline = fingerprint_response(response(b"<html>app shell</html>"))
    assert validate_api_response(response(b"<html>app shell</html>"), baseline).confirmed is False
    api = response(b'{"status":"ok"}', "application/json")
    assert validate_api_response(api, baseline).confirmed is True


def test_near_identical_soft_404_is_rejected():
    baseline = fingerprint_response(response(b"<html>route not found request=1111</html>"))
    candidate = fingerprint_response(response(b"<html>route not found request=2222</html>"))
    assert equivalent_to_baseline(candidate, baseline) is True
