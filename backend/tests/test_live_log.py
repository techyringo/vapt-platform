from core.live_log import classify_tool_log_level, prepare_tool_log_line, redact_tool_log_line


def test_redact_tool_log_line_hides_common_secret_assignments() -> None:
    rendered = redact_tool_log_line(
        "request api_key=super-secret token: bearer-value password=hunter2"
    )

    assert "super-secret" not in rendered
    assert "bearer-value" not in rendered
    assert "hunter2" not in rendered
    assert rendered.count("<redacted>") == 3


def test_redact_tool_log_line_hides_authorization_header_payload() -> None:
    rendered = redact_tool_log_line("Authorization: Bearer customer-token-value")

    assert "customer-token-value" not in rendered
    assert rendered == "Authorization: <redacted>"


def test_redact_tool_log_line_removes_nul_and_bounds_output() -> None:
    rendered = redact_tool_log_line("ok\x00" + ("x" * 3000))

    assert "\x00" not in rendered
    assert len(rendered) == 2000


def test_httpx_false_failed_field_is_compacted_and_not_error() -> None:
    rendered = prepare_tool_log_line(
        '{"url":"https://example.test","method":"GET","status_code":301,"failed":false,"tech":["Nginx"]}',
        "httpx",
    )

    assert rendered == "GET https://example.test → HTTP 301 · Nginx"
    assert classify_tool_log_level(rendered) == "info"


def test_katana_depth_noise_and_minified_body_are_not_streamed() -> None:
    depth = prepare_tool_log_line(
        '{"request":{"method":"GET","endpoint":"https://example.test/api"},"error":"max depth reached"}',
        "katana",
    )
    script = prepare_tool_log_line("function(e){" + ("x" * 1000), "katana")

    assert depth == ""
    assert script == ""


def test_structured_scanner_fragments_and_response_bodies_are_not_streamed() -> None:
    assert prepare_tool_log_line('"results": [', "semgrep") == ""
    assert prepare_tool_log_line("<html>" + ("x" * 900), "nuclei") == ""
    assert prepare_tool_log_line("Scanning 42 files", "semgrep") == "Scanning 42 files"
