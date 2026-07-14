from core.live_log import redact_tool_log_line


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
