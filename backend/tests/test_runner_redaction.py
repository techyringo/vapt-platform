from tools.runner import ToolResult, redact_command


def test_redact_command_hides_api_id_env_assignment():
    rendered = redact_command([
        "docker",
        "run",
        "-e",
        "CENSYS_API_ID=censys_example",
        "-e",
        "SHODAN_API_KEY=shodan_example",
        "image",
    ])

    assert "censys_example" not in rendered
    assert "shodan_example" not in rendered
    assert "CENSYS_API_ID=<redacted>" in rendered
    assert "SHODAN_API_KEY=<redacted>" in rendered


def test_timed_out_tool_with_stdout_is_partial_evidence() -> None:
    result = ToolResult(
        tool_name="nuclei",
        exit_code=-1,
        stdout='{"template-id":"example"}\n',
        stderr="Tool timed out after 240 seconds",
        duration=240.0,
        timed_out=True,
    )

    assert result.success is False
    assert result.partial is True
    assert result.outcome == "partial"
    assert result.to_dict()["evidence_captured"] is True


def test_failed_tool_help_text_is_not_partial_evidence() -> None:
    result = ToolResult("tool", 2, "usage: tool [flags]", "bad flag", 0.1)

    assert result.partial is False
    assert result.outcome == "failed"


def test_nonzero_osint_exit_with_urls_preserves_partial_evidence() -> None:
    result = ToolResult(
        "gau", 1, "https://example.test/a\nhttps://example.test/b\n",
        "one upstream archive was unavailable", 12.0,
    )

    assert result.partial is True
    assert result.outcome == "partial"
    assert result.to_dict()["evidence_captured"] is True
