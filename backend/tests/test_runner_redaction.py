import sys
from pathlib import Path

import pytest

import tools.runner as runner_module
from core.live_log import tool_log_context
from database.store import PersistenceStore
from tools.runner import DockerRunner, ToolResult, redact_command


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


@pytest.mark.asyncio
async def test_tool_output_is_disk_first_and_memory_bounded(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(runner_module, "SHARED_DIR", str(tmp_path))
    monkeypatch.setenv("VAPT_TOOL_RESULT_MAX_BYTES", "65536")
    token = tool_log_context.set({"scan_id": "scan-1", "agent": "recon", "phase": "recon"})
    try:
        result = await DockerRunner._execute_command(
            "python",
            [sys.executable, "-c", 'import sys; sys.stdout.write("x"*100000)'],
            None,
            10,
        )
    finally:
        tool_log_context.reset(token)

    assert result.success is True
    assert result.stdout_truncated is True
    assert len(result.stdout.encode()) == 65536
    source = Path(result.stdout_artifact_path)
    assert source.stat().st_size == 100000

    store = PersistenceStore(f"sqlite:///{tmp_path / 'vapt.db'}")
    run = result.to_dict() | {"phase": "recon"}
    store.append_tool_run("scan-1", "recon", run)
    persisted = store.load_tool_runs("scan-1")[0]
    assert persisted["stdout_size"] == 100000
    assert Path(persisted["stdout_artifact_path"]).is_file()
    assert source.exists() is False
