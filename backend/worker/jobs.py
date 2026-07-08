"""
ARQ job definitions — these run inside the worker process, completely
isolated from the FastAPI event loop.  The backend enqueues jobs via
DockerRunner.run(); the worker executes them and returns the result dict.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Optional

from loguru import logger

# Make backend package importable regardless of CWD
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


async def ping_worker(ctx: dict[str, Any]) -> dict[str, Any]:
    """Lightweight queue health probe used by the API before submitting tools."""
    return {"ok": True}


async def execute_tool(
    ctx: dict[str, Any],
    tool_name: str,
    args: list[str],
    input_data: Optional[str] = None,
    timeout: Optional[int] = None,
    env: Optional[dict[str, str]] = None,
    cwd: Optional[str] = None,
    log_context: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Execute a security tool inside a Docker container (or directly).

    This is the primary ARQ job.  The worker process has a long-lived
    DockerRunner in ``ctx["runner"]`` — no per-job overhead of building
    the runner or checking Docker availability.

    Args:
        ctx:        ARQ context dict injected by the worker.
        tool_name:  Name of the tool (must match config.yaml entry).
        args:       CLI arguments to pass to the tool.
        input_data: Optional stdin data.
        timeout:    Override the configured timeout (seconds).
        env:        Additional environment variables for the container.
        cwd:        Working directory override.

    Returns:
        Serialised ``ToolResult.to_dict()`` dict.
    """
    from tools.runner import DockerRunner, redact_command
    from core.live_log import tool_log_context

    # Re-establish the live-log context inside the worker process so the tool's
    # output is streamed to the API's SSE clients with the right scan/agent tag.
    if log_context:
        tool_log_context.set(dict(log_context))

    runner: DockerRunner = ctx.get("runner")
    if runner is None:
        # Fallback: build a fresh runner from config in context
        from core.config import AppConfig
        config: AppConfig = ctx.get("config") or AppConfig()
        runner = DockerRunner(config, use_queue=False)

    logger.info(
        "[worker] Executing tool={tool} cmd={cmd}",
        tool=tool_name,
        cmd=redact_command([tool_name, *args]),
    )
    try:
        result = await runner.run_local(
            tool_name=tool_name,
            args=args,
            input_data=input_data,
            timeout=timeout,
            env=env,
            cwd=cwd,
        )
        return result.to_dict()
    except Exception as exc:
        logger.error("[worker] Tool {tool} raised: {err}", tool=tool_name, err=exc)
        return {
            "tool": tool_name,
            "exit_code": -1,
            "success": False,
            "duration": 0.0,
            "timed_out": False,
            "stdout": "",
            "stderr": str(exc),
        }


async def pull_tool_images(
    ctx: dict[str, Any],
    images: Optional[list[str]] = None,
) -> dict[str, bool]:
    """Pull a list of Docker images on a worker node.

    Enqueue this job once at startup (or on demand) to warm the local
    image cache before scans start.
    """
    from tools.runner import DockerRunner, TIER1_IMAGES

    runner: DockerRunner = ctx.get("runner")
    if runner is None:
        from core.config import AppConfig
        runner = DockerRunner(ctx.get("config") or AppConfig(), use_queue=False)

    targets = images or TIER1_IMAGES
    return await runner.pull_required_images(targets)
