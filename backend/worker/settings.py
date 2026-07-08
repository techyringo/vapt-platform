"""
ARQ worker settings.

Start workers with:
    python -m arq worker.settings.WorkerSettings

Or via docker-compose (the `worker` service already does this).
Scale horizontally:
    docker compose up --scale worker=4
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from loguru import logger

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.logging import configure_runtime_logging
from utils.env import normalize_api_key_aliases

normalize_api_key_aliases()
configure_runtime_logging()

from arq.connections import RedisSettings

from worker.jobs import execute_tool, ping_worker, pull_tool_images

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
ARQ_QUEUE_NAME = os.environ.get("VAPT_ARQ_QUEUE", "vapt:tools")
ARQ_HEALTH_KEY = os.environ.get("VAPT_ARQ_HEALTH_KEY", f"{ARQ_QUEUE_NAME}:health")


def _hardened_redis_settings() -> RedisSettings:
    """RedisSettings with bounded retries + timeout so a transient Redis blip
    reconnects instead of killing the worker with ConnectionResetError (Errno
    104). Attributes are set defensively across arq/redis-py versions."""
    settings = RedisSettings.from_dsn(REDIS_URL)
    for attr, value in (
        ("conn_timeout", 10),
        ("conn_retries", 5),
        ("conn_retry_delay", 1),
        ("max_connections", int(os.environ.get("VAPT_ARQ_MAX_CONNECTIONS", "50"))),
    ):
        if hasattr(settings, attr):
            try:
                setattr(settings, attr, value)
            except Exception:
                pass
    return settings


async def startup(ctx: dict) -> None:
    """Initialise per-worker shared state (runs once per worker process)."""
    from core.config import AppConfig
    from tools.runner import DockerRunner, validate_shared_dir

    # Load config
    config_path = Path(__file__).resolve().parent.parent / "config.yaml"
    try:
        config = AppConfig.load(config_path) if config_path.exists() else AppConfig()
    except Exception as exc:
        logger.warning("[worker:startup] Config load failed ({err}) — using defaults", err=exc)
        config = AppConfig()

    ctx["config"] = config
    # Workers consume queued jobs and must execute tools locally. If queueing is
    # left enabled here, a worker with REDIS_URL set re-enqueues the same job
    # instead of running the container/command.
    runner = DockerRunner(config, use_queue=False)
    ctx["runner"] = runner

    # Validate shared-dir so tool input-file failures are surfaced immediately.
    ok, msg = validate_shared_dir()
    if not ok:
        logger.error("[worker:startup] Shared-dir check FAILED: {msg}", msg=msg)
    else:
        logger.info("[worker:startup] Shared-dir OK")

    # Pre-pull Tier-1 images so the first scan doesn't stall on docker pull.
    if runner.docker_available:
        logger.info("[worker:startup] Pre-pulling Tier-1 tool images…")
        results = await runner.pull_required_images()
        ready = sum(1 for v in results.values() if v)
        logger.info(
            "[worker:startup] Images ready: {ready}/{total}",
            ready=ready,
            total=len(results),
        )
    else:
        logger.warning("[worker:startup] Docker unavailable — tools will run directly if installed")

    logger.info("[worker:startup] Worker ready (max_jobs={max})", max=os.environ.get("WORKER_MAX_JOBS", "15"))


async def shutdown(ctx: dict) -> None:
    logger.info("[worker:shutdown] Worker shutting down")


class WorkerSettings:
    """ARQ worker configuration."""

    functions = [ping_worker, execute_tool, pull_tool_images]

    redis_settings = _hardened_redis_settings()

    # How many concurrent jobs this worker process handles.
    # Each job = one Docker container.  Keep under the host's container limit.
    max_jobs = int(os.environ.get("WORKER_MAX_JOBS", "15"))

    # Max seconds a single job can run before ARQ forcibly cancels it.
    job_timeout = 1800  # 30 min

    # Allow the API/orchestrator to abort a *running* job via job.abort().
    # Without this, aborting only cancels not-yet-started jobs, and a slow tool
    # would keep running past the report barrier (the premature-report bug).
    allow_abort_jobs = True

    # How long to keep job results in Redis (seconds) for result() polling.
    keep_result = 600   # 10 min

    on_startup = startup
    on_shutdown = shutdown

    # Health-check: ARQ will log a warning if queue depth exceeds this.
    queue_name = ARQ_QUEUE_NAME
    health_check_interval = int(os.environ.get("VAPT_ARQ_HEALTH_INTERVAL", "10"))
    health_check_key = ARQ_HEALTH_KEY
