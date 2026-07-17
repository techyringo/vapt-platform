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

from worker.jobs import execute_tool, generate_report_studio, ping_worker, pull_tool_images, run_appsec_assessment

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
ARQ_QUEUE_NAME = os.environ.get("VAPT_ARQ_QUEUE", "vapt:tools")
ARQ_HEALTH_KEY = os.environ.get("VAPT_ARQ_HEALTH_KEY", f"{ARQ_QUEUE_NAME}:health")


def _effective_max_jobs() -> tuple[int, int, int]:
    """Return requested, safety ceiling and effective scanner concurrency.

    A stale local .env previously overrode the compose default and silently put
    the worker back at three memory-heavy scanners. The hard ceiling makes the
    safe laptop profile deterministic. A deliberately sized runner can raise
    both values explicitly.
    """
    requested = max(1, int(os.environ.get("WORKER_MAX_JOBS", "2")))
    hard_limit = max(1, int(os.environ.get("WORKER_MAX_JOBS_HARD_LIMIT", "2")))
    return requested, hard_limit, min(requested, hard_limit)


_REQUESTED_MAX_JOBS, _MAX_JOBS_HARD_LIMIT, _MAX_JOBS = _effective_max_jobs()


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

    if _REQUESTED_MAX_JOBS > _MAX_JOBS:
        logger.warning(
            "[worker:startup] Requested max_jobs={requested} capped at {effective} "
            "by WORKER_MAX_JOBS_HARD_LIMIT={limit}",
            requested=_REQUESTED_MAX_JOBS,
            effective=_MAX_JOBS,
            limit=_MAX_JOBS_HARD_LIMIT,
        )
    logger.info("[worker:startup] Worker ready (max_jobs={max})", max=_MAX_JOBS)


async def shutdown(ctx: dict) -> None:
    logger.info("[worker:shutdown] Worker shutting down")


class WorkerSettings:
    """ARQ worker configuration."""

    functions = [ping_worker, execute_tool, pull_tool_images, run_appsec_assessment, generate_report_studio]

    redis_settings = _hardened_redis_settings()

    # How many concurrent jobs this worker process handles.
    # Each job = one Docker container.  Keep under the host's container limit.
    # Scanner jobs are not ordinary HTTP tasks: each may own a browser, JVM,
    # nuclei process or large crawler result. Fifteen jobs per worker caused
    # queue connection resets and host pressure on the reference laptop.
    max_jobs = _MAX_JOBS

    # Max seconds a single job can run before ARQ forcibly cancels it.
    job_timeout = max(1800, int(os.environ.get("VAPT_ARQ_JOB_TIMEOUT", "7200")))

    # Allow the API/orchestrator to abort a *running* job via job.abort().
    # Without this, aborting only cancels not-yet-started jobs, and a slow tool
    # would keep running past the report barrier (the premature-report bug).
    allow_abort_jobs = True

    # Keep results longer than the largest normal queue wait + tool runtime.
    # Otherwise a completed result can disappear before a delayed API waiter
    # reads it, which looks exactly like a scanner timeout to the UI.
    keep_result = max(900, int(os.environ.get("VAPT_ARQ_KEEP_RESULT", "1800")))

    on_startup = startup
    on_shutdown = shutdown

    # Health-check: ARQ will log a warning if queue depth exceeds this.
    queue_name = ARQ_QUEUE_NAME
    health_check_interval = int(os.environ.get("VAPT_ARQ_HEALTH_INTERVAL", "10"))
    health_check_key = ARQ_HEALTH_KEY
