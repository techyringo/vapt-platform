"""
VAPT Platform — Docker Tool Runner

Executes security tools inside isolated Docker containers, captures output,
and enforces timeouts/memory limits.

Architecture
------------
When REDIS_URL is set (production), DockerRunner.run() submits the job to the
ARQ worker queue instead of executing inline.  This decouples tool execution
from the FastAPI/orchestrator event loop so long-running scans (nmap, nuclei)
never block API responses or SSE delivery.

When REDIS_URL is unset (dev / local), tools run directly — same behaviour as
the original implementation.

Shared-dir contract
--------------------
The backend writes tool input files (wordlists, target lists) to VAPT_SHARED_DIR
(/tmp/vapt-shared inside the container).  Tool containers launched via docker.sock
must mount the same directory using the HOST-side path (VAPT_SHARED_HOST_DIR).
Call validate_shared_dir() at startup to catch misconfiguration early.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from loguru import logger

from core.config import AppConfig, ToolConfig
from core.job_tracker import JOB_TRACKER, current_scan_id
from core.live_log import LineThrottler, publish_tool_log, tool_log_context

try:
    from utils.env import normalize_api_key_aliases

    normalize_api_key_aliases()
except Exception:
    pass

# ─── Shared-dir paths ────────────────────────────────────────────────────────

SHARED_DIR = os.environ.get("VAPT_SHARED_DIR", "/tmp/vapt-shared")
HOST_SHARED_DIR = os.environ.get("VAPT_SHARED_HOST_DIR", SHARED_DIR)
CONTAINER_SHARED_DIR = "/tmp/vapt-shared"
WORDLIST_DIR = os.environ.get("VAPT_WORDLIST_DIR", "/app/wordlists")
HOST_WORDLIST_DIR = os.environ.get(
    "VAPT_WORDLIST_HOST_DIR",
    str(Path(__file__).resolve().parent.parent / "wordlists"),
)
CONTAINER_WORDLIST_DIR = "/wordlists"
ARQ_QUEUE_NAME = os.environ.get("VAPT_ARQ_QUEUE", "vapt:tools")
ARQ_HEALTH_KEY = os.environ.get("VAPT_ARQ_HEALTH_KEY", f"{ARQ_QUEUE_NAME}:health")

# ─── Tier-1 images — pre-pulled on worker startup ────────────────────────────

TIER1_IMAGES: list[str] = [
    "projectdiscovery/subfinder:latest",
    "projectdiscovery/httpx:latest",
    "projectdiscovery/dnsx:latest",
    "projectdiscovery/naabu:latest",
    "projectdiscovery/katana:latest",
    "projectdiscovery/tlsx:latest",
    "instrumentisto/nmap:latest",
    "ghcr.io/sullo/nikto:latest",
    "wpscanteam/wpscan:latest",
]

# ─── Global semaphore — cap concurrent docker containers ─────────────────────
# Lazily initialised on first use inside a running event loop.
_docker_semaphore: Optional[asyncio.Semaphore] = None
_MAX_CONCURRENT_CONTAINERS = int(os.environ.get("MAX_CONCURRENT_CONTAINERS", "12"))
_worker_ping_lock: Optional[asyncio.Lock] = None
_worker_ok_until = 0.0
_worker_fail_until = 0.0

# ─── Cached ARQ pool ─────────────────────────────────────────────────────────
# Previously every tool run did `async with await arq.create_pool(...)`, which
# opened and tore down a fresh Redis connection pool per job. Under high queue
# load that connection churn caused `ConnectionResetError: [Errno 104]`. We now
# keep one long-lived pool per event loop with retry + keepalive tuning.
_arq_pool: Any = None
_arq_pool_loop: Any = None
_arq_pool_lock: Optional[asyncio.Lock] = None
_ARQ_MAX_CONNECTIONS = int(os.environ.get("VAPT_ARQ_MAX_CONNECTIONS", "50"))


def _get_semaphore() -> asyncio.Semaphore:
    global _docker_semaphore
    if _docker_semaphore is None:
        _docker_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_CONTAINERS)
    return _docker_semaphore


def _get_worker_ping_lock() -> asyncio.Lock:
    global _worker_ping_lock
    if _worker_ping_lock is None:
        _worker_ping_lock = asyncio.Lock()
    return _worker_ping_lock


def _build_redis_settings(redis_url: str) -> Any:
    """Build hardened ARQ RedisSettings from a DSN.

    Adds bounded connection retries, a connection timeout, socket keepalive and
    a max-connection ceiling so transient Redis blips recover instead of
    crashing the worker with a reset-by-peer. Attributes are set defensively
    because the exact field set varies across arq/redis-py versions.
    """
    from arq.connections import RedisSettings

    settings = RedisSettings.from_dsn(redis_url)
    for attr, value in (
        ("conn_timeout", 10),
        ("conn_retries", 5),
        ("conn_retry_delay", 1),
        ("max_connections", _ARQ_MAX_CONNECTIONS),
    ):
        if hasattr(settings, attr):
            try:
                setattr(settings, attr, value)
            except Exception:
                pass
    return settings


async def _get_arq_pool(redis_url: str) -> Any:
    """Return a cached ARQ pool for the current event loop, creating it once.

    The pool is intentionally never closed per-call — closing/recreating it on
    every tool run was the source of the connection-reset crashes. It is rebuilt
    only if the event loop changes (e.g. across test cases) or if it was lost.
    """
    global _arq_pool, _arq_pool_loop, _arq_pool_lock
    import arq

    loop = asyncio.get_running_loop()
    if _arq_pool is not None and _arq_pool_loop is loop:
        return _arq_pool

    if _arq_pool_lock is None:
        _arq_pool_lock = asyncio.Lock()

    async with _arq_pool_lock:
        if _arq_pool is not None and _arq_pool_loop is loop:
            return _arq_pool
        # Drop a stale pool bound to a dead loop without awaiting close on it.
        _arq_pool = await arq.create_pool(_build_redis_settings(redis_url))
        _arq_pool_loop = loop
        logger.info("[worker] Created shared ARQ pool (max_connections={n})", n=_ARQ_MAX_CONNECTIONS)
        return _arq_pool


# ─── Shared-dir helpers ───────────────────────────────────────────────────────

def ensure_shared_dir() -> Path:
    """Create the shared temp dir if it doesn't exist. Returns its Path."""
    p = Path(SHARED_DIR)
    try:
        p.mkdir(parents=True, exist_ok=True)
    except OSError:
        p = Path(tempfile.gettempdir()) / "vapt-shared"
        p.mkdir(parents=True, exist_ok=True)
    return p


def shared_temp_path(suffix: str = ".txt", prefix: str = "vapt_") -> str:
    """Return a path inside the shared dir suitable for an input file."""
    ensure_shared_dir()
    fd, host_path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=SHARED_DIR)
    os.close(fd)
    return host_path


def host_to_container(host_path: str) -> str:
    """Translate a host-side shared path to its in-container equivalent."""
    try:
        rel = os.path.relpath(host_path, SHARED_DIR)
        return os.path.join(CONTAINER_SHARED_DIR, rel)
    except ValueError:
        return host_path


def validate_shared_dir() -> tuple[bool, str]:
    """Validate the shared-dir setup and return (ok, message).

    Checks:
    1. VAPT_SHARED_DIR exists and is writable.
    2. VAPT_SHARED_HOST_DIR is configured as an absolute host-side path when
       Docker sibling containers are used.

    Call this at startup to surface misconfiguration before any scan starts.
    """
    shared = Path(SHARED_DIR)
    try:
        shared.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return False, f"Cannot create VAPT_SHARED_DIR {shared}: {exc}"

    # Write a canary file to verify it's writable.
    canary = shared / ".vapt_healthcheck"
    try:
        canary.write_text("ok", encoding="utf-8")
        canary.unlink()
    except OSError as exc:
        return False, f"VAPT_SHARED_DIR {shared} is not writable: {exc}"

    # Check host path configuration. Inside Docker, the host-side absolute path
    # is not normally visible in the backend container namespace, so
    # Path(HOST_SHARED_DIR).exists() can be false even when the Docker daemon can
    # mount it correctly for sibling tool containers.
    host = Path(HOST_SHARED_DIR)
    if not host.is_absolute():
        return False, (
            f"VAPT_SHARED_HOST_DIR={host} must be an absolute host-side path "
            "when launching sibling Docker tool containers."
        )

    same_namespace_path = str(host.resolve()) == str(shared.resolve())
    if same_namespace_path or host.exists():
        return True, "ok"

    if Path("/.dockerenv").exists():
        return True, (
            "ok; VAPT_SHARED_HOST_DIR is a host path that is not visible inside "
            "this container namespace. Assuming the docker-compose bind mount "
            "maps it to VAPT_SHARED_DIR."
        )

    return False, (
        f"VAPT_SHARED_HOST_DIR={host} does not exist. "
        "Create it or set VAPT_SHARED_HOST_DIR to the absolute host-side path "
        "of the .vapt-shared bind-mount volume."
    )


# ─── ToolResult ───────────────────────────────────────────────────────────────

class ToolResult:
    """Result of a single tool execution."""

    def __init__(
        self,
        tool_name: str,
        exit_code: int,
        stdout: str,
        stderr: str,
        duration: float,
        timed_out: bool = False,
        command_preview: str = "",
        oom_killed: bool = False,
        timeout_reason: str = "",
    ) -> None:
        self.tool_name = tool_name
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration = duration
        self.timed_out = timed_out
        self.command_preview = command_preview
        # Reliability observability: distinguish an OOM SIGKILL (exit 137) and
        # carry a human-readable reason for any abnormal termination so it can
        # be persisted unconditionally to the tool_runs record.
        self.oom_killed = oom_killed
        self.timeout_reason = timeout_reason

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    @property
    def output(self) -> str:
        return self.stdout

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name,
            "exit_code": self.exit_code,
            "success": self.success,
            "duration": self.duration,
            "timed_out": self.timed_out,
            "command_preview": self.command_preview,
            "oom_killed": self.oom_killed,
            "timeout_reason": self.timeout_reason,
            "stdout": self.stdout,
            "stderr": self.stderr[:50_000],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolResult":
        return cls(
            tool_name=data.get("tool", ""),
            exit_code=data.get("exit_code", -1),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
            duration=data.get("duration", 0.0),
            timed_out=data.get("timed_out", False),
            command_preview=data.get("command_preview", ""),
            oom_killed=data.get("oom_killed", False),
            timeout_reason=data.get("timeout_reason", ""),
        )


SENSITIVE_ARG_FLAGS = {
    "--api-token",
    "--token",
    "--key",
    "--api-key",
    "--password",
    "--secret",
}


def redact_command(cmd: list[str]) -> str:
    """Return a shell-ish command preview with secrets redacted."""
    redacted: list[str] = []
    redact_next = False
    for part in cmd:
        text = str(part)
        lower = text.lower()
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        if lower in SENSITIVE_ARG_FLAGS:
            redacted.append(text)
            redact_next = True
            continue
        if _looks_sensitive_assignment(text):
            key = text.split("=", 1)[0]
            redacted.append(f"{key}=<redacted>")
            continue
        redacted.append(text)
    return " ".join(redacted)


def _looks_sensitive_assignment(text: str) -> bool:
    if "=" not in text:
        return False
    key = text.split("=", 1)[0].strip().lower().replace("-", "_")
    sensitive_markers = (
        "api",
        "token",
        "secret",
        "password",
        "passwd",
        "auth",
        "credential",
        "private_key",
    )
    return any(marker in key for marker in sensitive_markers)


# ─── DockerRunner ─────────────────────────────────────────────────────────────

class DockerRunner:
    """Runs security tools — via ARQ worker queue when available, else inline."""

    def __init__(self, config: AppConfig, use_queue: bool | None = None) -> None:
        self._config = config
        self._docker_config = config.docker
        self._tools_config = config.tools
        self._docker_available = self._check_docker()
        redis_url = os.environ.get("REDIS_URL", "").strip()
        self._redis_url = redis_url if (use_queue if use_queue is not None else True) else ""

        if not self._docker_available:
            logger.warning(
                "Docker is unavailable — tools will run directly when installed locally"
            )

    @property
    def docker_available(self) -> bool:
        return self._docker_available

    @staticmethod
    def _check_docker() -> bool:
        if shutil.which("docker") is None:
            return False
        try:
            return subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            ).returncode == 0
        except Exception:
            return False

    # ── Public API ─────────────────────────────────────────────────────────

    async def run(
        self,
        tool_name: str,
        args: list[str],
        input_data: Optional[str] = None,
        timeout: Optional[int] = None,
        env: Optional[dict[str, str]] = None,
        cwd: Optional[str] = None,
    ) -> ToolResult:
        """Execute a security tool.

        Routes to ARQ worker when REDIS_URL is configured, otherwise
        executes inline (Docker container or direct host command).
        """
        if self._redis_url:
            return await self._run_via_worker(tool_name, args, input_data, timeout, env, cwd)
        return await self._run_local(tool_name, args, input_data, timeout, env, cwd)

    async def run_local(
        self,
        tool_name: str,
        args: list[str],
        input_data: Optional[str] = None,
        timeout: Optional[int] = None,
        env: Optional[dict[str, str]] = None,
        cwd: Optional[str] = None,
    ) -> ToolResult:
        """Execute locally, bypassing the ARQ queue.

        Workers must use this method. Otherwise a worker with REDIS_URL set
        re-enqueues another worker job instead of actually running the tool.
        """
        return await self._run_local(tool_name, args, input_data, timeout, env, cwd)

    async def run_parallel(self, commands: list[dict[str, Any]]) -> list[ToolResult]:
        """Execute multiple tools concurrently."""
        tasks = [
            self.run(
                tool_name=cmd["tool_name"],
                args=cmd.get("args", []),
                input_data=cmd.get("input_data"),
                timeout=cmd.get("timeout"),
                env=cmd.get("env"),
                cwd=cmd.get("cwd"),
            )
            for cmd in commands
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out: list[ToolResult] = []
        for cmd, result in zip(commands, results):
            if isinstance(result, Exception):
                out.append(ToolResult(
                    tool_name=cmd["tool_name"], exit_code=-1,
                    stdout="", stderr=str(result), duration=0.0,
                ))
            else:
                out.append(result)
        return out

    async def pull_image(self, image: str) -> bool:
        """Pull a Docker image and return True on success."""
        if not self._docker_available:
            return False
        logger.info("[Docker] Pulling {img}", img=image)
        result = await self._execute_command(
            tool_name="docker-pull",
            cmd=["docker", "pull", image],
            input_data=None,
            timeout=300,
        )
        if result.success:
            logger.info("[Docker] Image ready: {img}", img=image)
        else:
            logger.warning(
                "[Docker] Pull failed for {img}: {err}",
                img=image, err=result.stderr[:200],
            )
        return result.success

    async def pull_required_images(
        self, images: Optional[list[str]] = None
    ) -> dict[str, bool]:
        """Pre-pull Tier-1 images concurrently. Returns {image: success}."""
        targets = images or TIER1_IMAGES
        statuses = await asyncio.gather(
            *[self.pull_image(img) for img in targets],
            return_exceptions=True,
        )
        return {
            img: (bool(s) if not isinstance(s, Exception) else False)
            for img, s in zip(targets, statuses)
        }

    # ── Worker path ────────────────────────────────────────────────────────

    async def _run_via_worker(
        self,
        tool_name: str,
        args: list[str],
        input_data: Optional[str],
        timeout: Optional[int],
        env: Optional[dict[str, str]],
        cwd: Optional[str],
    ) -> ToolResult:
        """Submit tool execution to the ARQ worker queue."""
        started = time.monotonic()
        job: Any = None
        try:
            tool_config = self._config.get_tool_config(tool_name)
            effective_timeout = timeout or tool_config.timeout

            # Reuse the long-lived, retry/keepalive-tuned pool instead of
            # opening a fresh one per job (the reset-by-peer root cause).
            pool = await _get_arq_pool(self._redis_url)

            if not await self._worker_responding(pool):
                logger.warning(
                    "[worker] No ARQ worker responded on queue {queue} — running {tool} locally",
                    queue=ARQ_QUEUE_NAME,
                    tool=tool_name,
                )
                return await self._run_local(tool_name, args, input_data, timeout, env, cwd)

            # Forward the live-log context so the worker can stream this tool's
            # output back to the API's SSE clients (cross-process).
            log_context = dict(tool_log_context.get() or {})
            job = await pool.enqueue_job(
                "execute_tool",
                tool_name,
                args,
                input_data,
                effective_timeout,
                env,
                cwd,
                log_context,
                _queue_name=ARQ_QUEUE_NAME,
                _expires=effective_timeout + 120,
            )
            if job is None:
                logger.warning("[worker] Duplicate job for {tool} — running locally", tool=tool_name)
                return await self._run_local(tool_name, args, input_data, timeout, env, cwd)

            # Register the in-flight job so the orchestrator can drain/abort it
            # (prevents orphaned jobs from running past the report barrier).
            self._register_job(job)
            result_data = await job.result(timeout=effective_timeout + 60, poll_delay=0.5)
            self._unregister_job(job)

            if isinstance(result_data, dict):
                return ToolResult.from_dict(result_data)
            return await self._run_local(tool_name, args, input_data, timeout, env, cwd)

        except asyncio.CancelledError:
            # The awaiting agent was cancelled (agent timeout or scan cancel).
            # Abort the worker job so it cannot keep running and produce output
            # after the report has been generated — the premature-report bug.
            await self._abort_job(job)
            raise
        except asyncio.TimeoutError as exc:
            duration = time.monotonic() - started
            # The result never arrived in time; the job may still be executing.
            # Abort it so it cannot orphan, then report the timeout.
            await self._abort_job(job)
            logger.warning(
                "[worker] ARQ job timed out waiting for {tool} after {dur:.1f}s "
                "({err_type}: {err!r}) — aborted worker job, not duplicating locally",
                tool=tool_name,
                dur=duration,
                err_type=type(exc).__name__,
                err=exc,
            )
            return ToolResult(
                tool_name=tool_name,
                exit_code=-1,
                stdout="",
                stderr=(
                    f"ARQ worker job timed out after {duration:.1f}s. "
                    "Check worker logs, queue depth, and tool timeout."
                ),
                duration=duration,
                timed_out=True,
                timeout_reason="ARQ result timeout — worker job aborted",
            )
        except Exception as exc:
            # Unknown failure. Abort any in-flight job before the local fallback
            # so we never run the same tool twice concurrently.
            await self._abort_job(job)
            logger.warning(
                "[worker] ARQ submission failed ({err_type}: {err!r}) — falling back to local execution",
                err_type=type(exc).__name__,
                err=exc,
            )
            return await self._run_local(tool_name, args, input_data, timeout, env, cwd)

    # ── Job tracking helpers (report barrier / abort-on-timeout) ────────────

    @staticmethod
    def _register_job(job: Any) -> None:
        """Associate an enqueued ARQ job with the current scan (via ContextVar)."""
        JOB_TRACKER.register(current_scan_id.get(), job)

    @staticmethod
    def _unregister_job(job: Any) -> None:
        JOB_TRACKER.unregister(current_scan_id.get(), job)

    @staticmethod
    async def _abort_job(job: Any) -> None:
        """Best-effort abort of a worker job, then unregister it."""
        if job is None:
            return
        try:
            await job.abort()
        except Exception as exc:
            logger.debug("[worker] job.abort() failed: {err}", err=exc)
        finally:
            JOB_TRACKER.unregister(current_scan_id.get(), job)

    async def _worker_responding(self, pool: Any) -> bool:
        """Return True when at least one ARQ worker is consuming our queue.

        Without this probe, a missing worker makes every tool wait for the full
        tool timeout before falling back to local execution, which makes scans
        look frozen. The primary signal is ARQ's worker health key; the queued
        ping fallback is only for older workers that do not publish health yet.
        """
        global _worker_ok_until, _worker_fail_until

        now = time.monotonic()
        if _worker_ok_until > now:
            return True
        if _worker_fail_until > now:
            return False

        async with _get_worker_ping_lock():
            now = time.monotonic()
            if _worker_ok_until > now:
                return True
            if _worker_fail_until > now:
                return False

            try:
                health = await pool.get(ARQ_HEALTH_KEY)
                if health:
                    _worker_ok_until = time.monotonic() + 30
                    return True

                queue_type = await pool.type(ARQ_QUEUE_NAME)
                queue_type_text = queue_type.decode() if isinstance(queue_type, bytes) else str(queue_type)
                if queue_type_text == "zset" and await pool.zcard(ARQ_QUEUE_NAME) > 0:
                    logger.warning(
                        "[worker] Queue {queue} has pending jobs but no health key {health}; "
                        "assuming workers are offline or stale",
                        queue=ARQ_QUEUE_NAME,
                        health=ARQ_HEALTH_KEY,
                    )
                    _worker_fail_until = time.monotonic() + 30
                    return False

                job = await pool.enqueue_job(
                    "ping_worker",
                    _queue_name=ARQ_QUEUE_NAME,
                    _expires=10,
                )
                if job is None:
                    _worker_ok_until = time.monotonic() + 10
                    return True
                result = await job.result(timeout=2, poll_delay=0.1)
                ok = isinstance(result, dict) and result.get("ok") is True
                if ok:
                    _worker_ok_until = time.monotonic() + 30
                    return True
            except Exception as exc:
                logger.debug(
                    "[worker] Ping failed on queue {queue}: {err_type}: {err!r}",
                    queue=ARQ_QUEUE_NAME,
                    err_type=type(exc).__name__,
                    err=exc,
                )

            _worker_fail_until = time.monotonic() + 10
            return False

    # ── Local path ─────────────────────────────────────────────────────────

    async def _run_local(
        self,
        tool_name: str,
        args: list[str],
        input_data: Optional[str],
        timeout: Optional[int],
        env: Optional[dict[str, str]],
        cwd: Optional[str],
    ) -> ToolResult:
        """Execute tool locally — Docker container or host command."""
        tool_config = self._config.get_tool_config(tool_name)
        effective_timeout = timeout or tool_config.timeout

        if not tool_config.enabled:
            logger.warning("Tool '{tool}' is disabled in config — skipping", tool=tool_name)
            return ToolResult(
                tool_name=tool_name, exit_code=-1, stdout="",
                stderr=f"Tool '{tool_name}' is disabled in configuration",
                duration=0.0,
            )

        if self._docker_available and tool_config.docker_image:
            container_args = [
                self._map_wordlist_for_docker(host_to_container(a) if a.startswith(SHARED_DIR) else a)
                for a in args
            ]
            return await self._run_docker(
                tool_name=tool_name,
                docker_image=tool_config.docker_image,
                args=container_args,
                input_data=input_data,
                timeout=effective_timeout,
                env=env,
                cwd=cwd,
            )

        direct_args = [self._map_wordlist_for_direct(a) for a in args]
        return await self._run_direct(
            tool_name=tool_name, args=direct_args, input_data=input_data,
            timeout=effective_timeout, env=env, cwd=cwd,
        )

    @staticmethod
    def _map_wordlist_for_direct(arg: str) -> str:
        if arg.startswith(CONTAINER_WORDLIST_DIR):
            rel = os.path.relpath(arg, CONTAINER_WORDLIST_DIR)
            return os.path.join(WORDLIST_DIR, rel)
        return arg

    @staticmethod
    def _map_wordlist_for_docker(arg: str) -> str:
        for source in (WORDLIST_DIR, HOST_WORDLIST_DIR):
            if arg.startswith(source):
                rel = os.path.relpath(arg, source)
                return os.path.join(CONTAINER_WORDLIST_DIR, rel)
        return arg


    async def _run_docker(
        self,
        tool_name: str,
        docker_image: str,
        args: list[str],
        input_data: Optional[str],
        timeout: int,
        env: Optional[dict[str, str]],
        cwd: Optional[str],
    ) -> ToolResult:
        """Execute a tool inside a Docker container."""
        # Per-tool resource tier with fallback to the global DockerConfig
        # default. Memory-hungry crawlers (Katana) need a higher ceiling than
        # the 512m default, otherwise the OOM-killer SIGKILLs them (exit 137).
        tool_config = self._config.get_tool_config(tool_name)
        mem_limit = tool_config.memory_limit or self._docker_config.memory_limit
        cpu_limit = tool_config.cpu_limit if tool_config.cpu_limit is not None else self._docker_config.cpu_limit
        docker_cmd: list[str] = [
            "docker", "run", "--rm",
            "--network", "host",
            "--memory", mem_limit,
            "--cpus", str(cpu_limit),
            "--pids-limit", "512",
        ]

        # Mount shared temp dir so input files written by the backend are
        # visible inside the container.
        try:
            ensure_shared_dir()
            docker_cmd.extend(["-v", f"{HOST_SHARED_DIR}:{CONTAINER_SHARED_DIR}"])
        except Exception:
            pass

        wordlist_source = (
            HOST_WORDLIST_DIR if os.path.exists(HOST_WORDLIST_DIR) else WORDLIST_DIR
        )
        if os.path.exists(wordlist_source):
            docker_cmd.extend(["-v", f"{wordlist_source}:{CONTAINER_WORDLIST_DIR}:ro"])

        # Forward required API-key env vars.
        passthrough_envs = [
            "SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
            "SECURITYTRAILS_API_KEY", "NVD_API_KEY", "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY",
            "TOGETHER_API_KEY", "WPSCAN_API_TOKEN",
            "VAPT_SHODAN_API_KEY", "VAPT_CENSYS_API_ID",
            "VAPT_CENSYS_API_SECRET", "VAPT_SECURITYTRAILS_API_KEY",
            "VAPT_NVD_API_KEY", "VAPT_WPSCAN_API_TOKEN",
        ]
        for var in passthrough_envs:
            val = os.environ.get(var, "")
            if val:
                docker_cmd.extend(["-e", f"{var}={val}"])

        if env:
            for key, value in env.items():
                docker_cmd.extend(["-e", f"{key}={value}"])

        if cwd:
            docker_cmd.extend(["-w", cwd])

        docker_cmd.append(docker_image)
        docker_cmd.extend(args)

        logger.info(
            "[Docker] {tool} (timeout={t}s, image={img}) cmd={cmd}",
            tool=tool_name, t=timeout, img=docker_image, cmd=redact_command(docker_cmd),
        )

        # Respect the global container concurrency limit.
        async with _get_semaphore():
            result = await self._execute_command(
                tool_name=tool_name, cmd=docker_cmd,
                input_data=input_data, timeout=timeout,
            )

        # OOM detection: `docker run` returns 137 (128 + SIGKILL) when the
        # container is killed by the cgroup OOM-killer for exceeding --memory.
        # We cannot `docker inspect` a `--rm` container post-mortem, so infer
        # from the exit code (and the "signal: killed" stderr marker) and record
        # it so operators see *why* a tool died instead of a bare failure.
        if result.exit_code == 137 and not result.timed_out:
            result.oom_killed = True
            result.timeout_reason = (
                f"Container OOM-killed (exit 137): exceeded memory limit "
                f"{mem_limit}. Raise this tool's memory_limit in config.yaml or "
                f"bound its workload (e.g. lower crawl depth)."
            )
            logger.warning(
                "[Docker] {tool} OOM-killed — exceeded --memory {mem}",
                tool=tool_name, mem=mem_limit,
            )
        return result

    async def _run_direct(
        self,
        tool_name: str,
        args: list[str],
        input_data: Optional[str],
        timeout: int,
        env: Optional[dict[str, str]],
        cwd: Optional[str],
    ) -> ToolResult:
        """Execute a tool directly on the host (no Docker isolation)."""
        cmd = [tool_name] + args
        logger.info("[Direct] {tool} (timeout={t}s) cmd={cmd}", tool=tool_name, t=timeout, cmd=redact_command(cmd))
        return await self._execute_command(
            tool_name=tool_name, cmd=cmd,
            input_data=input_data, timeout=timeout, env=env, cwd=cwd,
        )

    @staticmethod
    async def _execute_command(
        tool_name: str,
        cmd: list[str],
        input_data: Optional[str],
        timeout: int,
        env: Optional[dict[str, str]] = None,
        cwd: Optional[str] = None,
    ) -> ToolResult:
        """Execute a command with timeout and output capture."""
        start = time.monotonic()
        proc = None
        # Live-log context for streaming this tool's output to the UI. Full
        # output is still captured to the artifact file; this is only the
        # sampled live view.
        log_ctx = dict(tool_log_context.get() or {})
        log_scan_id = str(log_ctx.get("scan_id", ""))
        throttler = LineThrottler()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if input_data else asyncio.subprocess.DEVNULL,
                env=env,
                cwd=cwd,
            )

            stdout_chunks: list[bytes] = []
            stderr_chunks: list[bytes] = []

            async def _read_stream(stream: Any, chunks: list[bytes], stream_name: str) -> None:
                buffered = b""
                while True:
                    chunk = await stream.read(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if not log_scan_id:
                        continue
                    # Split into lines for live streaming (keep partial tail).
                    buffered += chunk
                    *lines, buffered = buffered.split(b"\n")
                    if len(buffered) > 8192:  # avoid unbounded buffering
                        buffered = buffered[-8192:]
                    for raw in lines:
                        text = raw.decode("utf-8", errors="replace").rstrip()
                        if text and throttler.allow():
                            await publish_tool_log(
                                text,
                                scan_id=log_scan_id,
                                tool=tool_name,
                                agent=str(log_ctx.get("agent", "")),
                                phase=str(log_ctx.get("phase", "")),
                                stream=stream_name,
                            )

            if input_data and proc.stdin is not None:
                proc.stdin.write(input_data.encode())
                await proc.stdin.drain()
                proc.stdin.close()

            if log_scan_id:
                await publish_tool_log(
                    f"$ {redact_command(cmd)}",
                    scan_id=log_scan_id, tool=tool_name,
                    agent=str(log_ctx.get("agent", "")), phase=str(log_ctx.get("phase", "")),
                    stream="meta",
                )

            stdout_task = asyncio.create_task(_read_stream(proc.stdout, stdout_chunks, "stdout"))
            stderr_task = asyncio.create_task(_read_stream(proc.stderr, stderr_chunks, "stderr"))

            await asyncio.wait_for(
                asyncio.gather(proc.wait(), stdout_task, stderr_task),
                timeout=timeout,
            )

            duration = time.monotonic() - start
            stdout = b"".join(stdout_chunks)
            stderr = b"".join(stderr_chunks)
            return ToolResult(
                tool_name=tool_name,
                exit_code=proc.returncode or 0,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                duration=duration,
                command_preview=redact_command(cmd),
            )

        except asyncio.TimeoutError:
            duration = time.monotonic() - start
            logger.warning("[{tool}] Timed out after {t}s", tool=tool_name, t=timeout)
            if proc is not None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            stdout = b"".join(locals().get("stdout_chunks", []))
            stderr = b"".join(locals().get("stderr_chunks", []))
            stderr_text = stderr.decode("utf-8", errors="replace")
            timeout_text = f"Tool timed out after {timeout} seconds"
            if stderr_text:
                stderr_text = f"{timeout_text}\n{stderr_text}"
            else:
                stderr_text = timeout_text
            return ToolResult(
                tool_name=tool_name, exit_code=-1,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr_text,
                duration=duration, timed_out=True,
                command_preview=redact_command(cmd),
                timeout_reason=timeout_text,
            )

        except FileNotFoundError:
            duration = time.monotonic() - start
            logger.error("[{tool}] Command not found: {cmd}", tool=tool_name, cmd=cmd[0])
            return ToolResult(
                tool_name=tool_name, exit_code=-1, stdout="",
                stderr=f"Command not found: {cmd[0]}. Install {tool_name} or configure a Docker image.",
                duration=duration,
                command_preview=redact_command(cmd),
            )

        except Exception as exc:
            duration = time.monotonic() - start
            logger.error("[{tool}] Execution error: {err}", tool=tool_name, err=exc)
            return ToolResult(
                tool_name=tool_name, exit_code=-1, stdout="",
                stderr=str(exc), duration=duration,
                command_preview=redact_command(cmd),
            )


# ─── OutputParser ─────────────────────────────────────────────────────────────

class OutputParser:
    """Parses raw tool output into structured data."""

    @staticmethod
    def parse_subfinder(output: str) -> list[str]:
        return [
            line.strip()
            for line in output.strip().splitlines()
            if line.strip() and not line.startswith("[")
        ]

    @staticmethod
    def parse_httpx(output: str) -> list[dict[str, Any]]:
        results = []
        for line in output.strip().splitlines():
            try:
                data = json.loads(line)
                results.append({
                    "url": data.get("url", ""),
                    "status_code": data.get("status_code", 0),
                    "title": data.get("title", ""),
                    "tech": data.get("tech", []),
                    "content_length": data.get("content_length", 0),
                    "webserver": data.get("webserver", ""),
                    "cdn": data.get("cdn", ""),
                    "tls": data.get("tls", {}),
                })
            except json.JSONDecodeError:
                continue
        return results

    @staticmethod
    def parse_nmap(output: str) -> list[dict[str, Any]]:
        """Parse nmap normal-format output.

        Prefers parsing the full service-version line so agents get
        product+version strings for NVD CPE lookups.
        """
        results = []
        seen: set[tuple[int, str, str, str]] = set()
        for line in output.strip().splitlines():
            line = line.strip()
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0]
                    port = port_proto.split("/")[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    # Version / product string lives in the rest of the line.
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""
                    key = (int(port), "tcp", service, version)
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append({
                        "port": int(port),
                        "protocol": "tcp",
                        "state": state,
                        "service": service,
                        "version": version,
                        "product": parts[3] if len(parts) > 3 else "",
                    })
        return results

    @staticmethod
    def parse_nmap_xml(output: str) -> list[dict[str, Any]]:
        """Parse nmap XML output (-oX -) for richer structured data."""
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(output)
        except Exception:
            return []

        results = []
        for host in root.findall("host"):
            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host.find("address")
            ip = addr_el.attrib.get("addr", "") if addr_el is not None else ""
            ports_el = host.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.attrib.get("state") != "open":
                    continue
                svc = port_el.find("service")
                results.append({
                    "ip": ip,
                    "port": int(port_el.attrib.get("portid", 0)),
                    "protocol": port_el.attrib.get("protocol", "tcp"),
                    "state": "open",
                    "service": svc.attrib.get("name", "") if svc is not None else "",
                    "product": svc.attrib.get("product", "") if svc is not None else "",
                    "version": svc.attrib.get("version", "") if svc is not None else "",
                    "extrainfo": svc.attrib.get("extrainfo", "") if svc is not None else "",
                    "cpe": [c.text for c in (svc.findall("cpe") if svc is not None else []) if c.text],
                })
        return results

    @staticmethod
    def parse_nuclei(output: str) -> list[dict[str, Any]]:
        results = []
        for line in output.strip().splitlines():
            try:
                data = json.loads(line)
                if "template-id" not in data:
                    continue
                severity = data.get("info", {}).get("severity", "info").lower()
                sev_map = {
                    "critical": "critical", "high": "high", "medium": "medium",
                    "low": "low", "info": "informational",
                }
                classification = data.get("info", {}).get("classification", {})
                results.append({
                    "template_id": data.get("template-id", ""),
                    "template_name": data.get("info", {}).get("name", ""),
                    "severity": sev_map.get(severity, "informational"),
                    "url": data.get("matched-at", data.get("host", "")),
                    "type": data.get("type", ""),
                    "extracted_results": data.get("extracted-results", []),
                    "curl_command": data.get("curl-command", ""),
                    "description": data.get("info", {}).get("description", ""),
                    "reference": data.get("info", {}).get("reference", []),
                    "tags": data.get("info", {}).get("tags", []),
                    "cve": classification.get("cve-id", ""),
                    "cwe": classification.get("cwe-id", ""),
                    "cvss_score": classification.get("cvss-score", ""),
                    "remediation": data.get("info", {}).get("remediation", ""),
                    "request": data.get("request", ""),
                    "response": data.get("response", ""),
                })
            except json.JSONDecodeError:
                continue
        return results

    @staticmethod
    def parse_nikto(output: str) -> list[dict[str, Any]]:
        results = []
        for line in output.strip().splitlines():
            if "+ " in line:
                clean = line.strip().lstrip("+ ").strip()
                clean_lower = clean.lower()
                if clean_lower.startswith(("error:", "target ", "start time", "end time")):
                    continue
                if clean and len(clean) > 10:
                    results.append({
                        "finding": clean,
                        "raw": line.strip(),
                        "reportable": OutputParser._is_reportable_nikto(clean_lower),
                    })
        return results

    @staticmethod
    def _is_reportable_nikto(clean_lower: str) -> bool:
        noisy_prefixes = (
            "server:",
            "root page",
            "no cgi directories",
            "ssl info:",
            "scan terminated:",
        )
        noisy_contains = (
            "host(s) tested",
            "requests:",
            "suggested security header missing",
            "uncommon header",
            "robots.txt: contains",
            "link header(s) found",
        )
        if clean_lower.startswith(noisy_prefixes):
            return False
        if any(token in clean_lower for token in noisy_contains):
            return False
        return any(token in clean_lower for token in (
            "cve-",
            "osvdb",
            "vulnerab",
            "directory indexing",
            "admin",
            "backup",
            "config",
            "credential",
            "default file",
            "interesting file",
            "phpinfo",
            "server-status",
            "x-frame-options header is deprecated",
            "hostname ",
        ))

    @staticmethod
    def parse_ffuf(output: str) -> list[dict[str, Any]]:
        results = []
        try:
            data = json.loads(output)
            for result in data.get("results", []):
                results.append({
                    "url": result.get("url", ""),
                    "status": result.get("status", 0),
                    "length": result.get("length", 0),
                    "words": result.get("words", 0),
                    "lines": result.get("lines", 0),
                    "input": result.get("input", {}).get("FUZZ", ""),
                })
        except (json.JSONDecodeError, AttributeError):
            for line in output.strip().splitlines():
                if "http" in line.lower():
                    results.append({"url": line.strip(), "status": 0, "length": 0})
        return results

    @staticmethod
    def parse_sqlmap(output: str) -> list[dict[str, Any]]:
        results = []
        for line in output.strip().splitlines():
            ll = line.lower()
            if any(kw in ll for kw in ("sqlmap", "parameter:", "inject", "payload:", "is vulnerable")):
                entry: dict[str, Any] = {"finding": line.strip()}
                if "is vulnerable" in ll:
                    entry["vulnerable"] = True
                results.append(entry)
        return results

    @staticmethod
    def parse_wpscan(output: str) -> list[dict[str, Any]]:
        """Parse WPScan JSON output.

        Extracts findings in two tiers:
        1. Known CVEs / vulnerabilities (requires API token in WPScan)
        2. Installed component versions, users, and interesting findings
           (available without API token — always extracted)
        """
        results: list[dict[str, Any]] = []

        try:
            data = json.loads(output)
        except (json.JSONDecodeError, TypeError, AttributeError):
            # Fallback: plain-text scraping
            for line in output.strip().splitlines():
                if "|" in line and any(kw in line for kw in ("WordPress", "vulnerability", "plugin", "version")):
                    results.append({"finding": line.strip(), "component": "wordpress", "informational": True})
            return results

        aborted = str(data.get("scan_aborted") or "")
        if aborted:
            return [{
                "finding": f"WPScan aborted: {aborted}",
                "component": "wordpress",
                "target_url": data.get("target_url", ""),
                "informational": True,
                "reportable": False,
                "raw": {"scan_aborted": aborted},
            }]

        # ── 1. WordPress core version ─────────────────────────────────────
        version_data = data.get("version") or {}
        if isinstance(version_data, dict):
            ver = version_data.get("number") or version_data.get("version")
            if ver:
                results.append({
                    "finding": f"WordPress version {ver} detected",
                    "component": "core",
                    "version": ver,
                    "confidence": version_data.get("confidence", 0),
                    "references": version_data.get("references") or {},
                    "informational": True,
                })
            for vuln in version_data.get("vulnerabilities") or []:
                title = vuln.get("title") or f"WordPress core CVE"
                results.append({
                    "finding": title, "component": "core", "version": ver or "",
                    "cve": vuln.get("references", {}).get("cve") or [],
                    "references": vuln.get("references") or {},
                    "severity": "high",
                    "raw": vuln,
                })

        # ── 2. Main theme ─────────────────────────────────────────────────
        theme_data = data.get("main_theme") or {}
        if isinstance(theme_data, dict):
            theme_name = theme_data.get("slug") or theme_data.get("name") or "unknown"
            theme_ver  = theme_data.get("version", {})
            theme_ver_str = (theme_ver.get("number") if isinstance(theme_ver, dict) else None) or ""
            results.append({
                "finding": f"WordPress theme detected: {theme_name}" + (f" v{theme_ver_str}" if theme_ver_str else ""),
                "component": "theme",
                "slug": theme_name,
                "version": theme_ver_str,
                "informational": True,
            })
            for vuln in theme_data.get("vulnerabilities") or []:
                title = vuln.get("title") or f"WordPress theme {theme_name} vulnerability"
                results.append({
                    "finding": title, "component": "theme", "slug": theme_name,
                    "cve": vuln.get("references", {}).get("cve") or [],
                    "references": vuln.get("references") or {},
                    "severity": "high", "raw": vuln,
                })

        # ── 3. Plugins ────────────────────────────────────────────────────
        plugins = data.get("plugins") or {}
        if not isinstance(plugins, dict):
            plugins = {}
        for slug, plugin_data in plugins.items():
            if not isinstance(plugin_data, dict):
                continue
            plugin_ver = plugin_data.get("version", {})
            plugin_ver_str = (plugin_ver.get("number") if isinstance(plugin_ver, dict) else None) or ""
            # Always emit an informational finding for each installed plugin.
            results.append({
                "finding": f"WordPress plugin installed: {slug}" + (f" v{plugin_ver_str}" if plugin_ver_str else ""),
                "component": "plugin",
                "slug": slug,
                "version": plugin_ver_str,
                "location": plugin_data.get("location") or "",
                "informational": True,
            })
            # Known CVEs for this plugin (need API token).
            for vuln in plugin_data.get("vulnerabilities") or []:
                title = vuln.get("title") or f"WordPress plugin {slug} vulnerability"
                results.append({
                    "finding": title, "component": "plugin", "slug": slug,
                    "cve": vuln.get("references", {}).get("cve") or [],
                    "references": vuln.get("references") or {},
                    "severity": "high", "raw": vuln,
                })

        # ── 4. Themes collection ──────────────────────────────────────────
        themes = data.get("themes") or {}
        if isinstance(themes, dict):
            for slug, theme_data in themes.items():
                if slug == (data.get("main_theme") or {}).get("slug"):
                    continue  # already emitted above
                if not isinstance(theme_data, dict):
                    continue
                theme_ver = theme_data.get("version", {})
                theme_ver_str = (theme_ver.get("number") if isinstance(theme_ver, dict) else None) or ""
                results.append({
                    "finding": f"WordPress theme installed: {slug}" + (f" v{theme_ver_str}" if theme_ver_str else ""),
                    "component": "theme", "slug": slug, "version": theme_ver_str,
                    "informational": True,
                })
                for vuln in theme_data.get("vulnerabilities") or []:
                    title = vuln.get("title") or f"WordPress theme {slug} vulnerability"
                    results.append({
                        "finding": title, "component": "theme", "slug": slug,
                        "cve": vuln.get("references", {}).get("cve") or [],
                        "references": vuln.get("references") or {},
                        "severity": "high", "raw": vuln,
                    })

        # ── 5. User enumeration ───────────────────────────────────────────
        users = data.get("users") or {}
        if isinstance(users, dict) and users:
            user_list = list(users.keys())
            results.append({
                "finding": f"WordPress user enumeration: {len(user_list)} user(s) found: {', '.join(user_list[:10])}",
                "component": "users",
                "users": user_list,
                "severity": "medium",
            })

        # ── 6. Interesting findings (readme, xmlrpc, etc.) ────────────────
        interesting_severity = {
            "xmlrpc": "medium",
            "readme": "informational",
            "license": "informational",
            "backup": "high",
            "debug": "high",
            "upload": "medium",
            "wp-config": "critical",
            "install": "high",
        }
        for item in data.get("interesting_findings") or []:
            name = item.get("to_s") or item.get("interesting_entries", [""])[0] or item.get("type") or "WordPress interesting finding"
            url  = item.get("url") or ""
            sev  = "informational"
            for kw, s in interesting_severity.items():
                if kw in (name + url).lower():
                    sev = s
                    break
            results.append({
                "finding": name,
                "component": "wordpress",
                "url": url,
                "severity": sev,
                "references": item.get("references") or {},
                "raw": item,
            })

        return results

    @staticmethod
    def parse_dnsx(output: str) -> list[dict[str, Any]]:
        results = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue
            try:
                data = json.loads(line)
                results.append({
                    "host": data.get("host", ""),
                    "a": data.get("a", []),
                    "aaaa": data.get("aaaa", []),
                    "cname": data.get("cname", []),
                    "status_code": data.get("status_code", ""),
                })
            except json.JSONDecodeError:
                results.append({"host": line, "a": [], "aaaa": [], "cname": []})
        return results

    @staticmethod
    def parse_naabu(output: str) -> list[dict[str, Any]]:
        results = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue
            try:
                data = json.loads(line)
                results.append({
                    "ip": data.get("ip", ""),
                    "port": data.get("port", 0),
                    "protocol": data.get("protocol", "tcp"),
                })
            except json.JSONDecodeError:
                if ":" in line:
                    parts = line.rsplit(":", 1)
                    try:
                        results.append({"ip": parts[0], "port": int(parts[1]), "protocol": "tcp"})
                    except ValueError:
                        pass
        return results

    @staticmethod
    def parse_urls_from_text(text: str) -> list[str]:
        import re
        return list(set(re.findall(r'https?://[^\s"\',\)\]\}]+', text)))

    @staticmethod
    def parse_domains_from_text(text: str) -> list[str]:
        import re
        domains = set(re.findall(r'(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}', text))
        return [d.replace("http://", "").replace("https://", "").rstrip("/") for d in domains]
