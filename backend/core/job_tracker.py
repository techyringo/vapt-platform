"""
VAPT Platform — ARQ Job Tracker

Tracks the in-flight ARQ jobs enqueued for each scan so the orchestrator can
enforce a **barrier before reporting**: no worker job may still be running when
the reporter agent generates the final report.

Background
----------
The production incident was a report generated at 10:18 while tool jobs kept
running until 10:47. Root cause: when an agent hit its ``asyncio.wait_for``
timeout, the orchestrator advanced the pipeline to REPORTING, but the ARQ jobs
that agent had already enqueued kept running on the workers — nothing aborted
them and nothing waited for them.

This module provides:
  * a ``current_scan_id`` ContextVar so the runner can associate an enqueued job
    with the owning scan without threading ``scan_id`` through every
    ``agent.run(...)`` call site;
  * a process-wide ``JOB_TRACKER`` that records in-flight jobs per scan;
  * ``drain()`` — wait until a scan's jobs are all terminal (with a grace
    period, then abort stragglers);
  * ``abort_scan()`` — abort every in-flight job for a scan immediately.
"""

from __future__ import annotations

import asyncio
import contextvars
import time
from typing import Any

from loguru import logger

# Set by the orchestrator around a scan run. Reads propagate across ``await``
# within the same task and into child tasks created via ``asyncio.create_task``
# (which copy the current context), so agent tool calls inherit it for free.
current_scan_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_scan_id", default=""
)


class JobTracker:
    """Process-wide registry of in-flight ARQ jobs, keyed by scan id."""

    def __init__(self) -> None:
        # scan_id -> set of ARQ Job objects still in flight.
        self._jobs: dict[str, set[Any]] = {}

    # ── registration (called by the runner) ─────────────────────────────
    def register(self, scan_id: str, job: Any) -> None:
        if not scan_id or job is None:
            return
        self._jobs.setdefault(scan_id, set()).add(job)

    def unregister(self, scan_id: str, job: Any) -> None:
        if not scan_id or job is None:
            return
        bucket = self._jobs.get(scan_id)
        if bucket is not None:
            bucket.discard(job)
            if not bucket:
                self._jobs.pop(scan_id, None)

    def in_flight(self, scan_id: str) -> int:
        return len(self._jobs.get(scan_id, ()))

    # ── control (called by the orchestrator) ────────────────────────────
    async def abort_scan(self, scan_id: str) -> int:
        """Abort every in-flight job for a scan. Returns how many were aborted.

        Requires ``WorkerSettings.allow_abort_jobs = True`` for jobs that have
        already started executing on a worker.
        """
        jobs = list(self._jobs.get(scan_id, ()))
        aborted = 0
        for job in jobs:
            try:
                await job.abort()
                aborted += 1
            except Exception as exc:  # abort is best-effort
                logger.debug(
                    "[job_tracker] abort failed for a {scan} job: {err}",
                    scan=scan_id, err=exc,
                )
            finally:
                self.unregister(scan_id, job)
        if aborted:
            logger.warning(
                "[job_tracker] Aborted {n} in-flight job(s) for scan {scan}",
                n=aborted, scan=scan_id,
            )
        return aborted

    async def drain(self, scan_id: str, grace_seconds: float = 30.0) -> None:
        """Block until a scan has no in-flight jobs.

        This is the report barrier. In the normal path the tracker is already
        empty (the runner unregisters each job as its result arrives), so this
        returns immediately. If jobs are still in flight after ``grace_seconds``
        they are aborted so a straggler can never run past the report.
        """
        if self.in_flight(scan_id) == 0:
            return

        logger.info(
            "[job_tracker] Draining {n} in-flight job(s) before reporting for scan {scan}",
            n=self.in_flight(scan_id), scan=scan_id,
        )
        deadline = time.monotonic() + grace_seconds
        while self.in_flight(scan_id) > 0 and time.monotonic() < deadline:
            await asyncio.sleep(0.5)

        remaining = self.in_flight(scan_id)
        if remaining > 0:
            logger.warning(
                "[job_tracker] {n} job(s) still in flight after {g}s grace — aborting",
                n=remaining, g=grace_seconds,
            )
            await self.abort_scan(scan_id)


# Process-wide singleton.
JOB_TRACKER = JobTracker()
