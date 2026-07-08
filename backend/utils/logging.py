"""Runtime logging setup for API and worker processes."""

from __future__ import annotations

import os
import sys
import logging

from loguru import logger

_CONFIGURED = False


class _InterceptHandler(logging.Handler):
    """Route stdlib logging through Loguru so timestamps are consistent."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno
        logger.opt(depth=6, exception=record.exc_info).log(level, record.getMessage())


def configure_runtime_logging(default_level: str = "INFO") -> None:
    """Configure Loguru once with a production-friendly default level."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    level = (os.environ.get("VAPT_LOG_LEVEL") or default_level or "INFO").upper()
    role = os.environ.get("VAPT_PROCESS_ROLE", "").strip()
    if not role:
        argv = " ".join(sys.argv).lower()
        role = "worker" if "arq" in argv or "worker.settings" in argv else "api"
    fmt = f"{{time:YYYY-MM-DD HH:mm:ss.SSS}} | {{level:<8}} | {role:<7} | {{name}}:{{function}}:{{line}} - {{message}}"
    logger.remove()
    logger.add(
        sys.stderr,
        level=level,
        backtrace=False,
        diagnose=False,
        enqueue=True,
        format=fmt,
    )
    log_dir = os.environ.get("VAPT_LOG_DIR", "/app/logs")
    try:
        os.makedirs(log_dir, exist_ok=True)
        logger.add(
            os.path.join(log_dir, "vapt-runtime.log"),
            level=level,
            backtrace=False,
            diagnose=False,
            enqueue=True,
            rotation=os.environ.get("VAPT_LOG_ROTATION", "25 MB"),
            retention=os.environ.get("VAPT_LOG_RETENTION", "10 days"),
            compression="gz",
            format=fmt,
        )
    except Exception:
        pass
    logging.basicConfig(handlers=[_InterceptHandler()], level=level, force=True)
    _CONFIGURED = True
