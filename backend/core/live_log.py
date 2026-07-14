"""
VAPT Platform — Live Tool-Log Streaming

Streams live tool-execution log lines ("Running nmap on X…", raw output lines)
from wherever a tool actually runs to the API's SSE clients.

Topology
--------
Tools run in the **worker** process (ARQ), but the SSE event bus lives in the
**API** process. A callback cannot cross that boundary, so live lines are
published to a Redis pub/sub channel on the event-bus Redis
(``VAPT_EVENT_REDIS_URL``, falling back to ``REDIS_URL``). The API subscribes
and re-broadcasts each line into its in-process SSE queues.

These lines are **ephemeral** — the durable record of a tool run remains the
artifact file on disk (stdout/stderr + SHA-256). We deliberately do not persist
tool_log lines to the events table.

Context threading
-----------------
``tool_log_context`` carries ``{scan_id, agent, phase}`` for the currently
executing agent. The orchestrator sets it in-process; for the worker path the
context is passed through the ARQ job and re-set inside the worker.
"""

from __future__ import annotations

import contextvars
import json
import os
import re
import time
from typing import Any, Awaitable, Callable, Optional

from loguru import logger

TOOL_LOG_CHANNEL = os.environ.get("VAPT_TOOL_LOG_CHANNEL", "vapt:tool_log")

# {scan_id, agent, phase} for the agent whose tools are currently running.
tool_log_context: contextvars.ContextVar[dict] = contextvars.ContextVar(
    "tool_log_context", default={}
)


def _event_redis_url() -> str:
    return os.environ.get("VAPT_EVENT_REDIS_URL") or os.environ.get("REDIS_URL") or ""


# ── Publisher (worker + local runner) ───────────────────────────────────────

_pub_client: Any = None
_pub_disabled = False

_SECRET_VALUE_RE = re.compile(
    r"(?i)(\b(?:api[_-]?key|token|secret|password|passwd)\b\s*[:=]\s*)([^\s,;]+)"
)
_HEADER_SECRET_RE = re.compile(
    r"(?i)(\b(?:authorization|cookie|set-cookie)\b\s*[:=]\s*)([^\r\n]+)"
)


def redact_tool_log_line(line: str) -> str:
    """Bound and redact a live line before it reaches console or SSE output."""
    bounded = str(line).replace("\x00", "")[:2000]
    bounded = _HEADER_SECRET_RE.sub(r"\1<redacted>", bounded)
    return _SECRET_VALUE_RE.sub(r"\1<redacted>", bounded)


def prepare_tool_log_line(line: str, tool: str = "") -> str:
    """Turn verbose scanner output into a compact, operator-safe live event.

    Full stdout/stderr remains in the durable tool artifact. The live stream is
    intentionally summarized so minified JavaScript and scanner JSON do not
    overwhelm the UI or container logs.
    """
    raw = str(line).strip().replace("\x00", "")
    if not raw:
        return ""
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        # Katana can emit entire minified response bodies as one line. Those
        # belong in the downloadable artifact, not the operational event feed.
        if len(raw) > 800 and tool.lower() in {"katana", "hakrawler", "gau", "waybackurls"}:
            return ""
        return redact_tool_log_line(raw[:600])

    if not isinstance(payload, dict):
        return redact_tool_log_line(json.dumps(payload, separators=(",", ":"))[:600])

    tool_name = tool.lower()
    if tool_name == "httpx":
        method = str(payload.get("method") or "GET")
        url = str(payload.get("url") or payload.get("input") or "target")
        status = payload.get("status_code")
        tech = ", ".join(str(item) for item in (payload.get("tech") or [])[:5])
        suffix = f" · {tech}" if tech else ""
        return redact_tool_log_line(f"{method} {url} → HTTP {status or 'unknown'}{suffix}")

    if tool_name == "katana":
        request = payload.get("request") if isinstance(payload.get("request"), dict) else {}
        endpoint = request.get("endpoint") or payload.get("url") or payload.get("endpoint")
        error = str(payload.get("error") or "")
        if error.lower() in {"max depth reached", "duplicate endpoint"}:
            return ""
        if endpoint:
            method = request.get("method") or "GET"
            suffix = f" · {error}" if error else ""
            return redact_tool_log_line(f"discovered {method} {endpoint}{suffix}")

    # Generic JSONL scanners: retain only useful scalar evidence fields.
    keys = (
        "template-id", "template_id", "name", "host", "url", "matched-at",
        "matched_at", "endpoint", "severity", "status_code", "level", "message",
    )
    compact = {key: payload[key] for key in keys if key in payload and not isinstance(payload[key], (dict, list))}
    if compact:
        return redact_tool_log_line(json.dumps(compact, separators=(",", ":"))[:600])
    return ""


def classify_tool_log_level(line: str, stream: str = "stdout") -> str:
    """Classify a normalized event without treating JSON field names as failures."""
    lowered = line.lower()
    if re.search(r"(?:fatal|exception|traceback|\bfailed\b|\bfailure\b)", lowered):
        return "error"
    if re.search(r"(?:\bwarn(?:ing)?\b|timed?\s*out|rate.?limit|retry|connection reset)", lowered):
        return "warn"
    return "info"


def _mirror_tool_log(msg: dict[str, Any]) -> None:
    """Mirror sampled tool output into worker/API container logs."""
    enabled = os.environ.get("VAPT_TOOL_LOG_MIRROR", "true").lower() in {"1", "true", "yes"}
    if not enabled:
        return
    try:
        configured_max = int(os.environ.get("VAPT_TOOL_LOG_MIRROR_MAX_CHARS", "1000"))
    except ValueError:
        configured_max = 1000
    max_chars = max(120, min(configured_max, 2000))
    rendered = str(msg.get("line") or "")[:max_chars]
    level = str(msg.get("level") or "info")
    if level == "error":
        log = logger.error
    elif level == "warn":
        log = logger.warning
    else:
        # Many CLI tools write normal progress to stderr; the stream alone is
        # not a reliable severity signal.
        log = logger.info
    log(
        "[tool_stream] scan={scan} agent={agent} phase={phase} tool={tool} stream={stream} | {line}",
        scan=msg.get("scan_id", ""),
        agent=msg.get("agent", ""),
        phase=msg.get("phase", ""),
        tool=msg.get("tool", ""),
        stream=msg.get("stream", "stdout"),
        line=rendered,
    )


async def _get_publisher() -> Any:
    """Return a cached redis.asyncio client for publishing, or None if disabled."""
    global _pub_client, _pub_disabled
    if _pub_disabled:
        return None
    if _pub_client is not None:
        return _pub_client
    url = _event_redis_url()
    if not url:
        _pub_disabled = True
        return None
    try:
        import redis.asyncio as aioredis

        _pub_client = aioredis.from_url(url, encoding="utf-8", decode_responses=True)
        return _pub_client
    except Exception as exc:  # never let logging break tool execution
        logger.debug("[live_log] publisher unavailable: {err}", err=exc)
        _pub_disabled = True
        return None


async def publish_tool_log(
    line: str,
    *,
    scan_id: str = "",
    tool: str = "",
    agent: str = "",
    phase: str = "",
    stream: str = "stdout",
) -> None:
    """Best-effort publish of one tool-log line. Never raises."""
    if not scan_id or not line:
        return
    prepared = prepare_tool_log_line(line, tool)
    if not prepared:
        return
    msg = {
        "scan_id": scan_id,
        "tool": tool,
        "agent": agent,
        "phase": phase,
        "stream": stream,
        "line": prepared,
        "level": classify_tool_log_level(prepared, stream),
        "ts": time.time(),
    }
    _mirror_tool_log(msg)
    client = await _get_publisher()
    if client is None:
        return
    try:
        await client.publish(TOOL_LOG_CHANNEL, json.dumps(msg))
    except Exception as exc:
        logger.debug("[live_log] publish failed: {err}", err=exc)


class LineThrottler:
    """Bounds live-log volume per tool run: a rate cap and a hard total cap.

    Prevents a chatty tool from flooding the SSE bus. Dropped lines are still
    captured in full in the durable artifact file — only the *live* view is
    sampled.
    """

    def __init__(self, max_lines: int = 400, max_per_sec: float = 20.0) -> None:
        self._max_lines = max_lines
        self._min_interval = 1.0 / max_per_sec if max_per_sec > 0 else 0.0
        self._count = 0
        self._last = 0.0

    def allow(self) -> bool:
        if self._count >= self._max_lines:
            return False
        now = time.monotonic()
        if self._min_interval and (now - self._last) < self._min_interval:
            return False
        self._count += 1
        self._last = now
        return True


# ── Subscriber (API) ─────────────────────────────────────────────────────────

async def subscribe_tool_logs(handler: Callable[[dict], Awaitable[None]]) -> None:
    """Subscribe to the tool-log channel and invoke ``handler`` per message.

    Runs until cancelled. Reconnects on transient errors. Intended to be
    launched as a background task by the API on startup.
    """
    url = _event_redis_url()
    if not url:
        logger.info("[live_log] No event Redis configured — live tool-log streaming disabled")
        return

    import asyncio

    while True:
        try:
            import redis.asyncio as aioredis

            client = aioredis.from_url(url, encoding="utf-8", decode_responses=True)
            pubsub = client.pubsub()
            await pubsub.subscribe(TOOL_LOG_CHANNEL)
            logger.info("[live_log] Subscribed to {ch} for live tool logs", ch=TOOL_LOG_CHANNEL)
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                try:
                    data = json.loads(message["data"])
                except Exception:
                    continue
                try:
                    await handler(data)
                except Exception as exc:
                    logger.debug("[live_log] handler error: {err}", err=exc)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("[live_log] subscriber error, retrying in 3s: {err}", err=exc)
            await asyncio.sleep(3)
