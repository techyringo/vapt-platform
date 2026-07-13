"""
VAPT Platform — Production Web API (FastAPI)

This is the API layer that connects the Next.js frontend to the Python backend.

Endpoints
---------
  POST /api/scans/start         Start scan, returns scan_id IMMEDIATELY
  GET  /api/scans               List all scans with severity counts
  GET  /api/scans/{id}          Full scan detail with agent status
  GET  /api/scans/{id}/findings Findings with filters (severity, agent, status)
  POST /api/scans/{id}/stop     Stop/cancel a running scan
  GET  /api/scans/{id}/agents   Real-time agent status
  GET  /api/scans/{id}/report   Download audit-ready report
  GET  /api/modes               Available scan modes (VA-only, IoT, etc.)
  GET  /api/stream              SSE real-time event stream
  GET  /api/health              Health check with NVD stats
  GET  /api/nvd/stats           NVD verification statistics
  GET  /api/tools/status        Which tools are available

Bug history
-----------
The previous implementation declared ``manager`` and ``config`` as
``@property`` objects *inside* ``create_app``. A ``property`` is a
descriptor, not a callable, so every ``manager(app)`` invocation raised
``TypeError: 'property' object is not callable`` — crashing every
endpoint. This file replaces that pattern with explicit getter functions
stored on ``app.state``.
"""

import asyncio
import copy
import os
import re
import json
import time
from pathlib import Path
from typing import Any, Optional
from datetime import datetime
from urllib.parse import urlparse, urlunparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from sse_starlette.sse import EventSourceResponse
from pydantic import BaseModel

from loguru import logger

# Ensure backend modules are importable regardless of CWD
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.display import display_port, display_target, redact_display_text
from utils.logging import configure_runtime_logging
from utils.env import env_configured, normalize_api_key_aliases

normalize_api_key_aliases()
configure_runtime_logging()

RUNTIME_MARKER = "vapt-runtime-2026-07-07-observable-tools-v1"


# ─── Request Models ───────────────────────────────────────────────

class ScanRequest(BaseModel):
    targets: list[str]
    mode: str = "full_vapt"
    name: str = ""
    scope_config: Optional[dict] = None


class ScanStopRequest(BaseModel):
    reason: str = "User cancelled"


class ApiImportRequest(BaseModel):
    """Import an OpenAPI/Swagger spec or Postman collection into endpoints."""
    spec: str                       # raw JSON or YAML text of the spec/collection
    base_url: str = ""              # fallback base URL when the spec omits servers


class ToolSelectionRequest(BaseModel):
    phase: Optional[str] = None
    target_layer: Optional[str] = None
    categories: list[str] = []
    detected_tech: list[str] = []
    include_aggressive: bool = False


class RecoveryRequest(BaseModel):
    apply: bool = False
    stale_scan_age_seconds: int = 3600
    inactive_scan_idle_seconds: int = 900
    clear_queue: bool = False


class LLMConfigRequest(BaseModel):
    """Frontend-driven LLM configuration (runtime, no code/config edit needed).

    ``api_key`` is stored locally (single-tenant) so cloud / Basic-Auth
    endpoints can be configured from the UI. Pass an empty string to preserve
    the previously stored key (so the UI never round-trips the secret).
    """
    provider: str
    model: str
    base_url: str = ""
    verify_ssl: bool = True
    api_key: str = ""
    api_key_env: str = ""
    analysis_model: str = ""
    report_model: str = ""
    review_model: str = ""
    temperature: float = 0.3
    max_tokens: int = 4096
    max_rpm: int = 40
    fallback_providers: list[dict[str, Any]] = []
    enabled: bool = True
    allow_fallbacks: bool = True


class LLMTestRequest(BaseModel):
    """Probe a candidate LLM endpoint without persisting it."""
    provider: str
    model: str = ""
    base_url: str = ""
    verify_ssl: bool = True
    api_key: str = ""
    api_key_env: str = ""


API_KEY_GROUPS: dict[str, list[str]] = {
    "llm": [
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
        "GROQ_API_KEY", "TOGETHER_API_KEY", "NVIDIA_API_KEY",
    ],
    "intel": [
        "NVD_API_KEY", "SHODAN_API_KEY", "CENSYS_API_ID",
        "CENSYS_API_SECRET", "SECURITYTRAILS_API_KEY",
    ],
    "cms": ["WPSCAN_API_TOKEN"],
    "platform": ["VAPT_API_KEY"],
}


def api_key_status_payload() -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for group, keys in API_KEY_GROUPS.items():
        groups[group] = [
            {
                "name": f"{group.upper()} credential {index}",
                "configured": env_configured(key),
            }
            for index, key in enumerate(keys, start=1)
        ]
    return {
        "groups": groups,
        "summary": {
            group: {
                "configured": sum(1 for item in items if item["configured"]),
                "total": len(items),
            }
            for group, items in groups.items()
        },
        "secrets_returned": False,
        "credential_names_returned": False,
        "storage_location_returned": False,
    }


# ─── Helpers (singletons live on app.state) ───────────────────────

def _config_path_for(app: FastAPI) -> str:
    """Resolve the config.yaml path used by this app instance."""
    explicit = getattr(app.state, "_config_path", None)
    if explicit:
        return explicit
    return str(Path(__file__).resolve().parent.parent / "config.yaml")


def get_manager(app: FastAPI):
    """Lazily build and cache the ScanManager on app.state."""
    mgr = getattr(app.state, "_manager", None)
    if mgr is None:
        from services.scan_manager import ScanManager
        from core.config import AppConfig
        cfg_path = _config_path_for(app)
        try:
            config = AppConfig.load(cfg_path)
        except Exception as exc:
            logger.warning("Failed to load config {p}: {e} — using defaults", p=cfg_path, e=exc)
            config = AppConfig()
        app.state._config = config
        app.state._manager = ScanManager(config)
    return app.state._manager


def get_config(app: FastAPI):
    """Lazily build and cache the AppConfig on app.state."""
    cfg = getattr(app.state, "_config", None)
    if cfg is None:
        from core.config import AppConfig
        cfg_path = _config_path_for(app)
        try:
            cfg = AppConfig.load(cfg_path)
        except Exception as exc:
            logger.warning("Failed to load config {p}: {e} — using defaults", p=cfg_path, e=exc)
            cfg = AppConfig()
        app.state._config = cfg
    return cfg


# ─── App Factory ──────────────────────────────────────────────────

def create_app(config_path: Optional[str] = None) -> FastAPI:
    """Create and configure the production FastAPI application."""
    from web.auth import api_key_middleware, auth_enabled

    app = FastAPI(
        title="VAPT Platform API",
        description="AI-Augmented Vulnerability Assessment & Penetration Testing Platform",
        version="2.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # ── CORS ──────────────────────────────────────────────────────────
    # Restrict to the configured frontend origin when VAPT_CORS_ORIGINS is set.
    # Default allows same-origin requests from the bundled Next.js frontend only.
    cors_origins_raw = os.environ.get("VAPT_CORS_ORIGINS", "").strip()
    cors_origins = (
        [o.strip() for o in cors_origins_raw.split(",") if o.strip()]
        if cors_origins_raw
        else ["http://localhost:3000", "http://frontend:3000"]
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-API-Key", "Authorization"],
    )

    # ── Auth ──────────────────────────────────────────────────────────
    app.middleware("http")(api_key_middleware)

    # Lazy-loaded state slots
    app.state._manager = None
    app.state._config = None
    app.state._config_path = config_path

    # ── Startup: validate shared-dir + pre-pull images ────────────────
    @app.on_event("startup")
    async def _startup() -> None:
        from tools.runner import validate_shared_dir
        ok, msg = validate_shared_dir()
        if not ok:
            logger.error("[startup] Shared-dir FAILED: {msg}", msg=msg)
            logger.error(
                "[startup] Tool input files will not reach Docker containers. "
                "Check VAPT_SHARED_HOST_DIR in your .env / docker-compose.yml."
            )
        else:
            logger.info("[startup] Shared-dir OK")

        redis_url = os.environ.get("REDIS_URL", "")
        if redis_url:
            logger.info(
                "[startup] ARQ worker queue configured at {url} — "
                "tool execution will be handled by worker containers.",
                url=redis_url,
            )
        else:
            logger.warning(
                "[startup] REDIS_URL not set — tools will run inline in the API process. "
                "Set REDIS_URL and scale worker containers for production use."
            )

        # Start the live tool-log relay so the UI can stream tool output.
        try:
            get_manager(app).start_live_log_consumer()
        except Exception as exc:
            logger.warning("[startup] Live tool-log consumer failed to start: {e}", e=exc)

        if auth_enabled():
            logger.info("[startup] API key authentication ENABLED")
        else:
            logger.warning(
                "[startup] VAPT_API_KEY not set — API is OPEN. "
                "Set VAPT_API_KEY in .env before exposing this service."
            )

    # ─── Health & System Info ───────────────────────────────────

    async def llm_status_payload(probe: bool = True) -> dict[str, Any]:
        """Return redacted LLM readiness and lightweight connectivity status."""
        cfg = get_config(app)
        try:
            from core.runtime_config import apply_runtime_llm_overlay
            apply_runtime_llm_overlay(cfg)
        except Exception:
            pass
        enabled = (
            bool(cfg.llm.enabled)
            if cfg.llm.enabled is not None
            else os.environ.get("VAPT_LLM_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}
        )
        provider = cfg.llm.provider
        model = cfg.llm.model
        base_url = (cfg.llm.base_url or "").rstrip("/")
        allow_fallbacks = (
            bool(cfg.llm.allow_fallbacks)
            if cfg.llm.allow_fallbacks is not None
            else os.environ.get("VAPT_LLM_ALLOW_FALLBACKS", "").strip().lower() in {"1", "true", "yes", "on"}
        )
        status: dict[str, Any] = {
            "enabled": enabled,
            "provider": provider,
            "model": model,
            "base_url": base_url,
            "allow_fallbacks": allow_fallbacks,
            "available_providers": [],
            "reachable": False,
            "models": [],
            "selected_model_present": None,
            "error": "",
        }
        try:
            from tools.llm_client import LLMClient
            client = LLMClient(cfg)
            status["available_providers"] = client.get_available_providers()
        except Exception as exc:
            status["error"] = f"{type(exc).__name__}: {exc!r}"
            return status

        if not enabled or not probe:
            status["reachable"] = None if enabled and not probe else False
            return status

        if provider == "ollama":
            try:
                import httpx
                async with httpx.AsyncClient(timeout=8) as client:
                    resp = await client.get(f"{base_url or 'http://localhost:11434'}/api/tags")
                if resp.status_code != 200:
                    status["error"] = f"HTTP {resp.status_code}: {resp.text[:200]}"
                    return status
                payload = resp.json()
                models = [
                    item.get("name") or item.get("model")
                    for item in payload.get("models", [])
                    if item.get("name") or item.get("model")
                ]
                status["models"] = models
                status["selected_model_present"] = model in models
                status["reachable"] = True
            except Exception as exc:
                status["error"] = f"{type(exc).__name__}: {exc!r}"
        else:
            status["reachable"] = bool(status["available_providers"])
            status["selected_model_present"] = None
        return status

    @app.get("/api/health")
    async def health():
        from web.auth import auth_enabled
        mgr = get_manager(app)
        all_scans = mgr.list_scans()
        redis_url = os.environ.get("REDIS_URL", "")
        queue_name = os.environ.get("VAPT_ARQ_QUEUE", "vapt:tools")
        health_key = os.environ.get("VAPT_ARQ_HEALTH_KEY", f"{queue_name}:health")
        redis_ok = False
        redis_error = ""
        queue_depth = None
        deferred_depth = None
        queue_type = ""
        worker_health_present = False
        worker_health_ttl = None
        worker_health_value = ""
        if redis_url:
            try:
                import redis.asyncio as aioredis
                r = aioredis.from_url(redis_url, socket_connect_timeout=2)
                await r.ping()
                raw_health = await r.get(health_key)
                worker_health_present = raw_health is not None
                worker_health_ttl = await r.ttl(health_key)
                if raw_health:
                    worker_health_value = raw_health.decode(errors="replace") if isinstance(raw_health, bytes) else str(raw_health)
                raw_type = await r.type(queue_name)
                queue_type = raw_type.decode() if isinstance(raw_type, bytes) else str(raw_type)
                if queue_type == "zset":
                    queue_depth = await r.zcard(queue_name)
                elif queue_type == "list":
                    queue_depth = await r.llen(queue_name)
                elif queue_type == "stream":
                    queue_depth = await r.xlen(queue_name)
                elif queue_type in {"none", ""}:
                    queue_depth = 0
                deferred_key = f"{queue_name}:deferred"
                raw_deferred_type = await r.type(deferred_key)
                deferred_type = raw_deferred_type.decode() if isinstance(raw_deferred_type, bytes) else str(raw_deferred_type)
                if deferred_type == "zset":
                    deferred_depth = await r.zcard(deferred_key)
                elif deferred_type in {"none", ""}:
                    deferred_depth = 0
                await r.aclose()
                redis_ok = True
            except Exception as exc:
                redis_error = f"{type(exc).__name__}: {exc!r}"
                redis_ok = False
        return {
            "status": "ok",
            "version": "2.0.0",
            "runtime_marker": RUNTIME_MARKER,
            "timestamp": datetime.utcnow().isoformat(),
            "active_scans": sum(1 for s in all_scans if s["status"] == "running"),
            "total_scans": len(all_scans),
            "nvd": mgr.nvd.stats,
            "llm": await llm_status_payload(probe=False),
            "auth_enabled": auth_enabled(),
            "worker_queue": {
                "configured": bool(redis_url),
                "reachable": redis_ok,
                "url": redis_url.split("@")[-1] if "@" in redis_url else redis_url,
                "queue_name": queue_name,
                "health_key": health_key,
                "worker_health_present": worker_health_present,
                "worker_health_ttl": worker_health_ttl,
                "worker_health_value": worker_health_value[:300],
                "queue_type": queue_type,
                "queued_jobs": queue_depth,
                "deferred_jobs": deferred_depth,
                "error": redis_error,
            },
        }

    @app.get("/api/nvd/stats")
    async def nvd_stats():
        mgr = get_manager(app)
        return {"nvd_service": mgr.nvd.stats}

    @app.get("/api/system/llm")
    async def llm_status():
        """Return LLM provider/model readiness without exposing secrets."""
        return await llm_status_payload(probe=True)

    # ─── Runtime LLM Configuration (frontend-configurable, no hardcoded model) ──

    def _public_llm_config(cfg) -> dict[str, Any]:
        """Return the effective LLM config with secrets redacted (has_api_key bool)."""
        llm = cfg.llm
        return {
            "provider": llm.provider,
            "model": llm.model,
            "base_url": llm.base_url or "",
            "verify_ssl": getattr(llm, "verify_ssl", True),
            "api_key_env": llm.api_key_env or "",
            "has_api_key": bool(getattr(llm, "api_key", "") or os.environ.get(llm.api_key_env, "")),
            "analysis_model": llm.analysis_model or llm.model,
            "report_model": llm.report_model or llm.model,
            "review_model": getattr(llm, "review_model", "") or llm.analysis_model or llm.model,
            "temperature": llm.temperature,
            "max_tokens": llm.max_tokens,
            "max_rpm": getattr(llm, "max_rpm", 40),
            "fallback_providers": [
                {
                    "provider": p.get("provider", ""),
                    "model": p.get("model", ""),
                    "base_url": p.get("base_url", ""),
                    "api_key_env": p.get("api_key_env", ""),
                    "verify_ssl": p.get("verify_ssl", True),
                    "max_rpm": int(p.get("max_rpm", 40)),
                    "has_api_key": bool(p.get("api_key", "") or os.environ.get(p.get("api_key_env", ""), "")),
                }
                for p in (llm.fallback_providers or [])
            ],
            "enabled": getattr(llm, "enabled", None),
            "allow_fallbacks": getattr(llm, "allow_fallbacks", None),
        }

    def _model_present(model: str, models: list[str]):
        """Tag-tolerant membership: ``llama3.2`` matches ``llama3.2:latest`` (Ollama default tag)."""
        if not model or not models:
            return None
        return any(model == m or m.startswith(model + ":") or model.startswith(m + ":") for m in models)

    def _strip_endpoint_path(base_url: str, suffixes: tuple[str, ...]) -> str:
        raw = (base_url or "").rstrip("/")
        if not raw:
            return ""
        parsed = urlparse(raw)
        path = parsed.path.rstrip("/")
        for suffix in suffixes:
            suffix = suffix.rstrip("/")
            if path == suffix or path.endswith(suffix):
                new_path = path[: -len(suffix)].rstrip("/")
                return urlunparse(parsed._replace(path=new_path, params="", query="", fragment="")).rstrip("/")
        return raw

    def _normalise_llm_endpoint(provider: str, base_url: str) -> tuple[str, str]:
        provider = (provider or "").lower().strip()
        base_url = (base_url or "").strip().rstrip("/")
        parsed_path = urlparse(base_url).path.rstrip("/")

        if provider == "ollama" and parsed_path.endswith("/chat"):
            provider = "http_basic_chat"
        if provider == "openai_compat":
            base_url = _strip_endpoint_path(base_url, ("/v1/chat/completions", "/v1/completions", "/v1/models", "/v1"))
        elif provider == "ollama":
            base_url = _strip_endpoint_path(base_url, ("/api/generate", "/api/chat", "/api/tags"))
        elif provider == "http_basic_chat":
            base_url = _strip_endpoint_path(base_url, ("/chat", "/models"))
        return provider, base_url

    async def _probe_llm(provider: str, model: str, base_url: str, api_key: str,
                         api_key_env: str = "", verify_ssl: bool = True) -> dict[str, Any]:
        """Probe a candidate LLM endpoint: reachable + available models.

        Covers ollama (/api/tags), http_basic_chat (Basic-auth <models_path>),
        and the OpenAI-compatible family (/v1/models).
        """
        provider, base_url = _normalise_llm_endpoint(provider, base_url)
        out: dict[str, Any] = {
            "reachable": False,
            "inference_ready": False,
            "latency_ms": None,
            "models": [],
            "selected_model_present": None,
            "error": "",
        }
        try:
            import httpx
            if provider == "ollama":
                url = base_url or "http://localhost:11434"
                async with httpx.AsyncClient(timeout=10, verify=verify_ssl) as c:
                    r = await c.get(f"{url}/api/tags")
                if r.status_code != 200:
                    out["error"] = f"HTTP {r.status_code}: {r.text[:200]}"
                    return out
                models = [it.get("name") or it.get("model") for it in r.json().get("models", []) if it.get("name") or it.get("model")]
                out["models"] = models
                out["reachable"] = True
                out["selected_model_present"] = _model_present(model, models)
                if model:
                    started = time.monotonic()
                    async with httpx.AsyncClient(timeout=30, verify=verify_ssl) as c:
                        completion = await c.post(
                            f"{url}/api/chat",
                            json={"model": model, "messages": [{"role": "user", "content": "Reply with OK."}], "stream": False},
                        )
                    out["latency_ms"] = round((time.monotonic() - started) * 1000)
                    out["inference_ready"] = completion.status_code == 200
                    if not out["inference_ready"]:
                        out["error"] = f"Inference failed (HTTP {completion.status_code}): {completion.text[:200]}"
            elif provider == "http_basic_chat":
                if not base_url:
                    out["error"] = "base_url required"
                    return out
                auth = api_key or os.environ.get(api_key_env, "")
                if not auth or ":" not in auth:
                    out["error"] = f"{api_key_env or 'api_key'} must be set as 'username:password'"
                    return out
                u, p = auth.split(":", 1)
                async with httpx.AsyncClient(timeout=10, verify=verify_ssl) as c:
                    r = await c.get(f"{base_url}/models", auth=(u, p))
                if r.status_code == 200:
                    try:
                        models = [m.get("name") or m.get("model") for m in r.json().get("models", []) if isinstance(m, dict)]
                    except Exception:
                        models = []
                    out["models"] = models
                    out["reachable"] = True
                    out["selected_model_present"] = _model_present(model, models)
                    if model:
                        started = time.monotonic()
                        async with httpx.AsyncClient(timeout=30, verify=verify_ssl) as c:
                            completion = await c.post(
                                f"{base_url}/chat",
                                auth=(u, p),
                                json={"model": model, "messages": [{"role": "user", "content": "Reply with OK."}]},
                            )
                        out["latency_ms"] = round((time.monotonic() - started) * 1000)
                        out["inference_ready"] = completion.status_code == 200
                        if not out["inference_ready"]:
                            out["error"] = f"Inference failed (HTTP {completion.status_code}): {completion.text[:200]}"
                else:
                    out["error"] = f"HTTP {r.status_code}: {r.text[:200]}"
            else:
                defaults = {"openai": "https://api.openai.com", "groq": "https://api.groq.com/openai", "together": "https://api.together.xyz"}
                url = base_url or defaults.get(provider, "")
                if not url:
                    out["error"] = "base_url required"
                    return out
                headers = {"Content-Type": "application/json"}
                key = (api_key or os.environ.get(api_key_env, "")).strip()
                if key.lower().startswith("bearer "):
                    key = key[7:].strip()
                if key:
                    headers["Authorization"] = f"Bearer {key}"
                async with httpx.AsyncClient(timeout=10, verify=verify_ssl) as c:
                    r = await c.get(f"{url}/v1/models", headers=headers)
                if r.status_code == 200:
                    models = [d.get("id") for d in r.json().get("data", []) if d.get("id")]
                    out["models"] = models
                    out["reachable"] = True
                    out["selected_model_present"] = (model in models) if model else None
                    if model:
                        started = time.monotonic()
                        async with httpx.AsyncClient(timeout=30, verify=verify_ssl) as c:
                            completion = await c.post(
                                f"{url}/v1/chat/completions",
                                headers=headers,
                                json={
                                    "model": model,
                                    "messages": [{"role": "user", "content": "Reply with OK."}],
                                    "temperature": 0,
                                    "max_tokens": 8,
                                },
                            )
                        out["latency_ms"] = round((time.monotonic() - started) * 1000)
                        if completion.status_code == 200:
                            out["inference_ready"] = True
                        elif completion.status_code in (401, 403):
                            out["error"] = (
                                f"Inference auth failed (HTTP {completion.status_code}). "
                                "Re-enter the API key; model listing alone does not validate inference credentials."
                            )
                        else:
                            out["error"] = f"Inference failed (HTTP {completion.status_code}): {completion.text[:200]}"
                elif r.status_code in (401, 403):
                    out["reachable"] = True
                    out["error"] = f"Auth failed (HTTP {r.status_code}) — endpoint reachable, key invalid"
                else:
                    out["error"] = f"HTTP {r.status_code}: {r.text[:200]}"
        except Exception as e:
            out["error"] = f"{type(e).__name__}: {e!r}"
        return out

    @app.get("/api/config/llm")
    async def get_llm_config_endpoint():
        """Return the effective (runtime-overlaid) LLM config, secrets redacted."""
        cfg = get_config(app)
        try:
            from core.runtime_config import apply_runtime_llm_overlay
            apply_runtime_llm_overlay(cfg)
        except Exception:
            pass
        return {"llm": _public_llm_config(cfg)}

    @app.put("/api/config/llm")
    async def put_llm_config_endpoint(req: LLMConfigRequest):
        """Persist frontend LLM settings and probe the endpoint.

        Empty ``api_key`` preserves the previously stored key. Invalidates the
        cached AppConfig so the next read (and every new LLMClient) picks up the
        new settings without a restart.
        """
        from core.runtime_config import get_runtime_llm, save_runtime_llm
        existing = get_runtime_llm() or {}
        primary_provider, primary_base_url = _normalise_llm_endpoint(req.provider, req.base_url)
        api_key = req.api_key if req.api_key else existing.get("api_key", "")
        # Preserve per-fallback secrets: a blank api_key means "keep stored"
        # (matched by provider+model+base_url), so re-saving the chain from the
        # UI never wipes a previously stored Basic-Auth / cloud key.
        existing_fb: dict[tuple, dict] = {}
        for f in (existing.get("fallback_providers") or []):
            if isinstance(f, dict):
                existing_fb[(f.get("provider"), f.get("model"), f.get("base_url"))] = f
                norm_provider, norm_base_url = _normalise_llm_endpoint(f.get("provider", ""), f.get("base_url", ""))
                existing_fb[(norm_provider, f.get("model"), norm_base_url)] = f
        merged_fb = []
        for f in req.fallback_providers:
            f = dict(f) if isinstance(f, dict) else {}
            f_provider, f_base_url = _normalise_llm_endpoint(f.get("provider", ""), f.get("base_url", ""))
            f["provider"] = f_provider
            f["base_url"] = f_base_url
            if not f.get("api_key"):
                prev = existing_fb.get((f.get("provider"), f.get("model"), f.get("base_url")))
                if prev and prev.get("api_key"):
                    f["api_key"] = prev["api_key"]
            merged_fb.append(f)
        llm = {
            "provider": primary_provider,
            "model": req.model,
            "base_url": primary_base_url,
            "verify_ssl": req.verify_ssl,
            "api_key_env": req.api_key_env,
            "api_key": api_key,
            "analysis_model": req.analysis_model or req.model,
            "report_model": req.report_model or req.model,
            "review_model": req.review_model or req.analysis_model or req.model,
            "temperature": req.temperature,
            "max_tokens": req.max_tokens,
            "max_rpm": req.max_rpm,
            "fallback_providers": merged_fb,
            "enabled": req.enabled,
            "allow_fallbacks": req.allow_fallbacks,
        }
        save_runtime_llm(llm)
        app.state._config = None  # invalidate cache → get_config re-applies overlay
        cfg = get_config(app)
        try:
            from core.runtime_config import apply_runtime_llm_overlay
            apply_runtime_llm_overlay(cfg)
        except Exception:
            pass
        probe = await _probe_llm(primary_provider, req.model, primary_base_url, api_key, req.api_key_env, req.verify_ssl)
        return {"llm": _public_llm_config(cfg), "probe": probe}

    @app.post("/api/config/llm/test")
    async def test_llm_config_endpoint(req: LLMTestRequest):
        """Probe a candidate LLM endpoint WITHOUT persisting (Test Connection)."""
        from core.runtime_config import get_runtime_llm
        rt = get_runtime_llm() or {}
        provider, base_url = _normalise_llm_endpoint(req.provider, req.base_url)
        api_key = req.api_key
        if not api_key:
            # Reuse the stored secret for the matching endpoint — primary first,
            # then fallbacks — so a Test with a blank key probes the saved creds.
            rt_provider, rt_base_url = _normalise_llm_endpoint(rt.get("provider", ""), rt.get("base_url", ""))
            if rt_provider == provider and rt_base_url == base_url:
                api_key = rt.get("api_key", "")
            else:
                for f in (rt.get("fallback_providers") or []):
                    if not isinstance(f, dict):
                        continue
                    f_provider, f_base_url = _normalise_llm_endpoint(f.get("provider", ""), f.get("base_url", ""))
                    if f_provider == provider and f_base_url == base_url:
                        api_key = f.get("api_key", "")
                        break
        api_key_env = req.api_key_env or (rt.get("api_key_env", "") if rt else "")
        probe = await _probe_llm(provider, req.model, base_url, api_key, api_key_env, req.verify_ssl)
        return {"probe": probe}

    def wordlist_status_payload() -> dict[str, Any]:
        """Return local wordlist readiness for audit/debug visibility."""
        roots = []
        for raw in [
            os.environ.get("VAPT_WORDLIST_DIR", "/app/wordlists"),
            str(Path(__file__).resolve().parent.parent / "wordlists"),
        ]:
            path = Path(raw)
            if path not in roots:
                roots.append(path)

        files: list[dict[str, Any]] = []
        seen_names: set[str] = set()
        for root in roots:
            if not root.exists() or not root.is_dir():
                continue
            for path in sorted(root.glob("*.txt")):
                if path.name in seen_names:
                    continue
                seen_names.add(path.name)
                try:
                    lines = [
                        line for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
                        if line.strip() and not line.strip().startswith("#")
                    ]
                except Exception:
                    lines = []
                files.append({
                    "name": path.name,
                    "path": str(path),
                    "entries": len(lines),
                    "size": path.stat().st_size if path.exists() else 0,
                })

        required = [
            "common-web.txt",
            "api-web.txt",
            "cms-web.txt",
            "sensitive-files.txt",
            "s3-buckets.txt",
        ]
        present = {item["name"] for item in files}
        missing = [name for name in required if name not in present]
        return {
            "roots": [str(root) for root in roots],
            "required": required,
            "missing": missing,
            "ready": not missing,
            "total_files": len(files),
            "total_entries": sum(int(item.get("entries") or 0) for item in files),
            "files": files,
        }

    @app.get("/api/tools/status")
    async def tools_status():
        """Check tool availability and capability metadata."""
        import os
        import shutil
        import subprocess
        from core.tool_registry import TOOL_CAPABILITIES, all_tool_capabilities

        cfg = get_config(app)
        docker_cli_available = shutil.which("docker") is not None
        docker_socket_available = os.path.exists("/var/run/docker.sock")
        docker_daemon_reachable = False
        local_docker_images: set[str] = set()
        if docker_cli_available:
            try:
                docker_daemon_reachable = subprocess.run(
                    ["docker", "info", "--format", "{{.ServerVersion}}"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                ).returncode == 0
            except Exception:
                docker_daemon_reachable = False
            if docker_daemon_reachable:
                try:
                    images = subprocess.run(
                        ["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        timeout=8,
                        check=False,
                        text=True,
                    )
                    if images.returncode == 0:
                        local_docker_images = {line.strip() for line in images.stdout.splitlines() if line.strip()}
                except Exception:
                    local_docker_images = set()
        docker_available = docker_cli_available and docker_daemon_reachable
        api_key_tools = {
            "shodan": ["SHODAN_API_KEY"],
            "censys": ["CENSYS_API_ID", "CENSYS_API_SECRET"],
            "securitytrails": ["SECURITYTRAILS_API_KEY"],
        }
        internal_tools = {"secretfinder"}
        tools = {}
        tool_names = sorted(set(cfg.tools) | set(TOOL_CAPABILITIES))
        for tool_name in tool_names:
            tool_cfg = cfg.get_tool_config(tool_name)
            capability = TOOL_CAPABILITIES.get(tool_name)
            available = shutil.which(tool_name) is not None
            has_docker = bool(tool_cfg.docker_image)
            required_keys = list(dict.fromkeys([
                *(api_key_tools.get(tool_name, [])),
                *((capability.requires_api_keys if capability else []) or []),
            ]))
            missing_keys = [key for key in required_keys if not env_configured(key)]
            image_present = bool(tool_cfg.docker_image and tool_cfg.docker_image in local_docker_images)
            if not tool_cfg.enabled:
                will_use = "disabled"
                availability = "disabled_by_config"
            elif has_docker and docker_available:
                will_use = "docker"
                availability = "ready" if image_present else "pullable"
            elif available:
                will_use = "local"
                availability = "ready"
            elif tool_name in internal_tools:
                will_use = "internal"
                availability = "ready"
            elif required_keys:
                will_use = "api" if not missing_keys else "needs_api_key"
                availability = "ready" if not missing_keys else "needs_api_key"
            else:
                will_use = "unavailable"
                availability = "missing"
            tools[tool_name] = {
                "enabled": tool_cfg.enabled,
                "available_locally": available,
                "docker_available": docker_available,
                "docker_image": tool_cfg.docker_image,
                "docker_image_present": image_present,
                "will_use": will_use,
                "availability": availability,
                "requires_credentials": bool(required_keys),
                "required_credentials_count": len(required_keys),
                "missing_credentials": bool(missing_keys),
                "missing_credentials_count": len(missing_keys),
                "display_name": capability.display_name if capability else tool_name,
                "phases": capability.phases if capability else [],
                "categories": capability.categories if capability else [],
                "target_layers": capability.target_layers if capability else [],
                "safe_by_default": capability.safe_by_default if capability else True,
                "aggressive": capability.aggressive if capability else False,
                "run_when": capability.run_when if capability else [],
                "evidence": capability.evidence if capability else [],
                "notes": capability.notes if capability else "",
            }
        summary = {
            "total": len(tools),
            "docker": sum(1 for t in tools.values() if t["will_use"] == "docker"),
            "local": sum(1 for t in tools.values() if t["will_use"] == "local"),
            "internal": sum(1 for t in tools.values() if t["will_use"] == "internal"),
            "api": sum(1 for t in tools.values() if t["will_use"] == "api"),
            "needs_api_key": sum(1 for t in tools.values() if t["will_use"] == "needs_api_key"),
            "pullable": sum(1 for t in tools.values() if t["availability"] == "pullable"),
            "disabled": sum(1 for t in tools.values() if t["availability"] == "disabled_by_config"),
            "unavailable": sum(1 for t in tools.values() if t["will_use"] == "unavailable"),
        }
        phase_summary: dict[str, int] = {}
        for item in tools.values():
            for phase in item["phases"]:
                phase_summary[phase] = phase_summary.get(phase, 0) + 1
        return {
            "docker": {
                "cli_available": docker_cli_available,
                "socket_available": docker_socket_available,
                "daemon_reachable": docker_daemon_reachable,
            },
            "scanner_ready": docker_available,
            "summary": summary,
            "phase_summary": phase_summary,
            "api_keys": api_key_status_payload(),
            "wordlists": wordlist_status_payload(),
            "capabilities": all_tool_capabilities(),
            "tools": tools,
        }

    @app.get("/api/system/diagnostics")
    async def system_diagnostics():
        """Return one-page operational diagnostics for the VA runtime.

        This endpoint is intentionally more detailed than /api/health. It is
        meant for engineering triage: prove which image is running, whether the
        queue is reachable, whether Docker isolation is available, and whether
        recent scans actually exercised the expected VA agents/tools.
        """
        from tools.runner import validate_shared_dir

        mgr = get_manager(app)
        scans = mgr.list_scans()
        health_payload = await health()
        tools_payload = await tools_status()
        llm_payload = await llm_status_payload(probe=True)
        shared_ok, shared_msg = validate_shared_dir()

        latest_scan = scans[0] if scans else None
        latest_scan_id = latest_scan.get("scan_id") if latest_scan else None
        latest_agents: dict[str, Any] = {}
        latest_events: list[dict[str, Any]] = []
        if latest_scan_id:
            latest_agents = mgr.get_agent_status(latest_scan_id)
            latest_events = mgr.get_recent_events(scan_id=latest_scan_id, limit=25)

        required_va_agents = ["recon", "enum", "vuln_scanner", "reporter"]
        latest_agent_names = set(latest_agents)
        missing_required_agents = [
            agent for agent in required_va_agents if agent not in latest_agent_names
        ] if latest_scan else required_va_agents

        stale_running_scans: list[dict[str, Any]] = []
        inactive_running_scans: list[dict[str, Any]] = []
        now = datetime.utcnow()
        for scan in scans:
            if scan.get("status") != "running":
                continue
            started_raw = scan.get("start_time") or ""
            try:
                started = datetime.fromisoformat(started_raw)
            except (TypeError, ValueError):
                started = now
            age_seconds = max(0.0, (now - started).total_seconds())
            if age_seconds > 3600:
                stale_running_scans.append({
                    "scan_id": scan.get("scan_id"),
                    "target": scan.get("targets", []),
                    "phase": scan.get("current_phase", ""),
                    "age_seconds": age_seconds,
                })
            recent_scan_events = mgr.get_recent_events(scan_id=scan.get("scan_id"), limit=10)
            last_event_ts = ""
            if recent_scan_events:
                last_event_ts = recent_scan_events[-1].get("timestamp", "")
            try:
                last_event_at = datetime.fromisoformat(last_event_ts) if last_event_ts else started
            except (TypeError, ValueError):
                last_event_at = started
            idle_seconds = max(0.0, (now - last_event_at).total_seconds())
            if idle_seconds > 300:
                inactive_running_scans.append({
                    "scan_id": scan.get("scan_id"),
                    "target": scan.get("targets", []),
                    "phase": scan.get("current_phase", ""),
                    "age_seconds": age_seconds,
                    "idle_seconds": idle_seconds,
                    "last_event": last_event_ts,
                })

        unavailable_tools = [
            name for name, tool in tools_payload["tools"].items()
            if tool.get("will_use") == "unavailable"
        ][:25]
        pullable_tools = [
            name for name, tool in tools_payload["tools"].items()
            if tool.get("availability") == "pullable"
        ][:25]

        checks = {
            "new_backend_image": health_payload.get("runtime_marker") == RUNTIME_MARKER,
            "redis_reachable": bool(health_payload.get("worker_queue", {}).get("reachable")),
            "worker_health_present": bool(health_payload.get("worker_queue", {}).get("worker_health_present")),
            "docker_isolation_ready": bool(tools_payload.get("docker", {}).get("daemon_reachable")),
            "shared_dir_ready": shared_ok,
            "llm_ready_when_enabled": (not llm_payload.get("enabled")) or bool(llm_payload.get("reachable")),
            "latest_scan_has_required_va_agents": not missing_required_agents,
            "no_stale_running_scans": not stale_running_scans,
            "no_inactive_running_scans": not inactive_running_scans,
        }
        status = "ok" if all(checks.values()) else "attention"

        return {
            "status": status,
            "runtime_marker": RUNTIME_MARKER,
            "timestamp": now.isoformat(),
            "checks": checks,
            "health": health_payload,
            "shared_dir": {
                "ok": shared_ok,
                "message": shared_msg,
                "container_path": os.environ.get("VAPT_SHARED_DIR", "/tmp/vapt-shared"),
                "host_path": os.environ.get("VAPT_SHARED_HOST_DIR", ""),
            },
                "tooling": {
                    "docker": tools_payload["docker"],
                    "summary": tools_payload["summary"],
                    "phase_summary": tools_payload["phase_summary"],
                    "unavailable_sample": unavailable_tools,
                    "pullable_sample": pullable_tools,
                    "wordlists": tools_payload.get("wordlists", {}),
                },
            "llm": llm_payload,
            "latest_scan": latest_scan,
            "latest_agents": latest_agents,
            "latest_events": latest_events,
            "missing_required_agents": missing_required_agents,
            "stale_running_scans": stale_running_scans,
            "inactive_running_scans": inactive_running_scans,
        }

    @app.get("/api/system/api-keys")
    async def api_keys_status():
        """Return redacted API-key readiness grouped by integration family."""
        return api_key_status_payload()

    def _log_dir() -> Path:
        raw = os.environ.get("VAPT_LOG_DIR", "/app/logs")
        path = Path(raw)
        if not path.is_absolute():
            path = Path.cwd() / path
        path.mkdir(parents=True, exist_ok=True)
        return path

    @app.get("/api/system/logs")
    async def list_log_files():
        """List runtime log files available for operator troubleshooting."""
        log_dir = _log_dir()
        files = []
        for path in sorted(log_dir.glob("*"), key=lambda item: item.stat().st_mtime, reverse=True):
            if not path.is_file():
                continue
            files.append({
                "name": path.name,
                "size": path.stat().st_size,
                "modified_at": datetime.utcfromtimestamp(path.stat().st_mtime).isoformat(),
                "download_url": f"/api/system/logs/{path.name}/download",
            })
        return {"log_dir": str(log_dir), "files": files}

    def _safe_log_path(filename: str) -> Path:
        if "/" in filename or "\\" in filename or filename in {"", ".", ".."}:
            raise HTTPException(status_code=400, detail="Invalid log filename")
        path = _log_dir() / filename
        if not path.exists() or not path.is_file():
            raise HTTPException(status_code=404, detail="Log file not found")
        return path

    @app.get("/api/system/logs/{filename}")
    async def tail_log_file(filename: str, lines: int = 300):
        """Return the last N lines of a runtime log file."""
        path = _safe_log_path(filename)
        max_lines = max(1, min(lines, 5000))
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Could not read log: {exc}") from exc
        tail = "\n".join(content.splitlines()[-max_lines:])
        return PlainTextResponse(tail, media_type="text/plain")

    @app.get("/api/system/logs/{filename}/download")
    async def download_log_file(filename: str):
        """Download a runtime log file."""
        path = _safe_log_path(filename)
        return FileResponse(
            path=str(path),
            filename=path.name,
            media_type="application/octet-stream",
        )

    @app.post("/api/tools/select")
    async def select_tools_for_context(request: ToolSelectionRequest):
        """Return target-aware tool choices for a phase/category/technology."""
        from core.tool_registry import public_tool_capability, select_tools

        status_payload = await tools_status()
        selected = select_tools(
            phase=request.phase,
            target_layer=request.target_layer,
            categories=request.categories,
            detected_tech=request.detected_tech,
            include_aggressive=request.include_aggressive,
        )
        tools = status_payload["tools"]
        return {
            "request": request.model_dump(),
            "tools": [
                {
                    **public_tool_capability(capability),
                    "status": tools.get(capability.name, {}),
                }
                for capability in selected
            ],
        }

    @app.post("/api/system/recover")
    async def recover_system(request: RecoveryRequest):
        """Recover from stale scans / abandoned ARQ jobs.

        Dry-run by default. Set ``apply=true`` to stop stale running scans.
        Set ``clear_queue=true`` as well to delete pending ARQ queue keys.
        """
        mgr = get_manager(app)
        now = datetime.utcnow()
        scans = mgr.list_scans()
        stale_scan_age = max(60, request.stale_scan_age_seconds)
        inactive_scan_idle = max(60, request.inactive_scan_idle_seconds)

        stale_scans: list[dict[str, Any]] = []
        inactive_scans: list[dict[str, Any]] = []
        for scan in scans:
            if scan.get("status") != "running":
                continue
            started_raw = scan.get("start_time") or ""
            try:
                started = datetime.fromisoformat(started_raw)
            except (TypeError, ValueError):
                started = now
            age_seconds = max(0.0, (now - started).total_seconds())
            if age_seconds >= stale_scan_age:
                stale_scans.append({
                    "scan_id": scan.get("scan_id"),
                    "targets": scan.get("targets", []),
                    "phase": scan.get("current_phase", ""),
                    "age_seconds": age_seconds,
                })
            recent_scan_events = mgr.get_recent_events(scan_id=scan.get("scan_id"), limit=10)
            last_event_ts = recent_scan_events[-1].get("timestamp", "") if recent_scan_events else ""
            try:
                last_event_at = datetime.fromisoformat(last_event_ts) if last_event_ts else started
            except (TypeError, ValueError):
                last_event_at = started
            idle_seconds = max(0.0, (now - last_event_at).total_seconds())
            if idle_seconds >= inactive_scan_idle:
                inactive_scans.append({
                    "scan_id": scan.get("scan_id"),
                    "targets": scan.get("targets", []),
                    "phase": scan.get("current_phase", ""),
                    "age_seconds": age_seconds,
                    "idle_seconds": idle_seconds,
                    "last_event": last_event_ts,
                })

        redis_report: dict[str, Any] = {
            "configured": False,
            "reachable": False,
            "queue_name": os.environ.get("VAPT_ARQ_QUEUE", "vapt:tools"),
            "deleted_keys": [],
            "error": "",
        }
        redis_url = os.environ.get("REDIS_URL", "")
        queue_name = redis_report["queue_name"]
        health_key = os.environ.get("VAPT_ARQ_HEALTH_KEY", f"{queue_name}:health")
        keys_to_clear = [queue_name, f"{queue_name}:deferred"]
        if redis_url:
            redis_report["configured"] = True
            try:
                import redis.asyncio as aioredis
                r = aioredis.from_url(redis_url, socket_connect_timeout=2)
                await r.ping()
                redis_report["reachable"] = True
                redis_report["health_key"] = health_key
                raw_health = await r.get(health_key)
                redis_report["worker_health_present"] = raw_health is not None
                redis_report["worker_health_ttl"] = await r.ttl(health_key)
                redis_report["queue_type"] = (
                    (await r.type(queue_name)).decode(errors="replace")
                )
                if redis_report["queue_type"] == "zset":
                    redis_report["queued_jobs"] = await r.zcard(queue_name)
                elif redis_report["queue_type"] == "list":
                    redis_report["queued_jobs"] = await r.llen(queue_name)
                else:
                    redis_report["queued_jobs"] = 0
                if request.apply and request.clear_queue:
                    for key in keys_to_clear:
                        deleted = await r.delete(key)
                        if deleted:
                            redis_report["deleted_keys"].append(key)
                await r.aclose()
            except Exception as exc:
                redis_report["error"] = f"{type(exc).__name__}: {exc!r}"

        actions: list[dict[str, Any]] = []
        scan_ids_to_stop = {
            item.get("scan_id") for item in [*stale_scans, *inactive_scans] if item.get("scan_id")
        }
        if request.apply:
            for scan_id in sorted(scan_ids_to_stop):
                try:
                    result = await mgr.stop_scan(scan_id)
                    actions.append({"scan_id": scan_id, "action": "stop_scan", "result": result})
                except Exception as exc:
                    actions.append({
                        "scan_id": scan_id,
                        "action": "stop_scan",
                        "error": f"{type(exc).__name__}: {exc!r}",
                    })

        return {
            "dry_run": not request.apply,
            "apply": request.apply,
            "clear_queue": request.clear_queue,
            "stale_scan_age_seconds": stale_scan_age,
            "inactive_scan_idle_seconds": inactive_scan_idle,
            "stale_scans": stale_scans,
            "inactive_scans": inactive_scans,
            "redis": redis_report,
            "actions": actions,
        }

    @app.get("/api/modes")
    async def get_modes():
        """Return available scan modes with their agent rosters."""
        mgr = get_manager(app)
        return {"modes": mgr.get_scan_modes()}

    # ─── Scan Management ────────────────────────────────────────

    @app.post("/api/scans/start")
    async def start_scan(request: ScanRequest):
        """Start a new VAPT scan. Returns IMMEDIATELY with scan_id;
        the scan runs in the background. Subscribe to /api/stream for updates."""
        if not request.targets:
            raise HTTPException(status_code=400, detail="At least one target is required")

        valid_modes = ["va_only", "full_vapt", "web_app", "api", "cloud", "iot_cctv", "custom"]
        if request.mode not in valid_modes:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid mode. Must be one of: {valid_modes}",
            )

        mgr = get_manager(app)
        result = await mgr.start_scan(
            targets=request.targets,
            mode=request.mode,
            scan_name=request.name,
            scope_config=request.scope_config,
        )
        return result

    @app.post("/api/import/spec")
    async def import_api_spec_endpoint(request: ApiImportRequest):
        """Parse an OpenAPI/Swagger/Postman spec into a normalised endpoint list.

        Feed the returned endpoints (or their URLs) into a new scan to test an
        API surface directly instead of relying only on crawling.
        """
        from services.api_import import import_api_spec

        result = import_api_spec(request.spec, fallback_base=request.base_url)
        if result.get("error") and not result.get("endpoints"):
            raise HTTPException(status_code=422, detail=result["error"])
        return result

    @app.get("/api/scans")
    async def list_scans():
        """List all scans with severity counts and status."""
        mgr = get_manager(app)
        return mgr.list_scans()

    @app.get("/api/scans/{scan_id}")
    async def get_scan(scan_id: str):
        """Get full scan details including agent status and all findings."""
        mgr = get_manager(app)
        scan = mgr.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan

    @app.post("/api/scans/{scan_id}/stop")
    async def stop_scan(scan_id: str, request: ScanStopRequest = ScanStopRequest()):
        """Stop or cancel a running scan."""
        mgr = get_manager(app)
        result = await mgr.stop_scan(scan_id)
        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])
        return result

    @app.delete("/api/scans/{scan_id}")
    async def delete_scan(scan_id: str):
        """Delete a non-running scan and its persisted data."""
        mgr = get_manager(app)
        result = await mgr.delete_scan(scan_id)
        if "error" in result:
            status_code = 404 if result["error"] == "Scan not found" else 400
            raise HTTPException(status_code=status_code, detail=result["error"])
        return result

    @app.get("/api/scans/{scan_id}/findings")
    async def get_findings(
        scan_id: str,
        severity: Optional[str] = None,
        agent: Optional[str] = None,
        status: Optional[str] = None,
        quarantined: Optional[bool] = None,
    ):
        """Get findings with optional filters.

        By default (``quarantined`` unset) all findings are returned. Pass
        ``quarantined=false`` for the report-grade set, or ``quarantined=true``
        to review what was quarantined.
        """
        mgr = get_manager(app)
        if scan_id not in mgr._scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        findings = mgr.get_findings(
            scan_id, severity=severity, agent=agent, status=status, quarantined=quarantined,
        )
        return {
            "scan_id": scan_id,
            "total": len(findings),
            "filtered": len(findings),
            "filters": {"severity": severity, "agent": agent, "status": status, "quarantined": quarantined},
            "findings": findings,
        }

    @app.get("/api/scans/{scan_id}/tool-runs")
    async def get_tool_runs(scan_id: str):
        """Return captured tool execution summaries for a scan."""
        mgr = get_manager(app)
        if scan_id not in mgr._scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        runs = mgr.get_tool_runs(scan_id)
        return {"scan_id": scan_id, "total": len(runs), "tool_runs": runs}

    @app.get("/api/scans/{scan_id}/tool-runs/{run_id}/artifact")
    async def download_tool_artifact(scan_id: str, run_id: int, stream: str = "stdout"):
        """Download captured stdout/stderr artifact for one tool run."""
        mgr = get_manager(app)
        artifact = mgr.get_tool_run_artifact(scan_id, run_id, stream)
        if not artifact:
            raise HTTPException(status_code=404, detail="Tool artifact not found")
        headers = {"Content-Disposition": f'attachment; filename="{artifact["filename"]}"'}
        return PlainTextResponse(
            content=artifact.get("content", ""),
            media_type="text/plain",
            headers=headers,
        )

    @app.get("/api/scans/{scan_id}/coverage")
    async def get_scan_coverage(scan_id: str):
        """Return P0 coverage contract for a scan."""
        mgr = get_manager(app)
        if scan_id not in mgr._scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {"scan_id": scan_id, "coverage": mgr.get_scan_coverage(scan_id)}

    @app.get("/api/scans/{scan_id}/assets")
    async def get_asset_graph(scan_id: str, asset_type: Optional[str] = None):
        """Return the persisted attack-surface graph for a scan."""
        mgr = get_manager(app)
        if scan_id not in mgr._scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        return mgr.get_asset_graph(scan_id, asset_type=asset_type)

    @app.get("/api/scans/{scan_id}/attack-surface/plan")
    async def get_attack_surface_plan(scan_id: str):
        """Return graph-driven capability recommendations for the scan."""
        mgr = get_manager(app)
        if scan_id not in mgr._scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        plan = mgr.build_attack_surface_plan(scan_id)
        status_payload = await tools_status()
        tool_status = status_payload.get("tools", {})
        tools_by_category: dict[str, list[dict]] = {}
        for name, tool in tool_status.items():
            for category in tool.get("categories", []):
                tools_by_category.setdefault(category, []).append({
                    "name": name,
                    "display_name": tool.get("display_name", name),
                    "availability": tool.get("availability"),
                    "will_use": tool.get("will_use"),
                    "aggressive": tool.get("aggressive", False),
                })
        for item in plan["planned_capabilities"]:
            candidates = []
            for category in item.get("categories", []):
                candidates.extend(tools_by_category.get(category, []))
            seen = set()
            item["candidate_tools"] = [
                candidate for candidate in candidates
                if not (candidate["name"] in seen or seen.add(candidate["name"]))
            ]
        for tools in plan.get("eligible_tools_by_phase", {}).values():
            for tool in tools:
                availability = tool_status.get(tool.get("name"), {})
                tool["availability"] = availability.get("availability", "unknown")
                tool["will_use"] = availability.get("will_use", "unknown")
                tool["requires_credentials"] = availability.get("requires_credentials", False)
                tool["missing_credentials"] = availability.get("missing_credentials", False)
                tool["missing_credentials_count"] = availability.get("missing_credentials_count", 0)
        return plan

    @app.get("/api/scans/{scan_id}/decisions")
    async def get_agent_decisions(scan_id: str, limit: int = 100):
        """Return the auditable planner ledger, including deterministic fallback."""
        mgr = get_manager(app)
        if scan_id not in mgr._scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        decisions = mgr.get_decisions(scan_id, limit=limit)
        return {"scan_id": scan_id, "total": len(decisions), "decisions": decisions}

    @app.get("/api/scans/{scan_id}/attack-chains")
    async def get_attack_chains(scan_id: str):
        """Return verified and hypothesized chains with per-edge evidence refs."""
        mgr = get_manager(app)
        if scan_id not in mgr._scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        return mgr.get_attack_chains(scan_id)

    @app.get("/api/scans/{scan_id}/agents")
    async def get_agent_status(scan_id: str):
        """Get real-time agent status for a scan (drives the Agent Roster panel)."""
        mgr = get_manager(app)
        if scan_id not in mgr._scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {"scan_id": scan_id, "agents": mgr.get_agent_status(scan_id)}

    @app.get("/api/events")
    async def get_recent_events(scan_id: Optional[str] = None, limit: int = 200):
        """Return recent scan events as a polling fallback for the live feed."""
        mgr = get_manager(app)
        return {"events": mgr.get_recent_events(scan_id=scan_id, limit=limit)}

    # ─── Report Download ────────────────────────────────────────

    @app.get("/api/scans/{scan_id}/report")
    async def download_report(scan_id: str, format: str = "html"):
        """Download an audit-ready report in html / pdf / markdown / json.

        If no report exists yet for the scan, it is generated on-the-fly by the
        ReportAgent (which now uses the LLM to write the executive summary and
        remediation guidance — see agents/reporter.py).
        """
        mgr = get_manager(app)
        scan = mgr.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        cfg = get_config(app)
        reports_dir = Path(cfg.reporting.output_dir)
        if not reports_dir.is_absolute():
            reports_dir = Path.cwd() / reports_dir
        reports_dir.mkdir(parents=True, exist_ok=True)

        scan_result = mgr.build_report_scan_result(scan_id)
        if not scan_result:
            raise HTTPException(status_code=404, detail="Scan not found")
        raw_report_targets = list((mgr._scans.get(scan_id) or {}).get("targets") or scan.get("targets") or [])

        requested_format = (format or "html").lower()
        if requested_format not in {"html", "pdf", "markdown", "md", "json"}:
            raise HTTPException(status_code=400, detail="Unsupported report format")

        report_format = "markdown" if requested_format == "md" else requested_format
        report_ext = "md" if report_format == "markdown" else report_format
        expected_findings = scan_result.total_findings
        safe_scan_name = re.sub(r"[^A-Za-z0-9._-]+", "_", scan_result.scan_name or scan_id).strip("._-") or scan_id

        def report_count(path: Path) -> Optional[int]:
            json_path = path if path.suffix == ".json" else path.with_suffix(".json")
            if not json_path.exists():
                return None
            try:
                payload = json.loads(json_path.read_text(encoding="utf-8"))
                return len(payload.get("findings") or [])
            except Exception:
                return None

        def matching_reports() -> list[Path]:
            patterns = []
            if scan.get("report_base_name"):
                patterns.append(f"{scan['report_base_name']}.{report_ext}")
            patterns.append(f"{safe_scan_name}_*.{report_ext}")
            candidates: list[Path] = []
            for pattern in patterns:
                candidates.extend(reports_dir.glob(pattern))
            return sorted(set(candidates), key=lambda p: p.stat().st_mtime, reverse=True)

        def report_has_raw_display_target(path: Path) -> bool:
            if path.suffix.lower() == ".pdf":
                return False
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return False
            return redact_display_text(text, raw_report_targets) != text

        def report_missing_quality(path: Path) -> bool:
            if path.suffix.lower() == ".pdf":
                return False
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return False
            if path.suffix.lower() == ".json":
                try:
                    payload = json.loads(text)
                    findings = payload.get("findings") or []
                    return bool(findings) and any("evidence_grade" not in item for item in findings if isinstance(item, dict))
                except Exception:
                    return True
            return bool(scan_result.findings) and "Evidence" not in text and "evidence_grade" not in text

        def write_fallback_report() -> Path:
            """Write a small deterministic partial report rather than returning 500.

            This path is used only when the full ReportAgent cannot produce an
            artifact, for example during an in-progress scan with unusual scan
            names or when optional PDF dependencies are unavailable.
            """
            from html import escape

            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            fallback_ext = "html" if report_ext == "pdf" else report_ext
            fallback_path = reports_dir / f"{safe_scan_name}_{timestamp}_partial.{fallback_ext}"
            findings = sorted(
                scan_result.findings,
                key=lambda item: (
                    {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(item.severity.value, 9),
                    item.title,
                ),
            )
            summary = scan_result.findings_by_severity

            if fallback_ext == "json":
                payload = {
                    "report_metadata": {
                        "title": f"VAPT Report - {scan_result.scan_name}",
                        "generated_at": datetime.utcnow().isoformat(),
                        "status": scan_result.status,
                        "mode": scan_result.mode.value,
                        "total_targets": len(scan_result.targets),
                        "total_findings": scan_result.total_findings,
                        "partial": scan.get("status") == "running",
                    },
                    "targets": [
                        {
                            "host": display_target(target.url or target.base_url or target.host),
                            "port": display_port(target.url or target.base_url or target.host, target.port),
                            "protocol": target.protocol,
                        }
                        for target in scan_result.targets
                    ],
                    "summary": {key: len(value) for key, value in summary.items()},
                    "findings": [finding.to_report_dict() for finding in findings],
                }
                fallback_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
                return fallback_path

            if fallback_ext == "md":
                lines = [
                    "# VAPT Security Assessment Report",
                    "",
                    f"**Scan:** {scan_result.scan_name}",
                    f"**Status:** {scan_result.status}",
                    f"**Mode:** {scan_result.mode.value}",
                    f"**Generated:** {datetime.utcnow().isoformat()} UTC",
                    "",
                    "| Severity | Count |",
                    "| --- | ---: |",
                    f"| Critical | {len(summary['critical'])} |",
                    f"| High | {len(summary['high'])} |",
                    f"| Medium | {len(summary['medium'])} |",
                    f"| Low | {len(summary['low'])} |",
                    f"| Informational | {len(summary['informational'])} |",
                    "",
                    "## Findings",
                    "",
                ]
                for idx, finding in enumerate(findings, 1):
                    report_finding = finding.to_report_dict()
                    lines.extend([
                        f"### {idx}. [{finding.severity.value.upper()}] {finding.title}",
                        "",
                        f"**Target:** {report_finding.get('target_display') or report_finding.get('target_host')}",
                        "",
                        report_finding.get("description") or "",
                        "",
                    ])
                    if finding.evidence:
                        lines.extend(["```", report_finding.get("evidence", "")[:1500], "```", ""])
                fallback_path.write_text("\n".join(lines), encoding="utf-8")
                return fallback_path

            rows = "\n".join(
                "<tr>"
                f"<td>{idx}</td>"
                f"<td>{escape(finding.severity.value.upper())}</td>"
                f"<td>{escape(finding.title)}</td>"
                f"<td>{escape(finding.to_report_dict().get('target_display') or finding.to_report_dict().get('target_host'))}</td>"
                f"<td>{escape(finding.status)}</td>"
                "</tr>"
                for idx, finding in enumerate(findings, 1)
            ) or "<tr><td colspan='5'>No findings recorded yet.</td></tr>"
            html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>VAPT Report - {escape(scan_result.scan_name)}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 32px; color: #172033; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
th, td {{ border: 1px solid #d7dde8; padding: 10px; text-align: left; }}
th {{ background: #eef3f8; }}
.note {{ padding: 12px 16px; background: #fff8df; border-left: 4px solid #d49b00; margin: 20px 0; }}
</style>
</head>
<body>
<h1>VAPT Security Assessment Report</h1>
<p><strong>Scan:</strong> {escape(scan_result.scan_name)}<br>
<strong>Status:</strong> {escape(str(scan_result.status))}<br>
<strong>Mode:</strong> {escape(scan_result.mode.value)}<br>
<strong>Generated:</strong> {datetime.utcnow().isoformat()} UTC</p>
<div class="note">Partial deterministic report generated from the canonical scan store because the full report renderer could not produce an artifact.</div>
<p><strong>Findings:</strong> {scan_result.total_findings}
({len(summary['critical'])} critical, {len(summary['high'])} high, {len(summary['medium'])} medium, {len(summary['low'])} low, {len(summary['informational'])} informational)</p>
<table><thead><tr><th>#</th><th>Severity</th><th>Finding</th><th>Target</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>
</body>
</html>"""
            fallback_path.write_text(html, encoding="utf-8")
            return fallback_path

        existing = [
            path for path in matching_reports()
            if report_count(path) in (expected_findings, None)
            and not report_has_raw_display_target(path)
            and not report_missing_quality(path)
        ]

        if not existing or (report_count(existing[0]) is not None and report_count(existing[0]) != expected_findings):
            from agents.reporter import ReportAgent
            from core.models import AgentTask, AgentType, ScanPhase, ScopeConfig, Target
            from core.scope import ScopeManager

            scope_mgr = ScopeManager(ScopeConfig())
            report_cfg = copy.deepcopy(cfg)
            report_cfg.reporting.output_dir = str(reports_dir)
            report_cfg.reporting.formats = [report_format] if report_format == "json" else [report_format, "json"]
            reporter = ReportAgent(scope_mgr, report_cfg)
            reporter._llm_available = False
            task = AgentTask(
                agent_type=AgentType.REPORTER,
                phase=ScanPhase.REPORTING,
                target=Target(host=scan_result.targets[0].host if scan_result.targets else "target"),
                tool_name="reporter",
                command="generate_report",
                parameters={"scan_result": scan_result},
            )
            await reporter.execute(task)
            generated_base = (task.result or {}).get("base_name")
            generated_path = reports_dir / f"{generated_base}.{report_ext}" if generated_base else None
            existing = [
                path for path in ([generated_path] if generated_path and generated_path.exists() else [])
                + matching_reports()
                if path.exists()
                and report_count(path) in (expected_findings, None)
                and not report_has_raw_display_target(path)
                and not report_missing_quality(path)
            ]

        if not existing:
            existing = [write_fallback_report()]

        report_path = existing[0]
        response_format = "html" if report_path.suffix == ".html" else requested_format
        return FileResponse(
            path=str(report_path),
            filename=report_path.name,
            media_type={
                "html": "text/html",
                "pdf": "application/pdf",
                "markdown": "text/markdown",
                "md": "text/markdown",
                "json": "application/json",
            }.get(response_format, "application/octet-stream"),
        )

    # ─── Real-time Event Stream ─────────────────────────────────

    @app.get("/api/stream")
    async def event_stream(request: Request):
        """SSE endpoint for real-time scan updates.

        Events: phase_change, finding, agent_status, log, scan_complete,
        scan_failed, ping.
        """
        mgr = get_manager(app)
        queue = mgr.subscribe_events()

        async def event_generator():
            try:
                yield {
                    "event": "ping",
                    "data": json.dumps({"event": "ping", "type": "ping", "status": "connected"}),
                }
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        data = await asyncio.wait_for(queue.get(), timeout=30)
                        event_type = data.get("event") or data.get("type") or "message"
                        yield {"event": event_type, "data": json.dumps(data)}
                    except asyncio.TimeoutError:
                        yield {"event": "ping", "data": json.dumps({"event": "ping", "type": "ping"})}
            except asyncio.CancelledError:
                pass
            finally:
                mgr.unsubscribe_events(queue)

        return EventSourceResponse(
            event_generator(),
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # ─── Fallback Dashboard (for direct API access) ──────────────

    @app.get("/", response_class=HTMLResponse)
    async def fallback_dashboard():
        return """<!DOCTYPE html>
<html><head><title>VAPT Platform API v2.0</title>
<style>
body{font-family:monospace;background:#0a0a1a;color:#e0e0e0;padding:40px}
a{color:#667eea}h1{color:#667eea}code{background:#1a1a3a;padding:2px 8px;border-radius:4px}
table{border-collapse:collapse;margin-top:20px;width:100%}
th,td{padding:10px 16px;border:1px solid #2a2a4a;text-align:left}
th{background:#141428;color:#a0a0cc}
</style></head><body>
<h1>VAPT Platform API</h1>
<p>Version 2.0.0 | AI-Augmented VAPT</p>
<p>Full UI: run the Next.js frontend under <code>frontend/</code></p>
<h2>API Endpoints</h2>
<table>
<tr><th>Method</th><th>Endpoint</th><th>Description</th></tr>
<tr><td>POST</td><td><a href="/api/docs">/api/scans/start</a></td><td>Start a new scan</td></tr>
<tr><td>GET</td><td>/api/scans</td><td>List all scans</td></tr>
<tr><td>GET</td><td>/api/scans/{scan_id}</td><td>Get scan details</td></tr>
<tr><td>GET</td><td>/api/scans/{scan_id}/findings</td><td>Get findings (filterable)</td></tr>
<tr><td>GET</td><td>/api/scans/{scan_id}/agents</td><td>Agent status</td></tr>
<tr><td>POST</td><td>/api/scans/{scan_id}/stop</td><td>Stop a scan</td></tr>
<tr><td>GET</td><td>/api/scans/{scan_id}/report</td><td>Download report</td></tr>
<tr><td>GET</td><td>/api/modes</td><td>Available scan modes</td></tr>
<tr><td>GET</td><td>/api/stream</td><td>SSE real-time events</td></tr>
<tr><td>GET</td><td>/api/health</td><td>Health check</td></tr>
<tr><td>GET</td><td>/api/system/diagnostics</td><td>Runtime and VA pipeline diagnostics</td></tr>
<tr><td>POST</td><td>/api/system/recover</td><td>Dry-run/apply stale scan and queue recovery</td></tr>
<tr><td>GET</td><td>/api/tools/status</td><td>Tool availability</td></tr>
<tr><td>GET</td><td>/api/nvd/stats</td><td>NVD verification stats</td></tr>
</table>
<h2>Interactive Docs</h2>
<p><a href="/api/docs">Swagger UI</a> | <a href="/api/redoc">ReDoc</a></p>
</body></html>"""

    return app
