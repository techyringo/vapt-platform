"""
API Key authentication middleware for the VAPT Platform.

When VAPT_API_KEY is set in the environment, every request to /api/*
must include a matching X-API-Key header (or ?api_key= query param).

Dev / local usage: leave VAPT_API_KEY unset — the middleware is a no-op
and the API is open (same behaviour as before).

Enterprise usage: set a strong random key (e.g. `openssl rand -hex 32`)
in .env and distribute it to authorised consumers only.

Public paths (health, docs, OpenAPI schema) are always allowed so
monitoring and Swagger UI keep working without credentials.
"""

from __future__ import annotations

import os
from typing import Callable, Awaitable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from loguru import logger

# Paths that are always reachable without authentication.
_PUBLIC_PATHS: frozenset[str] = frozenset(
    {
        "/api/health",
        "/api/docs",
        "/api/redoc",
        "/api/openapi.json",
        "/",
    }
)

_API_KEY: str = os.environ.get("VAPT_API_KEY", "").strip()


def _is_public(path: str) -> bool:
    """Return True if the path does not require an API key."""
    if not path.startswith("/api/"):
        return True  # Frontend static assets, etc.
    return path in _PUBLIC_PATHS


async def api_key_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """FastAPI middleware that enforces API-key auth on /api/* routes.

    Behaviour:
    - VAPT_API_KEY not set → passes all requests (open/dev mode).
    - VAPT_API_KEY set     → requires X-API-Key header or ?api_key= param
                             for all non-public /api/ paths.
    """
    # No key configured → dev/open mode, no enforcement.
    if not _API_KEY:
        return await call_next(request)

    if _is_public(request.url.path):
        return await call_next(request)

    # Accept key from header OR query-string (header preferred).
    presented = (
        request.headers.get("X-API-Key")
        or request.headers.get("x-api-key")
        or request.query_params.get("api_key")
        or ""
    ).strip()

    if presented != _API_KEY:
        logger.warning(
            "Auth rejected: {method} {path} from {client}",
            method=request.method,
            path=request.url.path,
            client=request.client.host if request.client else "unknown",
        )
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid or missing API key. Supply X-API-Key header."},
        )

    return await call_next(request)


def auth_enabled() -> bool:
    """Return True when API-key enforcement is active."""
    return bool(_API_KEY)
