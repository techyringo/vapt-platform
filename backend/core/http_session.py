"""
VAPT Platform — Authenticated HTTP Session Helper (P1)

Builds an httpx.AsyncClient pre-loaded with the engagement's authentication
context (bearer/basic token, custom headers, cookies) taken from ``ScopeConfig``.
Used by the safe web-validation modules and the false-positive reducer so that
authenticated surfaces are actually reachable and replays are consistent.

Non-destructive by design: callers issue benign probes only.
"""

from __future__ import annotations

import base64
from typing import Any, Optional

from loguru import logger


def build_auth_headers(scope_config: Any) -> dict[str, str]:
    """Derive request headers from a ScopeConfig's auth settings."""
    headers: dict[str, str] = {}
    if scope_config is None:
        return headers

    custom = getattr(scope_config, "custom_headers", None) or {}
    for key, value in custom.items():
        headers[str(key)] = str(value)

    token = getattr(scope_config, "auth_token", "") or ""
    auth_type = (getattr(scope_config, "auth_type", "") or "").lower()
    if token:
        if auth_type == "bearer":
            headers.setdefault("Authorization", f"Bearer {token}")
        elif auth_type == "basic":
            # token may already be base64(user:pass) or raw "user:pass"
            if ":" in token:
                token = base64.b64encode(token.encode()).decode()
            headers.setdefault("Authorization", f"Basic {token}")
        elif auth_type == "cookie":
            headers.setdefault("Cookie", token)
        else:
            headers.setdefault("Authorization", token)
    return headers


def build_cookies(scope_config: Any) -> dict[str, str]:
    cookies = getattr(scope_config, "cookies", None) or {}
    return {str(k): str(v) for k, v in cookies.items()}


def new_auth_client(
    scope_config: Any,
    *,
    timeout: float = 10.0,
    follow_redirects: bool = False,
    verify: bool = False,
) -> Any:
    """Return an httpx.AsyncClient carrying the engagement auth context.

    ``follow_redirects`` defaults to False so modules can observe redirects
    (e.g. open-redirect / auth-bypass checks) explicitly.
    """
    import httpx

    headers = build_auth_headers(scope_config)
    cookies = build_cookies(scope_config)
    if headers or cookies:
        logger.debug(
            "[http_session] Authenticated client: {h} header(s), {c} cookie(s)",
            h=len(headers), c=len(cookies),
        )
    return httpx.AsyncClient(
        headers=headers or None,
        cookies=cookies or None,
        timeout=timeout,
        follow_redirects=follow_redirects,
        verify=verify,
    )


def session_summary(scope_config: Any) -> dict[str, Any]:
    """Redacted description of the active session (for diagnostics/UI)."""
    headers = build_auth_headers(scope_config)
    cookies = build_cookies(scope_config)
    return {
        "authenticated": bool(headers or cookies),
        "auth_type": (getattr(scope_config, "auth_type", "") or "") if scope_config else "",
        "header_names": sorted(headers.keys()),
        "cookie_names": sorted(cookies.keys()),
    }
