"""
VAPT Platform — API Discovery Import (P1)

Parses an OpenAPI/Swagger spec or a Postman collection into a normalised list
of API endpoints so the fuzzer and targeted modules get a real route surface to
test instead of only crawled pages.

Output endpoint shape::

    {"method": "GET", "url": "https://api.example.com/v1/users/{id}",
     "path": "/v1/users/{id}", "params": ["id", "limit"], "source": "openapi"}

Pure-Python and dependency-light (json + optional yaml); fully unit-testable
without any external tool.
"""

from __future__ import annotations

import json
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from loguru import logger

HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}


def _load(text_or_obj: Any) -> Optional[dict]:
    """Load a spec from a dict, JSON string, or YAML string."""
    if isinstance(text_or_obj, dict):
        return text_or_obj
    if not isinstance(text_or_obj, str):
        return None
    text = text_or_obj.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    try:
        import yaml

        loaded = yaml.safe_load(text)
        return loaded if isinstance(loaded, dict) else None
    except Exception as exc:
        logger.debug("[api_import] Failed to parse spec as JSON or YAML: {err}", err=exc)
        return None


def detect_kind(spec: dict) -> str:
    """Return 'openapi' | 'swagger' | 'postman' | 'unknown'."""
    if "openapi" in spec:
        return "openapi"
    if "swagger" in spec:
        return "swagger"
    info = spec.get("info") or {}
    if isinstance(info, dict) and "schema" in info and "postman" in str(info.get("schema", "")):
        return "postman"
    if "item" in spec and "info" in spec:
        return "postman"
    return "unknown"


def _openapi_base_url(spec: dict, fallback_base: str) -> str:
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        url = servers[0].get("url") if isinstance(servers[0], dict) else None
        if url:
            return str(url).rstrip("/")
    # Swagger 2.0
    host = spec.get("host")
    if host:
        scheme = (spec.get("schemes") or ["https"])[0]
        base_path = spec.get("basePath", "") or ""
        return f"{scheme}://{host}{base_path}".rstrip("/")
    return fallback_base.rstrip("/")


def _parse_openapi(spec: dict, fallback_base: str) -> list[dict]:
    base = _openapi_base_url(spec, fallback_base)
    endpoints: list[dict] = []
    for path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, op in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            params: list[str] = []
            for p in (op.get("parameters") or []) if isinstance(op, dict) else []:
                name = p.get("name") if isinstance(p, dict) else None
                if name:
                    params.append(str(name))
            endpoints.append({
                "method": method.upper(),
                "url": f"{base}{path}",
                "path": path,
                "params": params,
                "source": "openapi",
            })
    return endpoints


def _parse_postman(spec: dict, fallback_base: str) -> list[dict]:
    endpoints: list[dict] = []

    def walk(items: list) -> None:
        for item in items or []:
            if not isinstance(item, dict):
                continue
            if "item" in item:  # folder
                walk(item.get("item") or [])
                continue
            request = item.get("request")
            if not isinstance(request, dict):
                continue
            method = str(request.get("method", "GET")).upper()
            url = request.get("url")
            raw = ""
            params: list[str] = []
            if isinstance(url, dict):
                raw = url.get("raw", "") or ""
                for q in url.get("query") or []:
                    if isinstance(q, dict) and q.get("key"):
                        params.append(str(q["key"]))
            elif isinstance(url, str):
                raw = url
            if not raw:
                continue
            if not urlparse(raw).netloc:
                raw = urljoin(fallback_base.rstrip("/") + "/", raw.lstrip("/"))
            endpoints.append({
                "method": method,
                "url": raw,
                "path": urlparse(raw).path,
                "params": params,
                "source": "postman",
            })

    walk(spec.get("item") or [])
    return endpoints


def import_api_spec(spec_text: Any, fallback_base: str = "") -> dict[str, Any]:
    """Parse a spec and return {kind, endpoints, count, error}."""
    spec = _load(spec_text)
    if spec is None:
        return {"kind": "unknown", "endpoints": [], "count": 0,
                "error": "Could not parse spec as JSON or YAML"}

    kind = detect_kind(spec)
    try:
        if kind in ("openapi", "swagger"):
            endpoints = _parse_openapi(spec, fallback_base)
        elif kind == "postman":
            endpoints = _parse_postman(spec, fallback_base)
        else:
            return {"kind": kind, "endpoints": [], "count": 0,
                    "error": "Unrecognised spec format (expected OpenAPI/Swagger/Postman)"}
    except Exception as exc:
        logger.warning("[api_import] Parse error for {kind} spec: {err}", kind=kind, err=exc)
        return {"kind": kind, "endpoints": [], "count": 0, "error": str(exc)}

    # De-duplicate by (method, url).
    seen: set[tuple[str, str]] = set()
    unique: list[dict] = []
    for ep in endpoints:
        key = (ep["method"], ep["url"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(ep)

    logger.info("[api_import] Parsed {n} endpoint(s) from {kind} spec", n=len(unique), kind=kind)
    return {"kind": kind, "endpoints": unique, "count": len(unique), "error": ""}
