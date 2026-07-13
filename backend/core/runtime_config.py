"""Runtime, frontend-configurable settings — nothing hardcoded.

The LLM endpoint/model/provider is chosen by the operator from the frontend
and persisted to a JSON file (default ``data/runtime_settings.json``). Because
the file lives under ``./backend/data`` (a shared Docker volume), both the API
container and the ARQ worker containers read the same settings, and the choice
survives restarts — with no ``config.yaml`` edit, no env rewrite, no redeploy.

Precedence (highest wins):
    runtime settings (frontend)  >  config.yaml  >  code defaults

``LLMClient`` calls :func:`apply_runtime_llm_overlay` at construction, so every
scan honours the operator's current choice automatically.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional


def _settings_path() -> Path:
    """Resolve the runtime-settings JSON path."""
    raw = os.environ.get("VAPT_RUNTIME_SETTINGS", "")
    if raw:
        p = Path(raw)
        return p if p.is_absolute() else Path.cwd() / p
    # Default: alongside the SQLite DB / artifacts on the shared data volume.
    if Path("/app/data").exists():
        return Path("/app/data/runtime_settings.json")
    return Path("data/runtime_settings.json")


def load_runtime_settings() -> dict[str, Any]:
    """Load the full runtime settings dict (``{}`` if absent/corrupt)."""
    try:
        path = _settings_path()
        if not path.exists():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_runtime_settings(settings: dict[str, Any]) -> None:
    """Persist the full runtime settings dict atomically."""
    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        prefix=".runtime_settings.", suffix=".json", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(settings, fh, indent=2, default=str)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise


def get_runtime_llm() -> Optional[dict[str, Any]]:
    """Return the persisted ``llm`` sub-dict, or ``None``."""
    llm = load_runtime_settings().get("llm")
    return llm if isinstance(llm, dict) else None


def save_runtime_llm(llm: dict[str, Any]) -> dict[str, Any]:
    """Merge ``llm`` into runtime settings and persist."""
    settings = load_runtime_settings()
    settings["llm"] = llm
    save_runtime_settings(settings)
    return settings


# Fields on LLMConfig that a runtime override may set. ``api_key`` is stored
# locally (single-tenant) so cloud providers can be configured from the UI
# without an env rewrite; it is never returned by the API.
_LLM_FIELDS = (
    "provider", "model", "base_url", "verify_ssl", "api_key_env", "api_key",
    "analysis_model", "report_model", "review_model", "temperature", "max_tokens", "max_rpm",
    "fallback_providers", "enabled", "allow_fallbacks",
)
_LLM_EMPTY_STRING_FIELDS = {"api_key", "api_key_env"}


def apply_runtime_llm_overlay(config: Any) -> Any:
    """Overlay persisted runtime LLM settings onto ``config.llm`` in place.

    Safe to call repeatedly (idempotent) and on any AppConfig-like object.
    Returns the same config object for convenience.
    """
    try:
        rt = get_runtime_llm()
        if not rt:
            return config
        from core.config import LLMConfig  # local import avoids cycles
        merged = config.llm.model_dump()
        for key in _LLM_FIELDS:
            if key in rt and key in _LLM_EMPTY_STRING_FIELDS:
                merged[key] = rt.get(key) or ""
                continue
            val = rt.get(key)
            if val not in (None, ""):
                merged[key] = val
        # ``fallback_providers`` explicitly set to [] means "no fallbacks".
        if "fallback_providers" in rt:
            merged["fallback_providers"] = rt.get("fallback_providers") or []
        config.llm = LLMConfig(**merged)
    except Exception:
        # Never let a runtime-settings hiccup break LLM client construction.
        pass
    return config
