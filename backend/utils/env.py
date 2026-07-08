"""Environment helpers shared by API, workers, and tool runners."""

from __future__ import annotations

import os


API_KEY_ALIASES: dict[str, tuple[str, ...]] = {
    "OPENAI_API_KEY": ("VAPT_OPENAI_API_KEY",),
    "ANTHROPIC_API_KEY": ("VAPT_ANTHROPIC_API_KEY",),
    "GEMINI_API_KEY": ("VAPT_GEMINI_API_KEY",),
    "GROQ_API_KEY": ("VAPT_GROQ_API_KEY",),
    "TOGETHER_API_KEY": ("VAPT_TOGETHER_API_KEY",),
    "NVD_API_KEY": ("VAPT_NVD_API_KEY",),
    "SHODAN_API_KEY": ("VAPT_SHODAN_API_KEY",),
    "CENSYS_API_ID": ("VAPT_CENSYS_API_ID",),
    "CENSYS_API_SECRET": ("VAPT_CENSYS_API_SECRET",),
    "SECURITYTRAILS_API_KEY": (
        "VAPT_SECURITYTRAILS_API_KEY",
        "SECURITYTRAILS_API",
    ),
    "WPSCAN_API_TOKEN": ("VAPT_WPSCAN_API_TOKEN",),
}


def first_env_value(name: str) -> str:
    """Return the first configured value for a canonical API key or alias."""
    candidates = (name, *API_KEY_ALIASES.get(name, ()))
    for candidate in candidates:
        value = os.environ.get(candidate, "").strip()
        if value:
            return value
    return ""


def env_configured(name: str) -> bool:
    return bool(first_env_value(name))


def normalize_api_key_aliases() -> None:
    """Mirror VAPT_* aliases into canonical env vars and vice versa.

    External CLIs and Docker tool images generally expect canonical names like
    SHODAN_API_KEY or WPSCAN_API_TOKEN. The product UI/config may use VAPT_*
    names. Normalizing once at process startup keeps both worlds consistent
    without ever exposing secret values through the API.
    """
    for canonical, aliases in API_KEY_ALIASES.items():
        canonical_value = os.environ.get(canonical, "").strip()
        if canonical_value:
            for alias in aliases:
                os.environ.setdefault(alias, canonical_value)
            continue

        alias_value = first_env_value(canonical)
        if alias_value:
            os.environ[canonical] = alias_value
            for alias in aliases:
                os.environ.setdefault(alias, alias_value)
