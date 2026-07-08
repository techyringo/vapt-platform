"""Display helpers for masking internal scan targets.

Scanner internals must keep the real host/port, but UI and reports should not
have to expose loopback/private infrastructure in demos or customer exports.
"""

from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlparse


def public_target_name() -> str:
    return os.environ.get("VAPT_PUBLIC_TARGET_NAME", "vapt.local").strip() or "vapt.local"


def mask_private_targets() -> bool:
    value = os.environ.get("VAPT_MASK_PRIVATE_TARGETS", "true")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _host_from_value(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or raw.split("/", 1)[0].split(":", 1)[0]).strip("[]").lower()


def _port_from_value(value: str) -> int | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    try:
        return parsed.port
    except ValueError:
        return None


def is_private_display_target(value: str) -> bool:
    if not mask_private_targets():
        return False
    host = _host_from_value(value)
    if host in {"localhost", "host.docker.internal"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


def display_host(value: str) -> str:
    return public_target_name() if is_private_display_target(value) else (_host_from_value(value) or str(value or ""))


def display_url(value: str, default_scheme: str = "https") -> str:
    raw = str(value or "").strip()
    if is_private_display_target(raw):
        return f"{default_scheme}://{public_target_name()}"
    return raw


def display_port(value: str, port: int | None = None, default: int = 443) -> int:
    return default if is_private_display_target(value) else int(port or default)


def display_target(value: str) -> str:
    raw = str(value or "").strip()
    if is_private_display_target(raw):
        return public_target_name()
    return raw


def redact_display_text(value: str, known_targets: list[str] | tuple[str, ...] | None = None) -> str:
    """Mask private/loopback targets inside text intended for UI or reports."""
    text = str(value or "")
    if not text or not mask_private_targets():
        return text

    targets = [str(target or "").strip() for target in (known_targets or []) if str(target or "").strip()]
    for target in sorted(targets, key=len, reverse=True):
        if not is_private_display_target(target):
            continue
        host = _host_from_value(target)
        port = _port_from_value(target)
        alias = public_target_name()
        text = text.replace(target, display_url(target) if "://" in target else alias)
        if host:
            text = re.sub(rf"\b{re.escape(host)}:\d+\b", alias, text)
            text = re.sub(rf"\b{re.escape(host)}\b", alias, text)
        if port:
            display = str(display_port(target, port))
            text = re.sub(rf'("port"\s*:\s*)"{port}"', rf'\g<1>"{display}"', text, flags=re.I)
            text = re.sub(rf'("port"\s*:\s*){port}\b', rf'\g<1>{display}', text, flags=re.I)
            text = re.sub(rf"((?:target\s+)?port\s*:\s*){port}\b", rf"\g<1>{display}", text, flags=re.I)

    alias = public_target_name()
    text = re.sub(r"https?://(?:localhost|host\.docker\.internal|127(?:\.\d{1,3}){3})(?::\d+)?", f"https://{alias}", text, flags=re.I)
    text = re.sub(r"\b(?:localhost|host\.docker\.internal|127(?:\.\d{1,3}){3})(?::\d+)?\b", alias, text, flags=re.I)
    text = re.sub(r"https?://10(?:\.\d{1,3}){3}(?::\d+)?", f"https://{alias}", text)
    text = re.sub(r"\b10(?:\.\d{1,3}){3}(?::\d+)?\b", alias, text)
    text = re.sub(r"https?://192\.168(?:\.\d{1,3}){2}(?::\d+)?", f"https://{alias}", text)
    text = re.sub(r"\b192\.168(?:\.\d{1,3}){2}(?::\d+)?\b", alias, text)
    text = re.sub(r"https?://172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}(?::\d+)?", f"https://{alias}", text)
    text = re.sub(r"\b172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}(?::\d+)?\b", alias, text)
    return text
