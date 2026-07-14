"""Resolve capabilities that can actually execute on this installation.

The registry describes what the product knows about. This module describes
what the current runtime can run, so planning never promotes an administrator
setup gap into an executable action.
"""

from __future__ import annotations

import os
import shutil
from typing import Any

from core.tool_registry import TOOL_CAPABILITIES


_INTERNAL_TOOLS = {"secretfinder"}


def _credential_available(name: str) -> bool:
    return bool(str(os.environ.get(name) or os.environ.get(f"VAPT_{name}") or "").strip())


def executable_tool_names(config: Any) -> set[str]:
    """Return enabled tools with a real local, container, internal or API path.

    An approved container image may be pulled on demand when the Docker socket
    is mounted. Unknown downloads and arbitrary package installation are never
    treated as executable.
    """

    docker_ready = bool(shutil.which("docker") and os.path.exists("/var/run/docker.sock"))
    executable: set[str] = set()
    names = set(getattr(config, "tools", {}) or {}) | set(TOOL_CAPABILITIES)
    for name in names:
        try:
            tool_config = config.get_tool_config(name)
        except Exception:
            continue
        if not getattr(tool_config, "enabled", False):
            continue
        if str(getattr(tool_config, "docker_image", "") or "").strip() and docker_ready:
            executable.add(name)
            continue
        if shutil.which(name) or name in _INTERNAL_TOOLS:
            executable.add(name)
            continue
        capability = TOOL_CAPABILITIES.get(name)
        required = tuple((capability.requires_api_keys if capability else []) or [])
        if required and all(_credential_available(key) for key in required):
            executable.add(name)
    return executable
