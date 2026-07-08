"""Safe web-validation module framework.

A ``SafeModule`` performs one class of non-destructive check against a target and
returns Finding objects. ``run_modules`` builds a single authenticated client,
runs the requested modules, and returns the aggregated findings.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from loguru import logger

from core.models import AgentType, Finding, Severity, Target
from core.http_session import new_auth_client


def make_finding(
    *,
    title: str,
    description: str,
    severity: Severity,
    target: Target,
    evidence: str = "",
    request_proof: str = "",
    response_proof: str = "",
    remediation: str = "",
    cwe_ids: Optional[list[str]] = None,
    tags: Optional[list[str]] = None,
    confidence: str = "medium",
    status: str = "suspected",
) -> Finding:
    """Build a Finding from a safe module, tagged for evidence scoring."""
    module_tags = ["module-replay", "web-module"]
    if tags:
        module_tags.extend(tags)
    return Finding(
        title=title,
        description=description,
        severity=severity,
        agent_source=AgentType.VULN_SCANNER,
        target=target,
        evidence=evidence,
        request_proof=request_proof or None,
        response_proof=response_proof or None,
        remediation=remediation,
        cwe_ids=cwe_ids or [],
        tags=module_tags,
        confidence=confidence,
        status=status,
    )


class SafeModule(ABC):
    """Base class for a single non-destructive validation module."""

    name: str = "module"
    category: str = "web"

    @abstractmethod
    async def run(self, target: Target, scope_config: Any, client: Any) -> list[Finding]:
        """Run the check against ``target`` using the shared authed ``client``."""
        ...


# Populated by importing the concrete modules below.
MODULE_REGISTRY: dict[str, type[SafeModule]] = {}


def register(cls: type[SafeModule]) -> type[SafeModule]:
    MODULE_REGISTRY[cls.name] = cls
    return cls


async def run_modules(
    target: Target,
    scope_config: Any,
    module_names: Optional[list[str]] = None,
) -> list[Finding]:
    """Run the requested safe modules against a target and aggregate findings.

    A single authenticated client is shared across modules for efficiency and
    consistent session state. Individual module failures are isolated.
    """
    # Import concrete modules so they self-register (cheap, idempotent).
    from agents.modules import checks  # noqa: F401

    selected = module_names or list(MODULE_REGISTRY.keys())
    findings: list[Finding] = []

    try:
        async with new_auth_client(scope_config, timeout=12.0, follow_redirects=False) as client:
            for name in selected:
                module_cls = MODULE_REGISTRY.get(name)
                if module_cls is None:
                    logger.debug("[modules] Unknown module '{n}' — skipping", n=name)
                    continue
                try:
                    module_findings = await module_cls().run(target, scope_config, client)
                    findings.extend(module_findings)
                    logger.info(
                        "[modules] {mod} produced {n} finding(s) for {host}",
                        mod=name, n=len(module_findings), host=target.host,
                    )
                except Exception as exc:
                    logger.warning("[modules] {mod} failed on {host}: {err}",
                                   mod=name, host=target.host, err=exc)
    except Exception as exc:
        logger.warning("[modules] Could not build HTTP client for {host}: {err}",
                       host=target.host, err=exc)

    return findings
