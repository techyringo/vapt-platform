"""VAPT Multi-Agent System — Base Agent Interface"""

from abc import ABC, abstractmethod
from typing import Any
from loguru import logger

from core.models import AgentTask, AgentType, Finding, ScanResult, ScopeConfig
from core.scope import ScopeManager


class BaseAgent(ABC):
    """Abstract base class for all VAPT worker agents.

    Every agent must implement the ``execute`` method which receives an
    ``AgentTask`` and returns a list of ``Finding`` objects.  The base
    class provides common utilities for scope checking, logging, and
    tool execution.

    Args:
        agent_type:  The type identifier for this agent.
        scope:       The scope manager enforcing engagement boundaries.
        config:      The application configuration.
    """

    def __init__(
        self,
        agent_type: AgentType,
        scope: ScopeManager,
        config: Any = None,
    ) -> None:
        self.agent_type = agent_type
        self.scope = scope
        self.config = config
        self._findings: list[Finding] = []
        self._tool_runs: list[dict[str, Any]] = []

    @abstractmethod
    async def execute(self, task: AgentTask) -> list[Finding]:
        """Execute the agent's primary task and return discovered findings.

        Args:
            task: The ``AgentTask`` describing what to do.

        Returns:
            A list of ``Finding`` objects produced by this agent.
        """
        ...

    def _add_finding(self, finding: Finding) -> None:
        """Add a finding to the internal list and log it.

        Args:
            finding: The finding to record.
        """
        self._findings.append(finding)
        logger.info(
            "[{agent}] Finding: [{severity}] {title}",
            agent=self.agent_type.value,
            severity=finding.severity.value,
            title=finding.title,
        )

    def is_in_scope(self, url: str) -> bool:
        """Delegate scope checking to the scope manager.

        Args:
            url: URL to check.

        Returns:
            Whether the URL is in scope.
        """
        return self.scope.is_in_scope(url)

    def get_findings(self) -> list[Finding]:
        """Return all findings collected so far.

        Returns:
            List of findings.
        """
        return list(self._findings)

    def clear_findings(self) -> None:
        """Clear all collected findings."""
        self._findings.clear()

    def _record_tool_run(self, result: Any, phase: str = "") -> None:
        """Record a tool execution summary for UI/report evidence."""
        if hasattr(result, "to_dict"):
            data = result.to_dict()
        elif isinstance(result, dict):
            data = dict(result)
        else:
            return
        if phase:
            data["phase"] = phase
        self._tool_runs.append(data)
        if data.get("success") is False:
            err_text = str(data.get("stderr", "") or data.get("stdout", ""))[:500]
            logger.warning(
                "[{agent}] Tool failed: {tool} phase={phase} exit={exit_code} output={output}",
                agent=self.agent_type.value,
                tool=data.get("tool", "unknown"),
                phase=phase or data.get("phase", ""),
                exit_code=data.get("exit_code"),
                output=err_text,
            )

    def get_tool_runs(self) -> list[dict[str, Any]]:
        """Return tool execution summaries collected by this agent."""
        return list(self._tool_runs)

    def clear_tool_runs(self) -> None:
        """Clear tool execution summaries."""
        self._tool_runs.clear()
