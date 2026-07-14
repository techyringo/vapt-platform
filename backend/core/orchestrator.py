"""
VAPT Multi-Agent System — Orchestrator

The central brain of the VAPT system.  Coordinates all agents, manages
scan lifecycle, enforces scope, and routes findings to the appropriate
downstream consumers.

The orchestrator is fully async and designed to run a single scan at a
time per instance (multiple instances can be created for parallel scans).
"""

import asyncio
import json
import os
from datetime import datetime
from typing import Optional, Callable, Any
from loguru import logger
from pathlib import Path
import yaml

from core.models import (
    ScanMode,
    ScanPhase,
    AgentType,
    Target,
    Finding,
    AgentTask,
    ScanResult,
    ScopeConfig,
    Severity,
)
from core.state import ScanStateMachine
from core.scope import ScopeManager
from core.config import AppConfig
from core.tool_registry import TOOL_CAPABILITIES, plan_next_tools, target_layers_from_evidence
from core.runtime_capabilities import executable_tool_names
from core.job_tracker import JOB_TRACKER, current_scan_id
from core.live_log import tool_log_context


# ────────────────────────────────────────────────────────────────────
# Phase → Agent Mapping
# ────────────────────────────────────────────────────────────────────

PHASE_AGENT_MAP: dict[ScanPhase, list[AgentType]] = {
    ScanPhase.INIT: [],
    ScanPhase.RECON: [AgentType.RECON],
    ScanPhase.ENUMERATION: [AgentType.ENUM, AgentType.CLOUD, AgentType.IOT_CCTV],
    ScanPhase.VULN_SCANNING: [AgentType.VULN_SCANNER],
    ScanPhase.FUZZING: [AgentType.FUZZER],
    ScanPhase.EXPLOITATION: [AgentType.EXPLOIT],
    ScanPhase.INTELLIGENCE: [AgentType.INTEL],
    ScanPhase.REPORTING: [AgentType.REPORTER],
    # Terminal phases have no agents
    ScanPhase.COMPLETED: [],
    ScanPhase.FAILED: [],
    ScanPhase.CANCELLED: [],
}

# Agents below consume accumulated phase context (recon_data, enum_data,
# scan_result, existing_findings) and internally fan out across discovered
# hosts/URLs. Dispatching them once per expanded target repeats expensive work
# such as nmap, nuclei, ffuf, and reporting. Recon stays per input target.
GLOBAL_CONTEXT_AGENTS: set[AgentType] = {
    AgentType.ENUM,
    AgentType.VULN_SCANNER,
    AgentType.FUZZER,
    AgentType.EXPLOIT,
    AgentType.INTEL,
    AgentType.CLOUD,
    AgentType.IOT_CCTV,
    AgentType.REPORTER,
}


class Orchestrator:
    """Central orchestrator that coordinates the VAPT scan pipeline.

    Loads configuration, initialises the state machine and scope manager,
    registers agents, and drives the scan through its phases from ``init``
    to ``reporting`` / ``completed``.

    Args:
        config_path: Path to the YAML configuration file.
    """

    def __init__(self, config_path: str = "config.yaml") -> None:
        """Initialise the orchestrator.

        Args:
            config_path: Path to the YAML configuration file.  If the
                file does not exist, a default configuration is used.
        """
        # Resolve a default config path that works regardless of CWD: look
        # for config.yaml next to the backend package (../config.yaml from
        # core/orchestrator.py). This removes the need for hardcoded absolute
        # paths in scan_manager.py.
        if config_path == "config.yaml":
            here = Path(__file__).resolve().parent.parent  # backend/
            candidate = here / "config.yaml"
            if candidate.exists():
                config_path = str(candidate)
        self._config_path = config_path
        self._config: AppConfig = self._load_config(config_path)

        # Core subsystems
        self._state_machine = ScanStateMachine()
        self._scope_manager: Optional[ScopeManager] = None

        # Agent registry: agent_type → agent instance
        self._agents: dict[AgentType, Any] = {}

        # Active scan tracking
        self._active_scans: dict[str, ScanResult] = {}
        self._scan_cancel_flags: dict[str, bool] = {}

        # ── Phase context store ────────────────────────────────────
        # Structured results from each completed phase, forwarded to the
        # next phase's agent parameters (recon_data, enum_data, …).
        self._phase_context: dict[str, Any] = {}

        # ── Evidence accumulator ───────────────────────────────────
        # Grows as agents complete.  plan_next_tools() reads this to decide
        # which tools are ready to fire next (evidence-driven scheduling).
        # Keys are evidence tokens from core/tool_registry.py taxonomy.
        self._evidence: set[str] = set()
        self._tools_run: set[str] = set()  # tracks tools already executed
        self._agent_timeout_seconds = int(os.environ.get("VAPT_AGENT_TIMEOUT_SECONDS", "1800"))

        # Callbacks
        self._on_finding_callbacks: list[Callable[[Finding], Any]] = []
        self._on_phase_change_callbacks: list[Callable[[str, str], Any]] = []
        self._on_phase_complete_callbacks: list[Callable[[str, ScanResult], Any]] = []
        self._on_agent_start_callbacks: list[Callable[[str, str], Any]] = []
        self._on_agent_complete_callbacks: list[Callable[[str, int], Any]] = []
        self._on_log_callbacks: list[Callable[[str, str], Any]] = []

        logger.info(
            "Orchestrator initialised — default mode: {mode}",
            mode=self._config.default_mode,
        )

    # ── Configuration ──────────────────────────────────────────────

    def _load_config(self, path: str) -> AppConfig:
        """Load and validate the YAML configuration file.

        If the file does not exist, logs a warning and returns a default
        ``AppConfig``.

        Args:
            path: Filesystem path to the YAML config.

        Returns:
            A validated ``AppConfig`` instance.
        """
        config_file = Path(path)
        if config_file.exists():
            try:
                config = AppConfig.load(config_file)
                logger.info("Configuration loaded from {path}", path=path)
                return config
            except Exception as exc:
                logger.error("Failed to load config from {path}: {err}", path=path, err=exc)
                raise
        else:
            logger.warning(
                "Config file not found at {path} — using defaults",
                path=path,
            )
            return AppConfig()

    def get_profile(self, mode: ScanMode) -> dict[str, Any]:
        """Retrieve the scan profile configuration for a given mode.

        Args:
            mode: The scan mode whose profile to retrieve.

        Returns:
            A dictionary containing the profile's agent list,
            aggressiveness flag, and exploitation flag.
        """
        profile = self._config.get_profile(mode.value)
        return {
            "name": profile.name,
            "agents": profile.agents,
            "aggressive": profile.aggressive,
            "exploit": profile.exploit,
            "focus": profile.focus,
            "description": profile.description,
        }

    # ── Agent Registration ─────────────────────────────────────────

    def register_agent(self, agent_type: AgentType, agent_instance: Any) -> None:
        """Register an agent instance for a given agent type.

        The agent instance must be an async callable or an object with
        an ``execute`` async method that accepts ``(task: AgentTask) ->
        list[Finding]``.

        Args:
            agent_type:     The type of agent being registered.
            agent_instance: The agent instance to register.
        """
        self._agents[agent_type] = agent_instance
        logger.info("Registered agent: {agent_type}", agent_type=agent_type.value)

    def seed_evidence(self, tokens: set[str] | list[str] | tuple[str, ...]) -> None:
        """Seed planner evidence before the first phase runs.

        User-supplied targets already tell us useful things: a URL can seed
        web checks, an IP can seed service discovery, and an S3-looking host can
        seed cloud checks. Recon still validates and enriches this evidence;
        this method only gives the planner a sane starting point.
        """
        cleaned = {str(token).strip() for token in tokens if str(token).strip()}
        if not cleaned:
            return
        self._evidence.update(cleaned)
        logger.info(
            "Seeded orchestrator evidence: {count} token(s)",
            count=len(cleaned),
        )

    def on_finding(self, callback: Callable[[Finding], Any]) -> None:
        """Register a callback to be invoked whenever a new finding is produced."""
        self._on_finding_callbacks.append(callback)

    def on_phase_change(self, callback: Callable[[str, str], Any]) -> None:
        """Register a callback for phase transitions (phase, message)."""
        self._on_phase_change_callbacks.append(callback)

    def on_phase_complete(self, callback: Callable[[str, ScanResult], Any]) -> None:
        """Register a callback after phase results have been attached."""
        self._on_phase_complete_callbacks.append(callback)

    def on_agent_start(self, callback: Callable[[str, str], Any]) -> None:
        """Register a callback when an agent starts (agent_type, tool_name)."""
        self._on_agent_start_callbacks.append(callback)

    def on_agent_complete(self, callback: Callable[[str, int], Any]) -> None:
        """Register a callback when an agent completes (agent_type, findings_count)."""
        self._on_agent_complete_callbacks.append(callback)

    def on_log(self, callback: Callable[[str, str], Any]) -> None:
        """Register a callback for log messages (message, level)."""
        self._on_log_callbacks.append(callback)

    def cancel(self) -> None:
        """Signal the current scan to stop."""
        for scan_id in self._scan_cancel_flags:
            self._scan_cancel_flags[scan_id] = True

    def _fire_phase_change(self, phase: str, message: str = "") -> None:
        for cb in self._on_phase_change_callbacks:
            try:
                cb(phase, message)
            except Exception:
                pass

    def _fire_phase_complete(self, phase: str, scan_result: ScanResult) -> None:
        for cb in self._on_phase_complete_callbacks:
            try:
                cb(phase, scan_result)
            except Exception:
                pass

    def _fire_agent_start(self, agent_type: str, tool_name: str = "") -> None:
        for cb in self._on_agent_start_callbacks:
            try:
                cb(agent_type, tool_name)
            except Exception:
                pass

    def _fire_agent_complete(self, agent_type: str, findings_count: int = 0) -> None:
        for cb in self._on_agent_complete_callbacks:
            try:
                cb(agent_type, findings_count)
            except Exception:
                pass

    def _fire_log(self, message: str, level: str = "info") -> None:
        for cb in self._on_log_callbacks:
            try:
                cb(message, level)
            except Exception:
                pass

    # ── Scan Lifecycle ─────────────────────────────────────────────

    async def start_scan(
        self,
        targets: list[str],
        mode: ScanMode,
        scan_name: str = "",
        scope_config: Optional[ScopeConfig] = None,
    ) -> ScanResult:
        """Begin a new VAPT scan.

        Validates targets, initialises scope and state, creates a
        ``ScanResult`` container, and launches the pipeline.

        Args:
            targets:      List of target URLs, domains, or IPs.
            mode:         The scan mode to use.
            scan_name:    Human-readable name for the scan.
            scope_config: Optional scope override.  If ``None``, a default
                          ``ScopeConfig`` is created from the first target.

        Returns:
            The ``ScanResult`` (may still be running; check ``status``).

        Raises:
            ValueError: If targets list is empty.
        """
        if not targets:
            raise ValueError("At least one target is required to start a scan")

        scan_name = scan_name or f"Scan-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        logger.info(
            "Starting scan '{name}' in {mode} mode with {count} target(s)",
            name=scan_name,
            mode=mode.value,
            count=len(targets),
        )

        # Build target objects
        parsed_targets = self._parse_targets(targets)

        # Build scope config
        if scope_config is None:
            scope_config = self._build_default_scope(parsed_targets)

        self._scope_manager = ScopeManager(scope_config)

        # Create scan result
        scan_result = ScanResult(
            scan_name=scan_name,
            mode=mode,
            targets=parsed_targets,
            status="running",
        )

        # Register in active scans
        self._active_scans[scan_result.id] = scan_result
        self._scan_cancel_flags[scan_result.id] = False

        # Bind the scan id into the async context so tool jobs enqueued by any
        # agent are associated with this scan for the report barrier / abort.
        current_scan_id.set(scan_result.id)

        # Reset state machine
        self._state_machine.reset()

        # Start the pipeline (non-blocking — caller can await for completion
        # via get_scan_progress or by awaiting the returned result)
        try:
            await self._run_pipeline(scan_result)
        except asyncio.CancelledError:
            scan_result.status = "cancelled"
            scan_result.current_phase = ScanPhase.CANCELLED
            logger.warning("Scan '{name}' was cancelled", name=scan_name)
        except Exception as exc:
            scan_result.status = "failed"
            scan_result.current_phase = ScanPhase.FAILED
            scan_result.end_time = datetime.utcnow()
            logger.error(
                "Scan '{name}' failed: {err}",
                name=scan_name,
                err=exc,
                exc_info=True,
            )

        return scan_result

    async def _run_pipeline(self, scan_result: ScanResult) -> None:
        """Execute the main scan pipeline loop.

        Execute the profile's phases in deterministic order. The previous
        implementation mixed state-machine look-ahead, partial parallel
        groups, and loop-back heuristics in one loop. That made VA scans
        fragile: a scan could re-enter expensive phases for the same target
        instead of progressing to the scanner/reporting stages.

        Adaptive re-scans should be scheduled as explicit queued work with
        bounded inputs. The core product path must be predictable first.

        Args:
            scan_result: The ``ScanResult`` to populate during the scan.
        """
        scan_id = scan_result.id
        phase_plan = self._phase_plan_for_scan(scan_result)
        logger.info(
            "Pipeline plan for {mode}: {phases}",
            mode=scan_result.mode.value,
            phases=" -> ".join(phase.value for phase in phase_plan),
        )

        for phase in phase_plan:
            if self._scan_cancel_flags.get(scan_id, False):
                # Cancelled mid-run: abort any in-flight worker jobs so they
                # cannot keep running after the scan is marked cancelled.
                await JOB_TRACKER.abort_scan(scan_id)
                self._state_machine.transition(ScanPhase.CANCELLED)
                scan_result.current_phase = ScanPhase.CANCELLED
                scan_result.status = "cancelled"
                scan_result.end_time = datetime.utcnow()
                logger.info("Scan '{name}' cancelled by user", name=scan_result.scan_name)
                return

            # Report barrier: before generating the final report, wait for every
            # tool job enqueued by earlier phases to reach a terminal state.
            # This is the fix for premature reporting — the report can no longer
            # be produced while worker jobs are still running.
            if phase == ScanPhase.REPORTING:
                await JOB_TRACKER.drain(scan_id)

            if self._state_machine.current_phase != phase:
                try:
                    self._state_machine.transition(phase)
                except ValueError as exc:
                    logger.error(
                        "Pipeline cannot transition {current} -> {target}: {err}",
                        current=self._state_machine.current_phase.value,
                        target=phase.value,
                        err=exc,
                    )
                    self._state_machine.transition(ScanPhase.FAILED)
                    break

            scan_result.current_phase = phase
            self._fire_phase_change(phase.value, f"Phase: {phase.value}")
            logger.info("Pipeline phase: {phase}", phase=phase.value)
            await self._run_phase(phase, scan_result)
            self._fire_phase_complete(phase.value, scan_result)

        if not self._state_machine.is_terminal:
            self._state_machine.transition(ScanPhase.COMPLETED)

        scan_result.current_phase = self._state_machine.current_phase
        scan_result.status = (
            "completed"
            if self._state_machine.current_phase == ScanPhase.COMPLETED
            else "failed"
        )
        scan_result.end_time = datetime.utcnow()

        logger.info(
            "Scan '{name}' finished — status: {status}, findings: {count}",
            name=scan_result.scan_name,
            status=scan_result.status,
            count=len(scan_result.findings),
        )

    def _phase_plan_for_scan(self, scan_result: ScanResult) -> list[ScanPhase]:
        """Return the ordered phase plan implied by the selected profile."""
        profile = self._config.get_profile(scan_result.mode.value)
        agent_to_phase = {
            "recon": ScanPhase.RECON,
            "enum": ScanPhase.ENUMERATION,
            "cloud": ScanPhase.ENUMERATION,
            "iot_cctv": ScanPhase.ENUMERATION,
            "vuln_scanner": ScanPhase.VULN_SCANNING,
            "fuzzer": ScanPhase.FUZZING,
            "exploit": ScanPhase.EXPLOITATION,
            "intel": ScanPhase.INTELLIGENCE,
            "reporter": ScanPhase.REPORTING,
        }
        plan: list[ScanPhase] = []
        for agent_name in profile.agents:
            phase = agent_to_phase.get(agent_name)
            if phase and phase not in plan:
                plan.append(phase)
        return plan or [ScanPhase.RECON, ScanPhase.REPORTING]

    # ── Phase Execution ────────────────────────────────────────────

    async def _run_phase(
        self, phase: ScanPhase, scan_result: ScanResult
    ) -> list[Any]:
        """Execute a single pipeline phase by dispatching to its agents.

        After the phase finishes, its structured result is stashed in
        ``self._phase_context`` under a phase-specific key (``recon_data``,
        ``enum_data``, ...) so downstream agents can consume it. This is the
        Bug #5 fix — previously no context was ever forwarded.

        Returns:
            A list of newly discovered assets (targets, endpoints, etc.).
        """
        new_assets: list[Any] = []
        agent_types = PHASE_AGENT_MAP.get(phase, [])

        for agent_type in agent_types:
            profile = self._config.get_profile(scan_result.mode.value)
            if agent_type.value not in profile.agents:
                logger.debug(
                    "Agent {agent} not in profile '{mode}' — skipping",
                    agent=agent_type.value, mode=scan_result.mode.value,
                )
                continue

            if agent_type not in self._agents:
                logger.warning(
                    "No agent registered for type '{agent}' — skipping phase agent",
                    agent=agent_type.value,
                )
                continue

            dispatch_targets = self._dispatch_targets_for_agent(agent_type, scan_result)
            findings = await self._dispatch_to_agent(
                agent_type, dispatch_targets, scan_result
            )
            for finding in findings:
                scan_result.add_finding(finding)
                await self._fire_finding_callbacks(finding)

            # Extract new assets from findings
            existing_hosts = {t.host for t in scan_result.targets}
            for finding in findings:
                if finding.target.host not in existing_hosts:
                    new_assets.append(finding.target.host)
                    scan_result.add_target(finding.target)

        # Stash this phase's structured result for the next phase to consume.
        # We read it back from the last dispatched task's `.result`.
        self._stash_phase_result(phase, scan_result)

        return new_assets

    def _stash_phase_result(self, phase: ScanPhase, scan_result: ScanResult) -> None:
        """Copy the most recent agent-task result for this phase into the
        shared context store under the conventional key expected by downstream
        agents (``recon_data``, ``enum_data``, ...).
        """
        # Find the latest task for this phase
        relevant = [t for t in scan_result.agent_tasks if t.phase == phase and t.result is not None]
        if not relevant:
            return
        result = relevant[-1].result
        key_map = {
            ScanPhase.RECON: "recon_data",
            ScanPhase.ENUMERATION: "enum_data",
            ScanPhase.VULN_SCANNING: "vuln_data",
            ScanPhase.FUZZING: "fuzz_data",
            ScanPhase.EXPLOITATION: "exploit_data",
            ScanPhase.INTELLIGENCE: "intel_data",
        }
        key = key_map.get(phase)
        if key and isinstance(result, dict):
            self._phase_context[key] = result
            logger.debug("Stashed phase context: {key} ({fields} fields)",
                         key=key, fields=len(result))
            # Feed evidence accumulator so the planner sees fresh tokens.
            self._ingest_evidence_from_phase_context(phase)
            for run in result.get("tool_runs") or []:
                if isinstance(run, dict) and run.get("tool"):
                    self._tools_run.add(str(run["tool"]))

    def _build_task_parameters(
        self, agent_type: AgentType, scan_result: ScanResult
    ) -> dict[str, Any]:
        """Build the parameters dict for a task, forwarding all accumulated
        phase context the agent might need. This is the core of the Bug #5 fix.
        """
        params: dict[str, Any] = {"mode": scan_result.mode.value}

        # Forward any phase context we have so far
        for k, v in self._phase_context.items():
            params[k] = v

        # Pass the full accumulated evidence set so agents can make
        # evidence-driven decisions (e.g. fire wpscan only if tech_wordpress
        # is present, fire redis nuclei only if service_redis is present).
        params["evidence_tokens"] = frozenset(self._evidence)
        current_phase = self._state_machine.current_phase.value
        include_aggressive = scan_result.mode == ScanMode.FULL_VAPT
        eligible = self.get_eligible_tools(
            phase=current_phase,
            include_aggressive=include_aggressive,
        )
        params["approved_capabilities"] = tuple(capability.name for capability in eligible)
        params["capability_decision"] = {
            "source": "deterministic_evidence_policy",
            "phase": current_phase,
            "evidence_tokens": sorted(self._evidence),
            "approved": [capability.name for capability in eligible],
            "aggressive_allowed": include_aggressive,
        }

        # Downstream decision-making agents need the live scan_result and
        # existing findings. vuln_scanner uses recon findings to choose
        # tech-specific checks such as WPScan even when the technology map is
        # incomplete.
        if agent_type in (AgentType.VULN_SCANNER, AgentType.FUZZER, AgentType.EXPLOIT, AgentType.INTEL, AgentType.REPORTER):
            params["scan_result"] = scan_result
            params["existing_findings"] = list(scan_result.findings)

        return params

    def _dispatch_targets_for_agent(
        self, agent_type: AgentType, scan_result: ScanResult
    ) -> list[Target]:
        """Return the target list for this agent without duplicating global work."""
        unique_targets: list[Target] = []
        seen: set[tuple[str, int, str]] = set()
        for target in scan_result.targets:
            key = (target.host.lower(), target.port, target.protocol)
            if key in seen:
                continue
            seen.add(key)
            unique_targets.append(target)

        if agent_type in GLOBAL_CONTEXT_AGENTS and unique_targets:
            return [unique_targets[0]]
        return unique_targets

    @staticmethod
    def _agent_in_profile(phase: ScanPhase, profile: Any) -> bool:
        """Return True if the agent for ``phase`` is listed in the scan profile.

        Maps a ScanPhase to its AgentType value string and checks membership
        in ``profile.agents``. Used to decide whether a parallel-phase group
        can actually run (every member must be in-profile).
        """
        phase_to_agent = {
            ScanPhase.RECON: "recon",
            ScanPhase.ENUMERATION: "enum",
            ScanPhase.VULN_SCANNING: "vuln_scanner",
            ScanPhase.FUZZING: "fuzzer",
            ScanPhase.EXPLOITATION: "exploit",
            ScanPhase.INTELLIGENCE: "intel",
            ScanPhase.REPORTING: "reporter",
        }
        agent_name = phase_to_agent.get(phase, "")
        return agent_name in (profile.agents if hasattr(profile, "agents") else [])

    async def _dispatch_to_agent(
        self,
        agent_type: AgentType,
        targets: list[Target],
        scan_result: ScanResult,
    ) -> list[Finding]:
        """Create a task for a specific agent and execute it."""
        agent = self._agents.get(agent_type)
        if agent is None:
            logger.warning("Cannot dispatch to unregistered agent: {agent}", agent=agent_type.value)
            return []

        all_findings: list[Finding] = []

        for target in targets:
            task = AgentTask(
                agent_type=agent_type,
                phase=self._state_machine.current_phase,
                target=target,
                tool_name=agent_type.value,
                command=f"vapt-agent {agent_type.value} --target {target.base_url}",
                parameters=self._build_task_parameters(agent_type, scan_result),
            )

            scan_result.add_task(task)
            task.mark_running()
            # Bind live-log context so every tool this agent runs streams its
            # output to the UI tagged with the right scan/agent/phase.
            tool_log_context.set({
                "scan_id": scan_result.id,
                "agent": agent_type.value,
                "phase": self._state_machine.current_phase.value,
            })
            self._fire_agent_start(agent_type.value, agent_type.value)
            self._fire_log(f"Dispatching {agent_type.value} to {target.host}", "info")
            logger.info(
                "Dispatching task {task_id} to agent '{agent}' for target {host}",
                task_id=task.id[:8], agent=agent_type.value, host=target.host,
            )

            try:
                # Invoke the agent — supports async callable and objects with
                # an async ``execute`` method.
                if asyncio.iscoroutinefunction(agent):
                    agent_call = agent(task)
                elif hasattr(agent, "execute") and asyncio.iscoroutinefunction(agent.execute):
                    agent_call = agent.execute(task)
                else:
                    agent_call = agent(task)

                if asyncio.iscoroutine(agent_call):
                    result = await asyncio.wait_for(
                        agent_call,
                        timeout=self._agent_timeout_seconds,
                    )
                else:
                    result = agent_call

                findings = self._normalise_agent_result(result, agent_type, target)
                structured_result = task.result
                task.mark_completed(result=structured_result if structured_result is not None else findings)
                self._fire_agent_complete(agent_type.value, len(findings))

                for finding in findings:
                    all_findings.append(finding)

                logger.info(
                    "Agent '{agent}' returned {count} finding(s) for {host}",
                    agent=agent_type.value, count=len(findings), host=target.host,
                )
                self._fire_log(
                    f"Agent {agent_type.value} completed for {target.host}: {len(findings)} finding(s)",
                    "success",
                )

            except asyncio.CancelledError:
                task.mark_failed("Task cancelled")
                raise
            except asyncio.TimeoutError:
                message = (
                    f"Agent {agent_type.value} timed out for {target.host} "
                    f"after {self._agent_timeout_seconds}s"
                )
                # Abort any jobs this agent left in flight so a slow tool cannot
                # keep running (and emit output) after the agent is abandoned.
                await JOB_TRACKER.abort_scan(scan_result.id)
                task.mark_failed(message)
                self._fire_agent_complete(agent_type.value, 0)
                self._fire_log(message, "error")
                logger.error(message)
            except Exception as exc:
                task.mark_failed(str(exc))
                self._fire_agent_complete(agent_type.value, 0)
                self._fire_log(f"Agent {agent_type.value} failed: {exc}", "error")
                logger.error(
                    "Agent '{agent}' failed for target {host}: {err}",
                    agent=agent_type.value, host=target.host, err=exc, exc_info=True,
                )

            # Throttle between targets if needed
            if self._scope_manager and self._scope_manager.is_rate_limited():
                logger.debug("Rate limit hit — sleeping briefly")
                await asyncio.sleep(1.0)

        return all_findings

    async def _handle_parallel_phases(
        self, phases: list[ScanPhase], scan_result: ScanResult
    ) -> None:
        """Execute multiple phases concurrently using ``asyncio.gather``.

        Args:
            phases:      List of phases to run in parallel.
            scan_result: The scan result to populate.
        """
        logger.info(
            "Running parallel phases: {phases}",
            phases=", ".join(p.value for p in phases),
        )

        async def _run_one(phase: ScanPhase) -> list[Any]:
            """Wrapper to run a single phase and return new assets."""
            scan_result.current_phase = phase
            return await self._run_phase(phase, scan_result)

        results = await asyncio.gather(
            *[_run_one(p) for p in phases],
            return_exceptions=True,
        )

        # Process results and log any exceptions
        all_new_assets: list[Any] = []
        for phase, result in zip(phases, results):
            if isinstance(result, Exception):
                logger.error(
                    "Parallel phase '{phase}' failed: {err}",
                    phase=phase.value,
                    err=result,
                )
            else:
                all_new_assets.extend(result)

        # Set current phase to the last in the parallel group
        scan_result.current_phase = phases[-1]

        # Transition state machine past the parallel phases
        # Pick the first phase in the group as the "current" for transition
        self._state_machine.current_phase = phases[-1]

        logger.info(
            "Parallel phases completed — total new assets: {count}",
            count=len(all_new_assets),
        )

    # ── Loop-Back Logic ────────────────────────────────────────────

    def _should_loop_back(
        self,
        phase: ScanPhase,
        findings: list[Finding],
        new_assets: list[Any],
    ) -> Optional[ScanPhase]:
        """Decide whether the pipeline should revisit a previous phase.

        Uses both finding metadata and newly discovered assets to make
        the determination.

        Args:
            phase:       The phase that just completed.
            findings:    Findings produced during this phase.
            new_assets:  Newly discovered hosts/endpoints.

        Returns:
            The ``ScanPhase`` to loop back to, or ``None``.
        """
        # Build context dict for the state machine's loop-back logic
        result_context: dict[str, Any] = {
            "new_subdomains_found": False,
            "new_endpoints_found": False,
            "new_attack_vectors": False,
            "new_hosts_discovered": False,
        }

        # Check for new hosts
        if new_assets:
            result_context["new_hosts_discovered"] = True
            result_context["new_subdomains_found"] = True

        # Check findings for indicators that warrant loop-back
        for finding in findings:
            # Findings with tags suggesting new endpoints
            if "new_endpoint" in finding.tags or "new_subdomain" in finding.tags:
                result_context["new_endpoints_found"] = True
                result_context["new_subdomains_found"] = True
            # Findings that suggest new attack surface
            if "new_attack_surface" in finding.tags or "new_service" in finding.tags:
                result_context["new_attack_vectors"] = True

        # High/critical findings that need further exploitation
        critical_high = [
            f for f in findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH) and f.status == "confirmed"
        ]
        if critical_high:
            result_context["new_attack_vectors"] = True

        # Recon-discovered hosts move forward as expanded context/targets.
        # Re-entering recon for every subdomain causes recon loops and blocks VA.
        if phase != ScanPhase.RECON:
            loop_target = self._state_machine.should_loop_back(result_context)
            if loop_target:
                return loop_target

        # Additional heuristic: if fuzzing found new endpoints, go back to vuln scanning
        if phase == ScanPhase.FUZZING and result_context["new_endpoints_found"]:
            if self._state_machine.can_transition(phase, ScanPhase.VULN_SCANNING):
                return ScanPhase.VULN_SCANNING

        # If intelligence found new attack vectors, loop back to exploitation
        if phase == ScanPhase.INTELLIGENCE and result_context["new_attack_vectors"]:
            if self._state_machine.can_transition(phase, ScanPhase.EXPLOITATION):
                return ScanPhase.EXPLOITATION

        return None

    # ── Progress & Control ─────────────────────────────────────────

    def get_scan_progress(self, scan_id: str) -> dict[str, Any]:
        """Return the current progress of a scan.

        Args:
            scan_id: The scan identifier.

        Returns:
            A dictionary with progress information including phase,
            finding counts, task counts, and timing.
        """
        scan = self._active_scans.get(scan_id)
        if scan is None:
            return {"error": f"Scan '{scan_id}' not found"}

        tasks_by_status: dict[str, int] = {}
        for task in scan.agent_tasks:
            tasks_by_status[task.status] = tasks_by_status.get(task.status, 0) + 1

        return {
            "scan_id": scan.id,
            "scan_name": scan.scan_name,
            "mode": scan.mode.value,
            "status": scan.status,
            "current_phase": scan.current_phase.value,
            "targets_count": len(scan.targets),
            "findings_count": len(scan.findings),
            "findings_by_severity": {
                sev: len(flist)
                for sev, flist in scan.findings_by_severity.items()
                if flist
            },
            "tasks_total": len(scan.agent_tasks),
            "tasks_by_status": tasks_by_status,
            "duration_seconds": scan.duration_seconds,
            "start_time": scan.start_time.isoformat(),
            "end_time": scan.end_time.isoformat() if scan.end_time else None,
            "state_machine": {
                "current_phase": self._state_machine.current_phase.value,
                "is_terminal": self._state_machine.is_terminal,
                "transition_count": self._state_machine.transition_count,
            },
            "evidence": self.get_evidence_snapshot(),
        }

    async def cancel_scan(self, scan_id: str) -> None:
        """Request cancellation of a running scan.

        Sets a cancellation flag that is checked at the start of each
        pipeline iteration.

        Args:
            scan_id: The scan to cancel.
        """
        if scan_id not in self._active_scans:
            logger.warning("Cannot cancel — scan '{id}' not found", id=scan_id)
            return

        self._scan_cancel_flags[scan_id] = True
        scan = self._active_scans[scan_id]
        scan.status = "cancelling"
        logger.info("Cancellation requested for scan '{name}'", name=scan.scan_name)

    def get_findings(
        self,
        scan_id: str,
        severity: Optional[Severity] = None,
    ) -> list[Finding]:
        """Retrieve findings for a scan, optionally filtered by severity.

        Args:
            scan_id:  The scan identifier.
            severity: If provided, only return findings of this severity.

        Returns:
            A list of matching ``Finding`` objects.
        """
        scan = self._active_scans.get(scan_id)
        if scan is None:
            return []

        if severity is None:
            return list(scan.findings)

        return [f for f in scan.findings if f.severity == severity]

    # ── Internal Helpers ───────────────────────────────────────────

    def _parse_targets(self, raw_targets: list[str]) -> list[Target]:
        """Parse raw target strings into ``Target`` objects.

        Handles URLs, host:port pairs, and bare domains/IPs.

        Args:
            raw_targets: List of raw target strings.

        Returns:
            A list of validated ``Target`` objects.
        """
        targets: list[Target] = []
        seen: set[str] = set()

        for raw in raw_targets:
            raw = raw.strip()
            if not raw:
                continue

            # Deduplicate
            key = raw.lower()
            if key in seen:
                continue
            seen.add(key)

            # Parse URL
            from urllib.parse import urlparse

            wildcard_scope = raw.startswith("*.")
            if wildcard_scope:
                raw = raw[2:]

            if raw.startswith(("http://", "https://")):
                parsed = urlparse(raw)
                host = parsed.hostname or raw
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                protocol = parsed.scheme
                url = raw
            elif ":" in raw and not raw.startswith("["):
                # host:port
                parts = raw.rsplit(":", 1)
                host = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    port = 443
                protocol = "https"
                url = f"https://{host}:{port}"
            else:
                # Bare host
                host = raw
                port = 443
                protocol = "https"
                url = f"https://{host}:{port}"

            target = Target(
                host=host,
                port=port,
                protocol=protocol,
                url=url,
                scope_tags=["initial"] + (["wildcard_scope"] if wildcard_scope else []),
                metadata={"wildcard_scope": wildcard_scope} if wildcard_scope else {},
            )
            targets.append(target)
            logger.debug("Parsed target: {host}:{port} ({proto})", host=host, port=port, proto=protocol)

        return targets

    def _build_default_scope(self, targets: list[Target]) -> ScopeConfig:
        """Build a default ``ScopeConfig`` from the initial target list.

        Extracts unique domains from the targets and adds them to the
        authorised domains list.  Also adds any IP addresses.

        Args:
            targets: The parsed target list.

        Returns:
            A ``ScopeConfig`` with appropriate defaults.
        """
        domains: list[str] = []
        ips: list[str] = []

        for target in targets:
            # Check if host looks like an IP
            try:
                import ipaddress
                ipaddress.ip_address(target.host)
                ips.append(target.host)
            except ValueError:
                host = target.host.lower().rstrip(".")
                pattern = f"*.{host[2:]}" if host.startswith("*.") else host
                if target.metadata.get("wildcard_scope") and not pattern.startswith("*."):
                    pattern = f"*.{pattern}"
                if pattern not in domains:
                    domains.append(pattern)

        return ScopeConfig(
            authorized_domains=domains,
            authorized_ips=ips,
            rate_limit=self._config.rate_limiting.requests_per_second,
            max_requests_total=self._config.rate_limiting.requests_per_second * 3600,
        )

    def _advance_from_phase(
        self, current_phase: ScanPhase, scan_result: ScanResult
    ) -> None:
        """Advance the state machine forward from the given phase.

        Picks the next logical phase using a pipeline-order preference
        (vuln_scanning before fuzzing, intelligence before reporting, etc.)
        rather than alphabetical order — ``get_next_phases`` returns sorted
        phases, which previously caused ``fuzzing`` to be chosen over
        ``vuln_scanning`` after enumeration, skipping the vuln scanner.
        """
        next_phases = self._state_machine.get_next_phases()
        if not next_phases:
            return

        # Filter out emergency transitions for normal advancement
        normal_next = [
            p for p in next_phases
            if p not in (ScanPhase.FAILED, ScanPhase.CANCELLED)
        ]
        if not normal_next:
            return

        profile = self._config.get_profile(scan_result.mode.value)

        # Profile-aware choices
        if current_phase == ScanPhase.EXPLOITATION:
            target_phase = (ScanPhase.INTELLIGENCE
                            if AgentType.INTEL.value in profile.agents
                            else ScanPhase.REPORTING)
            if target_phase in normal_next:
                self._state_machine.transition(target_phase)
                return

        # Prefer phases whose agent is actually in the scan profile, in
        # canonical pipeline order. This ensures e.g. vuln_scanning runs
        # before fuzzing, and skipped agents don't pull us off the path.
        pipeline_order = [
            ScanPhase.VULN_SCANNING,
            ScanPhase.FUZZING,
            ScanPhase.EXPLOITATION,
            ScanPhase.INTELLIGENCE,
            ScanPhase.REPORTING,
            ScanPhase.COMPLETED,
        ]
        for candidate in pipeline_order:
            if candidate in normal_next:
                # If the candidate's agent isn't in profile, skip to the next
                agent_name = {
                    ScanPhase.VULN_SCANNING: "vuln_scanner",
                    ScanPhase.FUZZING: "fuzzer",
                    ScanPhase.EXPLOITATION: "exploit",
                    ScanPhase.INTELLIGENCE: "intel",
                    ScanPhase.REPORTING: "reporter",
                }.get(candidate, "")
                if agent_name and agent_name not in profile.agents:
                    continue
                self._state_machine.transition(candidate)
                return

        # Fallback: first normal next phase
        self._state_machine.transition(normal_next[0])

    def _get_phase_after_parallel(
        self, parallel_phases: list[ScanPhase], scan_result: ScanResult
    ) -> Optional[ScanPhase]:
        """Determine which phase should come after a parallel group finishes.

        Args:
            parallel_phases: The phases that ran in parallel.
            scan_result:     The scan result for profile-aware decisions.

        Returns:
            The next phase, or ``None`` if the state machine should be
            allowed to decide naturally.
        """
        # After vuln_scanning + fuzzing, the next should be exploitation
        if ScanPhase.VULN_SCANNING in parallel_phases:
            profile = self._config.get_profile(scan_result.mode.value)
            if profile.exploit:
                return ScanPhase.EXPLOITATION
            return ScanPhase.REPORTING
        return None

    @staticmethod
    def _normalise_agent_result(
        result: Any, agent_type: AgentType, target: Target
    ) -> list[Finding]:
        """Normalise an agent's return value to a list of findings.

        Agents may return:
        - A single ``Finding``
        - A list of ``Finding`` objects
        - A dict (converted to a basic Finding)
        - ``None`` (no findings)

        Args:
            result:     The raw return value from the agent.
            agent_type: The agent type (used for default finding metadata).
            target:     The target (used for default finding metadata).

        Returns:
            A list of ``Finding`` objects (possibly empty).
        """
        from datetime import datetime as _dt

        if result is None:
            return []

        if isinstance(result, list):
            findings: list[Finding] = []
            for item in result:
                if isinstance(item, Finding):
                    findings.append(item)
                elif isinstance(item, dict):
                    findings.append(Finding(
                        title=item.get("title", "Untitled Finding"),
                        description=item.get("description", ""),
                        severity=Severity(item.get("severity", "medium")),
                        agent_source=agent_type,
                        target=target,
                        evidence=item.get("evidence", ""),
                        created_at=_dt.utcnow(),
                    ))
            return findings

        if isinstance(result, Finding):
            return [result]

        if isinstance(result, dict):
            return [Finding(
                title=result.get("title", "Untitled Finding"),
                description=result.get("description", ""),
                severity=Severity(result.get("severity", "medium")),
                agent_source=agent_type,
                target=target,
                evidence=result.get("evidence", ""),
                created_at=_dt.utcnow(),
            )]

        logger.warning(
            "Agent '{agent}' returned unexpected type: {type}",
            agent=agent_type.value,
            type=type(result).__name__,
        )
        return []

    # ── Evidence-driven planning ────────────────────────────────────

    def _ingest_evidence_from_phase_context(self, phase: ScanPhase) -> None:
        """Extract evidence tokens from the most recent phase result and
        accumulate them in self._evidence so plan_next_tools() can fire."""
        key_map = {
            ScanPhase.RECON: "recon_data",
            ScanPhase.ENUMERATION: "enum_data",
            ScanPhase.VULN_SCANNING: "vuln_data",
            ScanPhase.FUZZING: "fuzz_data",
            ScanPhase.EXPLOITATION: "exploit_data",
            ScanPhase.INTELLIGENCE: "intel_data",
        }
        ctx_key = key_map.get(phase)
        if not ctx_key:
            return
        data = self._phase_context.get(ctx_key)
        if not isinstance(data, dict):
            return

        # Map structured phase-result fields to evidence tokens.
        field_evidence_map: dict[str, list[str]] = {
            "subdomains":          ["subdomain"],
            "live_urls":           ["live_url"],
            "dns_records":         ["dns_record"],
            "open_ports":          ["open_port"],
            "services":            ["service_banner"],
            "technologies":        ["technology"],
            "javascript_urls":     ["javascript_url"],
            "crawled_urls":        ["endpoint"],
            "historical_urls":     ["historical_url"],
            "parameters":          ["parameter"],
            "api_endpoints":       ["api_endpoint"],
            "cloud_assets":        ["cloud_asset"],
            "s3_buckets":          ["s3_bucket_hint", "cloud_asset"],
            "discovered_paths":    ["discovered_path"],
            "findings":            ["finding_cve"],
        }

        for field, tokens in field_evidence_map.items():
            value = data.get(field)
            if value:
                for token in tokens:
                    self._evidence.add(token)

        # Tech-specific tokens.
        technologies = data.get("technologies") or {}
        if isinstance(technologies, dict):
            for tech_list in technologies.values():
                for tech in (tech_list or []):
                    token = f"tech_{tech.lower().replace(' ', '_').replace('-', '_')}"
                    self._evidence.add(token)
        elif isinstance(technologies, list):
            for tech in technologies:
                token = f"tech_{str(tech).lower().replace(' ', '_').replace('-', '_')}"
                self._evidence.add(token)

        # Boolean flags.
        if data.get("waf_detected"):
            self._evidence.add("waf_detected")
        if data.get("cloudflare_detected"):
            self._evidence.add("cloudflare_detected")
        if data.get("tls_detected"):
            self._evidence.add("tls_service")

        # Per-service evidence tokens from nmap/naabu output.
        # Maps well-known service names and port numbers to specific tokens so
        # downstream agents can fire targeted nuclei templates without guessing.
        _SERVICE_TOKEN_MAP: dict[str, str] = {
            "redis": "service_redis",
            "mysql": "service_mysql", "mariadb": "service_mysql",
            "postgresql": "service_postgresql", "postgres": "service_postgresql",
            "mongodb": "service_mongodb", "mongod": "service_mongodb",
            "elasticsearch": "service_elasticsearch",
            "memcached": "service_memcached",
            "rabbitmq": "service_rabbitmq", "amqp": "service_rabbitmq",
            "kafka": "service_kafka",
            "smb": "smb_open", "microsoft-ds": "smb_open", "netbios-ssn": "smb_open",
            "ssh": "ssh_open",
            "rdp": "rdp_open", "ms-wbt-server": "rdp_open",
            "smtp": "service_smtp",
            "ftp": "service_ftp",
            "snmp": "snmp_open",
            "rtsp": "rtsp_open",
            "jenkins": "service_jenkins",
            "kubernetes": "service_kubernetes", "k8s": "service_kubernetes",
            "docker": "service_docker",
        }
        _PORT_TOKEN_MAP: dict[int, str] = {
            22: "ssh_open", 25: "service_smtp", 21: "service_ftp",
            445: "smb_open", 139: "smb_open", 3389: "rdp_open",
            161: "snmp_open", 554: "rtsp_open",
            3306: "service_mysql", 5432: "service_postgresql",
            6379: "service_redis", 27017: "service_mongodb",
            9200: "service_elasticsearch", 9300: "service_elasticsearch",
            11211: "service_memcached", 5672: "service_rabbitmq",
            8080: "service_http_alt", 8443: "service_https_alt",
            8888: "service_http_alt", 9090: "service_prometheus",
            3000: "service_grafana_candidate", 5601: "service_kibana",
            8161: "service_activemq", 4848: "service_glassfish",
            8500: "service_consul", 2379: "service_etcd",
        }
        services_list = data.get("services") or []
        if isinstance(services_list, list):
            for svc in services_list:
                if not isinstance(svc, dict):
                    continue
                svc_name = (svc.get("service") or svc.get("name") or "").lower().strip()
                port = svc.get("port")
                if svc_name:
                    token = _SERVICE_TOKEN_MAP.get(svc_name)
                    if token:
                        self._evidence.add(token)
                if port:
                    try:
                        token = _PORT_TOKEN_MAP.get(int(port))
                        if token:
                            self._evidence.add(token)
                    except (TypeError, ValueError):
                        pass

        logger.debug(
            "Evidence after {phase}: {count} tokens",
            phase=phase.value,
            count=len(self._evidence),
        )

    def get_eligible_tools(
        self,
        phase: Optional[str] = None,
        include_aggressive: bool = False,
    ) -> list[Any]:
        """Return tools ready to run given current accumulated evidence.

        This exposes the evidence-driven planner to external consumers
        (e.g. the API's /attack-surface/plan endpoint and future LLM brain).
        """
        return plan_next_tools(
            available_evidence=self._evidence,
            already_run=self._tools_run,
            phase=phase,
            include_aggressive=include_aggressive,
            available_tools=executable_tool_names(self._config),
            target_layers=target_layers_from_evidence(self._evidence) or None,
        )

    def record_tool_run(self, tool_name: str) -> None:
        """Mark a tool as executed so the planner doesn't re-schedule it."""
        self._tools_run.add(tool_name)

    def get_evidence_snapshot(self) -> dict[str, Any]:
        """Return the current evidence state for debugging / API exposure."""
        return {
            "evidence_tokens": sorted(self._evidence),
            "tools_run": sorted(self._tools_run),
            "eligible_next": [c.name for c in self.get_eligible_tools()],
        }

    async def _fire_finding_callbacks(self, finding: Finding) -> None:
        """Invoke all registered finding callbacks.

        Supports both sync and async callbacks. The scan_manager registers an
        ``async def on_finding`` that performs dedup + NVD verification + SSE
        broadcast — if we call it synchronously the coroutine is never awaited
        and findings never reach the dashboard. We detect coroutine results
        and await them here.
        """
        for callback in self._on_finding_callbacks:
            try:
                result = callback(finding)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                logger.error("Finding callback error: {err}", err=exc, exc_info=True)
