"""
VAPT Platform — Scan Lifecycle Manager

Manages the full lifecycle of scans:
  - Create, start, pause, resume, stop, cancel
  - Track agent status and progress per scan
  - Broadcast real-time events via SSE queues
  - Deduplicate findings across targets
  - Coordinate with NVD service for CVE verification

This is the layer that Faraday calls the "Workspace Manager" and
OpenVAS calls the "Scan Task Manager".
"""

import asyncio
import hashlib
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Optional
from collections import defaultdict
from urllib.parse import urlparse

from loguru import logger
from core.models import (
    ScanMode, ScanPhase, AgentType, Target, Finding, AgentTask,
    ScanResult, ScopeConfig, Severity,
)
from core.asset_graph import AssetGraphBuilder, canonical_graph_projection, summarize_assets
from core.config import AppConfig
from core.display import display_port, display_target, display_url, redact_display_text
from core.engagement_policy import engagement_limits
from core.quality import enrich_finding_quality
from core.adaptive_planner import AdaptivePlanner
from core.attack_chain import compile_attack_chains
from core.control_evidence import build_control_evidence
from core.assurance_coverage import build_assurance_coverage
from core.scope import ScopeManager
from core.targeting import (
    TargetClassification,
    classify_targets,
    evidence_from_asset_records,
    evidence_from_classifications,
    scope_from_classifications,
)
from core.tool_registry import plan_next_tools, target_layers_from_evidence
from core.runtime_capabilities import executable_tool_names
from database import PersistenceStore
from services.nvd_service import NVDService


@dataclass
class AgentStatus:
    """Real-time status of an agent during a scan."""
    agent_type: str
    status: str = "idle"  # idle, running, completed, failed, skipped, cancelled
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    findings_count: int = 0
    tools_run: list[str] = field(default_factory=list)
    current_tool: str = ""
    progress_pct: int = 0
    error: str = ""
    log_messages: list[str] = field(default_factory=list)


@dataclass
class ScanEvent:
    """An event to be broadcast via SSE/WebSocket."""
    event_type: str  # phase_change, finding, agent_status, log, scan_complete, scan_failed
    scan_id: str
    data: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class ScanManager:
    """Manages scan lifecycle, agent orchestration, and event broadcasting.

    This is the backbone that connects the web API to the actual scanning engine.
    It handles:
    1. Scan creation with proper scope enforcement
    2. Real-time event broadcasting to connected clients
    3. Finding deduplication across targets (fixes the "same vulns" bug)
    4. NVD verification integration
    5. Agent status tracking (fixes the "agents sitting idle" bug)
    6. Report generation and download (fixes the "no download" bug)

    Like Faraday's workspace manager, this is a singleton that manages
    all active scans and their state.
    """

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._scans: dict[str, dict] = {}          # scan_id -> scan data
        self._findings: dict[str, list[dict]] = {}  # scan_id -> findings
        self._agent_status: dict[str, dict[str, AgentStatus]] = {}  # scan_id -> agent_type -> status
        # Queue -> channel. Control-plane clients never receive raw tool-line
        # traffic, so a chatty crawler cannot evict lifecycle events from their
        # bounded queue.
        self._events: dict[asyncio.Queue, str] = {}  # SSE client queues
        self._event_history: list[dict] = []         # recent events replayed to new SSE clients
        self._nvd = NVDService()
        self._scan_id_counter = 0
        self._orchestrators: dict[str, Any] = {}    # scan_id -> orchestrator instance
        self._persisted_task_runs: set[tuple[str, str]] = set()
        self._live_log_task: Optional[asyncio.Task] = None  # live tool-log relay
        self._store = PersistenceStore(config.database.url)
        self._adaptive_planner = AdaptivePlanner(config)
        self._hydrate_from_store()

    @property
    def nvd(self) -> NVDService:
        return self._nvd

    def _hydrate_from_store(self) -> None:
        """Load durable scan state into memory when the backend starts."""
        self._scans = self._store.load_scans()
        self._findings = self._store.load_all_findings()
        persisted_statuses = self._store.load_agent_status()
        self._agent_status = {}
        for scan_id, statuses in persisted_statuses.items():
            self._agent_status[scan_id] = {
                agent_name: AgentStatus(**status_data)
                for agent_name, status_data in statuses.items()
            }
        self._event_history = self._store.load_recent_events(limit=1000)
        recovered_actions = self._store.recover_stale_actions(
            (datetime.utcnow() - timedelta(minutes=30)).isoformat()
        )
        if recovered_actions:
            logger.warning(
                "Marked {count} stale runner action(s) retryable after startup recovery",
                count=recovered_actions,
            )

        for scan_id, scan in self._scans.items():
            if scan.get("status") == "running":
                scan.update({
                    "status": "interrupted",
                    "error": (
                        "API process restarted. Completed runner actions and evidence were retained; "
                        "the operation requires an operator resume from its last checkpoint."
                    ),
                })
                self._store.upsert_scan(scan_id, scan)
            self._findings.setdefault(scan_id, [])
            self._agent_status.setdefault(scan_id, {})
            if scan.get("status") in {"failed", "cancelled", "completed"}:
                self._reconcile_agent_statuses_sync(
                    scan_id,
                    scan.get("status", ""),
                    scan.get("error", ""),
                )

        highest_counter = 0
        for scan_id in self._scans:
            try:
                highest_counter = max(highest_counter, int(scan_id.rsplit("_", 1)[-1]))
            except (TypeError, ValueError):
                continue
        self._scan_id_counter = highest_counter

    def subscribe_events(self, after_sequence: int = 0, channel: str = "all") -> asyncio.Queue:
        """Subscribe to scan events. Returns a queue for SSE streaming."""
        channel = channel if channel in {"all", "control", "telemetry"} else "control"
        queue = asyncio.Queue(maxsize=500)
        replay = (
            self._store.load_events_after(after_sequence, limit=500)
            if after_sequence > 0
            else self._event_history[-200:]
        )
        for event in replay:
            if channel == "telemetry" and event.get("type") != "tool_log":
                continue
            if channel == "control" and event.get("type") == "tool_log":
                continue
            try:
                queue.put_nowait(self._display_event(event))
            except asyncio.QueueFull:
                break
        self._events[queue] = channel
        return queue

    def unsubscribe_events(self, queue: asyncio.Queue) -> None:
        """Remove an SSE subscriber."""
        self._events.pop(queue, None)

    def get_recent_events(self, scan_id: Optional[str] = None, limit: int = 200) -> list[dict]:
        """Return recent events for polling/recovery clients."""
        events = self._event_history
        if scan_id:
            events = [e for e in events if e.get("scan_id") == scan_id or e.get("type") == "ping"]
        limit = max(1, min(limit, 500))
        return [self._display_event(event) for event in events[-limit:]]

    def get_decisions(self, scan_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """Return the durable, replayable agent decision ledger for one scan."""
        decisions = self._store.load_events(
            scan_id,
            event_type="agent_decision",
            limit=max(1, min(limit, 500)),
        )
        return [self._display_event(event) for event in decisions]

    def get_attack_chains(self, scan_id: str) -> dict[str, Any]:
        """Compile evidence-backed paths without promoting hypotheses to findings."""
        result = compile_attack_chains(self._findings.get(scan_id, []))
        return {"scan_id": scan_id, **result}

    def get_operation(self, scan_id: str) -> dict[str, Any]:
        """Return the durable, reconnectable execution ledger for one assessment."""
        actions = self._store.load_durable_actions(scan_id)
        events = self._store.load_events(scan_id, limit=200)
        statuses: dict[str, int] = defaultdict(int)
        for action in actions:
            statuses[str(action.get("status") or "unknown")] += 1
        sequence = max((int(event.get("sequence") or 0) for event in events), default=0)
        scan = self._scans.get(scan_id, {})
        return {
            "operation_id": f"operation_{scan_id}",
            "scan_id": scan_id,
            "status": scan.get("status", "unknown"),
            "current_phase": scan.get("current_phase", ""),
            "reconnect_cursor": sequence,
            "summary": {
                "total_actions": len(actions),
                "running": statuses.get("running", 0),
                "completed": statuses.get("completed", 0),
                "partial": statuses.get("partial", 0),
                "retrying": statuses.get("retrying", 0),
                "failed": statuses.get("failed", 0) + statuses.get("timed_out", 0),
            },
            "actions": actions,
            "events": [self._display_event(event) for event in events],
            "recovery": {
                "durable_results": True,
                "event_replay": True,
                "operator_resume_required": scan.get("status") == "interrupted",
            },
        }

    def get_control_evidence(self, scan_id: str) -> dict[str, Any]:
        return {
            "scan_id": scan_id,
            **build_control_evidence(
                scan=self._scans.get(scan_id, {}),
                coverage=self.get_scan_coverage(scan_id),
                findings=self._findings.get(scan_id, []),
                assets=self._store.load_assets(scan_id),
                actions=self._store.load_durable_actions(scan_id),
            ),
        }

    def get_assurance_coverage(self, scan_id: str) -> dict[str, Any]:
        """Project persisted evidence onto recognized OWASP testing domains."""
        validation_events = self._store.load_events(
            scan_id,
            event_type="dast_validation_summary",
            limit=1,
        )
        validation_summary = validation_events[-1] if validation_events else {}
        return {
            "scan_id": scan_id,
            **build_assurance_coverage(
                scan=self._scans.get(scan_id, {}),
                findings=self._findings.get(scan_id, []),
                assets=self.get_asset_graph(scan_id).get("assets", []),
                actions=self._store.load_durable_actions(scan_id),
                validation_summary=validation_summary,
            ),
        }

    async def _record_adaptive_decision(self, scan_id: str, phase: str) -> None:
        orchestrator = self._orchestrators.get(scan_id)
        if orchestrator is None or not hasattr(orchestrator, "get_evidence_snapshot"):
            return
        snapshot = orchestrator.get_evidence_snapshot()
        decision = await self._adaptive_planner.plan(
            scan_id=scan_id,
            phase=phase,
            evidence_tokens=set(snapshot.get("evidence_tokens") or []),
            already_run=set(snapshot.get("tools_run") or []),
            available_tools=executable_tool_names(self._config),
        )
        await self._broadcast(ScanEvent(
            event_type="agent_decision",
            scan_id=scan_id,
            data=decision,
        ))

    async def _record_adaptive_outcome(
        self,
        scan_id: str,
        phase: str,
        phase_result: ScanResult,
    ) -> None:
        """Persist what actually ran, including partial evidence and recovery advice."""
        executed: list[dict[str, Any]] = []
        for task in phase_result.agent_tasks:
            if task.phase.value != phase or not isinstance(task.result, dict):
                continue
            for run in task.result.get("tool_runs") or []:
                if not isinstance(run, dict):
                    continue
                success = bool(run.get("success"))
                partial = bool(run.get("partial")) or (
                    not success and bool(run.get("timed_out"))
                    and bool(str(run.get("stdout") or "").strip())
                )
                outcome = (
                    "completed" if success else
                    "partial" if partial else
                    "resource_exhausted" if run.get("oom_killed") else
                    "timed_out" if run.get("timed_out") else
                    "failed"
                )
                executed.append({
                    "tool": str(run.get("tool") or "unknown"),
                    "outcome": outcome,
                    "duration": float(run.get("duration") or 0),
                    "evidence_captured": success or partial,
                    "exit_code": int(run.get("exit_code", -1) or 0),
                })

        failed = [item for item in executed if item["outcome"] not in {"completed", "partial"}]
        partial = [item for item in executed if item["outcome"] == "partial"]
        if failed and len(failed) == len(executed):
            status = "failed"
        elif failed or partial:
            status = "partial"
        elif executed:
            status = "completed"
        else:
            status = "no_tool_evidence"

        recovery_actions: list[dict[str, str]] = []
        for item in failed:
            if item["outcome"] == "timed_out":
                action = "Retry with a narrower target batch and the engagement time budget enforced."
            elif item["outcome"] == "resource_exhausted":
                action = "Reduce concurrency or memory pressure before an approved retry."
            else:
                action = "Inspect the captured artifact and select an approved alternate capability."
            recovery_actions.append({"tool": item["tool"], "action": action})

        orchestrator = self._orchestrators.get(scan_id)
        snapshot = (
            orchestrator.get_evidence_snapshot()
            if orchestrator is not None and hasattr(orchestrator, "get_evidence_snapshot")
            else {}
        )
        digest_source = json.dumps(executed, sort_keys=True, default=str)
        decision = {
            "decision_id": f"outcome_{hashlib.sha256(f'{scan_id}:{phase}:{digest_source}'.encode()).hexdigest()[:16]}",
            "scan_id": scan_id,
            "phase": phase,
            "decision_type": "execution_outcome",
            "status": status,
            "created_at": datetime.utcnow().isoformat(),
            "input_evidence": sorted(snapshot.get("evidence_tokens") or []),
            "selected": [],
            "executed_capabilities": executed,
            "recovery_actions": recovery_actions,
            "policy": {
                "decision_authority": "deterministic_engagement_policy",
                "model_role": "none",
            },
            "execution": {
                "mode": "observed",
                "automatically_executed": True,
                "note": "Recorded from real tool-run artifacts after the phase completed.",
            },
            "hypotheses": [],
            "coverage_gaps": [],
            "model_trace": {"used": False, "provider": "", "model": "", "error": ""},
        }
        await self._broadcast(ScanEvent(
            event_type="agent_decision",
            scan_id=scan_id,
            data=decision,
        ))

    async def _broadcast(self, event: ScanEvent, persist: bool = True) -> None:
        """Broadcast an event to all connected SSE clients.

        ``persist=False`` is used for high-volume ephemeral events (live
        tool-log lines): they are pushed to connected clients only, never
        written to the durable events table or the replay history. The durable
        record of a tool run remains its artifact file.
        """
        payload = {
            "event": event.event_type,
            "type": event.event_type,
            "scan_id": event.scan_id,
            "timestamp": event.timestamp,
            **event.data,
        }
        if persist:
            sequence = await self._store.append_event_async(payload)
            payload["sequence"] = sequence
        display_payload = self._display_event(payload)
        if persist:
            self._event_history.append(display_payload)
            if len(self._event_history) > 1000:
                self._event_history = self._event_history[-1000:]
        dead_queues = []
        event_type = str(display_payload.get("type") or display_payload.get("event") or "")
        for queue, channel in list(self._events.items()):
            if channel == "control" and event_type == "tool_log":
                continue
            if channel == "telemetry" and event_type != "tool_log":
                continue
            try:
                queue.put_nowait(display_payload)
            except asyncio.QueueFull:
                dead_queues.append(queue)
            except Exception:
                dead_queues.append(queue)
        for q in dead_queues:
            self.unsubscribe_events(q)

    def start_live_log_consumer(self) -> None:
        """Launch the background task that relays live tool-log lines.

        Tools run in the worker process and publish output lines to the
        event-bus Redis; this consumer subscribes and re-broadcasts them to the
        API's connected SSE clients as ``tool_log`` events (ephemeral).
        Idempotent — safe to call once on startup.
        """
        if getattr(self, "_live_log_task", None) is not None:
            return
        from core.live_log import subscribe_tool_logs

        async def _handle(msg: dict) -> None:
            scan_id = str(msg.get("scan_id") or "")
            if not scan_id:
                return
            await self._broadcast(
                ScanEvent(
                    event_type="tool_log",
                    scan_id=scan_id,
                    data={
                        "tool": msg.get("tool", ""),
                        "agent": msg.get("agent", ""),
                        "phase": msg.get("phase", ""),
                        "stream": msg.get("stream", "stdout"),
                        "line": msg.get("line", ""),
                    },
                ),
                persist=False,
            )

        self._live_log_task = asyncio.create_task(subscribe_tool_logs(_handle))
        logger.info("[scan_manager] Live tool-log consumer started")

    async def _broadcast_log(self, scan_id: str, message: str, level: str = "info") -> None:
        """Broadcast a log message."""
        await self._broadcast(ScanEvent(
            event_type="log",
            scan_id=scan_id,
            data={"message": message, "level": level},
        ))

    async def _broadcast_agent_status(self, scan_id: str, agent_type: str, status: AgentStatus) -> None:
        """Broadcast agent status update."""
        await self._broadcast(ScanEvent(
            event_type="agent_status",
            scan_id=scan_id,
            data={
                "agent_type": agent_type,
                "status": status.status,
                "findings_count": status.findings_count,
                "current_tool": status.current_tool,
                "progress_pct": status.progress_pct,
                "tools_run": status.tools_run,
                "error": status.error,
            },
        ))

    async def _broadcast_phase(self, scan_id: str, phase: str, message: str = "") -> None:
        """Broadcast phase transition."""
        await self._broadcast(ScanEvent(
            event_type="phase_change",
            scan_id=scan_id,
            data={"phase": phase, "message": message or f"Phase: {phase}"},
        ))

    async def _reconcile_agent_statuses(
        self,
        scan_id: str,
        terminal_status: str,
        error: str = "",
        broadcast: bool = True,
    ) -> None:
        """Bring per-agent state in line with a terminal scan state."""
        statuses = self._agent_status.get(scan_id, {})
        if not statuses:
            return

        now = datetime.utcnow().isoformat()
        terminal_agent_states = {"completed", "failed", "skipped", "cancelled"}
        for agent_name, status in statuses.items():
            if status.status in terminal_agent_states:
                continue

            if terminal_status == "cancelled":
                status.status = "cancelled" if status.status == "running" else "skipped"
                status.error = status.error or error or "Scan cancelled before this agent completed"
            elif terminal_status == "failed":
                status.status = "failed" if status.status == "running" else "skipped"
                status.error = status.error or error or "Scan failed before this agent completed"
            else:
                status.status = "skipped"

            status.completed_at = status.completed_at or now
            status.current_tool = ""
            status.progress_pct = max(status.progress_pct, 100)
            self._store.upsert_agent_status(scan_id, agent_name, status)
            if broadcast:
                await self._broadcast_agent_status(scan_id, agent_name, status)

    def _reconcile_agent_statuses_sync(self, scan_id: str, terminal_status: str, error: str = "") -> None:
        """Synchronous startup variant used while hydrating durable state."""
        statuses = self._agent_status.get(scan_id, {})
        if not statuses:
            return

        now = datetime.utcnow().isoformat()
        terminal_agent_states = {"completed", "failed", "skipped", "cancelled"}
        for agent_name, status in statuses.items():
            if status.status in terminal_agent_states:
                continue
            if terminal_status == "cancelled":
                status.status = "cancelled" if status.status == "running" else "skipped"
                status.error = status.error or error or "Scan cancelled before this agent completed"
            elif terminal_status == "failed":
                status.status = "failed" if status.status == "running" else "skipped"
                status.error = status.error or error or "Scan failed before this agent completed"
            else:
                status.status = "skipped"
            status.completed_at = status.completed_at or now
            status.current_tool = ""
            status.progress_pct = max(status.progress_pct, 100)
            self._store.upsert_agent_status(scan_id, agent_name, status)

    def _deduplicate_finding(self, finding: Finding, existing: list[dict]) -> bool:
        """Check if a finding is a duplicate.

        Deduplication key: (title_lower, target_host)
        This fixes the "both websites having same vulnerability" bug.

        Returns True if the finding is a duplicate and should be skipped.
        """
        target_key = self._canonical_finding_target(
            finding.target.url or finding.target.base_url or finding.target.host
        )
        cves = {str(value).upper() for value in finding.cve_ids if str(value).strip()}
        title = re.sub(
            r"^(cms vulnerability|potential vulnerability|vulnerability)\s*:\s*",
            "",
            finding.title.lower().strip(),
        )
        key = ("cve", tuple(sorted(cves)), target_key.split("/", 1)[0]) if cves else ("title", title, target_key)
        for existing_f in existing:
            existing_target = self._canonical_finding_target(
                existing_f.get("target_url") or existing_f.get("target_host") or ""
            )
            existing_cves = {
                str(value).upper() for value in (existing_f.get("cve_ids") or []) if str(value).strip()
            }
            existing_title = re.sub(
                r"^(cms vulnerability|potential vulnerability|vulnerability)\s*:\s*",
                "",
                str(existing_f.get("title") or "").lower().strip(),
            )
            existing_key = (
                ("cve", tuple(sorted(existing_cves)), existing_target.split("/", 1)[0])
                if existing_cves else ("title", existing_title, existing_target)
            )
            if existing_key == key:
                return True
        return False

    @staticmethod
    def _canonical_finding_target(value: str) -> str:
        raw = display_target(str(value or "").strip()).lower()
        if not raw:
            return ""
        parsed = urlparse(raw if "://" in raw else f"//{raw}")
        host = parsed.hostname or raw.split("/", 1)[0].split(":", 1)[0]
        path = parsed.path or ""
        if path in {"", "/"}:
            path = ""
        return f"{host}{path}"

    @staticmethod
    def _display_finding(item: dict[str, Any]) -> dict[str, Any]:
        out = enrich_finding_quality(item)
        raw_target = item.get("target_url") or item.get("target_host") or ""
        out["target_host"] = display_target(raw_target)
        out["target_url"] = display_url(raw_target)
        out["target_port"] = display_port(raw_target, item.get("target_port"))
        out["target_display"] = display_target(raw_target)
        known_targets = [raw_target]
        for key in ("description", "evidence", "request_proof", "response_proof", "remediation"):
            if key in out:
                out[key] = redact_display_text(out.get(key, ""), known_targets)
        if isinstance(out.get("poc_steps"), list):
            out["poc_steps"] = [redact_display_text(step, known_targets) for step in out["poc_steps"]]
        return out

    @staticmethod
    def _display_scan(data: dict[str, Any]) -> dict[str, Any]:
        out = dict(data)
        targets = list(data.get("targets") or [])
        out["display_targets"] = [display_target(target) for target in targets]
        return out

    def _scan_targets(self, scan_id: str) -> list[str]:
        return list((self._scans.get(scan_id) or {}).get("targets") or [])

    def _display_event(self, event: dict[str, Any]) -> dict[str, Any]:
        out = dict(event)
        scan_id = str(out.get("scan_id") or "")
        known_targets = self._scan_targets(scan_id)
        event_type = out.get("type") or out.get("event")

        if event_type == "finding":
            out = self._display_finding(out)
            known_targets.extend([
                str(event.get("target_url") or ""),
                str(event.get("target_host") or ""),
            ])

        if isinstance(out.get("targets"), list):
            out["targets"] = [display_target(target) for target in out["targets"]]
        if "target" in out and isinstance(out["target"], str):
            out["target"] = display_target(out["target"])

        for key in ("message", "error", "line"):
            if key in out:
                out[key] = redact_display_text(out.get(key, ""), known_targets)
        return out

    def _display_tool_run(self, item: dict[str, Any], scan_id: str) -> dict[str, Any]:
        out = dict(item)
        known_targets = self._scan_targets(scan_id)
        for key in ("command_preview", "stdout_snippet", "stderr_snippet"):
            out[key] = redact_display_text(out.get(key, ""), known_targets)
        run_id = out.get("id")
        if run_id:
            if out.get("stdout_size", 0):
                out["stdout_artifact_url"] = f"/api/scans/{scan_id}/tool-runs/{run_id}/artifact?stream=stdout"
            if out.get("stderr_size", 0):
                out["stderr_artifact_url"] = f"/api/scans/{scan_id}/tool-runs/{run_id}/artifact?stream=stderr"
        return out

    @staticmethod
    def _is_ip_target(value: str) -> bool:
        parsed = urlparse(str(value or "") if "://" in str(value or "") else f"//{value}")
        host = parsed.hostname or str(value or "").split("/", 1)[0].split(":", 1)[0]
        try:
            ipaddress.ip_address(host.strip("[]"))
            return True
        except ValueError:
            return False

    def _initial_coverage_contract(self, targets: list[str], profile_agents: list[str]) -> dict[str, Any]:
        has_domain = any(not self._is_ip_target(target) for target in targets)
        has_wildcard_domain = any(
            str(target or "").strip().lower().removeprefix("http://").removeprefix("https://").startswith("*.")
            for target in targets
        )
        has_web = True
        def status(agent: str, applicable: bool = True) -> str:
            if not applicable:
                return "not_applicable"
            return "planned" if agent in profile_agents else "not_planned"

        checks = [
            {
                "id": "recon_subdomains",
                "label": "Subdomain discovery",
                "phase": "recon",
                "status": status("recon", has_wildcard_domain),
                "expected_tools": ["subfinder", "amass", "assetfinder", "crt.sh"],
                "notes": (
                    "Required only when wildcard subdomains are explicitly authorised. "
                    "Exact-host targets do not expand into child hosts."
                ),
            },
            {
                "id": "recon_dns_resolution",
                "label": "DNS resolution",
                "phase": "recon",
                "status": status("recon", has_domain),
                "expected_tools": ["dnsx"],
                "notes": "Validates discovered hostnames into DNS evidence.",
            },
            {
                "id": "recon_http_probe",
                "label": "HTTP live probing",
                "phase": "recon",
                "status": status("recon", has_web),
                "expected_tools": ["httpx"],
                "notes": "Required before downstream web scanning can be trusted.",
            },
            {
                "id": "recon_url_collection",
                "label": "Historical URL collection",
                "phase": "recon",
                "status": status("recon", has_domain),
                "expected_tools": ["gau", "waybackurls"],
                "notes": "Finds old endpoints and parameters.",
            },
            {
                "id": "recon_crawling",
                "label": "Live crawling",
                "phase": "recon",
                "status": status("recon", has_web),
                "expected_tools": ["katana"],
                "notes": "Finds current linked endpoints.",
            },
            {
                "id": "cloud_s3_storage",
                "label": "S3/cloud storage discovery",
                "phase": "enumeration",
                "status": status("cloud", has_domain),
                "expected_tools": ["cloud_agent", "s3scanner", "cloud_enum"],
                "notes": "If this is not completed, do not claim S3/cloud storage exposure is absent.",
            },
            {
                "id": "enum_ports_services",
                "label": "Port and service enumeration",
                "phase": "enumeration",
                "status": status("enum"),
                "expected_tools": ["nmap", "naabu"],
                "notes": "Required before network exposure conclusions.",
            },
            {
                "id": "vuln_templates",
                "label": "Template vulnerability scanning",
                "phase": "vuln_scanning",
                "status": status("vuln_scanner"),
                "expected_tools": ["nuclei", "nikto", "wpscan"],
                "notes": "Findings need tool artifacts or explicit validation notes.",
            },
            {
                "id": "report_evidence_pack",
                "label": "Evidence report generation",
                "phase": "reporting",
                "status": status("reporter"),
                "expected_tools": ["reporter"],
                "notes": "Report should include evidence grades and tool artifacts.",
            },
        ]
        return {
            "version": "p0-coverage-v1",
            "summary": {"total": len(checks), "completed": 0, "blind_spots": 0},
            "checks": checks,
        }

    def get_scan_coverage(self, scan_id: str) -> dict[str, Any]:
        scan = self._scans.get(scan_id)
        if not scan:
            return {"version": "p0-coverage-v1", "summary": {}, "checks": []}
        contract = scan.get("coverage") or self._initial_coverage_contract(
            list(scan.get("targets") or []),
            list(scan.get("profile_agents") or []),
        )
        checks = [dict(item) for item in contract.get("checks", []) if isinstance(item, dict)]
        runs = self._store.load_tool_runs(scan_id)
        tools_run = {str(run.get("tool") or "") for run in runs}
        successful_tools = {str(run.get("tool") or "") for run in runs if run.get("success")}
        partial_tools = {str(run.get("tool") or "") for run in runs if run.get("partial")}
        agent_status = self._agent_status.get(scan_id, {})

        for item in checks:
            expected = set(item.get("expected_tools") or [])
            phase = item.get("phase", "")
            status = item.get("status", "planned")
            if status in {"not_planned", "not_applicable"}:
                item["tools_observed"] = sorted(expected.intersection(tools_run))
                continue
            agent_key = "cloud" if item.get("id") == "cloud_s3_storage" else ""
            if not agent_key:
                if phase == "recon":
                    agent_key = "recon"
                elif phase == "enumeration":
                    agent_key = "enum"
                elif phase == "vuln_scanning":
                    agent_key = "vuln_scanner"
                elif phase == "reporting":
                    agent_key = "reporter"
            observed = expected.intersection(tools_run)
            successful = expected.intersection(successful_tools)
            partial = expected.intersection(partial_tools)
            agent = agent_status.get(agent_key)
            agent_state = getattr(agent, "status", "") if agent else ""
            if successful or (item.get("id") == "cloud_s3_storage" and agent_state == "completed"):
                item["status"] = "completed"
            elif partial:
                item["status"] = "partial"
            elif observed:
                item["status"] = "attempted"
            elif agent_state == "running":
                item["status"] = "running"
            elif agent_state == "failed":
                item["status"] = "failed"
            elif agent_state == "completed":
                item["status"] = "completed_without_tool_artifact"
            item["tools_observed"] = sorted(observed)
            item["successful_tools"] = sorted(successful)
            item["partial_tools"] = sorted(partial)

        blind_statuses = {"not_planned", "planned", "failed", "attempted", "partial", "completed_without_tool_artifact"}
        summary = {
            "total": len(checks),
            "completed": sum(1 for item in checks if item.get("status") == "completed"),
            "running": sum(1 for item in checks if item.get("status") == "running"),
            "partial": sum(1 for item in checks if item.get("status") == "partial"),
            "blind_spots": sum(1 for item in checks if item.get("status") in blind_statuses),
        }
        return {
            "version": contract.get("version", "p0-coverage-v1"),
            "summary": summary,
            "checks": checks,
        }

    def get_tool_run_artifact(self, scan_id: str, run_id: int, stream: str) -> Optional[dict[str, Any]]:
        if scan_id not in self._scans:
            return None
        run = self._store.load_tool_run(scan_id, run_id)
        if not run:
            return None
        stream_name = "stderr" if stream == "stderr" else "stdout"
        path_value = run.get(f"{stream_name}_artifact_path") or ""
        if not path_value:
            return None
        path = Path(path_value).expanduser().resolve()
        root = self._store.artifact_root.resolve()
        try:
            path.relative_to(root)
        except ValueError:
            logger.warning("[MANAGER] Refusing artifact outside root: {path}", path=path)
            return None
        if not path.exists() or not path.is_file():
            return None
        known_targets = list(self._scans.get(scan_id, {}).get("targets") or [])
        for item in self._scans.get(scan_id, {}).get("target_classifications") or []:
            if isinstance(item, dict):
                known_targets.extend(
                    str(item.get(key) or "")
                    for key in ("raw", "normalized", "host", "scope_ip", "scope_domain")
                    if item.get(key)
                )
        content = redact_display_text(path.read_text(errors="replace"), known_targets)
        return {
            "path": path,
            "filename": path.name,
            "tool": run.get("tool", ""),
            "stream": stream_name,
            "content": content,
        }

    def _upsert_graph(self, scan_id: str, builder: AssetGraphBuilder) -> None:
        assets, edges = builder.records()
        if assets:
            self._store.upsert_asset_graph(scan_id, assets, edges)

    def _ingest_initial_targets(
        self,
        scan_id: str,
        targets: list[str],
        classifications: list[TargetClassification] | None = None,
    ) -> None:
        builder = AssetGraphBuilder(scan_id)
        classified = classifications or classify_targets(targets)
        for item in classified:
            if not item.normalized:
                continue
            metadata = {
                **item.metadata,
                "target_type": item.target_type,
                "provider": item.provider,
                "evidence_tokens": sorted(item.evidence_tokens),
                "scope_seed": True,
            }
            if item.target_type == "url":
                builder.add_url(item.normalized, "target", metadata=metadata)
                if item.host:
                    host_node = builder.add_asset("ip" if item.scope_ip else "domain", item.host, "target", "high", metadata)
                    url_node = builder.add_asset("url", item.normalized, "target", "high", metadata)
                    builder.add_edge(host_node, url_node, "seed_url")
                if "api_endpoint" in item.evidence_tokens:
                    api_node = builder.add_asset("api_endpoint", item.normalized, "target", "high", metadata)
                    url_node = builder.add_asset("url", item.normalized, "target", "high", metadata)
                    builder.add_edge(url_node, api_node, "seed_api_endpoint")
                if "javascript_url" in item.evidence_tokens:
                    builder.add_asset("js_file", item.normalized, "target", "high", metadata)
            elif item.target_type == "cidr":
                builder.add_asset("cidr", item.normalized, "target", "high", metadata)
            else:
                builder.add_asset(item.asset_type, item.normalized, "target", "high", metadata)
            if item.provider:
                cloud_node = builder.add_asset("cloud_asset", item.normalized, "target", "high", metadata)
                host_node = builder.add_asset(item.asset_type, item.normalized, "target", "high", metadata)
                builder.add_edge(host_node, cloud_node, "cloud_provider_hint")
        self._upsert_graph(scan_id, builder)

    def _ingest_finding_asset(self, scan_id: str, finding: dict[str, Any]) -> None:
        builder = AssetGraphBuilder(scan_id)
        builder.ingest_finding(finding)
        self._upsert_graph(scan_id, builder)

    def _ingest_scan_result_assets(self, scan_id: str, result: ScanResult) -> None:
        builder = AssetGraphBuilder(scan_id)
        for target in result.targets:
            builder.add_target(target.host, "target")
            if target.url:
                builder.add_url(target.url, "target")
        for finding in self._findings.get(scan_id, []):
            builder.ingest_finding(finding)
        for task in result.agent_tasks:
            builder.ingest_task_result(
                task.result,
                source=task.agent_type.value,
                target_host=task.target.host if task.target else "",
            )
        self._upsert_graph(scan_id, builder)

    async def _sync_reporter_enrichment(self, scan_id: str, result: ScanResult) -> None:
        """Persist reporter-stage LLM enrichment back into the canonical store.

        The reporter agent fills LLM remediation and an ``llm_reasoning`` trace
        on the Finding objects. Those live only on the orchestrator's result, so
        without this sync the UI/API (which read the manager store) would never
        show them. Matches on the same ``title|target_host`` key used for dedup.
        """
        stored = self._findings.get(scan_id, [])
        if not stored:
            return
        by_key: dict[str, dict] = {}
        for item in stored:
            key = f"{str(item.get('title', '')).lower().strip()}|{str(item.get('target_host', '')).lower().strip()}"
            by_key[key] = item

        updated = 0
        for finding in getattr(result, "findings", []):
            reasoning = getattr(finding, "llm_reasoning", None)
            remediation = getattr(finding, "remediation", "")
            if not reasoning and not remediation:
                continue
            report = finding.to_report_dict()
            key = f"{str(report.get('title', '')).lower().strip()}|{str(report.get('target_host', '')).lower().strip()}"
            item = by_key.get(key)
            if item is None:
                continue
            if reasoning:
                item["llm_reasoning"] = reasoning
            if remediation and len(remediation) > len(str(item.get("remediation", ""))):
                item["remediation"] = report.get("remediation", remediation)
            await self._store.upsert_finding_async(scan_id, item)
            updated += 1
        if updated:
            logger.info(
                "[scan_manager] Synced LLM enrichment for {n} finding(s) in {scan}",
                n=updated, scan=scan_id,
            )

    def _ingest_task_tool_runs(self, scan_id: str, result: ScanResult) -> None:
        """Copy per-agent tool execution evidence into agent status."""
        statuses = self._agent_status.get(scan_id, {})
        changed: set[str] = set()
        for task in result.agent_tasks:
            task_key = (scan_id, str(task.id))
            if task_key in self._persisted_task_runs:
                continue
            agent_key = task.agent_type.value
            status = statuses.get(agent_key)
            if not status or not isinstance(task.result, dict):
                continue
            runs_to_store: list[dict[str, Any]] = []
            for run in task.result.get("tool_runs") or []:
                if not isinstance(run, dict):
                    continue
                runs_to_store.append(run)
                tool_name = run.get("tool") or run.get("tool_name")
                if tool_name and tool_name not in status.tools_run:
                    status.tools_run.append(tool_name)
                    status.current_tool = tool_name
                    changed.add(agent_key)
                if run.get("partial"):
                    output = str(run.get("stdout") or run.get("stderr") or "")[:300]
                    msg = f"{tool_name or 'tool'} captured partial evidence: {output}"
                    if msg not in status.log_messages:
                        status.log_messages.append(msg)
                    changed.add(agent_key)
                elif run.get("success") is False:
                    output = str(run.get("stderr") or run.get("stdout") or "")[:300]
                    msg = f"{tool_name or 'tool'} failed exit={run.get('exit_code')}: {output}"
                    if msg not in status.log_messages:
                        status.log_messages.append(msg)
                    if status.status not in {"failed", "cancelled"}:
                        status.error = status.error or msg
                    changed.add(agent_key)
            if runs_to_store:
                self._store.append_tool_runs(scan_id, agent_key, runs_to_store)
            self._persisted_task_runs.add(task_key)
        for agent_key in changed:
            self._store.upsert_agent_status(scan_id, agent_key, statuses[agent_key])

    def get_asset_graph(self, scan_id: str, asset_type: Optional[str] = None) -> dict[str, Any]:
        raw_assets = self._store.load_assets(scan_id)
        raw_edges = self._store.load_asset_edges(scan_id)
        assets, edges = canonical_graph_projection(raw_assets, raw_edges)
        if asset_type:
            assets = [item for item in assets if item.get("asset_type") == asset_type]
            visible = {str(item.get("asset_key")) for item in assets}
            edges = [item for item in edges if item.get("source_key") in visible or item.get("target_key") in visible]
        return {
            "scan_id": scan_id,
            "summary": summarize_assets(assets),
            "total_assets": len(assets),
            "total_edges": len(edges),
            "raw_observations": len(raw_assets),
            "raw_relationships": len(raw_edges),
            "canonicalized": len(raw_assets) != len(assets),
            "assets": assets,
            "edges": edges,
        }

    def build_attack_surface_plan(self, scan_id: str) -> dict[str, Any]:
        assets = self._store.load_assets(scan_id)
        summary = summarize_assets(assets)
        asset_types = {asset.get("asset_type") for asset in assets}
        scan = self._scans.get(scan_id, {})
        seed_classifications = [
            item for item in scan.get("target_classifications", [])
            if isinstance(item, dict)
        ]
        evidence_tokens = evidence_from_asset_records(assets)
        for item in seed_classifications:
            evidence_tokens.update(item.get("evidence_tokens") or [])

        orchestrator = self._orchestrators.get(scan_id)
        orchestrator_snapshot: dict[str, Any] = {}
        if orchestrator and hasattr(orchestrator, "get_evidence_snapshot"):
            orchestrator_snapshot = orchestrator.get_evidence_snapshot()
            evidence_tokens.update(orchestrator_snapshot.get("evidence_tokens") or [])
        target_layers = target_layers_from_evidence(evidence_tokens)

        planned: list[dict[str, Any]] = []
        def add(capability: str, reason: str, phase: str, categories: list[str], target_layer: str = "") -> None:
            planned.append({
                "capability": capability,
                "reason": reason,
                "phase": phase,
                "target_layer": target_layer,
                "categories": categories,
            })

        if {"domain", "subdomain", "ip"} & asset_types:
            add("http probing", "Hosts exist and need live-service confirmation.", "recon", ["http-probing"], "domain")
            add("port/service discovery", "Hosts need exposed service mapping.", "enumeration", ["port-scanning"], "domain")
        if "url" in asset_types:
            add("web crawling", "Live URLs exist; crawl for endpoints and JavaScript.", "recon", ["web-crawling"], "web")
            add("template vulnerability scan", "Live URLs can be checked with low-noise templates.", "vuln_scanning", ["vuln-templates"], "web")
            add("content discovery", "Live web roots can expose backup/admin/config paths.", "fuzzing", ["web-content-discovery"], "web")
        if "js_file" in asset_types or "js_signal" in asset_types:
            add("JavaScript secret and endpoint analysis", "JavaScript assets/signals exist.", "vuln_scanning", ["js-recon", "secrets-detection"], "javascript")
        if "api_endpoint" in asset_types or "parameter" in asset_types:
            add("API and parameter assessment", "API endpoints or parameters were discovered.", "fuzzing", ["parameter-discovery"], "api")
        if "technology" in asset_types:
            add("technology-specific checks", "Fingerprint data can select CMS/framework checks.", "vuln_scanning", ["cms-specific-scanner", "tech-fingerprinting"], "web")
        if "service" in asset_types:
            add("service CVE verification", "Open services need version/CVE correlation.", "vuln_scanning", ["network-vulnerability-scanning"], "ip")
        if "repository" in asset_types:
            add("repository secret scan", "Repository exposure exists or is suspected.", "vuln_scanning", ["exposed-repository", "secrets-detection"], "repository")

        eligible_tools_by_phase: dict[str, list[dict[str, Any]]] = {}
        for phase in [phase.value for phase in ScanPhase if phase not in {ScanPhase.INIT, ScanPhase.COMPLETED, ScanPhase.FAILED, ScanPhase.CANCELLED}]:
            tools = plan_next_tools(
                available_evidence=evidence_tokens,
                already_run=set(orchestrator_snapshot.get("tools_run") or []),
                phase=phase,
                include_aggressive=True,
                target_layers=target_layers or None,
            )
            eligible_tools_by_phase[phase] = [
                {
                    "name": tool.name,
                    "display_name": tool.display_name,
                    "categories": tool.categories,
                    "target_layers": tool.target_layers,
                    "consumes": tool.consumes,
                    "produces": tool.produces,
                    "aggressive": tool.aggressive,
                    "requires_credentials": bool(tool.requires_api_keys),
                    "required_credentials_count": len(tool.requires_api_keys),
                    "notes": tool.notes,
                }
                for tool in tools
            ]

        return {
            "scan_id": scan_id,
            "asset_summary": summary,
            "seed_classifications": seed_classifications,
            "evidence_tokens": sorted(evidence_tokens),
            "target_layers": sorted(target_layers),
            "orchestrator_evidence": orchestrator_snapshot,
            "eligible_tools_by_phase": eligible_tools_by_phase,
            "planned_capabilities": planned,
        }

    @staticmethod
    def _extract_cve_ids(finding: Finding) -> list[str]:
        """Extract CVE IDs from structured fields and raw tool evidence."""
        haystack = " ".join(filter(None, [
            finding.title,
            finding.description,
            finding.evidence,
            finding.raw_tool_output or "",
            " ".join(finding.references),
            " ".join(finding.tags),
        ]))
        found = re.findall(r"CVE-\d{4}-\d{4,7}", haystack, flags=re.IGNORECASE)
        return sorted({*finding.cve_ids, *(item.upper() for item in found)})

    @staticmethod
    def _version_cpes_for_finding(finding: Finding) -> list[str]:
        """Return conservative CPE guesses only for explicit version strings.

        Generic banners like "Apache detected" are not enough for NVD version
        matching. Exact version strings are still treated as enrichment data,
        not automatic proof that the asset is vulnerable.
        """
        text = " ".join(filter(None, [finding.title, finding.description, finding.evidence]))
        cpes: list[str] = []
        patterns = [
            (r"\bApache/(\d+(?:\.\d+){1,3})\b", "cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*"),
            (r"\bnginx/(\d+(?:\.\d+){1,3})\b", "cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*"),
            (r"\bOpenSSH[_ /](\d+(?:\.\d+){1,3})\b", "cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*"),
            (r"\bjQuery[ /-](\d+(?:\.\d+){1,3})\b", "cpe:2.3:a:jquery:jquery:{version}:*:*:*:*:*:*:*"),
        ]
        for regex, template in patterns:
            for match in re.findall(regex, text, flags=re.IGNORECASE):
                cpes.append(template.format(version=match))
        return sorted(set(cpes))

    @staticmethod
    def _severity_from_cvss(score: Optional[float]) -> Severity:
        if score is None:
            return Severity.INFORMATIONAL
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score > 0:
            return Severity.LOW
        return Severity.INFORMATIONAL

    async def _enrich_with_nvd(self, finding: Finding) -> None:
        """Verify explicit CVEs and enrich versioned technology findings."""
        finding.cve_ids = self._extract_cve_ids(finding)

        if finding.cve_ids:
            verified = await self._nvd.verify_finding_cves(finding.cve_ids)
            for item in verified:
                if item["verified"] and item["cvss_score"]:
                    finding.cvss_score = max(finding.cvss_score or 0, item["cvss_score"])
                    finding.cvss_vector = finding.cvss_vector or item["cvss_vector"]
                    finding.description += f"\n\n[NVD Verified] {item['cve_id']}: {item['description']}"
                    finding.references.extend(ref for ref in item["references"][:3] if ref not in finding.references)
                    finding.references.append(item["nvd_url"])
                    finding.cwe_ids.extend(cwe for cwe in item["cwe_ids"] if cwe not in finding.cwe_ids)
                    if "nvd-verified" not in finding.tags:
                        finding.tags.append("nvd-verified")
                    logger.info("[NVD] Verified {cve}: CVSS {score}", cve=item["cve_id"], score=item["cvss_score"])
                elif item["status"] == "REJECTED":
                    logger.warning("[NVD] {cve} is REJECTED — flagging as potential false positive", cve=item["cve_id"])
                    finding.status = "suspected"
                    finding.confidence = "low"
            if finding.cvss_score is not None:
                finding.severity = self._severity_from_cvss(finding.cvss_score)
            finding.cve_ids = sorted(set(finding.cve_ids))
            finding.references = list(dict.fromkeys(finding.references))
            finding.cwe_ids = sorted(set(finding.cwe_ids))
            return

        cpe_names = self._version_cpes_for_finding(finding)
        if not cpe_names:
            return

        records = []
        for cpe_name in cpe_names:
            records.extend(await self._nvd.search_by_cpe(cpe_name))
        verified_records = [record for record in records if record.verified]
        if not verified_records:
            return

        verified_records.sort(key=lambda record: record.cvss_v3_score or 0, reverse=True)
        selected = verified_records[:12]
        finding.cve_ids = sorted({record.cve_id for record in selected})
        finding.references = list(dict.fromkeys([
            *finding.references,
            *(record.nvd_url for record in selected[:5] if record.nvd_url),
        ]))
        for record in selected:
            finding.cwe_ids.extend(cwe for cwe in record.cwe_ids if cwe not in finding.cwe_ids)

        # CPE/version search is useful intelligence, but it is not proof that
        # this exact deployed package is vulnerable. Backports, distro patches,
        # CPE ambiguity, and banner spoofing can all create false positives.
        # Keep the CVE links as enrichment, but never let version-intelligence
        # alone inflate severity/CVSS.
        finding.status = "suspected"
        finding.confidence = "medium" if finding.confidence == "high" else finding.confidence
        if "nvd-version-intel" not in finding.tags:
            finding.tags.append("nvd-version-intel")
        finding.description += (
            "\n\n[NVD Enrichment] The detected version maps to published NVD CVEs. "
            "This is version-intelligence only: it requires package/backport validation "
            "or direct exploit/template evidence before severity is raised."
        )

    async def start_scan(self, targets: list[str], mode: str = "full_vapt",
                         scan_name: str = "", scope_config: Optional[dict] = None) -> dict:
        """Start a new VAPT scan.

        Returns immediately with scan_id; the actual scanning runs in a
        background asyncio task.
        """
        # NOTE: do NOT insert hardcoded absolute paths here. The orchestrator
        # resolves config.yaml relative to the backend package, so this works
        # regardless of where the process is launched from.
        from core.orchestrator import Orchestrator
        from agents.recon import ReconAgent
        from agents.enum_agent import EnumAgent
        from agents.vuln_scanner import VulnScannerAgent
        from agents.fuzzer import FuzzingAgent
        from agents.exploit import ExploitAgent
        from agents.intel import IntelAgent
        from agents.cloud_agent import CloudAgent
        from agents.iot_agent import IoTAgent
        from agents.reporter import ReportAgent

        # Generate scan ID immediately (before background task)
        self._scan_id_counter += 1
        scan_id = f"scan_{int(time.time())}_{self._scan_id_counter:04d}"
        display_name = scan_name or f"Scan {self._scan_id_counter}"

        classifications = classify_targets(targets)
        authorized_domains, authorized_ips = scope_from_classifications(classifications)
        seed_evidence = evidence_from_classifications(classifications)
        execution_targets = [
            item.metadata.get("execution_seed") or item.normalized or item.raw
            for item in classifications
        ] or targets

        # Merge caller-supplied session/auth presets (P1 authenticated scans)
        # into the scope so crawlers and safe modules reach protected surfaces.
        overrides = scope_config or {}
        execution_policy = engagement_limits(overrides)
        def _as_list(value: Any) -> list[str]:
            if value is None:
                return []
            if isinstance(value, str):
                return [item.strip() for item in re.split(r"[\n,]+", value) if item.strip()]
            if isinstance(value, list):
                return [str(item).strip() for item in value if str(item).strip()]
            return []

        for domain in _as_list(overrides.get("authorized_domains")):
            if domain not in authorized_domains:
                authorized_domains.append(domain)
        for ip_entry in _as_list(overrides.get("authorized_ips")):
            if ip_entry not in authorized_ips:
                authorized_ips.append(ip_entry)

        auth_type = overrides.get("auth_type") if overrides.get("auth_type") in {"bearer", "basic", "cookie"} else None
        scope_cfg = ScopeConfig(
            authorized_domains=authorized_domains,
            authorized_ips=authorized_ips,
            out_of_scope=_as_list(overrides.get("out_of_scope")),
            max_depth=execution_policy["max_depth"],
            max_pages=execution_policy["max_pages"],
            max_requests_total=execution_policy["max_requests_total"],
            exclude_paths=_as_list(overrides.get("exclude_paths")),
            include_paths=_as_list(overrides.get("include_paths")) or None,
            rate_limit=execution_policy["rate_limit"],
            auth_token=overrides.get("auth_token") or None,
            auth_type=auth_type or ("bearer" if overrides.get("auth_token") else None),
            custom_headers=overrides.get("custom_headers") or {},
            cookies=overrides.get("cookies") or {},
        )
        scope = ScopeManager(scope_cfg)
        scope_summary = scope.get_scope_summary()
        scope_summary["execution_targets"] = execution_targets
        scope_summary["scope_semantics"] = {
            "exact_domain": "active testing is limited to the exact host",
            "wildcard_domain": "*.example.com authorises active testing of discovered subdomains",
            "passive_discovery": "child domains may be reported as inventory without being probed",
            "out_of_scope": "out-of-scope entries override all authorisation",
        }
        rules_of_engagement = {
            "authorized_domains": scope_cfg.authorized_domains,
            "authorized_ips": scope_cfg.authorized_ips,
            "out_of_scope": scope_cfg.out_of_scope,
            "rate_limit": scope_cfg.rate_limit,
            "max_depth": scope_cfg.max_depth,
            "max_pages": scope_cfg.max_pages,
            "max_requests_total": scope_cfg.max_requests_total,
            "exclude_paths": scope_cfg.exclude_paths,
            "include_paths": scope_cfg.include_paths or [],
            "intensity": execution_policy["intensity"],
            "authorization_confirmed": True,
            "lab_target_confirmed": execution_policy["lab_target_confirmed"],
            "emergency_stop": f"/api/scans/{scan_id}/stop",
        }
        artifact_payload = json.dumps(rules_of_engagement, sort_keys=True, default=str)
        rules_of_engagement["artifact_sha256"] = hashlib.sha256(
            artifact_payload.encode("utf-8")
        ).hexdigest()

        # Create orchestrator. The orchestrator locates config.yaml next to
        # the backend package, so no hardcoded path is needed.
        orchestrator = Orchestrator()
        orchestrator.seed_evidence(seed_evidence)
        scan_mode = ScanMode(mode)
        profile = self._config.get_profile(mode)

        # Register agents based on profile (THIS is how VA-only vs IoT-only works)
        agent_registry = {
            "recon": (AgentType.RECON, lambda: ReconAgent(scope, self._config)),
            "enum": (AgentType.ENUM, lambda: EnumAgent(scope, self._config)),
            "vuln_scanner": (AgentType.VULN_SCANNER, lambda: VulnScannerAgent(scope, self._config)),
            "fuzzer": (AgentType.FUZZER, lambda: FuzzingAgent(scope, self._config)),
            "exploit": (AgentType.EXPLOIT, lambda: ExploitAgent(scope, self._config)),
            "intel": (AgentType.INTEL, lambda: IntelAgent(scope, self._config)),
            "cloud": (AgentType.CLOUD, lambda: CloudAgent(scope, self._config)),
            "iot_cctv": (AgentType.IOT_CCTV, lambda: IoTAgent(scope, self._config)),
            "reporter": (AgentType.REPORTER, lambda: ReportAgent(scope, self._config)),
        }

        for agent_name in profile.agents:
            if agent_name in agent_registry:
                atype, factory = agent_registry[agent_name]
                orchestrator.register_agent(atype, factory())

        # Initialize scan tracking
        self._scans[scan_id] = {
            "id": scan_id,
            "name": display_name,
            "mode": mode,
            "status": "running",
            "current_phase": "init",
            "targets": targets,
            "execution_targets": execution_targets,
            "display_targets": [display_target(target) for target in targets],
            "start_time": datetime.utcnow().isoformat(),
            "duration": 0,
            "profile_agents": profile.agents,
            "exploit_enabled": profile.exploit,
            "target_classifications": [item.to_dict() for item in classifications],
            "scope": scope_summary,
            "rules_of_engagement": rules_of_engagement,
            "seed_evidence": sorted(seed_evidence),
            "coverage": self._initial_coverage_contract(targets, profile.agents),
        }
        self._findings[scan_id] = []
        self._store.upsert_scan(scan_id, self._scans[scan_id])
        self._ingest_initial_targets(scan_id, targets, classifications)

        # Initialize agent status tracking
        self._agent_status[scan_id] = {}
        for agent_name in profile.agents:
            self._agent_status[scan_id][agent_name] = AgentStatus(agent_type=agent_name)
            self._store.upsert_agent_status(scan_id, agent_name, self._agent_status[scan_id][agent_name])

        self._orchestrators[scan_id] = orchestrator
        logger.info(
            "[MANAGER] Scan {id} accepted: mode={mode} targets={targets} agents={agents}",
            id=scan_id,
            mode=mode,
            targets=", ".join(targets),
            agents=", ".join(profile.agents),
        )

        # Finding callback with deduplication + NVD verification
        async def on_finding(finding: Finding):
            # Deduplicate
            if self._deduplicate_finding(finding, self._findings[scan_id]):
                logger.debug("[MANAGER] Deduplicated finding: {title}", title=finding.title)
                return

            # Verify direct CVEs and enrich explicit version detections with NVD.
            try:
                await self._enrich_with_nvd(finding)
            except Exception as exc:
                logger.debug("[NVD] Verification error: {err}", err=exc)

            finding_dict = finding.to_report_dict()
            finding_dict["nvd_verified"] = "nvd-verified" in finding.tags
            finding_dict = enrich_finding_quality(finding_dict)
            self._findings[scan_id].append(finding_dict)
            await self._store.upsert_finding_async(scan_id, finding_dict)
            self._ingest_finding_asset(scan_id, finding_dict)

            # Update agent status
            agent_key = finding.agent_source.value
            if agent_key in self._agent_status.get(scan_id, {}):
                self._agent_status[scan_id][agent_key].findings_count += 1
                await self._store.upsert_agent_status_async(scan_id, agent_key, self._agent_status[scan_id][agent_key])

            # Broadcast
            await self._broadcast(ScanEvent(
                event_type="finding",
                scan_id=scan_id,
            data=self._display_finding(finding_dict),
            ))

        orchestrator.on_finding(on_finding)

        # Phase change callback
        def on_phase_change(phase: str, message: str = ""):
            if scan_id in self._scans:
                self._scans[scan_id]["current_phase"] = phase
                asyncio.create_task(
                    self._store.update_scan_async(scan_id, {"current_phase": phase})
                )
            asyncio.create_task(self._broadcast_phase(scan_id, phase, message))
            asyncio.create_task(self._record_adaptive_decision(scan_id, phase))

        orchestrator.on_phase_change(on_phase_change)

        # Persist the attack surface after every phase rather than waiting for
        # the final report. This gives reconnecting clients a durable live view
        # of body-verified URLs, technologies, endpoints, parameters and
        # services while the assessment is still running.
        def on_phase_complete(phase: str, phase_result: ScanResult):
            self._ingest_scan_result_assets(scan_id, phase_result)
            self._ingest_task_tool_runs(scan_id, phase_result)
            asyncio.create_task(self._record_adaptive_outcome(scan_id, phase, phase_result))
            graph = self.get_asset_graph(scan_id)
            phase_context: dict[str, Any] = {}
            for task in reversed(phase_result.agent_tasks):
                if task.phase.value == phase and isinstance(task.result, dict):
                    phase_context = task.result
                    break
            if phase == "exploitation":
                asyncio.create_task(self._broadcast(ScanEvent(
                    event_type="dast_validation_summary",
                    scan_id=scan_id,
                    data={
                        "hypotheses_planned": int(phase_context.get("hypotheses_planned") or 0),
                        "hypotheses_scheduled": int(phase_context.get("hypotheses_scheduled") or 0),
                        "hypotheses_tested": int(phase_context.get("hypotheses_tested") or 0),
                        "proofs_confirmed": int(phase_context.get("proofs_confirmed") or 0),
                        "validator_summary": phase_context.get("validator_summary") or {},
                        "validation_attempts": (phase_context.get("validation_attempts") or [])[:250],
                    },
                )))
            asyncio.create_task(self._broadcast(ScanEvent(
                event_type="phase_complete",
                scan_id=scan_id,
                data={
                    "phase": phase,
                    "asset_summary": graph.get("summary", {}),
                    "total_assets": graph.get("total_assets", 0),
                    "target_health": phase_context.get("target_health", {}),
                    "message": f"{phase.replace('_', ' ').title()} evidence persisted",
                },
            )))

        orchestrator.on_phase_complete(on_phase_complete)

        # Agent status callback
        def on_agent_start(agent_type: str, tool_name: str = ""):
            if scan_id in self._agent_status:
                status = self._agent_status[scan_id].get(agent_type)
                if status:
                    status.status = "running"
                    status.started_at = datetime.utcnow().isoformat()
                    status.current_tool = tool_name
                    if tool_name and tool_name not in status.tools_run:
                        status.tools_run.append(tool_name)
                    asyncio.create_task(
                        self._store.upsert_agent_status_async(scan_id, agent_type, status)
                    )
            asyncio.create_task(self._broadcast_agent_status(
                scan_id, agent_type,
                self._agent_status.get(scan_id, {}).get(agent_type, AgentStatus(agent_type=agent_type)),
            ))

        def on_agent_complete(agent_type: str, findings_count: int = 0):
            if scan_id in self._agent_status:
                status = self._agent_status[scan_id].get(agent_type)
                if status:
                    status.status = "completed"
                    status.completed_at = datetime.utcnow().isoformat()
                    status.findings_count = findings_count
                    status.progress_pct = 100
                    asyncio.create_task(
                        self._store.upsert_agent_status_async(scan_id, agent_type, status)
                    )
            asyncio.create_task(self._broadcast_agent_status(
                scan_id, agent_type,
                self._agent_status.get(scan_id, {}).get(agent_type, AgentStatus(agent_type=agent_type)),
            ))

        orchestrator.on_agent_start(on_agent_start)
        orchestrator.on_agent_complete(on_agent_complete)

        # Log callback
        def on_log(message: str, level: str = "info"):
            asyncio.create_task(self._broadcast_log(scan_id, message, level))

        orchestrator.on_log(on_log)

        asyncio.create_task(self._broadcast(ScanEvent(
            event_type="scan_started",
            scan_id=scan_id,
            data={
                "name": display_name,
                "mode": mode,
                "targets": targets,
                "agents": profile.agents,
                "message": f"Scan accepted for {', '.join(targets)}",
            },
        )))

        # Run scan in background
        async def run_background():
            try:
                result = await orchestrator.start_scan(
                    targets=execution_targets,
                    mode=scan_mode,
                    scan_name=display_name,
                    scope_config=scope_cfg,
                )

                # Update scan data. Preserve cancellation if the user stopped
                # the scan while the orchestrator was returning.
                duration = result.duration_seconds or 0
                self._ingest_scan_result_assets(scan_id, result)
                self._ingest_task_tool_runs(scan_id, result)
                # Sync reporter-stage LLM enrichment (remediation + reasoning
                # trace) back into the canonical store so the UI evidence chain
                # shows it, not just the exported report.
                await self._sync_reporter_enrichment(scan_id, result)
                for agent_key, status in self._agent_status.get(scan_id, {}).items():
                    if status.tools_run:
                        await self._broadcast_agent_status(scan_id, agent_key, status)
                result_status = getattr(result, "status", "completed") or "completed"
                current_status = self._scans.get(scan_id, {}).get("status")
                terminal_status = "cancelled" if current_status == "cancelled" else result_status
                if terminal_status not in {"completed", "failed", "cancelled"}:
                    terminal_status = "completed"

                self._scans[scan_id].update({
                    "status": terminal_status,
                    "current_phase": terminal_status,
                    "duration": duration,
                    "end_time": datetime.utcnow().isoformat(),
                    "total_findings": len(self._findings[scan_id]),
                    "total_agent_tasks": len(result.agent_tasks),
                })
                if terminal_status == "cancelled":
                    self._scans[scan_id]["error"] = self._scans[scan_id].get("error") or "Scan cancelled by user"
                elif terminal_status == "failed":
                    self._scans[scan_id]["error"] = self._scans[scan_id].get("error") or "Scan failed"

                for task in result.agent_tasks:
                    if task.agent_type == AgentType.REPORTER and isinstance(task.result, dict):
                        self._scans[scan_id]["report_base_name"] = task.result.get("base_name", "")
                        self._scans[scan_id]["report_output_dir"] = task.result.get("output_dir", "")
                        break

                # NVD stats
                nvd_stats = self._nvd.stats
                self._scans[scan_id]["nvd_stats"] = nvd_stats
                self._store.upsert_scan(scan_id, self._scans[scan_id])
                await self._reconcile_agent_statuses(
                    scan_id,
                    terminal_status,
                    self._scans[scan_id].get("error", ""),
                )

                if terminal_status == "completed":
                    await self._broadcast(ScanEvent(
                        event_type="scan_complete",
                        scan_id=scan_id,
                        data={
                            "duration_seconds": duration,
                            "total_findings": len(self._findings[scan_id]),
                            "nvd_stats": nvd_stats,
                        },
                    ))
                    logger.info("[MANAGER] Scan {id} completed: {count} findings in {dur:.1f}s",
                               id=scan_id, count=len(self._findings[scan_id]), dur=duration)
                else:
                    await self._broadcast(ScanEvent(
                        event_type="scan_failed",
                        scan_id=scan_id,
                        data={"error": self._scans[scan_id].get("error", terminal_status)},
                    ))
                    logger.info("[MANAGER] Scan {id} ended as {status}", id=scan_id, status=terminal_status)

            except Exception as exc:
                logger.error("[MANAGER] Scan {id} failed: {err}", id=scan_id, err=exc)
                self._scans[scan_id]["status"] = "failed"
                self._scans[scan_id]["current_phase"] = "failed"
                self._scans[scan_id]["end_time"] = datetime.utcnow().isoformat()
                self._scans[scan_id]["error"] = str(exc)
                self._store.upsert_scan(scan_id, self._scans[scan_id])
                await self._reconcile_agent_statuses(scan_id, "failed", str(exc))
                await self._broadcast(ScanEvent(
                    event_type="scan_failed",
                    scan_id=scan_id,
                    data={"error": str(exc)},
                ))

        asyncio.create_task(run_background())

        return {"scan_id": scan_id, "status": "starting", "name": display_name}

    async def stop_scan(self, scan_id: str) -> dict:
        """Stop a running scan."""
        if scan_id not in self._scans:
            return {"error": "Scan not found"}
        if self._scans[scan_id]["status"] != "running":
            return {"error": f"Scan is {self._scans[scan_id]['status']}, cannot stop"}

        orchestrator = self._orchestrators.get(scan_id)
        if orchestrator:
            orchestrator.cancel()

        self._scans[scan_id]["status"] = "cancelled"
        self._scans[scan_id]["current_phase"] = "cancelled"
        self._scans[scan_id]["end_time"] = datetime.utcnow().isoformat()
        self._scans[scan_id]["error"] = "Scan cancelled by user"
        self._store.upsert_scan(scan_id, self._scans[scan_id])
        await self._reconcile_agent_statuses(scan_id, "cancelled", "Scan cancelled by user")
        await self._broadcast(ScanEvent(
            event_type="scan_failed",
            scan_id=scan_id,
            data={"error": "Scan cancelled by user"},
        ))
        return {"scan_id": scan_id, "status": "cancelled"}

    async def delete_scan(self, scan_id: str) -> dict:
        """Delete a terminal scan and all persisted artifacts tracked in SQLite."""
        if scan_id not in self._scans:
            return {"error": "Scan not found"}
        if self._scans[scan_id].get("status") == "running":
            return {"error": "Stop the running scan before deleting it"}

        scan = self._scans.get(scan_id, {})
        output_dir = scan.get("report_output_dir") or self._config.reporting.output_dir
        base_name = scan.get("report_base_name") or ""
        if base_name:
            from pathlib import Path
            report_dir = Path(output_dir)
            if not report_dir.is_absolute():
                report_dir = Path.cwd() / report_dir
            for ext in ("html", "pdf", "md", "json"):
                try:
                    (report_dir / f"{base_name}.{ext}").unlink(missing_ok=True)
                except Exception as exc:
                    logger.debug("[MANAGER] Could not delete report artifact {base}.{ext}: {err}",
                                 base=base_name, ext=ext, err=exc)

        deleted = await self._store.delete_scan_async(scan_id)
        if not deleted:
            return {"error": "Scan not found"}
        self._scans.pop(scan_id, None)
        self._findings.pop(scan_id, None)
        self._agent_status.pop(scan_id, None)
        self._orchestrators.pop(scan_id, None)
        self._persisted_task_runs = {
            key for key in self._persisted_task_runs if key[0] != scan_id
        }
        self._event_history = [
            event for event in self._event_history
            if event.get("scan_id") != scan_id
        ]
        await self._broadcast(ScanEvent(
            event_type="scan_deleted",
            scan_id=scan_id,
            data={"message": "Scan deleted"},
        ))
        return {"scan_id": scan_id, "status": "deleted"}

    def get_scan(self, scan_id: str) -> Optional[dict]:
        """Get scan details."""
        if scan_id not in self._scans:
            return None
        data = dict(self._scans[scan_id])
        data["scan_id"] = scan_id
        raw_targets = list(data.get("targets", []) or [])
        data["raw_targets_count"] = len(raw_targets)
        data["targets"] = [display_target(target) for target in raw_targets]
        data["display_targets"] = list(data["targets"])
        if data.get("target_classifications"):
            safe_classifications = []
            for item in data.get("target_classifications") or []:
                if not isinstance(item, dict):
                    continue
                safe_item = dict(item)
                display = display_target(item.get("raw") or item.get("normalized") or item.get("host") or "")
                for key in ("raw", "normalized", "host", "scope_domain", "scope_ip"):
                    if key in safe_item:
                        safe_item[key] = display
                safe_classifications.append(safe_item)
            data["target_classifications"] = safe_classifications
            data["duration_seconds"] = data.get("duration", 0)
            data["coverage"] = self.get_scan_coverage(scan_id)
            findings = self._findings.get(scan_id, [])
        data["total_findings"] = len(findings)
        data["critical_count"] = sum(1 for f in findings if f.get("severity") == "critical")
        data["high_count"] = sum(1 for f in findings if f.get("severity") == "high")
        data["medium_count"] = sum(1 for f in findings if f.get("severity") == "medium")
        data["low_count"] = sum(1 for f in findings if f.get("severity") == "low")
        data["info_count"] = sum(1 for f in findings if f.get("severity") == "informational")
        data["findings"] = [self._display_finding(f) for f in self._findings.get(scan_id, [])]
        data["agent_status"] = {
            k: {
                "agent_type": v.agent_type,
                "status": v.status,
                "findings_count": v.findings_count,
                "tools_run": v.tools_run,
                "current_tool": v.current_tool,
                "progress_pct": v.progress_pct,
                "error": v.error,
                "started_at": v.started_at,
                "completed_at": v.completed_at,
            }
            for k, v in self._agent_status.get(scan_id, {}).items()
        }
        return data

    def get_tool_runs(self, scan_id: str) -> list[dict[str, Any]]:
        if scan_id not in self._scans:
            return []
        return [self._display_tool_run(run, scan_id) for run in self._store.load_tool_runs(scan_id)]

    def list_scans(self) -> list[dict]:
        """List all scans with summary."""
        results = []
        for scan_id, data in self._scans.items():
            findings = self._findings.get(scan_id, [])
            results.append({
                "scan_id": scan_id,
                "name": data.get("name", ""),
                "mode": data.get("mode", ""),
                "status": data.get("status", ""),
                "current_phase": data.get("current_phase", ""),
                "targets": [display_target(target) for target in data.get("targets", [])],
                "raw_targets_count": len(data.get("targets", []) or []),
                "display_targets": [display_target(target) for target in data.get("targets", [])],
                "total_findings": len(findings),
                "critical_count": sum(1 for f in findings if f.get("severity") == "critical"),
                "high_count": sum(1 for f in findings if f.get("severity") == "high"),
                "medium_count": sum(1 for f in findings if f.get("severity") == "medium"),
                "low_count": sum(1 for f in findings if f.get("severity") == "low"),
                "info_count": sum(1 for f in findings if f.get("severity") == "informational"),
                "start_time": data.get("start_time", ""),
                "end_time": data.get("end_time", ""),
                "duration_seconds": data.get("duration", 0),
                "nvd_stats": data.get("nvd_stats", {}),
                "coverage_summary": self.get_scan_coverage(scan_id).get("summary", {}),
                "error": data.get("error", ""),
            })
        active_statuses = {"running", "starting", "pending", "queued"}
    
        def sort_key(scan: dict) -> tuple[int, float, str]:
            status = str(scan.get("status", "")).lower()
            timestamp = scan.get("start_time") or scan.get("created_at") or ""
            try:
                sort_time = datetime.fromisoformat(timestamp).timestamp() if timestamp else 0.0
            except (TypeError, ValueError):
                sort_time = 0.0
            return (0 if status in active_statuses else 1, -sort_time, scan.get("scan_id", ""))
    
        results.sort(key=sort_key)
        return results

    def get_findings(self, scan_id: str, severity: Optional[str] = None,
                     agent: Optional[str] = None, status: Optional[str] = None,
                     quarantined: Optional[bool] = None) -> list[dict]:
        """Get findings with optional filters."""
        findings = self._findings.get(scan_id, [])
        if severity:
            findings = [f for f in findings if f.get("severity") == severity]
        if agent:
            findings = [f for f in findings if f.get("agent_source") == agent]
        if status:
            findings = [f for f in findings if f.get("status") == status]
        displayed = [self._display_finding(f) for f in findings]
        if quarantined is not None:
            displayed = [f for f in displayed if bool(f.get("quarantined")) == quarantined]
        return displayed

    async def triage_finding(
        self,
        scan_id: str,
        finding_id: int,
        disposition: str,
        actor: str,
        reason: str,
    ) -> dict[str, Any] | None:
        """Apply an analyst disposition and keep an immutable audit event."""
        updated = await self._store.triage_finding_async(
            scan_id, finding_id, disposition, actor, reason,
        )
        if not updated:
            return None
        findings = self._findings.setdefault(scan_id, [])
        for index, item in enumerate(findings):
            if int(item.get("finding_id") or -1) == finding_id:
                findings[index] = updated
                break
        else:
            # Older in-memory rows were hydrated before finding ids were
            # exposed. Refresh the canonical set rather than guessing by title.
            self._findings[scan_id] = self._store.load_findings(scan_id)
        history = self._store.load_finding_triage(scan_id, finding_id)
        await self._broadcast(ScanEvent(
            event_type="finding_triage",
            scan_id=scan_id,
            data={
                "finding_id": finding_id,
                "disposition": disposition,
                "actor": actor,
            },
        ))
        return {**self._display_finding(updated), "triage_history": history}

    def build_report_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """Build a report-ready ScanResult from the canonical manager store.

        The orchestrator can contain raw per-agent findings, while the manager
        store is the deduplicated source used by the dashboard and API. Reports
        must use this canonical view so downloaded report counts match the UI.
        """
        scan = self.get_scan(scan_id)
        if not scan:
            return None

        severity_map = {item.value: item for item in Severity}
        agent_map = {item.value: item for item in AgentType}
        findings: list[Finding] = []

        for item in self._findings.get(scan_id, []):
            host = item.get("target_host") or (scan.get("targets") or [""])[0]
            if not host:
                continue
            target_url = item.get("target_url") or ""
            protocol = "http" if target_url.startswith("http://") else "https"
            try:
                port = int(item.get("target_port") or (80 if protocol == "http" else 443))
            except (TypeError, ValueError):
                port = 443
            created_at = item.get("created_at")
            try:
                created_dt = datetime.fromisoformat(created_at) if created_at else datetime.utcnow()
            except ValueError:
                created_dt = datetime.utcnow()

            findings.append(Finding(
                title=item.get("title") or "Untitled Finding",
                description=item.get("description") or "No description provided.",
                severity=severity_map.get(item.get("severity"), Severity.INFORMATIONAL),
                cvss_score=item.get("cvss_score"),
                cvss_vector=item.get("cvss_vector"),
                agent_source=agent_map.get(item.get("agent_source"), AgentType.VULN_SCANNER),
                target=Target(host=host, port=port, protocol=protocol, url=target_url or None),
                evidence=item.get("evidence") or "",
                request_proof=item.get("request_proof"),
                response_proof=item.get("response_proof"),
                poc_steps=item.get("poc_steps") or [],
                remediation=item.get("remediation") or "",
                references=item.get("references") or [],
                cve_ids=item.get("cve_ids") or [],
                cwe_ids=item.get("cwe_ids") or [],
                tags=item.get("tags") or [],
                confidence=item.get("confidence") or "medium",
                status=item.get("status") or "suspected",
                created_at=created_dt,
            ))

        targets = []
        for raw in scan.get("targets") or []:
            targets.append(Target(host=raw))

        result = ScanResult(
            scan_name=scan.get("name") or scan_id,
            mode=ScanMode(scan.get("mode") or "full_vapt"),
            targets=targets,
            findings=findings,
            status=scan.get("status") or "completed",
        )
        result.id = scan_id
        try:
            result.start_time = datetime.fromisoformat(scan.get("start_time")) if scan.get("start_time") else result.start_time
        except ValueError:
            pass
        if scan.get("end_time"):
            try:
                result.end_time = datetime.fromisoformat(scan["end_time"])
            except ValueError:
                pass
        elif scan.get("status") in {"completed", "failed", "cancelled"}:
            result.end_time = datetime.utcnow()
        return result

    def get_agent_status(self, scan_id: str) -> dict[str, dict]:
        """Get real-time agent status for a scan."""
        result = {}
        for agent_type, status in self._agent_status.get(scan_id, {}).items():
            result[agent_type] = {
                "agent_type": status.agent_type,
                "status": status.status,
                "findings_count": status.findings_count,
                "tools_run": status.tools_run,
                "current_tool": status.current_tool,
                "progress_pct": status.progress_pct,
                "error": status.error,
                "started_at": status.started_at,
                "completed_at": status.completed_at,
            }
        return result

    def get_scan_modes(self) -> list[dict]:
        """Return available scan modes with descriptions."""
        modes = []
        for mode_name, profile in self._config.profiles.items():
            modes.append({
                "id": mode_name,
                "name": profile.name,
                "description": profile.description,
                "agents": profile.agents,
                "exploit": profile.exploit,
                "aggressive": profile.aggressive,
                "focus": profile.focus,
            })
        return modes
