"""Durable SQLite store for the VAPT backend.

All public methods that write to SQLite are now offered in both sync and async
variants.  The async variants run the blocking sqlite3 call in the default
thread-pool executor so they never stall the FastAPI/asyncio event loop.

Pattern:
    sync  → self._write_sync(...)          (used internally and at startup)
    async → await self.upsert_scan(...)    (used by ScanManager during scans)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sqlite3
import uuid
from pathlib import Path
from threading import RLock
from typing import Any, Optional
from urllib.parse import unquote, urlparse
from datetime import datetime


def _utc_now() -> str:
    return datetime.utcnow().isoformat()


def _json_dump(value: Any) -> str:
    return json.dumps(value if value is not None else [], default=str)


def _json_load(value: Any, fallback: Any = None) -> Any:
    if value in (None, ""):
        return [] if fallback is None else fallback
    try:
        return json.loads(value)
    except Exception:
        return [] if fallback is None else fallback


class PersistenceStore:
    """SQLite repository used by ScanManager.

    Sync methods are used during startup (hydration) and by the worker.
    The *_async suffix variants run the same work in a thread-pool executor
    so they don't block the asyncio event loop during active scans.
    """

    def __init__(self, database_url: str = "sqlite:///./data/vapt.db") -> None:
        self.path = self._path_from_url(database_url)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        artifact_root = os.environ.get("VAPT_ARTIFACT_DIR", "")
        self.artifact_root = Path(artifact_root).expanduser() if artifact_root else self.path.parent.parent / "artifacts"
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._init_schema()

    # ── Async helper ──────────────────────────────────────────────────────

    async def _run_sync(self, fn, *args, **kwargs):
        """Run a synchronous method in the thread-pool executor."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: fn(*args, **kwargs))

    @staticmethod
    def _path_from_url(database_url: str) -> Path:
        url = database_url or "sqlite:///./data/vapt.db"
        if url.startswith("sqlite:///"):
            return Path(unquote(url[len("sqlite:///"):])).expanduser()
        if url.startswith("sqlite://"):
            parsed = urlparse(url)
            return Path(unquote(parsed.path)).expanduser()
        return Path(url).expanduser()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                    CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    current_phase TEXT NOT NULL,
                    targets_json TEXT NOT NULL,
                start_time TEXT,
                    end_time TEXT,
                    duration REAL DEFAULT 0,
                    profile_agents_json TEXT NOT NULL DEFAULT '[]',
                exploit_enabled INTEGER NOT NULL DEFAULT 0,
                    nvd_stats_json TEXT NOT NULL DEFAULT '{}',
                    report_base_name TEXT NOT NULL DEFAULT '',
                    report_output_dir TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT '',
                    total_agent_tasks INTEGER NOT NULL DEFAULT 0,
                    scan_metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                    );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    dedupe_key TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT 'medium',
                    cvss_score REAL,
                    cvss_vector TEXT,
                    target_host TEXT NOT NULL,
                    target_port INTEGER NOT NULL DEFAULT 443,
                    target_url TEXT NOT NULL DEFAULT '',
                    evidence TEXT NOT NULL DEFAULT '',
                    request_proof TEXT,
                    response_proof TEXT,
                    poc_steps_json TEXT NOT NULL DEFAULT '[]',
                    remediation TEXT NOT NULL DEFAULT '',
                    references_json TEXT NOT NULL DEFAULT '[]',
                    cve_ids_json TEXT NOT NULL DEFAULT '[]',
                    cwe_ids_json TEXT NOT NULL DEFAULT '[]',
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    confidence TEXT NOT NULL DEFAULT 'medium',
                    status TEXT NOT NULL DEFAULT 'suspected',
                    agent_source TEXT NOT NULL DEFAULT '',
                    nvd_verified INTEGER NOT NULL DEFAULT 0,
                    evidence_score REAL NOT NULL DEFAULT 0,
                    evidence_grade TEXT NOT NULL DEFAULT 'E',
                    validation_notes_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
                    UNIQUE(scan_id, dedupe_key)
                );

                CREATE TABLE IF NOT EXISTS agent_statuses (
                    scan_id TEXT NOT NULL,
                    agent_type TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'idle',
                    started_at TEXT,
                    completed_at TEXT,
                    findings_count INTEGER NOT NULL DEFAULT 0,
                    tools_run_json TEXT NOT NULL DEFAULT '[]',
                    current_tool TEXT NOT NULL DEFAULT '',
                    progress_pct INTEGER NOT NULL DEFAULT 0,
                    error TEXT NOT NULL DEFAULT '',
                    log_messages_json TEXT NOT NULL DEFAULT '[]',
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(scan_id, agent_type),
                    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tool_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    agent_type TEXT NOT NULL DEFAULT '',
                    phase TEXT NOT NULL DEFAULT '',
                    tool TEXT NOT NULL,
                    success INTEGER NOT NULL DEFAULT 0,
                    exit_code INTEGER NOT NULL DEFAULT -1,
                    duration REAL NOT NULL DEFAULT 0,
                    timed_out INTEGER NOT NULL DEFAULT 0,
                    command_preview TEXT NOT NULL DEFAULT '',
                    stdout_snippet TEXT NOT NULL DEFAULT '',
                    stderr_snippet TEXT NOT NULL DEFAULT '',
                    stdout_artifact_path TEXT NOT NULL DEFAULT '',
                    stderr_artifact_path TEXT NOT NULL DEFAULT '',
                    stdout_sha256 TEXT NOT NULL DEFAULT '',
                    stderr_sha256 TEXT NOT NULL DEFAULT '',
                    stdout_size INTEGER NOT NULL DEFAULT 0,
                    stderr_size INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS assets (
                    scan_id TEXT NOT NULL,
                    asset_key TEXT NOT NULL,
                    asset_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence TEXT NOT NULL DEFAULT 'medium',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY(scan_id, asset_key),
                    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS asset_edges (
                    scan_id TEXT NOT NULL,
                    edge_key TEXT NOT NULL,
                    source_key TEXT NOT NULL,
                    target_key TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    evidence TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY(scan_id, edge_key),
                    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
                CREATE INDEX IF NOT EXISTS idx_events_scan_id ON events(scan_id, id);
                CREATE INDEX IF NOT EXISTS idx_tool_runs_scan ON tool_runs(scan_id, id);
                CREATE INDEX IF NOT EXISTS idx_scans_updated ON scans(updated_at);
                CREATE INDEX IF NOT EXISTS idx_assets_scan_type ON assets(scan_id, asset_type);
                CREATE INDEX IF NOT EXISTS idx_asset_edges_scan_source ON asset_edges(scan_id, source_key);
                """
            )
            self._ensure_column(conn, "tool_runs", "command_preview", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "tool_runs", "stdout_artifact_path", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "tool_runs", "stderr_artifact_path", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "tool_runs", "stdout_sha256", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "tool_runs", "stderr_sha256", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "tool_runs", "stdout_size", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "tool_runs", "stderr_size", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "tool_runs", "oom_killed", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "tool_runs", "timeout_reason", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "findings", "evidence_score", "REAL NOT NULL DEFAULT 0")
            self._ensure_column(conn, "findings", "evidence_grade", "TEXT NOT NULL DEFAULT 'E'")
            self._ensure_column(conn, "findings", "validation_notes_json", "TEXT NOT NULL DEFAULT '[]'")
            self._ensure_column(conn, "findings", "quarantined", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "findings", "llm_reasoning_json", "TEXT NOT NULL DEFAULT '{}'")
            self._ensure_column(conn, "scans", "scan_metadata_json", "TEXT NOT NULL DEFAULT '{}'")

    @staticmethod
    def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    @staticmethod
    def _finding_key(finding: dict[str, Any]) -> str:
        return f"{finding.get('title', '').lower().strip()}|{finding.get('target_host', '').lower().strip()}"

    @staticmethod
    def _safe_name(value: str, fallback: str = "artifact") -> str:
        cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(value or "").strip())
        return cleaned.strip("._")[:80] or fallback

    def _write_tool_artifact(
        self,
        scan_id: str,
        agent_type: str,
        run: dict[str, Any],
        stream_name: str,
        text: str,
        created_at: str,
    ) -> dict[str, Any]:
        raw = text or ""
        data = raw.encode("utf-8", errors="replace")
        if not data:
            return {"path": "", "sha256": "", "size": 0}

        tool = self._safe_name(run.get("tool", "tool"), "tool")
        phase = self._safe_name(run.get("phase", "phase"), "phase")
        agent = self._safe_name(agent_type, "agent")
        stamp = self._safe_name(created_at.replace(":", "").replace(".", "_"), "time")
        name = f"{stamp}_{phase}_{tool}_{uuid.uuid4().hex[:8]}.{stream_name}.txt"
        out_dir = self.artifact_root / self._safe_name(scan_id, "scan") / agent
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / name
        path.write_bytes(data)
        return {
            "path": str(path),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }

    def upsert_scan(self, scan_id: str, data: dict[str, Any]) -> None:
        now = _utc_now()
        metadata = dict(data.get("scan_metadata") or {})
        for key in ("target_classifications", "seed_evidence", "coverage"):
            if key in data:
                metadata[key] = data.get(key)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scans (
                    scan_id, name, mode, status, current_phase, targets_json,
                    start_time, end_time, duration, profile_agents_json,
                    exploit_enabled, nvd_stats_json, report_base_name,
                    report_output_dir, error, total_agent_tasks, scan_metadata_json,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    name=excluded.name,
                    mode=excluded.mode,
                    status=excluded.status,
                    current_phase=excluded.current_phase,
                    targets_json=excluded.targets_json,
                    start_time=excluded.start_time,
                    end_time=excluded.end_time,
                    duration=excluded.duration,
                    profile_agents_json=excluded.profile_agents_json,
                    exploit_enabled=excluded.exploit_enabled,
                    nvd_stats_json=excluded.nvd_stats_json,
                    report_base_name=excluded.report_base_name,
                    report_output_dir=excluded.report_output_dir,
                    error=excluded.error,
                    total_agent_tasks=excluded.total_agent_tasks,
                    scan_metadata_json=excluded.scan_metadata_json,
                    updated_at=excluded.updated_at
                """,
                (
                    scan_id,
                    data.get("name", scan_id),
                    data.get("mode", ""),
                    data.get("status", "pending"),
                    data.get("current_phase", "init"),
                    _json_dump(data.get("targets", [])),
                    data.get("start_time"),
                    data.get("end_time"),
                    data.get("duration", data.get("duration_seconds", 0)) or 0,
                    _json_dump(data.get("profile_agents", [])),
                    1 if data.get("exploit_enabled") else 0,
                    _json_dump(data.get("nvd_stats", {})),
                    data.get("report_base_name", ""),
                    data.get("report_output_dir", ""),
                    data.get("error", ""),
                    data.get("total_agent_tasks", 0) or 0,
                    _json_dump(metadata),
                    data.get("created_at", now),
                    now,
                ),
            )

    async def upsert_scan_async(self, scan_id: str, data: dict[str, Any]) -> None:
        """Non-blocking variant of upsert_scan for use inside async handlers."""
        await self._run_sync(self.upsert_scan, scan_id, data)

    def update_scan(self, scan_id: str, updates: dict[str, Any]) -> None:
        current = self.load_scan(scan_id)
        if not current:
            return
        current.update(updates)
        self.upsert_scan(scan_id, current)

    async def update_scan_async(self, scan_id: str, updates: dict[str, Any]) -> None:
        await self._run_sync(self.update_scan, scan_id, updates)

    def delete_scan(self, scan_id: str) -> bool:
        with self._lock, self._connect() as conn:
            exists = conn.execute(
                "SELECT 1 FROM scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
            if not exists:
                return False
            conn.execute("DELETE FROM events WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM tool_runs WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM asset_edges WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM assets WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM agent_statuses WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            return True

    async def delete_scan_async(self, scan_id: str) -> bool:
        return await self._run_sync(self.delete_scan, scan_id)

    def load_scan(self, scan_id: str) -> Optional[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        return self._scan_from_row(row) if row else None

    def load_scans(self) -> dict[str, dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM scans ORDER BY created_at DESC").fetchall()
        return {row["scan_id"]: self._scan_from_row(row) for row in rows}

    @staticmethod
    def _scan_from_row(row: sqlite3.Row) -> dict[str, Any]:
        data = {
            "id": row["scan_id"],
            "scan_id": row["scan_id"],
            "name": row["name"],
            "mode": row["mode"],
            "status": row["status"],
            "current_phase": row["current_phase"],
            "targets": _json_load(row["targets_json"], []),
            "start_time": row["start_time"],
            "end_time": row["end_time"],
            "duration": row["duration"] or 0,
            "profile_agents": _json_load(row["profile_agents_json"], []),
            "exploit_enabled": bool(row["exploit_enabled"]),
            "nvd_stats": _json_load(row["nvd_stats_json"], {}),
            "report_base_name": row["report_base_name"],
            "report_output_dir": row["report_output_dir"],
            "error": row["error"],
            "total_agent_tasks": row["total_agent_tasks"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        metadata = _json_load(row["scan_metadata_json"], {})
        if isinstance(metadata, dict):
            data["scan_metadata"] = metadata
            for key in ("target_classifications", "seed_evidence", "coverage"):
                if key in metadata:
                    data[key] = metadata.get(key)
        return data

    def upsert_finding(self, scan_id: str, finding: dict[str, Any]) -> None:
        now = _utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO findings (
                scan_id, dedupe_key, title, description, severity, cvss_score,
                    cvss_vector, target_host, target_port, target_url, evidence,
                    request_proof, response_proof, poc_steps_json, remediation,
                    references_json, cve_ids_json, cwe_ids_json, tags_json,
                    confidence, status, agent_source, nvd_verified, evidence_score,
                    evidence_grade, validation_notes_json, quarantined, llm_reasoning_json,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, dedupe_key) DO UPDATE SET
                    description=excluded.description,
                    severity=excluded.severity,
                    cvss_score=excluded.cvss_score,
                    cvss_vector=excluded.cvss_vector,
                    target_port=excluded.target_port,
                    target_url=excluded.target_url,
                    evidence=excluded.evidence,
                    request_proof=excluded.request_proof,
                    response_proof=excluded.response_proof,
                    poc_steps_json=excluded.poc_steps_json,
                    remediation=excluded.remediation,
                    references_json=excluded.references_json,
                    cve_ids_json=excluded.cve_ids_json,
                    cwe_ids_json=excluded.cwe_ids_json,
                    tags_json=excluded.tags_json,
                    confidence=excluded.confidence,
                status=excluded.status,
                    agent_source=excluded.agent_source,
                    nvd_verified=excluded.nvd_verified,
                    evidence_score=excluded.evidence_score,
                    evidence_grade=excluded.evidence_grade,
                    validation_notes_json=excluded.validation_notes_json,
                    quarantined=excluded.quarantined,
                    llm_reasoning_json=excluded.llm_reasoning_json,
                updated_at=excluded.updated_at
                """,
                (
                scan_id,
                    self._finding_key(finding),
                    finding.get("title", "Untitled Finding"),
                    finding.get("description", ""),
                    finding.get("severity", "medium"),
                    finding.get("cvss_score"),
                    finding.get("cvss_vector"),
                    finding.get("target_host", ""),
                    finding.get("target_port", 443) or 443,
                    finding.get("target_url", ""),
                    finding.get("evidence", ""),
                    finding.get("request_proof"),
                    finding.get("response_proof"),
                    _json_dump(finding.get("poc_steps", [])),
                    finding.get("remediation", ""),
                    _json_dump(finding.get("references", [])),
                    _json_dump(finding.get("cve_ids", [])),
                    _json_dump(finding.get("cwe_ids", [])),
                    _json_dump(finding.get("tags", [])),
                    finding.get("confidence", "medium"),
                    finding.get("status", "suspected"),
                    finding.get("agent_source", ""),
                    1 if finding.get("nvd_verified") else 0,
                    float(finding.get("evidence_score", 0) or 0),
                    finding.get("evidence_grade", "E"),
                    _json_dump(finding.get("validation_notes", [])),
                    1 if finding.get("quarantined") else 0,
                    _json_dump(finding.get("llm_reasoning", {})),
                    finding.get("created_at", now),
                    now,
                ),
            )

    async def upsert_finding_async(self, scan_id: str, finding: dict[str, Any]) -> None:
        """Non-blocking variant of upsert_finding."""
        await self._run_sync(self.upsert_finding, scan_id, finding)

    def load_findings(self, scan_id: str) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY id ASC",
                (scan_id,),
            ).fetchall()
        return [self._finding_from_row(row) for row in rows]

    def load_all_findings(self) -> dict[str, list[dict[str, Any]]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM findings ORDER BY id ASC").fetchall()
        findings: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            findings.setdefault(row["scan_id"], []).append(self._finding_from_row(row))
        return findings

    @staticmethod
    def _finding_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "title": row["title"],
            "description": row["description"],
            "severity": row["severity"],
            "cvss_score": row["cvss_score"],
            "cvss_vector": row["cvss_vector"],
            "target_host": row["target_host"],
            "target_port": row["target_port"],
            "target_url": row["target_url"],
            "evidence": row["evidence"],
            "request_proof": row["request_proof"],
            "response_proof": row["response_proof"],
            "poc_steps": _json_load(row["poc_steps_json"], []),
            "remediation": row["remediation"],
            "references": _json_load(row["references_json"], []),
            "cve_ids": _json_load(row["cve_ids_json"], []),
            "cwe_ids": _json_load(row["cwe_ids_json"], []),
            "tags": _json_load(row["tags_json"], []),
            "confidence": row["confidence"],
            "status": row["status"],
            "agent_source": row["agent_source"],
            "nvd_verified": bool(row["nvd_verified"]),
            "evidence_score": row["evidence_score"],
            "evidence_grade": row["evidence_grade"],
            "validation_notes": _json_load(row["validation_notes_json"], []),
            "quarantined": bool(row["quarantined"]),
            "llm_reasoning": _json_load(row["llm_reasoning_json"], {}),
            "created_at": row["created_at"],
        }

    def upsert_agent_status(self, scan_id: str, agent_type: str, status: Any) -> None:
        now = _utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO agent_statuses (
                scan_id, agent_type, status, started_at, completed_at,
                    findings_count, tools_run_json, current_tool, progress_pct,
                    error, log_messages_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, agent_type) DO UPDATE SET
                status=excluded.status,
                    started_at=excluded.started_at,
                    completed_at=excluded.completed_at,
                    findings_count=excluded.findings_count,
                    tools_run_json=excluded.tools_run_json,
                    current_tool=excluded.current_tool,
                    progress_pct=excluded.progress_pct,
                error=excluded.error,
                    log_messages_json=excluded.log_messages_json,
                updated_at=excluded.updated_at
                """,
                (
                scan_id,
                    agent_type,
                    getattr(status, "status", "idle"),
                    getattr(status, "started_at", None),
                    getattr(status, "completed_at", None),
                    getattr(status, "findings_count", 0),
                    _json_dump(getattr(status, "tools_run", [])),
                    getattr(status, "current_tool", ""),
                    getattr(status, "progress_pct", 0),
                    getattr(status, "error", ""),
                    _json_dump(getattr(status, "log_messages", [])),
                    now,
                ),
            )

    async def upsert_agent_status_async(
        self, scan_id: str, agent_type: str, status: Any
    ) -> None:
        """Non-blocking variant of upsert_agent_status."""
        await self._run_sync(self.upsert_agent_status, scan_id, agent_type, status)

    def load_agent_status(self) -> dict[str, dict[str, dict[str, Any]]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM agent_statuses").fetchall()
        statuses: dict[str, dict[str, dict[str, Any]]] = {}
        for row in rows:
            statuses.setdefault(row["scan_id"], {})[row["agent_type"]] = {
                "agent_type": row["agent_type"],
                "status": row["status"],
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
                "findings_count": row["findings_count"],
                "tools_run": _json_load(row["tools_run_json"], []),
                "current_tool": row["current_tool"],
                "progress_pct": row["progress_pct"],
                "error": row["error"],
                "log_messages": _json_load(row["log_messages_json"], []),
            }
        return statuses

    def append_event(self, payload: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO events (scan_id, event_type, timestamp, payload_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    payload.get("scan_id", ""),
                    payload.get("event") or payload.get("type") or "message",
                    payload.get("timestamp") or _utc_now(),
                    _json_dump(payload),
                ),
            )

    async def append_event_async(self, payload: dict[str, Any]) -> None:
        """Non-blocking variant of append_event."""
        await self._run_sync(self.append_event, payload)

    def append_tool_run(self, scan_id: str, agent_type: str, run: dict[str, Any]) -> None:
        now = _utc_now()
        stdout = str(run.get("stdout", "") or "")
        stderr = str(run.get("stderr", "") or "")
        stdout_artifact = self._write_tool_artifact(scan_id, agent_type, run, "stdout", stdout, now)
        stderr_artifact = self._write_tool_artifact(scan_id, agent_type, run, "stderr", stderr, now)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tool_runs (
                scan_id, agent_type, phase, tool, success, exit_code,
                    duration, timed_out, command_preview, stdout_snippet, stderr_snippet,
                    stdout_artifact_path, stderr_artifact_path, stdout_sha256, stderr_sha256,
                    stdout_size, stderr_size, oom_killed, timeout_reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                scan_id,
                    agent_type,
                    run.get("phase", ""),
                    run.get("tool", ""),
                    1 if run.get("success") else 0,
                    int(run.get("exit_code", -1) or 0),
                    float(run.get("duration", 0) or 0),
                    1 if run.get("timed_out") else 0,
                    str(run.get("command_preview", ""))[:2000],
                    stdout[:5000],
                    stderr[:5000],
                    stdout_artifact["path"],
                    stderr_artifact["path"],
                    stdout_artifact["sha256"],
                    stderr_artifact["sha256"],
                    stdout_artifact["size"],
                    stderr_artifact["size"],
                    1 if run.get("oom_killed") else 0,
                    str(run.get("timeout_reason", ""))[:1000],
                    now,
                ),
            )

    def append_tool_runs(self, scan_id: str, agent_type: str, runs: list[dict[str, Any]]) -> None:
        for run in runs:
            if isinstance(run, dict):
                self.append_tool_run(scan_id, agent_type, run)

    async def append_tool_runs_async(self, scan_id: str, agent_type: str, runs: list[dict[str, Any]]) -> None:
        await self._run_sync(self.append_tool_runs, scan_id, agent_type, runs)

    def load_tool_runs(self, scan_id: str) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM tool_runs WHERE scan_id = ? ORDER BY id ASC",
                (scan_id,),
            ).fetchall()
        return [self._tool_run_from_row(row) for row in rows]

    def load_tool_run(self, scan_id: str, run_id: int) -> Optional[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM tool_runs WHERE scan_id = ? AND id = ?",
                (scan_id, run_id),
            ).fetchone()
        return self._tool_run_from_row(row) if row else None

    @staticmethod
    def _tool_run_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "scan_id": row["scan_id"],
            "agent_type": row["agent_type"],
            "phase": row["phase"],
            "tool": row["tool"],
            "success": bool(row["success"]),
            "exit_code": row["exit_code"],
            "duration": row["duration"],
            "timed_out": bool(row["timed_out"]),
            "command_preview": row["command_preview"],
            "stdout_snippet": row["stdout_snippet"],
            "stderr_snippet": row["stderr_snippet"],
            "stdout_artifact_path": row["stdout_artifact_path"],
            "stderr_artifact_path": row["stderr_artifact_path"],
            "stdout_sha256": row["stdout_sha256"],
            "stderr_sha256": row["stderr_sha256"],
            "stdout_size": row["stdout_size"],
            "stderr_size": row["stderr_size"],
            "oom_killed": bool(row["oom_killed"]),
            "timeout_reason": row["timeout_reason"],
            "created_at": row["created_at"],
        }

    def load_recent_events(self, limit: int = 1000) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 2000))
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [_json_load(row["payload_json"], {}) for row in reversed(rows)]

    def load_events(
        self,
        scan_id: str,
        *,
        event_type: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Load a durable per-scan event slice for replay/audit APIs."""
        limit = max(1, min(limit, 2000))
        query = "SELECT payload_json FROM events WHERE scan_id = ?"
        params: list[Any] = [scan_id]
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [_json_load(row["payload_json"], {}) for row in reversed(rows)]

    def upsert_asset(self, scan_id: str, asset: dict[str, Any]) -> None:
        now = _utc_now()
        metadata = asset.get("metadata", {})
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO assets (
                scan_id, asset_key, asset_type, value, source, confidence,
                    metadata_json, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, asset_key) DO UPDATE SET
                    source=excluded.source,
                    confidence=excluded.confidence,
                    metadata_json=excluded.metadata_json,
                    last_seen=excluded.last_seen
                """,
                (
                scan_id,
                    asset["asset_key"],
                    asset.get("asset_type", "unknown"),
                    asset.get("value", ""),
                    asset.get("source", ""),
                    asset.get("confidence", "medium"),
                    _json_dump(metadata if isinstance(metadata, dict) else {}),
                    now,
                    now,
                ),
            )

    def upsert_asset_edge(self, scan_id: str, edge: dict[str, Any]) -> None:
        now = _utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO asset_edges (
                scan_id, edge_key, source_key, target_key, relation,
                    evidence, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, edge_key) DO UPDATE SET
                    evidence=excluded.evidence,
                    last_seen=excluded.last_seen
                """,
                (
                scan_id,
                    edge["edge_key"],
                    edge.get("source_key", ""),
                    edge.get("target_key", ""),
                    edge.get("relation", ""),
                    edge.get("evidence", ""),
                    now,
                    now,
                ),
            )

    def upsert_asset_graph(
        self,
        scan_id: str,
        assets: list[dict[str, Any]],
        edges: list[dict[str, Any]] | None = None,
    ) -> None:
        for asset in assets:
            self.upsert_asset(scan_id, asset)
        for edge in edges or []:
            self.upsert_asset_edge(scan_id, edge)

    def load_assets(self, scan_id: str, asset_type: Optional[str] = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM assets WHERE scan_id = ?"
        params: list[Any] = [scan_id]
        if asset_type:
            query += " AND asset_type = ?"
            params.append(asset_type)
        query += " ORDER BY asset_type, value"
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._asset_from_row(row) for row in rows]

    def load_asset_edges(self, scan_id: str) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM asset_edges WHERE scan_id = ? ORDER BY relation, source_key",
                (scan_id,),
            ).fetchall()
        return [self._asset_edge_from_row(row) for row in rows]

    @staticmethod
    def _asset_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "asset_key": row["asset_key"],
            "asset_type": row["asset_type"],
            "value": row["value"],
            "source": row["source"],
            "confidence": row["confidence"],
            "metadata": _json_load(row["metadata_json"], {}),
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
        }

    @staticmethod
    def _asset_edge_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "edge_key": row["edge_key"],
            "source_key": row["source_key"],
            "target_key": row["target_key"],
            "relation": row["relation"],
            "evidence": row["evidence"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
        }
