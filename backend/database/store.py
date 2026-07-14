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
import shutil
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

                CREATE TABLE IF NOT EXISTS durable_actions (
                    action_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL DEFAULT '',
                    phase TEXT NOT NULL DEFAULT '',
                    capability TEXT NOT NULL DEFAULT '',
                    tool TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'queued',
                    attempt INTEGER NOT NULL DEFAULT 1,
                    max_attempts INTEGER NOT NULL DEFAULT 2,
                    idempotency_key TEXT NOT NULL,
                    input_hash TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT '',
                    runner TEXT NOT NULL DEFAULT 'arq',
                    result_json TEXT NOT NULL DEFAULT '{}',
                    checkpoint_json TEXT NOT NULL DEFAULT '{}',
                    error TEXT NOT NULL DEFAULT '',
                    queued_at TEXT NOT NULL,
                    started_at TEXT,
                    heartbeat_at TEXT,
                    completed_at TEXT,
                    updated_at TEXT NOT NULL,
                    UNIQUE(idempotency_key)
                );

                CREATE TABLE IF NOT EXISTS oob_tokens (
                    token TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL DEFAULT '',
                    hypothesis_id TEXT NOT NULL DEFAULT '',
                    interaction_type TEXT NOT NULL DEFAULT 'http',
                    expires_at TEXT NOT NULL,
                    interacted_at TEXT,
                    interaction_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
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

                CREATE TABLE IF NOT EXISTS appsec_assessments (
                    assessment_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    ref TEXT NOT NULL DEFAULT 'main',
                    commit_sha TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'queued',
                    phase TEXT NOT NULL DEFAULT 'queued',
                    progress INTEGER NOT NULL DEFAULT 0,
                    job_id TEXT NOT NULL DEFAULT '',
                    coverage_json TEXT NOT NULL DEFAULT '{}',
                    summary_json TEXT NOT NULL DEFAULT '{}',
                    error TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS appsec_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    source TEXT NOT NULL,
                    category TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT 'medium',
                    confidence TEXT NOT NULL DEFAULT 'medium',
                    status TEXT NOT NULL DEFAULT 'candidate',
                    repository TEXT NOT NULL,
                    path TEXT NOT NULL DEFAULT '',
                    start_line INTEGER,
                    end_line INTEGER,
                    package TEXT NOT NULL DEFAULT '',
                    installed_version TEXT NOT NULL DEFAULT '',
                    fixed_version TEXT NOT NULL DEFAULT '',
                    cve_ids_json TEXT NOT NULL DEFAULT '[]',
                    cwe_ids_json TEXT NOT NULL DEFAULT '[]',
                    references_json TEXT NOT NULL DEFAULT '[]',
                    evidence TEXT NOT NULL DEFAULT '',
                    remediation TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(assessment_id) REFERENCES appsec_assessments(assessment_id) ON DELETE CASCADE,
                    UNIQUE(assessment_id, fingerprint)
                );

                CREATE TABLE IF NOT EXISTS appsec_tool_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT NOT NULL,
                    lane TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    success INTEGER NOT NULL DEFAULT 0,
                    exit_code INTEGER NOT NULL DEFAULT -1,
                    duration REAL NOT NULL DEFAULT 0,
                    timed_out INTEGER NOT NULL DEFAULT 0,
                    stderr_snippet TEXT NOT NULL DEFAULT '',
                    stdout_artifact_path TEXT NOT NULL DEFAULT '',
                    stderr_artifact_path TEXT NOT NULL DEFAULT '',
                    stdout_sha256 TEXT NOT NULL DEFAULT '',
                    stderr_sha256 TEXT NOT NULL DEFAULT '',
                    stdout_size INTEGER NOT NULL DEFAULT 0,
                    stderr_size INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(assessment_id) REFERENCES appsec_assessments(assessment_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS appsec_artifacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    format TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(assessment_id) REFERENCES appsec_assessments(assessment_id) ON DELETE CASCADE,
                    UNIQUE(assessment_id, kind, format)
                );

                CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
                CREATE INDEX IF NOT EXISTS idx_events_scan_id ON events(scan_id, id);
                CREATE INDEX IF NOT EXISTS idx_tool_runs_scan ON tool_runs(scan_id, id);
                CREATE INDEX IF NOT EXISTS idx_durable_actions_scan ON durable_actions(scan_id, queued_at);
                CREATE INDEX IF NOT EXISTS idx_durable_actions_status ON durable_actions(status, updated_at);
                CREATE INDEX IF NOT EXISTS idx_oob_tokens_scan ON oob_tokens(scan_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_scans_updated ON scans(updated_at);
                CREATE INDEX IF NOT EXISTS idx_assets_scan_type ON assets(scan_id, asset_type);
                CREATE INDEX IF NOT EXISTS idx_asset_edges_scan_source ON asset_edges(scan_id, source_key);
                CREATE INDEX IF NOT EXISTS idx_appsec_assessments_updated ON appsec_assessments(updated_at);
                CREATE INDEX IF NOT EXISTS idx_appsec_findings_assessment ON appsec_findings(assessment_id, severity);
                CREATE INDEX IF NOT EXISTS idx_appsec_runs_assessment ON appsec_tool_runs(assessment_id, id);
                CREATE INDEX IF NOT EXISTS idx_appsec_artifacts_assessment ON appsec_artifacts(assessment_id, kind);
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
            self._ensure_column(conn, "appsec_tool_runs", "stdout_artifact_path", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "appsec_tool_runs", "stderr_artifact_path", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "appsec_tool_runs", "stdout_sha256", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "appsec_tool_runs", "stderr_sha256", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "appsec_tool_runs", "stdout_size", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "appsec_tool_runs", "stderr_size", "INTEGER NOT NULL DEFAULT 0")
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
        host = str(finding.get("target_host") or "").lower().strip()
        cves = sorted({str(value).upper() for value in (finding.get("cve_ids") or []) if str(value).strip()})
        if cves:
            return f"{host}|cve|{','.join(cves)}"
        title = re.sub(
            r"^(cms vulnerability|potential vulnerability|vulnerability)\s*:\s*",
            "",
            str(finding.get("title") or "").lower().strip(),
        )
        title = re.sub(r"\s+", " ", title)
        return f"{host}|title|{title}"

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
        source_key = f"{stream_name}_source_path"
        source_path = Path(str(run.get(source_key) or ""))
        raw = text or ""
        data = raw.encode("utf-8", errors="replace")
        source_available = source_path.is_file()
        if not data and not source_available:
            return {"path": "", "sha256": "", "size": 0}

        tool = self._safe_name(run.get("tool", "tool"), "tool")
        phase = self._safe_name(run.get("phase", "phase"), "phase")
        agent = self._safe_name(agent_type, "agent")
        stamp = self._safe_name(created_at.replace(":", "").replace(".", "_"), "time")
        name = f"{stamp}_{phase}_{tool}_{uuid.uuid4().hex[:8]}.{stream_name}.txt"
        out_dir = self.artifact_root / self._safe_name(scan_id, "scan") / agent
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / name
        if source_available:
            shutil.copyfile(source_path, path)
            try:
                source_path.unlink()
            except OSError:
                pass
        else:
            path.write_bytes(data)
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        return {
            "path": str(path),
            "sha256": digest.hexdigest(),
            "size": size,
        }

    def upsert_scan(self, scan_id: str, data: dict[str, Any]) -> None:
        now = _utc_now()
        metadata = dict(data.get("scan_metadata") or {})
        for key in (
            "target_classifications", "seed_evidence", "coverage", "scope",
            "rules_of_engagement", "execution_targets", "display_targets",
        ):
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
            conn.execute("DELETE FROM durable_actions WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM oob_tokens WHERE scan_id = ?", (scan_id,))
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
            for key in (
                "target_classifications", "seed_evidence", "coverage", "scope",
                "rules_of_engagement", "execution_targets", "display_targets",
            ):
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

    def append_event(self, payload: dict[str, Any]) -> int:
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
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
            sequence = int(cursor.lastrowid)
            stored_payload = dict(payload)
            stored_payload["sequence"] = sequence
            conn.execute(
                "UPDATE events SET payload_json = ? WHERE id = ?",
                (_json_dump(stored_payload), sequence),
            )
            return sequence

    async def append_event_async(self, payload: dict[str, Any]) -> int:
        """Non-blocking variant of append_event."""
        return await self._run_sync(self.append_event, payload)

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
        success = bool(row["success"])
        partial = not success and bool(row["timed_out"]) and int(row["stdout_size"] or 0) > 0
        return {
            "id": row["id"],
            "scan_id": row["scan_id"],
            "agent_type": row["agent_type"],
            "phase": row["phase"],
            "tool": row["tool"],
            "success": success,
            "partial": partial,
            "evidence_captured": success or partial,
            "outcome": "completed" if success else "partial" if partial else "timed_out" if row["timed_out"] else "failed",
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

    def load_events_after(self, sequence: int, limit: int = 500) -> list[dict[str, Any]]:
        """Replay persisted events after a client's last acknowledged sequence."""
        limit = max(1, min(limit, 2000))
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT id, payload_json FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
                (max(0, int(sequence or 0)), limit),
            ).fetchall()
        events: list[dict[str, Any]] = []
        for row in rows:
            payload = _json_load(row["payload_json"], {})
            if isinstance(payload, dict):
                payload.setdefault("sequence", row["id"])
                events.append(payload)
        return events

    # ── Durable capability actions ─────────────────────────────────

    def create_durable_action(self, action: dict[str, Any]) -> dict[str, Any]:
        """Persist an idempotent capability action before it enters the queue."""
        now = _utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO durable_actions (
                    action_id, scan_id, phase, capability, tool, status, attempt,
                    max_attempts, idempotency_key, input_hash, reason, runner,
                    result_json, checkpoint_json, error, queued_at, started_at,
                    heartbeat_at, completed_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(idempotency_key) DO NOTHING
                """,
                (
                    action["action_id"], action.get("scan_id", ""), action.get("phase", ""),
                    action.get("capability", action.get("tool", "")), action.get("tool", ""),
                    action.get("status", "queued"), int(action.get("attempt", 1) or 1),
                    int(action.get("max_attempts", 2) or 2), action["idempotency_key"],
                    action.get("input_hash", ""), action.get("reason", ""),
                    action.get("runner", "arq"), _json_dump(action.get("result", {})),
                    _json_dump(action.get("checkpoint", {})), action.get("error", ""),
                    action.get("queued_at", now), action.get("started_at"),
                    action.get("heartbeat_at"), action.get("completed_at"), now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM durable_actions WHERE idempotency_key = ?",
                (action["idempotency_key"],),
            ).fetchone()
        return self._durable_action_from_row(row)

    def update_durable_action(self, action_id: str, updates: dict[str, Any]) -> None:
        allowed = {
            "status", "attempt", "result", "checkpoint", "error", "started_at",
            "heartbeat_at", "completed_at", "reason", "runner", "phase", "capability",
        }
        assignments: list[str] = []
        values: list[Any] = []
        json_fields = {"result": "result_json", "checkpoint": "checkpoint_json"}
        for key, value in updates.items():
            if key not in allowed:
                continue
            column = json_fields.get(key, key)
            assignments.append(f"{column} = ?")
            values.append(_json_dump(value) if key in json_fields else value)
        if not assignments:
            return
        assignments.append("updated_at = ?")
        values.extend([_utc_now(), action_id])
        with self._lock, self._connect() as conn:
            conn.execute(
                f"UPDATE durable_actions SET {', '.join(assignments)} WHERE action_id = ?",
                values,
            )

    async def update_durable_action_async(self, action_id: str, updates: dict[str, Any]) -> None:
        await self._run_sync(self.update_durable_action, action_id, updates)

    def load_durable_action(self, action_id: str) -> Optional[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM durable_actions WHERE action_id = ?", (action_id,),
            ).fetchone()
        return self._durable_action_from_row(row) if row else None

    def load_durable_actions(self, scan_id: str) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM durable_actions WHERE scan_id = ? ORDER BY queued_at, action_id",
                (scan_id,),
            ).fetchall()
        return [self._durable_action_from_row(row) for row in rows]

    def register_oob_token(self, token: str, data: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO oob_tokens (
                    token, scan_id, hypothesis_id, interaction_type, expires_at,
                    interaction_json, created_at
                ) VALUES (?, ?, ?, ?, ?, '{}', ?)
                """,
                (
                    token, data.get("scan_id", ""), data.get("hypothesis_id", ""),
                    data.get("interaction_type", "http"), data["expires_at"], _utc_now(),
                ),
            )

    def record_oob_interaction(self, token: str, interaction: dict[str, Any]) -> bool:
        now = _utc_now()
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE oob_tokens SET interacted_at = ?, interaction_json = ?
                WHERE token = ? AND expires_at >= ?
                """,
                (now, _json_dump(interaction), token, now),
            )
            return bool(cursor.rowcount)

    def load_oob_token(self, token: str) -> Optional[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM oob_tokens WHERE token = ?", (token,)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["interaction"] = _json_load(item.pop("interaction_json"), {})
        return item

    def recover_stale_actions(self, stale_before: str) -> int:
        """Move abandoned queued/running actions to a visible retry state."""
        now = _utc_now()
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE durable_actions
                SET status = 'retrying', error = CASE WHEN error = ''
                    THEN 'Runner heartbeat expired; safe retry is available.' ELSE error END,
                    updated_at = ?
                WHERE status IN ('queued', 'running') AND updated_at < ?
                """,
                (now, stale_before),
            )
            return int(cursor.rowcount or 0)

    @staticmethod
    def _durable_action_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "action_id": row["action_id"], "scan_id": row["scan_id"],
            "phase": row["phase"], "capability": row["capability"], "tool": row["tool"],
            "status": row["status"], "attempt": row["attempt"],
            "max_attempts": row["max_attempts"], "idempotency_key": row["idempotency_key"],
            "input_hash": row["input_hash"], "reason": row["reason"], "runner": row["runner"],
            "result": _json_load(row["result_json"], {}),
            "checkpoint": _json_load(row["checkpoint_json"], {}), "error": row["error"],
            "queued_at": row["queued_at"], "started_at": row["started_at"],
            "heartbeat_at": row["heartbeat_at"], "completed_at": row["completed_at"],
            "updated_at": row["updated_at"],
        }

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

    # ── Unified AppSec assessments ─────────────────────────────────────

    def create_appsec_assessment(self, assessment_id: str, data: dict[str, Any]) -> None:
        now = _utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO appsec_assessments (
                    assessment_id, name, repository, ref, status, phase,
                    progress, coverage_json, summary_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment_id,
                    data.get("name") or assessment_id,
                    data.get("repository", ""),
                    data.get("ref", "main"),
                    data.get("status", "queued"),
                    data.get("phase", "queued"),
                    int(data.get("progress", 0) or 0),
                    _json_dump(data.get("coverage", {})),
                    _json_dump(data.get("summary", {})),
                    now,
                    now,
                ),
            )

    def update_appsec_assessment(self, assessment_id: str, updates: dict[str, Any]) -> None:
        allowed = {
            "name": "name", "repository": "repository", "ref": "ref",
            "commit_sha": "commit_sha", "status": "status", "phase": "phase",
            "progress": "progress", "job_id": "job_id", "error": "error",
            "coverage": "coverage_json", "summary": "summary_json",
        }
        assignments: list[str] = []
        values: list[Any] = []
        for key, column in allowed.items():
            if key not in updates:
                continue
            value = updates[key]
            if key in {"coverage", "summary"}:
                value = _json_dump(value if isinstance(value, dict) else {})
            assignments.append(f"{column} = ?")
            values.append(value)
        if not assignments:
            return
        assignments.append("updated_at = ?")
        values.extend([_utc_now(), assessment_id])
        with self._lock, self._connect() as conn:
            conn.execute(
                f"UPDATE appsec_assessments SET {', '.join(assignments)} WHERE assessment_id = ?",
                values,
            )

    def replace_appsec_findings(self, assessment_id: str, findings: list[dict[str, Any]]) -> None:
        now = _utc_now()
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM appsec_findings WHERE assessment_id = ?", (assessment_id,))
            for item in findings:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO appsec_findings (
                        assessment_id, fingerprint, source, category, rule_id,
                        title, description, severity, confidence, status,
                        repository, path, start_line, end_line, package,
                        installed_version, fixed_version, cve_ids_json,
                        cwe_ids_json, references_json, evidence, remediation, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        assessment_id, item["fingerprint"], item.get("source", ""),
                        item.get("category", ""), item.get("rule_id", ""),
                        item.get("title", ""), item.get("description", ""),
                        item.get("severity", "medium"), item.get("confidence", "medium"),
                        item.get("status", "candidate"), item.get("repository", ""),
                        item.get("path", ""), item.get("start_line"), item.get("end_line"),
                        item.get("package", ""), item.get("installed_version", ""),
                        item.get("fixed_version", ""), _json_dump(item.get("cve_ids", [])),
                        _json_dump(item.get("cwe_ids", [])), _json_dump(item.get("references", [])),
                        item.get("evidence", ""), item.get("remediation", ""), now,
                    ),
                )

    def append_appsec_run(self, assessment_id: str, lane: str, run: dict[str, Any]) -> None:
        now = _utc_now()
        artifact_run = dict(run) | {"phase": lane}
        stdout_artifact = self._write_tool_artifact(
            assessment_id, "appsec", artifact_run, "stdout", str(run.get("stdout", "") or ""), now,
        )
        stderr_artifact = self._write_tool_artifact(
            assessment_id, "appsec", artifact_run, "stderr", str(run.get("stderr", "") or ""), now,
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO appsec_tool_runs (
                    assessment_id, lane, tool, success, exit_code, duration,
                    timed_out, stderr_snippet, stdout_artifact_path,
                    stderr_artifact_path, stdout_sha256, stderr_sha256,
                    stdout_size, stderr_size, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment_id, lane, run.get("tool", ""),
                    1 if run.get("success") else 0, int(run.get("exit_code", -1) or 0),
                    float(run.get("duration", 0) or 0), 1 if run.get("timed_out") else 0,
                    str(run.get("stderr", ""))[-2000:],
                    stdout_artifact["path"], stderr_artifact["path"],
                    stdout_artifact["sha256"], stderr_artifact["sha256"],
                    stdout_artifact["size"], stderr_artifact["size"], now,
                ),
            )

    def load_appsec_assessment(self, assessment_id: str) -> Optional[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM appsec_assessments WHERE assessment_id = ?", (assessment_id,),
            ).fetchone()
        if not row:
            return None
        item = self._appsec_assessment_from_row(row)
        item["findings"] = self.load_appsec_findings(assessment_id)
        item["tool_runs"] = self.load_appsec_runs(assessment_id)
        item["artifacts"] = self.load_appsec_artifacts(assessment_id)
        return item

    def load_appsec_assessments(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM appsec_assessments ORDER BY updated_at DESC",
            ).fetchall()
        return [self._appsec_assessment_from_row(row) for row in rows]

    def load_previous_appsec_assessment(
        self,
        repository: str,
        *,
        exclude_id: str,
        ref: str = "",
    ) -> Optional[dict[str, Any]]:
        """Return the newest like-for-like assessment for baseline analysis."""
        with self._lock, self._connect() as conn:
            if ref:
                row = conn.execute(
                    """
                    SELECT * FROM appsec_assessments
                    WHERE repository = ? AND ref = ? AND assessment_id != ?
                        AND status IN ('completed', 'partial')
                    ORDER BY updated_at DESC LIMIT 1
                    """,
                    (repository, ref, exclude_id),
                ).fetchone()
            else:
                row = conn.execute(
                    """
                    SELECT * FROM appsec_assessments
                    WHERE repository = ? AND assessment_id != ?
                        AND status IN ('completed', 'partial')
                    ORDER BY updated_at DESC LIMIT 1
                    """,
                    (repository, exclude_id),
                ).fetchone()
        if not row:
            return None
        item = self._appsec_assessment_from_row(row)
        item["findings"] = self.load_appsec_findings(item["assessment_id"])
        return item

    def load_appsec_findings(self, assessment_id: str) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM appsec_findings WHERE assessment_id = ? ORDER BY id ASC",
                (assessment_id,),
            ).fetchall()
        return [self._appsec_finding_from_row(row) for row in rows]

    def load_appsec_runs(self, assessment_id: str) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM appsec_tool_runs WHERE assessment_id = ? ORDER BY id ASC",
                (assessment_id,),
            ).fetchall()
        return [dict(row) | {"success": bool(row["success"]), "timed_out": bool(row["timed_out"])} for row in rows]

    def save_appsec_artifact(
        self,
        assessment_id: str,
        *,
        kind: str,
        format: str,
        filename: str,
        content: str,
    ) -> dict[str, Any]:
        safe_kind = self._safe_name(kind, "artifact")
        safe_format = self._safe_name(format, "json")
        safe_filename = self._safe_name(filename, f"{safe_kind}.{safe_format}")
        data = content.encode("utf-8", errors="replace")
        out_dir = self.artifact_root / "appsec" / self._safe_name(assessment_id, "assessment")
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / safe_filename
        path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        now = _utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO appsec_artifacts (
                    assessment_id, kind, format, filename, path, sha256, size, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(assessment_id, kind, format) DO UPDATE SET
                    filename=excluded.filename, path=excluded.path, sha256=excluded.sha256,
                    size=excluded.size, created_at=excluded.created_at
                """,
                (assessment_id, safe_kind, safe_format, safe_filename, str(path), digest, len(data), now),
            )
        return {
            "assessment_id": assessment_id, "kind": safe_kind, "format": safe_format,
            "filename": safe_filename, "path": str(path), "sha256": digest,
            "size": len(data), "created_at": now,
        }

    def load_appsec_artifacts(self, assessment_id: str) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM appsec_artifacts WHERE assessment_id = ? ORDER BY kind, format",
                (assessment_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def load_appsec_artifact(self, assessment_id: str, kind: str) -> Optional[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM appsec_artifacts WHERE assessment_id = ? AND kind = ? ORDER BY id DESC LIMIT 1",
                (assessment_id, self._safe_name(kind, "artifact")),
            ).fetchone()
        return dict(row) if row else None

    @staticmethod
    def _appsec_assessment_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "assessment_id": row["assessment_id"], "name": row["name"],
            "repository": row["repository"], "ref": row["ref"],
            "commit_sha": row["commit_sha"], "status": row["status"],
            "phase": row["phase"], "progress": row["progress"],
            "job_id": row["job_id"], "coverage": _json_load(row["coverage_json"], {}),
            "summary": _json_load(row["summary_json"], {}), "error": row["error"],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
        }

    @staticmethod
    def _appsec_finding_from_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["cve_ids"] = _json_load(item.pop("cve_ids_json"), [])
        item["cwe_ids"] = _json_load(item.pop("cwe_ids_json"), [])
        item["references"] = _json_load(item.pop("references_json"), [])
        return item
