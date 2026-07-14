"""
VAPT Multi-Agent System — Core Data Models

All data structures used throughout the system, defined with Pydantic v2
for validation, serialization, and type safety.
"""

from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime
from typing import Optional, Any
from uuid import uuid4

from core.display import display_host, display_port, display_target, display_url, redact_display_text
from core.quality import assess_finding_quality


# ────────────────────────────────────────────────────────────────────
# Enumerations
# ────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    """Vulnerability severity levels aligned with CVSS v3.1 rating taxonomy."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ScanMode(str, Enum):
    """Supported scanning modes, each selecting a different agent pipeline."""

    VA_ONLY = "va_only"
    FULL_VAPT = "full_vapt"
    WEB_APP = "web_app"
    API = "api"
    CLOUD = "cloud"
    IOT_CCTV = "iot_cctv"
    CUSTOM = "custom"


class ScanPhase(str, Enum):
    """Ordered phases of the VAPT pipeline.

    The scan progresses through these phases under the control of the
    state machine in ``core.state.ScanStateMachine``.
    """

    INIT = "init"
    RECON = "recon"
    ENUMERATION = "enumeration"
    VULN_SCANNING = "vuln_scanning"
    FUZZING = "fuzzing"
    EXPLOITATION = "exploitation"
    INTELLIGENCE = "intelligence"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentType(str, Enum):
    """Types of specialised agents in the VAPT ecosystem."""

    RECON = "recon"
    ENUM = "enum"
    VULN_SCANNER = "vuln_scanner"
    FUZZER = "fuzzer"
    EXPLOIT = "exploit"
    INTEL = "intel"
    CLOUD = "cloud"
    IOT_CCTV = "iot_cctv"
    REPORTER = "reporter"
    ORCHESTRATOR = "orchestrator"


# ────────────────────────────────────────────────────────────────────
# Domain Models
# ────────────────────────────────────────────────────────────────────

class Target(BaseModel):
    """Represents a single target (host / service) under assessment.

    Attributes:
        id:          Unique identifier for this target.
        host:        Hostname, IP address, or domain name.
        port:        TCP/UDP port number (defaults to 443).
        protocol:    Application-layer protocol (``http`` or ``https``).
        url:         Fully-qualified URL if available.
        scope_tags:  Free-form tags for scope categorisation.
        metadata:    Arbitrary key-value metadata attached to the target.
    """

    id: str = Field(default_factory=lambda: uuid4().hex, description="Unique target identifier")
    host: str = Field(..., min_length=1, description="Hostname, IP, or domain")
    port: int = Field(default=443, ge=1, le=65535, description="TCP/UDP port")
    protocol: str = Field(default="https", pattern=r"^(http|https)$", description="Protocol scheme")
    url: Optional[str] = Field(default=None, description="Fully-qualified URL")
    scope_tags: list[str] = Field(default_factory=list, description="Scope categorisation tags")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary metadata")

    @property
    def netloc(self) -> str:
        """Return ``host:port`` suitable for network operations."""
        return f"{self.host}:{self.port}"

    @property
    def base_url(self) -> str:
        """Return the base URL derived from protocol, host, and port."""
        if self.url:
            return self.url
        return f"{self.protocol}://{self.host}:{self.port}"


class Finding(BaseModel):
    """A single security finding produced by any agent.

    Carries full evidence, classification, and remediation guidance so it
    can be rendered directly into a report.

    Attributes:
        id:               Unique identifier.
        title:            Short human-readable title.
        description:      Detailed description of the vulnerability.
        severity:         Severity rating.
        cvss_score:       CVSS v3.1 base score (0.0 – 10.0).
        cvss_vector:      Full CVSS v3.1 vector string.
        agent_source:     Which agent produced this finding.
        target:           The target on which the finding was observed.
        evidence:         Primary evidence description.
        request_proof:    HTTP request proof-of-concept.
        response_proof:   HTTP response proof-of-concept.
        poc_steps:        Ordered list of steps to reproduce.
        remediation:      Recommended fix.
        references:       External reference URLs.
        cve_ids:          Associated CVE identifiers.
        cwe_ids:          Associated CWE identifiers.
        tags:             Free-form classification tags.
        confidence:       Finding confidence level.
        status:           Validation status of the finding.
        created_at:       Timestamp when the finding was recorded.
        raw_tool_output:  Unparsed raw output from the tool that found it.
    """

    id: str = Field(default_factory=lambda: uuid4().hex, description="Unique finding identifier")
    title: str = Field(..., min_length=1, description="Finding title")
    description: str = Field(..., min_length=1, description="Detailed description")
    severity: Severity = Field(..., description="Severity rating")
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0, description="CVSS v3.1 base score")
    cvss_vector: Optional[str] = Field(default=None, description="CVSS v3.1 vector string")
    agent_source: AgentType = Field(..., description="Agent that produced this finding")
    target: Target = Field(..., description="Target where the finding was observed")
    evidence: str = Field(default="", description="Primary evidence text")
    request_proof: Optional[str] = Field(default=None, description="HTTP request PoC")
    response_proof: Optional[str] = Field(default=None, description="HTTP response PoC")
    poc_steps: list[str] = Field(default_factory=list, description="Steps to reproduce")
    remediation: str = Field(default="", description="Recommended remediation")
    references: list[str] = Field(default_factory=list, description="External reference URLs")
    cve_ids: list[str] = Field(default_factory=list, description="Associated CVE IDs")
    cwe_ids: list[str] = Field(default_factory=list, description="Associated CWE IDs")
    tags: list[str] = Field(default_factory=list, description="Classification tags")
    confidence: str = Field(
        default="medium",
        pattern=r"^(high|medium|low)$",
        description="Confidence level",
    )
    status: str = Field(
        default="suspected",
        pattern=r"^(confirmed|suspected|false_positive)$",
        description="Validation status",
    )
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    raw_tool_output: Optional[str] = Field(default=None, description="Raw tool output")
    llm_reasoning: dict[str, Any] = Field(
        default_factory=dict,
        description="LLM analysis trace for the evidence chain: provider, model, "
        "token counts, and prompt/response summaries. Empty when no LLM touched "
        "this finding.",
    )

    def to_report_dict(self) -> dict[str, Any]:
        """Return a clean, serialisable dictionary optimised for report rendering.

        Strips internal identifiers and raw tool output, and converts enum
        values to their string representations.

        Returns:
            A flat dictionary suitable for JSON serialisation and template
            rendering in reports.
        """
        raw_target = self.target.url or self.target.base_url or self.target.host
        target_host = display_host(raw_target or self.target.host)
        payload = {
            "title": self.title,
            "description": redact_display_text(self.description, [raw_target]),
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "target_host": target_host,
            "target_port": display_port(raw_target, self.target.port),
            "target_url": display_url(raw_target),
            "target_display": display_target(raw_target),
            "evidence": redact_display_text(self.evidence, [raw_target]),
            "request_proof": redact_display_text(self.request_proof, [raw_target]),
            "response_proof": redact_display_text(self.response_proof, [raw_target]),
            "poc_steps": [redact_display_text(step, [raw_target]) for step in self.poc_steps],
            "remediation": redact_display_text(self.remediation, [raw_target]),
            "references": [redact_display_text(ref, [raw_target]) for ref in self.references],
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "tags": self.tags,
            "confidence": self.confidence,
            "status": self.status,
            "agent_source": self.agent_source.value,
            "llm_reasoning": self.llm_reasoning,
            "created_at": self.created_at.isoformat(),
        }
        payload.update(assess_finding_quality(payload))
        return payload


class AgentTask(BaseModel):
    """A unit of work dispatched to a specific agent.

    The orchestrator creates one ``AgentTask`` per tool invocation and
    tracks its lifecycle through the status field.

    Attributes:
        id:            Unique task identifier.
        agent_type:    Which agent should execute this task.
        phase:         Pipeline phase this task belongs to.
        target:        Target the task operates on.
        tool_name:     Name of the security tool to invoke.
        command:       Full command string to execute.
        parameters:    Structured parameters for the tool.
        priority:      Execution priority (lower = higher priority).
        status:        Current lifecycle status.
        result:        Structured result produced by the agent.
        error:         Error message if the task failed.
        started_at:    Timestamp when execution began.
        completed_at:  Timestamp when execution finished.
    """

    id: str = Field(default_factory=lambda: uuid4().hex, description="Unique task identifier")
    agent_type: AgentType = Field(..., description="Agent that executes this task")
    phase: ScanPhase = Field(..., description="Pipeline phase")
    target: Target = Field(..., description="Target for this task")
    tool_name: str = Field(..., min_length=1, description="Security tool name")
    command: str = Field(..., min_length=1, description="Command to execute")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Tool parameters")
    priority: int = Field(default=5, ge=0, le=10, description="Execution priority")
    status: str = Field(
        default="pending",
        pattern=r"^(pending|running|completed|failed)$",
        description="Task lifecycle status",
    )
    result: Optional[Any] = Field(default=None, description="Task result data")
    error: Optional[str] = Field(default=None, description="Error message on failure")
    started_at: Optional[datetime] = Field(default=None, description="Start timestamp")
    completed_at: Optional[datetime] = Field(default=None, description="Completion timestamp")

    def mark_running(self) -> None:
        """Transition this task to running status and record start time."""
        self.status = "running"
        self.started_at = datetime.utcnow()

    def mark_completed(self, result: Any = None) -> None:
        """Transition this task to completed status and record completion time.

        Args:
            result: Optional result data to attach to the task.
        """
        self.status = "completed"
        self.result = result
        self.completed_at = datetime.utcnow()

    def mark_failed(self, error: str) -> None:
        """Transition this task to failed status with an error message.

        Args:
            error: Human-readable error description.
        """
        self.status = "failed"
        self.error = error
        self.completed_at = datetime.utcnow()

    @property
    def duration_seconds(self) -> Optional[float]:
        """Return the wall-clock duration of this task in seconds, or ``None``
        if the task has not been started or completed."""
        if self.started_at and self.completed_at:
            delta = self.completed_at - self.started_at
            return delta.total_seconds()
        return None


class ScanResult(BaseModel):
    """Top-level result container for an entire VAPT scan engagement.

    Aggregates all targets, findings, and agent tasks produced during the
    scan lifecycle.

    Attributes:
        id:              Unique scan identifier.
        scan_name:       Human-readable scan name.
        mode:            Scan mode that was selected.
        targets:         All targets included in the scan.
        findings:        All findings produced across all agents.
        agent_tasks:     All agent tasks that were dispatched.
        current_phase:   The phase the scan is currently in.
        start_time:      When the scan was initiated.
        end_time:        When the scan finished (``None`` if still running).
        status:          Overall scan status.
        metadata:        Arbitrary scan metadata.
    """

    id: str = Field(default_factory=lambda: uuid4().hex, description="Unique scan identifier")
    scan_name: str = Field(default="Untitled Scan", description="Human-readable scan name")
    mode: ScanMode = Field(default=ScanMode.FULL_VAPT, description="Selected scan mode")
    targets: list[Target] = Field(default_factory=list, description="Scan targets")
    findings: list[Finding] = Field(default_factory=list, description="Discovered findings")
    agent_tasks: list[AgentTask] = Field(default_factory=list, description="Dispatched agent tasks")
    current_phase: ScanPhase = Field(default=ScanPhase.INIT, description="Current pipeline phase")
    start_time: datetime = Field(default_factory=datetime.utcnow, description="Scan start time")
    end_time: Optional[datetime] = Field(default=None, description="Scan end time")
    status: str = Field(
        default="pending",
        pattern=r"^(pending|running|completed|failed|cancelled)$",
        description="Overall scan status",
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary scan metadata")

    @property
    def duration_seconds(self) -> Optional[float]:
        """Return the wall-clock duration of this scan in seconds, or ``None``
        if the scan has not finished."""
        end = self.end_time or datetime.utcnow()
        delta = end - self.start_time
        return delta.total_seconds()

    @property
    def findings_by_severity(self) -> dict[str, list[Finding]]:
        """Group findings by their severity level.

        Returns:
            A dictionary mapping severity names (str) to lists of findings.
        """
        grouped: dict[str, list[Finding]] = {
            s.value: [] for s in Severity
        }
        for finding in self.findings:
            grouped[finding.severity.value].append(finding)
        return grouped

    @property
    def critical_and_high_count(self) -> int:
        """Return the combined count of critical and high findings."""
        return sum(
            1 for f in self.findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        )

    @property
    def total_findings(self) -> int:
        """Return the total number of findings."""
        return len(self.findings)

    def add_finding(self, finding: Finding) -> None:
        """Append a finding to this scan result.

        Args:
            finding: The ``Finding`` to add.
        """
        new_key = (finding.title.lower().strip(), finding.target.host.lower().strip())
        for existing in self.findings:
            existing_key = (existing.title.lower().strip(), existing.target.host.lower().strip())
            if existing_key == new_key:
                return
        self.findings.append(finding)

    def add_task(self, task: AgentTask) -> None:
        """Append an agent task to this scan result.

        Args:
            task: The ``AgentTask`` to add.
        """
        self.agent_tasks.append(task)

    def add_target(self, target: Target) -> None:
        """Append a target to this scan result.

        Args:
            target: The ``Target`` to add.
        """
        for existing in self.targets:
            if (
                existing.host.lower() == target.host.lower()
                and existing.port == target.port
                and existing.protocol == target.protocol
            ):
                return
        self.targets.append(target)


class ScopeConfig(BaseModel):
    """Defines the authorised scope boundaries for a scan engagement.

    The ``ScopeManager`` (``core.scope``) enforces these rules in real
    time to prevent accidental out-of-scope activity.

    Attributes:
        authorized_domains:   Domains explicitly authorised for testing.
        authorized_ips:       IP addresses / CIDRs authorised for testing.
        out_of_scope:         Domains or IPs that must never be touched.
        max_depth:            Maximum URL path depth to follow.
        max_pages:            Maximum unique pages to visit.
        max_requests_total:   Hard cap on total HTTP requests.
        exclude_paths:        Path prefixes to skip.
        include_paths:        Path prefixes to force-include (overrides excludes).
        rate_limit:           Maximum requests per second.
        auth_token:           Bearer or API token for authenticated testing.
        auth_type:            Authentication mechanism.
        custom_headers:       Extra HTTP headers to send with every request.
        cookies:              Cookies to include in every request.
    """

    authorized_domains: list[str] = Field(default_factory=list, description="Authorised domains")
    authorized_ips: list[str] = Field(default_factory=list, description="Authorised IPs / CIDRs")
    out_of_scope: list[str] = Field(default_factory=list, description="Out-of-scope entries")
    max_depth: int = Field(default=5, ge=1, le=50, description="Max crawl depth")
    max_pages: int = Field(default=500, ge=1, description="Max pages to visit")
    max_requests_total: int = Field(default=50000, ge=1, description="Hard request cap")
    exclude_paths: list[str] = Field(default_factory=list, description="Paths to exclude")
    include_paths: Optional[list[str]] = Field(default=None, description="Paths to force-include")
    rate_limit: int = Field(default=5, ge=1, description="Requests per second")
    auth_token: Optional[str] = Field(default=None, description="Authentication token")
    auth_type: Optional[str] = Field(
        default=None,
        pattern=r"^(bearer|basic|cookie)$",
        description="Authentication type",
    )
    custom_headers: dict[str, str] = Field(default_factory=dict, description="Custom HTTP headers")
    cookies: dict[str, str] = Field(default_factory=dict, description="Cookies")
