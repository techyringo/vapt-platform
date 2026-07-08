"""
VAPT Multi-Agent System — Report Generator Agent

Professional VAPT report generation:
  - Executive Summary (for management)
  - Technical Details (for developers)
  - CVSS v3.1 scoring
  - Proof of Concept steps
  - Remediation guidance
  - Output formats: HTML, PDF, Markdown, JSON
"""

import asyncio
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from loguru import logger

from core.models import (
    AgentTask, AgentType, Finding, Severity, ScanResult, ScanPhase,
)
from core.display import display_host, display_port, display_target, display_url, redact_display_text
from core.quality import assess_finding_quality
from core.scope import ScopeManager
from core.config import AppConfig
from agents.base import BaseAgent


# Severity sort order (critical first)
SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFORMATIONAL: 4}

# CVSS score ranges for severity
CVSS_RANGES = {
    Severity.CRITICAL: (9.0, 10.0),
    Severity.HIGH: (7.0, 8.9),
    Severity.MEDIUM: (4.0, 6.9),
    Severity.LOW: (0.1, 3.9),
    Severity.INFORMATIONAL: (0.0, 0.0),
}

SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#28a745",
    "informational": "#17a2b8",
}


class ReportAgent(BaseAgent):
    """Generates professional VAPT reports in multiple formats.

    The executive summary and per-finding remediation are written by the LLM
    (when a provider is available) so the prose is tailored to the actual
    findings rather than boilerplate. If no LLM is configured, a deterministic
    template-based fallback is used so reports still render.
    """

    def __init__(self, scope: ScopeManager, config: AppConfig) -> None:
        super().__init__(AgentType.REPORTER, scope, config)
        self._llm_client = None
        self._llm_available: Optional[bool] = None

    def _get_llm(self):
        """Lazily build the LLM client; cache availability so we don't keep
        re-checking env vars on every finding."""
        if self._llm_available is False:
            return None
        if self._llm_client is None:
            try:
                from tools.llm_client import LLMClient
                self._llm_client = LLMClient(self.config)
                self._llm_available = bool(self._llm_client.get_available_providers())
            except Exception:
                self._llm_client = None
                self._llm_available = False
        return self._llm_client if self._llm_available else None

    async def execute(self, task: AgentTask) -> list[Finding]:
        logger.info("[REPORTER] Generating VAPT report")
        self.clear_findings()

        scan_result: Optional[ScanResult] = task.parameters.get("scan_result")
        if not scan_result:
            logger.error("[REPORTER] No scan result provided for report generation")
            return []

        # ── Quarantine weak-evidence findings out of the report ──
        # They remain persisted (for audit/replay) but must not pollute the
        # customer-facing report. Uses the same deterministic scorer as ingest.
        self._exclude_quarantined(scan_result)

        # ── LLM-driven remediation for findings missing it ──
        await self._llm_fill_remediations(scan_result)

        output_dir = Path(self.config.reporting.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        base_name = f"{self._safe_filename_stem(scan_result.scan_name)}_{timestamp}"

        for fmt in self.config.reporting.formats:
            try:
                if fmt == "html":
                    path = await self._generate_html(scan_result, output_dir / f"{base_name}.html")
                elif fmt == "pdf":
                    html_path = await self._generate_html(scan_result, output_dir / f"{base_name}.html")
                    path = await self._convert_html_to_pdf(html_path, output_dir / f"{base_name}.pdf")
                elif fmt == "markdown":
                    path = await self._generate_markdown(scan_result, output_dir / f"{base_name}.md")
                elif fmt == "json":
                    path = await self._generate_json(scan_result, output_dir / f"{base_name}.json")
                else:
                    logger.warning("[REPORTER] Unknown format: {fmt}", fmt=fmt)
                    continue
                logger.info("[REPORTER] Generated {fmt} report: {path}", fmt=fmt, path=path)
            except Exception as exc:
                logger.error("[REPORTER] Failed to generate {fmt}: {err}", fmt=fmt, err=exc)

        task.result = {
            "output_dir": str(output_dir),
            "base_name": base_name,
            "formats_generated": self.config.reporting.formats,
            "llm_used": self._llm_available is True,
        }
        return self.get_findings()

    @staticmethod
    def _exclude_quarantined(scan_result: ScanResult) -> None:
        """Drop quarantined (weak-evidence) findings from the report set.

        Findings stay in the datastore; only the generated report is filtered so
        low-quality signals never reach a customer-facing document.
        """
        kept: list[Finding] = []
        dropped = 0
        for finding in scan_result.findings:
            try:
                quality = assess_finding_quality(finding.to_report_dict())
            except Exception:
                quality = {}
            if quality.get("quarantined"):
                dropped += 1
                continue
            kept.append(finding)
        if dropped:
            logger.info(
                "[REPORTER] Excluded {n} quarantined finding(s) from the report "
                "({kept} remain)",
                n=dropped, kept=len(kept),
            )
            scan_result.findings = kept

    async def _llm_fill_remediations(self, scan_result: ScanResult) -> None:
        """Ask the LLM to write a tailored remediation for every finding that
        has an empty or generic remediation string. Findings that already
        carry tool-provided remediation (e.g. from nuclei templates) are left
        untouched. No hardcoding — every remediation is generated from the
        finding's actual title/description/evidence.
        """
        llm = self._get_llm()
        if llm is None:
            return
        for f in scan_result.findings:
            # Skip if remediation already looks substantial
            if f.remediation and len(f.remediation) > 80:
                continue
            try:
                remediation = await self._llm_write_remediation(llm, f)
                if remediation:
                    f.remediation = remediation
            except Exception as exc:
                logger.debug("[REPORTER] LLM remediation failed for '{t}': {err}",
                             t=f.title[:60], err=exc)

    async def _llm_write_remediation(self, llm, finding: Finding) -> str:
        """Generate a single finding's remediation via LLM."""
        raw_target = finding.target.url or finding.target.base_url or finding.target.host
        prompt = (
            "You are a senior security engineer writing remediation guidance for a "
            "vulnerability finding. Be specific, actionable, and concise (3-5 sentences). "
            "Reference the actual technology/issue in the finding. Do NOT invent CVEs.\n\n"
            f"TITLE: {finding.title}\n"
            f"SEVERITY: {finding.severity.value}\n"
            f"DESCRIPTION: {redact_display_text(finding.description, [raw_target])[:800]}\n"
            f"EVIDENCE: {redact_display_text(finding.evidence or '', [raw_target])[:800]}\n"
            f"CVES: {', '.join(finding.cve_ids) if finding.cve_ids else 'none'}\n"
            f"CWES: {', '.join(finding.cwe_ids) if finding.cwe_ids else 'none'}\n\n"
            "Write ONLY the remediation text (no preamble, no JSON, no markdown headers)."
        )
        try:
            response = await llm.complete(prompt=prompt, temperature=0.2, max_tokens=400)
            text = (response.content or "").strip()
            # Strip any accidental markdown fencing
            if text.startswith("```"):
                text = text.strip("`").strip()
            # Record the LLM trace for the finding's evidence chain (Finding ->
            # Tool Output -> Parsed Data -> LLM Reasoning).
            finding.llm_reasoning = {
                "task": "remediation",
                "provider": getattr(response, "provider", ""),
                "model": getattr(response, "model", ""),
                "tokens_prompt": getattr(response, "tokens_prompt", 0),
                "tokens_completion": getattr(response, "tokens_completion", 0),
                "duration_ms": getattr(response, "duration_ms", 0),
                "prompt_summary": f"Remediation guidance for '{finding.title[:80]}'",
                "response_summary": text[:600],
            }
            return text
        except Exception as exc:
            logger.debug("[REPORTER] Remediation LLM call failed: {err}", err=exc)
            return ""

    async def _llm_executive_summary(self, scan_result: ScanResult) -> tuple[str, bool]:
        """Generate the executive summary via LLM.

        Returns ``(prose, was_llm_generated)``. Falls back to a deterministic
        template if the LLM is unavailable or the call fails. The
        ``was_llm_generated`` flag lets the caller show an accurate
        "Generated by AI" badge only when the LLM truly produced the text
        (not when we fell back to the template because ollama wasn't running).
        """
        llm = self._get_llm()
        if llm is None:
            return self._template_executive_summary(scan_result), False

        grouped = scan_result.findings_by_severity
        crit = len(grouped["critical"])
        high = len(grouped["high"])
        med = len(grouped["medium"])
        low = len(grouped["low"])
        info = len(grouped["informational"])

        top_findings = sorted(
            scan_result.findings,
            key=lambda f: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(f.severity.value, 5),
                -(f.cvss_score or 0),
            ),
        )[:15]
        digest = "\n".join(
            f"- [{f.severity.value.upper()}] {f.title} ({self._display_target_label(f)})"
            + (f" — CVE: {', '.join(f.cve_ids)}" if f.cve_ids else "")
            for f in top_findings
        )

        prompt = (
            "You are the lead security assessor writing the executive summary of a VAPT "
            "engagement for a non-technical executive audience. Be clear, prioritised, and "
            "actionable. 2-3 short paragraphs. Do NOT invent findings not listed below.\n\n"
            f"ENGAGEMENT: {scan_result.scan_name}\n"
            f"MODE: {scan_result.mode.value}\n"
            f"TARGETS: {len(scan_result.targets)}\n"
            f"FINDING COUNTS: {crit} critical, {high} high, {med} medium, {low} low, {info} informational\n"
            f"DURATION (s): {scan_result.duration_seconds or 0:.0f}\n\n"
            f"TOP FINDINGS:\n{digest or 'None'}\n\n"
            "Write ONLY the executive summary prose (no JSON, no markdown headers)."
        )
        try:
            response = await llm.complete(prompt=prompt, temperature=0.3, max_tokens=800)
            text = (response.content or "").strip()
            if text.startswith("```"):
                text = text.strip("`").strip()
            if text:
                return text, True
            return self._template_executive_summary(scan_result), False
        except Exception as exc:
            logger.debug("[REPORTER] Executive summary LLM call failed: {err}", err=exc)
            return self._template_executive_summary(scan_result), False

    def _template_executive_summary(self, scan_result: ScanResult) -> str:
        """Deterministic fallback executive summary (no LLM)."""
        grouped = scan_result.findings_by_severity
        crit = len(grouped["critical"])
        high = len(grouped["high"])
        med = len(grouped["medium"])
        total = scan_result.total_findings
        duration = scan_result.duration_seconds or 0
        risk = ("CRITICAL" if crit > 0 else "HIGH" if high > 0
                else "MEDIUM" if med > 0 else "LOW")
        return (
            f"A comprehensive security assessment was conducted against "
            f"{len(scan_result.targets)} target(s) using the {scan_result.mode.value.upper()} "
            f"methodology. The assessment identified {total} findings ({crit} critical, "
            f"{high} high, {med} medium) over {duration/60:.1f} minutes. "
            f"Overall risk rating: {risk}."
        )

    async def _generate_html(self, scan_result: ScanResult, output_path: Path) -> str:
        """Generate a professional HTML report."""
        grouped = scan_result.findings_by_severity

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VAPT Report — {scan_result.scan_name}</title>
<style>
  :root {{ --critical: {SEVERITY_COLORS['critical']}; --high: {SEVERITY_COLORS['high']}; --medium: {SEVERITY_COLORS['medium']}; --low: {SEVERITY_COLORS['low']}; --info: {SEVERITY_COLORS['informational']}; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #1a1a2e; line-height: 1.6; background: #f8f9fa; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 20px; }}
  .header {{ background: linear-gradient(135deg, #0f0c29, #302b63, #24243e); color: white; padding: 60px 40px; border-radius: 16px; margin-bottom: 40px; }}
  .header h1 {{ font-size: 2.5em; margin-bottom: 10px; letter-spacing: -0.5px; }}
  .header .meta {{ opacity: 0.8; font-size: 0.95em; }}
  .header .meta span {{ margin-right: 20px; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 40px; }}
  .stat-card {{ padding: 24px; border-radius: 12px; text-align: center; color: white; }}
  .stat-card h3 {{ font-size: 2.5em; font-weight: 700; }}
  .stat-card p {{ font-size: 0.9em; opacity: 0.9; margin-top: 4px; }}
  .stat-critical {{ background: var(--critical); }}
  .stat-high {{ background: var(--high); }}
  .stat-medium {{ background: var(--medium); color: #333; }}
  .stat-low {{ background: var(--low); }}
  .stat-info {{ background: var(--info); }}
  .section {{ background: white; border-radius: 12px; padding: 32px; margin-bottom: 24px; box-shadow: 0 2px 12px rgba(0,0,0,0.06); }}
  .section h2 {{ font-size: 1.5em; margin-bottom: 20px; padding-bottom: 12px; border-bottom: 2px solid #e9ecef; color: #0f0c29; }}
  .exec-summary {{ background: linear-gradient(135deg, #667eea22, #764ba222); border-left: 4px solid #667eea; padding: 24px; border-radius: 0 12px 12px 0; margin-bottom: 24px; }}
  .exec-summary h3 {{ color: #667eea; margin-bottom: 12px; }}
  .finding {{ border: 1px solid #e9ecef; border-radius: 12px; margin-bottom: 20px; overflow: hidden; }}
  .finding-header {{ padding: 16px 20px; color: white; display: flex; justify-content: space-between; align-items: center; }}
  .finding-header h3 {{ font-size: 1.1em; }}
  .finding-header .badge {{ padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: 600; background: rgba(255,255,255,0.25); }}
  .finding-body {{ padding: 20px; }}
  .finding-body p {{ margin-bottom: 12px; }}
  .finding-body label {{ font-weight: 600; color: #495057; }}
  .evidence-box {{ background: #1e1e2e; color: #cdd6f4; padding: 16px; border-radius: 8px; font-family: 'Fira Code', 'Consolas', monospace; font-size: 0.85em; overflow-x: auto; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; margin: 12px 0; }}
  .poc-steps {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 16px; border-radius: 0 8px 8px 0; margin: 12px 0; }}
  .poc-steps h4 {{ color: #856404; margin-bottom: 8px; }}
  .poc-steps ol {{ padding-left: 20px; }}
  .poc-steps li {{ margin-bottom: 6px; }}
  .remediation {{ background: #d4edda; border-left: 4px solid #28a745; padding: 16px; border-radius: 0 8px 8px 0; margin: 12px 0; }}
  .remediation h4 {{ color: #155724; margin-bottom: 8px; }}
  .tags {{ display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }}
  .tag {{ background: #e9ecef; padding: 2px 10px; border-radius: 12px; font-size: 0.75em; color: #495057; }}
  .scope-table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
  .scope-table th, .scope-table td {{ padding: 10px 16px; text-align: left; border-bottom: 1px solid #dee2e6; }}
  .scope-table th {{ background: #f8f9fa; font-weight: 600; color: #495057; }}
  .finding-index {{ width: 100%; border-collapse: collapse; font-size: 0.92em; }}
  .finding-index th, .finding-index td {{ padding: 12px 14px; border-bottom: 1px solid #e9ecef; text-align: left; vertical-align: top; }}
  .finding-index th {{ background: #f1f3f5; color: #343a40; font-size: 0.82em; text-transform: uppercase; letter-spacing: 0.04em; }}
  .risk-pill {{ display:inline-block; min-width: 74px; border-radius: 999px; padding: 3px 10px; color: white; text-align: center; font-size: 0.75em; font-weight: 700; }}
  .report-note {{ background: #f8f9fa; border-left: 4px solid #17a2b8; padding: 14px 16px; margin-top: 16px; color: #495057; border-radius: 0 8px 8px 0; }}
  .footer {{ text-align: center; padding: 40px 0; color: #6c757d; font-size: 0.85em; }}
  @media print {{ .container {{ padding: 20px; }} .section {{ box-shadow: none; border: 1px solid #dee2e6; }} .stats-grid {{ grid-template-columns: repeat(5, 1fr); }} }}
</style>
</head>
<body>
<div class="container">

<div class="header">
  <h1>VAPT Security Assessment Report</h1>
  <div class="meta">
    <span>Client: {scan_result.scan_name}</span>
    <span>Date: {datetime.utcnow().strftime('%B %d, %Y')}</span>
    <span>Mode: {scan_result.mode.value.upper()}</span>
    <span>Targets: {len(scan_result.targets)}</span>
  </div>
</div>

<div class="stats-grid">
  <div class="stat-card stat-critical"><h3>{len(grouped['critical'])}</h3><p>Critical</p></div>
  <div class="stat-card stat-high"><h3>{len(grouped['high'])}</h3><p>High</p></div>
  <div class="stat-card stat-medium"><h3>{len(grouped['medium'])}</h3><p>Medium</p></div>
  <div class="stat-card stat-low"><h3>{len(grouped['low'])}</h3><p>Low</p></div>
  <div class="stat-card stat-info"><h3>{len(grouped['informational'])}</h3><p>Informational</p></div>
</div>
"""

        # Executive Summary (LLM-written when available, template fallback otherwise)
        if self.config.reporting.executive_summary:
            html += await self._build_executive_summary(scan_result)

        # Scope section
        html += """<div class="section"><h2>2. Assessment Scope</h2>
<table class="scope-table"><tr><th>Target</th><th>Port</th><th>Protocol</th></tr>"""
        for t in scan_result.targets:
            raw = t.url or t.base_url or t.host
            html += f"<tr><td>{self._escape_html(display_target(raw))}</td><td>{display_port(raw, t.port)}</td><td>{self._escape_html(t.protocol)}</td></tr>"
        html += "</table></div>"

        # Findings by severity
        all_findings = sorted(scan_result.findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.title))
        html += self._build_finding_index(all_findings)
        html += '<div class="section"><h2>4. Technical Findings</h2>'
        if not all_findings:
            html += '<p>No findings were recorded for this scan.</p>'
        for idx, finding in enumerate(all_findings, 1):
            html += self._build_finding_html(finding, idx)
        html += "</div>"

        # Footer
        html += f"""
<div class="footer">
  <p>Generated by VAPT Multi-Agent System on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
  <p>This report is confidential and intended for authorized recipients only.</p>
</div>
</div>
</body></html>"""

        output_path.write_text(html, encoding="utf-8")
        return str(output_path)

    def _build_finding_index(self, findings: list[Finding]) -> str:
        """Build a concise audit index before the technical finding details."""
        html = """<div class="section"><h2>3. Finding Index</h2>"""
        if not findings:
            return html + "<p>No findings recorded.</p></div>"
        html += """<table class="finding-index">
<tr><th>#</th><th>Severity</th><th>Finding</th><th>Target</th><th>Evidence</th><th>Status</th><th>CVE / CWE</th></tr>"""
        for idx, finding in enumerate(findings, 1):
            sev = finding.severity.value
            refs = ", ".join(finding.cve_ids[:4] or finding.cwe_ids[:4] or ["-"])
            quality = finding.to_report_dict()
            evidence_label = f"{quality.get('evidence_grade', 'E')} ({quality.get('evidence_score', 0)})"
            html += (
                "<tr>"
                f"<td>{idx}</td>"
                f"<td><span class='risk-pill' style='background:{SEVERITY_COLORS.get(sev, '#6c757d')}'>{sev.upper()}</span></td>"
                f"<td>{self._escape_html(finding.title)}</td>"
                f"<td>{self._escape_html(self._display_target_label(finding))}</td>"
                f"<td>{self._escape_html(evidence_label)}</td>"
                f"<td>{self._escape_html(finding.status)}</td>"
                f"<td>{self._escape_html(refs)}</td>"
                "</tr>"
            )
        html += "</table><div class='report-note'>CVEs marked through version intelligence require package/backport validation before final risk acceptance.</div></div>"
        return html

    async def _build_executive_summary(self, scan_result: ScanResult) -> str:
        """Build the executive summary section (LLM-written prose wrapped in HTML)."""
        prose, was_llm = await self._llm_executive_summary(scan_result)
        safe = self._escape_html(prose)
        grouped = scan_result.findings_by_severity
        crit = len(grouped["critical"])
        high = len(grouped["high"])

        risk_level = "CRITICAL" if crit > 0 else "HIGH" if high > 0 else "MEDIUM" if len(grouped["medium"]) > 0 else "LOW"
        llm_badge = '<div style="font-size:0.75em;opacity:0.7;margin-top:8px">Generated by AI</div>' if was_llm else ""

        return f"""
<div class="section">
<h2>1. Executive Summary</h2>
<div class="exec-summary">
  <h3>Risk Assessment: {risk_level}</h3>
  <p>{safe}</p>
  {llm_badge}
</div>
</div>"""

    @staticmethod
    def _display_target_label(finding: Finding) -> str:
        raw = finding.target.url or finding.target.base_url or finding.target.host
        host = display_host(raw)
        port = display_port(raw, finding.target.port)
        return host if host == display_target(raw) else f"{host}:{port}"

    def _build_finding_html(self, finding: Finding, idx: int) -> str:
        """Build HTML for a single finding."""
        sev_color = SEVERITY_COLORS.get(finding.severity.value, "#6c757d")
        cvss_str = f"CVSS {finding.cvss_score:.1f}" if finding.cvss_score else finding.severity.value.upper()
        title = self._escape_html(finding.title)
        raw_target = finding.target.url or finding.target.base_url or finding.target.host
        description = self._escape_html(redact_display_text(finding.description, [raw_target]))
        confidence = self._escape_html(finding.confidence)
        status = self._escape_html(finding.status)
        quality = finding.to_report_dict()
        evidence_label = self._escape_html(f"{quality.get('evidence_grade', 'E')} ({quality.get('evidence_score', 0)}/100)")
        validation_notes = quality.get("validation_notes") or []

        html = f"""
<div class="finding">
  <div class="finding-header" style="background:{sev_color}">
    <h3>{idx}. {title}</h3>
    <span class="badge">{cvss_str}</span>
  </div>
  <div class="finding-body">
    <p>{description}</p>
    <p><label>Target:</label> {self._escape_html(self._display_target_label(finding))}</p>
    <p><label>Confidence:</label> {confidence} | <label>Status:</label> {status} | <label>Evidence:</label> {evidence_label}</p>"""

        if validation_notes:
            notes = "".join(f"<li>{self._escape_html(str(note))}</li>" for note in validation_notes[:4])
            html += f"\n    <div class='report-note'><strong>Validation notes:</strong><ul>{notes}</ul></div>"

        if finding.evidence:
            evidence = redact_display_text(finding.evidence[:2000], [raw_target])
            html += f"\n    <label>Evidence:</label>\n    <div class='evidence-box'>{self._escape_html(evidence)}</div>"

        if self.config.reporting.include_poc and finding.poc_steps:
            html += f"\n    <div class='poc-steps'><h4>Proof of Concept</h4><ol>"
            for step in finding.poc_steps:
                html += f"<li>{self._escape_html(redact_display_text(step, [raw_target]))}</li>"
            html += "</ol></div>"

        if self.config.reporting.include_remediation and finding.remediation:
            remediation = redact_display_text(finding.remediation, [raw_target])
            html += f"\n    <div class='remediation'><h4>Remediation</h4><p>{self._escape_html(remediation)}</p></div>"

        if finding.cve_ids:
            html += f"\n    <p><label>CVE IDs:</label> {self._escape_html(', '.join(finding.cve_ids))}</p>"
        if finding.cwe_ids:
            html += f"\n    <p><label>CWE IDs:</label> {self._escape_html(', '.join(finding.cwe_ids))}</p>"
        if finding.references:
            html += f"\n    <p><label>References:</label></p><ul>"
            for ref in finding.references[:5]:
                safe_ref = self._escape_html(redact_display_text(ref, [raw_target]))
                html += f"<li><a href='{safe_ref}' target='_blank' rel='noopener noreferrer'>{safe_ref}</a></li>"
            html += "</ul>"

        if finding.tags:
            html += f"\n    <div class='tags'>"
            for tag in finding.tags[:8]:
                html += f"<span class='tag'>{self._escape_html(tag)}</span>"
            html += "</div>"

        html += "\n  </div>\n</div>"
        return html

    async def _generate_markdown(self, scan_result: ScanResult, output_path: Path) -> str:
        """Generate a Markdown report."""
        grouped = scan_result.findings_by_severity
        all_findings = sorted(scan_result.findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.title))

        md = f"""# VAPT Security Assessment Report

**Client:** {scan_result.scan_name}
**Date:** {datetime.utcnow().strftime('%B %d, %Y')}
**Mode:** {scan_result.mode.value.upper()}
**Targets:** {len(scan_result.targets)}

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | {len(grouped['critical'])} |
| High | {len(grouped['high'])} |
| Medium | {len(grouped['medium'])} |
| Low | {len(grouped['low'])} |
| Informational | {len(grouped['informational'])} |
| **Total** | **{scan_result.total_findings}** |

---

## Scope

| Target | Port | Protocol |
|--------|------|----------|
"""
        for t in scan_result.targets:
            raw = t.url or t.base_url or t.host
            md += f"| {display_target(raw)} | {display_port(raw, t.port)} | {t.protocol} |\n"

        md += "\n---\n\n## Findings\n\n"
        for idx, f in enumerate(all_findings, 1):
            md += f"### {idx}. [{f.severity.value.upper()}] {f.title}\n\n"
            md += f"**Target:** {self._display_target_label(f)}\n"
            quality = f.to_report_dict()
            md += (
                f"**Confidence:** {f.confidence} | **Status:** {f.status} | "
                f"**Evidence:** {quality.get('evidence_grade', 'E')} ({quality.get('evidence_score', 0)}/100)\n\n"
            )
            if quality.get("validation_notes"):
                md += "**Validation Notes:**\n"
                for note in quality.get("validation_notes", [])[:4]:
                    md += f"- {note}\n"
                md += "\n"
            if f.cvss_score:
                md += f"**CVSS Score:** {f.cvss_score:.1f}\n\n"
            raw_target = f.target.url or f.target.base_url or f.target.host
            md += f"{redact_display_text(f.description, [raw_target])}\n\n"
            if f.evidence:
                md += f"**Evidence:**\n```\n{redact_display_text(f.evidence[:1000], [raw_target])}\n```\n\n"
            if f.poc_steps:
                md += "**Proof of Concept:**\n"
                for step in f.poc_steps:
                    md += f"{redact_display_text(step, [raw_target])}\n"
                md += "\n"
            if f.remediation:
                md += f"**Remediation:** {redact_display_text(f.remediation, [raw_target])}\n\n"
            if f.cve_ids:
                md += f"**CVE IDs:** {', '.join(f.cve_ids)}\n\n"
            if f.cwe_ids:
                md += f"**CWE IDs:** {', '.join(f.cwe_ids)}\n\n"
            if f.references:
                md += f"**References:** {', '.join(redact_display_text(ref, [raw_target]) for ref in f.references[:5])}\n\n"
            md += "---\n\n"

        md += f"\n*Generated by VAPT Multi-Agent System — {datetime.utcnow().isoformat()}*\n"

        output_path.write_text(md, encoding="utf-8")
        return str(output_path)

    async def _generate_json(self, scan_result: ScanResult, output_path: Path) -> str:
        """Generate a JSON report."""
        report = {
            "report_metadata": {
                "title": f"VAPT Report — {scan_result.scan_name}",
                "generated_at": datetime.utcnow().isoformat(),
                "mode": scan_result.mode.value,
                "total_targets": len(scan_result.targets),
                "total_findings": scan_result.total_findings,
                "duration_seconds": scan_result.duration_seconds,
            },
            "targets": [
                {
                    "host": display_target(t.url or t.base_url or t.host),
                    "port": display_port(t.url or t.base_url or t.host, t.port),
                    "protocol": t.protocol,
                    "url": display_url(t.url or t.base_url or t.host),
                }
                for t in scan_result.targets
            ],
            "summary": {
                "critical": len(scan_result.findings_by_severity["critical"]),
                "high": len(scan_result.findings_by_severity["high"]),
                "medium": len(scan_result.findings_by_severity["medium"]),
                "low": len(scan_result.findings_by_severity["low"]),
                "informational": len(scan_result.findings_by_severity["informational"]),
            },
            "findings": [f.to_report_dict() for f in scan_result.findings],
        }

        output_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        return str(output_path)

    async def _convert_html_to_pdf(self, html_path: str, pdf_path: Path) -> str:
        """Convert HTML report to PDF."""
        try:
            from weasyprint import HTML
            HTML(filename=html_path).write_pdf(str(pdf_path))
            return str(pdf_path)
        except ImportError:
            logger.warning("[REPORTER] weasyprint not installed — PDF generation skipped")
            return html_path
        except Exception as exc:
            logger.error("[REPORTER] PDF conversion failed: {err}", err=exc)
            return html_path

    @staticmethod
    def _escape_html(text: str) -> str:
        """Escape HTML special characters."""
        text = "" if text is None else str(text)
        return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))

    @staticmethod
    def _safe_filename_stem(value: str) -> str:
        """Return a filesystem-safe report basename stem.

        Scan names can contain dates such as ``7/4/2026``. Without sanitising,
        those slashes become path separators and report generation fails.
        """
        stem = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "scan").strip("._-")
        return stem[:120] or "scan"
