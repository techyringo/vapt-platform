"""
VAPT Multi-Agent System — LLM-driven, NVD-verified CVE/CWE Resolver
===================================================================

This module implements the platform's core anti-hallucination contract for
vulnerability classification:

    1. The LLM **proposes** candidate CVE / CWE identifiers based ONLY on the
       concrete evidence a scanner produced (HTTP headers, tool output, the
       detected tech stack). It is explicitly instructed not to guess.
    2. Every proposed CVE is then **verified** against the NVD 2.0 API.
       - If NVD confirms the CVE exists and is PUBLISHED, the official CVSS
         score, vector, description and references are attached.
       - If NVD says the CVE is REJECTED or NOT_FOUND, the proposal is
         DISCARDED — it never reaches the final finding.
       - If NVD is unreachable, the proposal is kept but tagged
         ``nvd_unverified`` so the report reader knows it wasn't confirmed.
    3. CWE identifiers are validated against the canonical ``CWE-<digits>``
       format. The LLM's reasoning for each CWE is preserved in the finding's
       tags so a human reviewer can audit why it was assigned.

There is NO hardcoded CVE/CWE table anywhere in this flow. Every identifier
is either emitted by the tool that found the issue (e.g. nuclei) or proposed
by the LLM — and in both cases it must survive NVD verification before it is
attached to a Finding.

Usage
-----
    resolver = CVEResolver(llm_client, nvd_service)
    enriched = await resolver.enrich(finding)

``enrich`` mutates the finding in place (attaching verified cve_ids, cwe_ids,
cvss_score, cvss_vector, references) and returns the list of NVD verification
records so the caller can log them.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from loguru import logger

from core.models import Finding, Severity
from services.nvd_service import NVDService, NVDRecord


# Canonical CVE / CWE format matchers
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CWE_RE = re.compile(r"CWE-\d{1,5}", re.IGNORECASE)


@dataclass
class VerificationRecord:
    """Outcome of verifying one proposed identifier against NVD."""
    identifier: str
    kind: str  # "cve" | "cwe"
    source: str  # "tool" | "llm"
    nvd_status: str  # PUBLISHED | REJECTED | NOT_FOUND | UNREACHABLE | N/A
    verified: bool = False
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    nvd_description: str = ""
    nvd_references: list[str] = field(default_factory=list)
    llm_reasoning: str = ""
    dropped: bool = False  # True if we discarded this proposal
    drop_reason: str = ""


class CVEResolver:
    """Resolves CVE/CWE identifiers via LLM proposal + NVD verification."""

    def __init__(self, llm_client: Any, nvd_service: Optional[NVDService] = None) -> None:
        self._llm = llm_client
        self._nvd = nvd_service or NVDService()

    async def enrich(self, finding: Finding) -> list[VerificationRecord]:
        """Enrich a single finding with verified CVE/CWE data.

        Strategy:
          1. Collect CVE/CWE already supplied by the originating tool.
          2. Ask the LLM to PROPOSE additional candidates from the evidence.
          3. Deduplicate.
          4. Verify every CVE against NVD — keep only confirmed ones
             (or keep-but-flag if NVD is unreachable).
          5. Validate CWE format + keep the LLM's reasoning.
          6. Attach official CVSS/vector/description/references from NVD.

        Mutates ``finding`` in place and returns the verification log.
        """
        records: list[VerificationRecord] = []

        # ── Step 1: collect identifiers the tool already attached ──
        tool_cves = self._extract_cves(finding)
        tool_cwes = self._extract_cwes(finding)
        for cve in tool_cves:
            records.append(VerificationRecord(
                identifier=cve, kind="cve", source="tool",
                nvd_status="PENDING",
            ))
        for cwe in tool_cwes:
            records.append(VerificationRecord(
                identifier=cwe, kind="cwe", source="tool",
                nvd_status="N/A",
            ))

        # ── Step 2: ask the LLM to propose additional candidates ──
        # Per-finding CVE guessing creates a large, low-value API fan-out and
        # repeats work again in the intelligence phase. Scanner-emitted CVEs
        # are still verified with NVD. Optional LLM proposals are an explicit
        # operator choice, disabled by default.
        enable_llm = os.environ.get("VAPT_CVE_LLM_PROPOSALS", "false").lower() in {
            "1", "true", "yes", "on",
        }
        llm_proposals = await self._llm_propose(finding) if enable_llm else []
        for prop in llm_proposals:
            identifier = prop.get("identifier", "").upper().strip()
            kind = prop.get("kind", "").lower()
            reasoning = prop.get("reasoning", "")
            confidence = prop.get("confidence", "medium")

            if kind == "cve" and CVE_RE.fullmatch(identifier):
                if not any(r.identifier == identifier for r in records):
                    records.append(VerificationRecord(
                        identifier=identifier, kind="cve", source="llm",
                        nvd_status="PENDING", llm_reasoning=reasoning,
                    ))
            elif kind == "cwe" and CWE_RE.fullmatch(identifier):
                if not any(r.identifier == identifier for r in records):
                    records.append(VerificationRecord(
                        identifier=identifier, kind="cwe", source="llm",
                        nvd_status="N/A", llm_reasoning=reasoning,
                    ))
            else:
                # Malformed proposal — drop it (anti-hallucination guard)
                records.append(VerificationRecord(
                    identifier=identifier or "<empty>", kind=kind, source="llm",
                    nvd_status="N/A", dropped=True,
                    drop_reason="Malformed identifier (does not match CVE/CWE format)",
                    llm_reasoning=reasoning,
                ))

        # ── Step 3: verify CVEs against NVD ──
        cve_records = [r for r in records if r.kind == "cve" and not r.dropped]
        for rec in cve_records:
            await self._verify_cve(rec, finding)

        # ── Step 4: finalise CWE list (keep well-formed ones, attach reasoning) ──
        cwe_records = [r for r in records if r.kind == "cwe" and not r.dropped]

        # ── Step 5: write back to the finding ──
        verified_cves = [r.identifier for r in cve_records if r.verified]
        unverified_cves = [r.identifier for r in cve_records
                           if not r.verified and not r.dropped]
        # Keep verified + unverified-but-not-dropped (report shows the distinction)
        final_cves = verified_cves + unverified_cves
        finding.cve_ids = final_cves

        final_cwes = list({r.identifier for r in cwe_records})
        finding.cwe_ids = final_cwes

        # If NVD gave us an official CVSS, prefer it over any LLM guess
        verified_with_score = [r for r in cve_records if r.verified and r.cvss_score is not None]
        if verified_with_score:
            best = max(verified_with_score, key=lambda r: r.cvss_score or 0)
            finding.cvss_score = best.cvss_score
            finding.cvss_vector = best.cvss_vector
            if best.nvd_description:
                finding.description = (
                    finding.description.rstrip()
                    + f"\n\n[NVD Verified — {best.identifier}]\n{best.nvd_description}"
                )
            if best.nvd_references:
                existing = set(finding.references)
                for ref in best.nvd_references[:5]:
                    if ref not in existing:
                        finding.references.append(ref)
                        existing.add(ref)

        # Tag the finding so the report can distinguish verified vs proposed
        tags_to_add = []
        if verified_cves:
            tags_to_add.append("nvd-verified")
        if unverified_cves:
            tags_to_add.append("cve-unverified")
        if any(r.dropped for r in records):
            tags_to_add.append("had-rejected-proposal")
        for t in tags_to_add:
            if t not in finding.tags:
                finding.tags.append(t)

        # Promote severity if NVD says it's worse than what we had
        self._maybe_promote_severity(finding, verified_with_score)

        verified_count = sum(1 for r in records if r.verified)
        dropped_count = sum(1 for r in records if r.dropped)
        logger.info(
            "[CVERESOLVER] {title}: {v} verified, {d} dropped, {c} cwe, {u} unverified",
            title=finding.title[:60], v=verified_count, d=dropped_count,
            c=len(final_cwes), u=len(unverified_cves),
        )
        return records

    # ── LLM proposal ──────────────────────────────────────────────

    async def _llm_propose(self, finding: Finding) -> list[dict[str, str]]:
        """Ask the LLM to propose CVE/CWE candidates from the evidence.

        The prompt is explicitly constrained:
          - Only propose identifiers you are confident about.
          - Every proposal MUST include a one-sentence reasoning grounded in
            the evidence.
          - Output strict JSON; no prose.
          - If you cannot identify a specific CVE/CWE, return an empty list.

        Returns a list of {identifier, kind, reasoning, confidence} dicts.
        """
        if self._llm is None:
            return []
        try:
            available = self._llm.get_available_providers()
        except Exception:
            available = []
        if not available:
            return []

        # Build an evidence digest (cap sizes to keep prompt small)
        evidence = (finding.evidence or "")[:2000]
        description = (finding.description or "")[:1500]
        tech_hint = ", ".join(finding.tags[:10]) if finding.tags else "unknown"
        existing_cves = ", ".join(finding.cve_ids) if finding.cve_ids else "none"
        existing_cwes = ", ".join(finding.cwe_ids) if finding.cwe_ids else "none"

        prompt = (
            "You are a senior vulnerability analyst. Given the security finding below, "
            "propose SPECIFIC CVE and CWE identifiers that plausibly match the evidence.\n\n"
            "STRICT RULES (anti-hallucination):\n"
            "1. Only propose identifiers you are confident about. Quality over quantity.\n"
            "2. CVE format must be exactly CVE-YYYY-NNNNN. CWE format must be exactly CWE-NNN.\n"
            "3. For EVERY proposal, give a one-sentence reasoning grounded in the evidence.\n"
            "4. If you cannot identify a specific CVE/CWE with confidence, return an empty list.\n"
            "5. Do NOT invent CVE numbers. If unsure, say nothing.\n\n"
            f"FINDING TITLE: {finding.title}\n"
            f"DESCRIPTION: {description}\n"
            f"TARGET: {finding.target.host}:{finding.target.port}\n"
            f"TECH/HINTS: {tech_hint}\n"
            f"ALREADY-KNOWN CVES: {existing_cves}\n"
            f"ALREADY-KNOWN CWES: {existing_cwes}\n"
            f"EVIDENCE:\n{evidence}\n\n"
            "Respond in JSON ONLY:\n"
            '{"proposals": [{"identifier": "CVE-YYYY-NNNNN", "kind": "cve", '
            '"reasoning": "...", "confidence": "high|medium|low"}, '
            '{"identifier": "CWE-NNN", "kind": "cwe", "reasoning": "...", '
            '"confidence": "high|medium|low"}]}\n\n'
            "Return {\"proposals\": []} if you have no confident proposals."
        )

        try:
            result = await self._llm.analyze(prompt, task="cve")
        except Exception as exc:
            logger.debug("[CVERESOLVER] LLM proposal failed: {err}", err=exc)
            return []

        if not result or "proposals" not in result:
            return []
        proposals = result.get("proposals", [])
        if not isinstance(proposals, list):
            return []
        # Filter to well-formed entries
        clean: list[dict[str, str]] = []
        for p in proposals:
            if not isinstance(p, dict):
                continue
            identifier = str(p.get("identifier", "")).upper().strip()
            kind = str(p.get("kind", "")).lower().strip()
            if not identifier or kind not in ("cve", "cwe"):
                continue
            clean.append({
                "identifier": identifier,
                "kind": kind,
                "reasoning": str(p.get("reasoning", ""))[:500],
                "confidence": str(p.get("confidence", "medium")),
            })
        return clean

    # ── NVD verification ──────────────────────────────────────────

    async def _verify_cve(self, rec: VerificationRecord, finding: Finding) -> None:
        """Verify a single CVE record against NVD and update it in place."""
        try:
            record: NVDRecord = await self._nvd.lookup_cve(rec.identifier)
        except Exception as exc:
            rec.nvd_status = "UNREACHABLE"
            rec.verified = False
            rec.drop_reason = f"NVD lookup error: {exc}"
            logger.debug("[CVERESOLVER] NVD unreachable for {cve}: {err}",
                         cve=rec.identifier, err=exc)
            return

        rec.nvd_status = record.status
        if record.verified:
            rec.verified = True
            rec.cvss_score = record.cvss_v3_score
            rec.cvss_vector = record.cvss_v3_vector
            rec.nvd_description = record.description
            rec.nvd_references = list(record.references)
        elif record.status in ("REJECTED", "NOT_FOUND"):
            # Hallucination guard: drop proposals NVD explicitly rejects.
            rec.dropped = True
            rec.drop_reason = f"NVD status: {record.status}"
        # else: RATE_LIMITED / TIMEOUT / ERROR / LOOKUP_FAILED → keep but unverified

    # ── Helpers ───────────────────────────────────────────────────

    def _extract_cves(self, finding: Finding) -> list[str]:
        """Extract CVE IDs already on the finding + any embedded in its text."""
        found: list[str] = []
        seen: set[str] = set()
        for cve in finding.cve_ids:
            cve_up = cve.upper().strip()
            if CVE_RE.fullmatch(cve_up) and cve_up not in seen:
                found.append(cve_up)
                seen.add(cve_up)
        # Also scan evidence/description for CVE patterns the tool may have
        # mentioned in prose without adding to cve_ids.
        for text_blob in (finding.evidence or "", finding.description or "",
                          finding.raw_tool_output or ""):
            for match in CVE_RE.findall(text_blob):
                cve_up = match.upper()
                if cve_up not in seen:
                    found.append(cve_up)
                    seen.add(cve_up)
        return found

    def _extract_cwes(self, finding: Finding) -> list[str]:
        found: list[str] = []
        seen: set[str] = set()
        for cwe in finding.cwe_ids:
            cwe_up = cwe.upper().strip()
            if CWE_RE.fullmatch(cwe_up) and cwe_up not in seen:
                found.append(cwe_up)
                seen.add(cwe_up)
        for text_blob in (finding.evidence or "", finding.description or ""):
            for match in CWE_RE.findall(text_blob):
                cwe_up = match.upper()
                if cwe_up not in seen:
                    found.append(cwe_up)
                    seen.add(cwe_up)
        return found

    def _maybe_promote_severity(
        self, finding: Finding, verified_records: list[VerificationRecord]
    ) -> None:
        """If NVD reports a higher CVSS than the finding's current severity
        implies, promote the severity so critical issues aren't under-reported.
        """
        if not verified_records:
            return
        best_score = max((r.cvss_score or 0) for r in verified_records)
        if best_score >= 9.0 and finding.severity != Severity.CRITICAL:
            finding.severity = Severity.CRITICAL
        elif 7.0 <= best_score < 9.0 and finding.severity not in (Severity.CRITICAL, Severity.HIGH):
            finding.severity = Severity.HIGH
        elif 4.0 <= best_score < 7.0 and finding.severity not in (
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM
        ):
            finding.severity = Severity.MEDIUM


async def enrich_findings(
    findings: list[Finding],
    llm_client: Any,
    nvd_service: Optional[NVDService] = None,
) -> dict[str, list[VerificationRecord]]:
    """Convenience: enrich a batch of findings.

    Returns a mapping of finding.id → verification records.
    """
    resolver = CVEResolver(llm_client, nvd_service)
    out: dict[str, list[VerificationRecord]] = {}
    for f in findings:
        try:
            out[f.id] = await resolver.enrich(f)
        except Exception as exc:
            logger.error("[CVERESOLVER] Failed to enrich '{t}': {err}",
                         t=f.title[:60], err=exc)
            out[f.id] = []
    return out
