"""Evidence quality scoring for findings.

The platform should show the difference between a proven issue, a useful lead,
and an AI/tool suspicion. This module keeps that judgment deterministic so
reports can be trusted even when an LLM is enabled.
"""

from __future__ import annotations

import os
from typing import Any

# Findings scoring below this threshold are quarantined: kept for audit/replay
# but excluded from customer-facing reports so weak signals do not pollute them.
QUARANTINE_SCORE_THRESHOLD = float(os.environ.get("VAPT_QUARANTINE_SCORE_THRESHOLD", "40"))


TOOL_EVIDENCE_TAGS = {
    "arjun",
    "cms",
    "dalfox",
    "ffuf",
    "httpx",
    "nikto",
    "nmap",
    "nuclei",
    "scanner-evidence",
    "service",
    "sqlmap",
    "technology",
    "wpscan",
}


def evidence_grade(score: float) -> str:
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 40:
        return "D"
    return "E"


def assess_finding_quality(finding: dict[str, Any]) -> dict[str, Any]:
    """Return evidence score, grade, and validation notes for one finding."""
    tags = {str(tag).lower() for tag in finding.get("tags") or []}
    evidence = str(finding.get("evidence") or "")
    request = str(finding.get("request_proof") or "")
    response = str(finding.get("response_proof") or "")
    description = str(finding.get("description") or "")
    confidence = str(finding.get("confidence") or "medium").lower()
    status = str(finding.get("status") or "suspected").lower()
    severity = str(finding.get("severity") or "medium").lower()
    cves = finding.get("cve_ids") or []
    cwes = finding.get("cwe_ids") or []
    nvd_verified = bool(finding.get("nvd_verified")) or "nvd-verified" in tags

    score = 12.0
    notes: list[str] = []

    if status == "confirmed":
        score += 24
    elif status == "suspected":
        score += 8
        notes.append("Status is suspected; keep manual validation in the report.")
    elif status == "false_positive":
        score -= 25
        notes.append("Marked false positive.")

    if confidence == "high":
        score += 18
    elif confidence == "medium":
        score += 10
    elif confidence == "low":
        score += 2
        notes.append("Low confidence signal.")

    if evidence:
        score += min(22, 6 + len(evidence) / 120)
    else:
        notes.append("No primary evidence text is attached.")

    if request:
        score += 10
    if response:
        score += 10
    if cves:
        score += 14
    if cwes:
        score += 4
    if nvd_verified:
        score += 18
    if tags.intersection(TOOL_EVIDENCE_TAGS):
        score += 12

    llm_only = bool(tags.intersection({"llm", "ai-analysis", "ai-vuln", "ai-fuzz"})) and not tags.intersection(TOOL_EVIDENCE_TAGS)
    if llm_only:
        score -= 18
        notes.append("AI-only finding; requires independent tool or manual validation.")

    if severity in {"critical", "high"} and not (request or response or cves or nvd_verified):
        score -= 8
        notes.append("High-impact severity lacks replay proof, CVE, or NVD validation.")

    if len(description) < 40:
        score -= 4
        notes.append("Description is too short for audit-grade reporting.")

    score = max(0.0, min(100.0, round(score, 1)))
    grade = evidence_grade(score)
    if grade in {"D", "E"} and "Needs stronger validation before customer-facing reporting." not in notes:
        notes.append("Needs stronger validation before customer-facing reporting.")

    # A confirmed false positive is always quarantined regardless of score.
    quarantined = score < QUARANTINE_SCORE_THRESHOLD or status == "false_positive"
    if quarantined and "Quarantined: excluded from reports until validated." not in notes:
        notes.append("Quarantined: excluded from reports until validated.")

    return {
        "evidence_score": score,
        "evidence_grade": grade,
        "validation_notes": notes[:6],
        "quarantined": quarantined,
    }


def enrich_finding_quality(finding: dict[str, Any]) -> dict[str, Any]:
    out = dict(finding)
    quality = assess_finding_quality(out)
    out.update(quality)
    return out
