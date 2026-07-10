"""
VAPT Platform — Dual-Model Review for Critical/High findings (Phase 1)

Critical and High findings carry the most reputational risk if they are false
positives. Before such a finding reaches a customer report, a SECOND model
independently judges whether the evidence actually supports it. Disagreement
downgrades confidence and flags the finding so the reporter excludes it.

The reviewer is deliberately a DIFFERENT model from the one used for primary
reasoning (e.g. gemma reviews qwen's/tools' conclusions) — an independent second
opinion, grounded strictly in the finding's own evidence.
"""

from __future__ import annotations

from typing import Any, Optional

from loguru import logger

REVIEW_SEVERITIES = {"critical", "high"}
DISAGREE_TAG = "dual-review-failed"

_SYSTEM = (
    "You are an independent senior security reviewer. Judge ONLY from the evidence "
    "given whether the finding is a true positive. Do not assume facts not present. "
    "If the evidence does not clearly support the finding, mark it invalid. "
    "Respond in valid JSON only."
)


def _build_prompt(report: dict[str, Any]) -> str:
    return (
        "Validate this security finding strictly against its evidence.\n\n"
        f"TITLE: {report.get('title', '')}\n"
        f"SEVERITY: {report.get('severity', '')}\n"
        f"DESCRIPTION: {str(report.get('description', ''))[:800]}\n"
        f"EVIDENCE: {str(report.get('evidence', ''))[:1200]}\n"
        f"REQUEST PROOF: {str(report.get('request_proof', ''))[:600]}\n"
        f"RESPONSE PROOF: {str(report.get('response_proof', ''))[:600]}\n"
        f"CVES: {', '.join(report.get('cve_ids', []) or []) or 'none'}\n\n"
        'Respond in JSON: {"valid": true|false, "confidence": "high|medium|low", '
        '"reasoning": "one sentence grounded in the evidence"}'
    )


async def review_finding(
    finding: Any,
    llm_client: Any,
    reviewer_model: str = "",
) -> Optional[dict[str, Any]]:
    """Return a verdict dict for one Finding, or None if the review call failed."""
    try:
        report = finding.to_report_dict()
    except Exception:
        return None
    try:
        resp = await llm_client.complete(
            prompt=_build_prompt(report),
            system_prompt=_SYSTEM,
            model=reviewer_model or None,
            json_mode=True,
            temperature=0.1,
            max_tokens=300,
            use_fallback=False,
            task="dual_review",
        )
    except Exception as exc:
        logger.debug("[dual_review] review call failed: {e}", e=exc)
        return None

    parsed = resp.json_content() if resp else None
    if not isinstance(parsed, dict) or "valid" not in parsed:
        return None
    return {
        "valid": bool(parsed.get("valid")),
        "confidence": str(parsed.get("confidence", "low")),
        "reasoning": str(parsed.get("reasoning", ""))[:400],
        "reviewer_model": getattr(resp, "model", reviewer_model) or reviewer_model,
    }


async def dual_review(findings: list[Any], llm_client: Any, reviewer_model: str = "") -> dict[str, int]:
    """Review all Critical/High findings in place.

    On disagreement: append the ``dual-review-failed`` tag, drop confidence to
    ``low``, and record the verdict under ``finding.llm_reasoning['dual_review']``.
    Returns {reviewed, disagreed}.
    """
    reviewed = 0
    disagreed = 0
    for finding in findings:
        severity = getattr(getattr(finding, "severity", None), "value", "") or ""
        if severity.lower() not in REVIEW_SEVERITIES:
            continue
        verdict = await review_finding(finding, llm_client, reviewer_model)
        if verdict is None:
            continue
        reviewed += 1
        reasoning = dict(getattr(finding, "llm_reasoning", {}) or {})
        reasoning["dual_review"] = verdict
        finding.llm_reasoning = reasoning
        if not verdict["valid"]:
            disagreed += 1
            if DISAGREE_TAG not in finding.tags:
                finding.tags.append(DISAGREE_TAG)
            finding.confidence = "low"
    if reviewed:
        logger.info(
            "[dual_review] Reviewed {r} crit/high finding(s); {d} disagreed and were flagged",
            r=reviewed, d=disagreed,
        )
    return {"reviewed": reviewed, "disagreed": disagreed}
