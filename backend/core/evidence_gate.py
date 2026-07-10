"""Evidence gate for DAST proof results.

The gate is the policy boundary: validators may produce proof objects, but only
confirmed proof becomes a customer-facing Finding.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

from core.dast_validators import ValidationProof
from core.models import AgentType, Finding, Severity, Target


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
}


class EvidenceGate:
    """Convert confirmed validation proof into Finding objects."""

    @staticmethod
    def finding_from_proof(proof: ValidationProof, *, agent_source: AgentType = AgentType.EXPLOIT) -> Finding | None:
        if not proof.confirmed:
            return None
        parsed = urlparse(proof.url)
        host = parsed.hostname or "unknown"
        tags = list(dict.fromkeys([
            *proof.tags,
            proof.vuln_type,
            proof.validator,
            "replay-proof",
            "confirmed",
        ]))
        finding = Finding(
            title=proof.title,
            description=(
                f"The DAST proof engine confirmed `{proof.vuln_type}` on parameter "
                f"`{proof.parameter}` using validator `{proof.validator}`. The proof is "
                "non-destructive and replayable from the attached request/response evidence."
            ),
            severity=SEVERITY_MAP.get(proof.severity.lower(), Severity.MEDIUM),
            agent_source=agent_source,
            target=Target(host=host, url=proof.url),
            evidence=proof.evidence,
            request_proof=proof.request_proof,
            response_proof=proof.response_proof,
            remediation=proof.remediation,
            cwe_ids=proof.cwe_ids,
            tags=tags,
            confidence=proof.confidence if proof.confidence in {"high", "medium", "low"} else "medium",
            status="confirmed",
            raw_tool_output=json.dumps(proof.to_dict(), default=str),
        )
        finding.poc_steps = [
            f"1. Send the proof request: {proof.request_proof}",
            "2. Observe the response evidence attached to this finding.",
            "3. Compare against a normal request for the same endpoint/parameter.",
        ]
        return finding
