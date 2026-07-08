"""
VAPT Platform — False-Positive Reducer (P1)

Cross-references a finding's tool evidence with a live HTTP replay to promote it
to ``confirmed`` or demote it to ``false_positive``. Non-destructive: replays are
benign GET/HEAD/OPTIONS-style probes that re-observe the reported signal.

Two entry points:
  * ``replay_confirm`` — re-issue a request and check whether an expected
    signature is still present (used by the safe web modules).
  * ``heuristic_verdict`` — evidence-completeness judgement with no network I/O
    (used as a fallback and to flag AI-only claims).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from loguru import logger

from core.http_session import new_auth_client


@dataclass
class ReplayVerdict:
    status: str                       # confirmed | suspected | false_positive
    confidence: str                   # high | medium | low
    matched: bool = False
    http_status: Optional[int] = None
    notes: list[str] = field(default_factory=list)
    evidence: str = ""


async def replay_confirm(
    url: str,
    *,
    signature: str,
    scope_config: Any = None,
    method: str = "GET",
    absent_means_fixed: bool = False,
    timeout: float = 10.0,
) -> ReplayVerdict:
    """Replay ``url`` and check whether ``signature`` appears in the response.

    * ``matched`` True  → the reported condition still holds → confirmed.
    * ``matched`` False → with ``absent_means_fixed`` the finding is demoted to
      false_positive (the signal could not be reproduced).
    """
    signature_l = (signature or "").lower()
    try:
        async with new_auth_client(scope_config, timeout=timeout, follow_redirects=False) as client:
            resp = await client.request(method, url)
            body = resp.text or ""
            hay = (body + " " + " ".join(f"{k}: {v}" for k, v in resp.headers.items())).lower()
            matched = bool(signature_l) and signature_l in hay
            verdict = ReplayVerdict(
                status="confirmed" if matched else ("false_positive" if absent_means_fixed else "suspected"),
                confidence="high" if matched else ("medium" if absent_means_fixed else "low"),
                matched=matched,
                http_status=resp.status_code,
                evidence=f"HTTP {resp.status_code} on {method} {url}; "
                         f"signature {'present' if matched else 'absent'}.",
            )
            if not matched and absent_means_fixed:
                verdict.notes.append("Replay could not reproduce the reported signal.")
            return verdict
    except Exception as exc:
        logger.debug("[fp_reducer] replay failed for {url}: {err}", url=url, err=exc)
        return ReplayVerdict(
            status="suspected", confidence="low",
            notes=[f"Replay error: {type(exc).__name__}"],
            evidence=f"Replay of {method} {url} failed: {exc}",
        )


def heuristic_verdict(finding: dict[str, Any]) -> ReplayVerdict:
    """Evidence-completeness verdict without network I/O.

    Flags AI-only claims lacking any tool corroboration or replay proof as
    likely false positives so they don't reach reports unchallenged.
    """
    tags = {str(t).lower() for t in finding.get("tags") or []}
    has_proof = bool(finding.get("request_proof") or finding.get("response_proof"))
    has_tool = bool(tags.intersection({
        "nuclei", "nikto", "nmap", "sqlmap", "wpscan", "ffuf", "arjun",
        "dalfox", "scanner-evidence", "module-replay",
    }))
    ai_only = bool(tags.intersection({"llm", "ai-analysis", "ai-vuln"})) and not has_tool

    if ai_only and not has_proof:
        return ReplayVerdict(
            status="false_positive", confidence="low",
            notes=["AI-only claim with no tool evidence or replay proof."],
        )
    if has_proof and has_tool:
        return ReplayVerdict(status="confirmed", confidence="high")
    if has_proof or has_tool:
        return ReplayVerdict(status="suspected", confidence="medium")
    return ReplayVerdict(
        status="suspected", confidence="low",
        notes=["No replay proof or tool evidence attached."],
    )
