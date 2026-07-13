"""Evidence-backed attack-chain compilation.

An LLM may explain a chain, but it must not establish the chain as fact.  This
module derives narrowly defined two-step paths from canonical findings and
attaches stable evidence references to every edge.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any


def evidence_ref(finding: dict[str, Any]) -> str:
    raw = "|".join(
        str(finding.get(key) or "").strip().lower()
        for key in ("title", "target_host", "target_url", "created_at")
    )
    return f"ev_{hashlib.sha256(raw.encode()).hexdigest()[:16]}"


def _tokens(finding: dict[str, Any]) -> set[str]:
    tags = {str(tag).lower().replace("_", "-") for tag in finding.get("tags") or []}
    cwes = {str(cwe).upper() for cwe in finding.get("cwe_ids") or []}
    text = " ".join(
        str(finding.get(key) or "").lower()
        for key in ("title", "description", "evidence")
    )
    out = set(tags)
    rules = {
        "secret-exposure": ("secret", "credential", "api key", "access token", "private key"),
        "auth-weakness": ("auth bypass", "authentication bypass", "default login", "default credential", "exposed admin"),
        "sqli": ("sql injection", "sqli"),
        "data-exposure": ("sensitive data", "database dump", "data exposure", "information disclosure"),
        "ssrf": ("ssrf", "server-side request forgery"),
        "cloud-metadata": ("cloud metadata", "instance metadata", "iam credential", "aws credential"),
        "xss": ("cross-site scripting", "xss"),
        "session-weakness": ("session cookie", "httponly", "samesite", "session fixation"),
        "rce": ("remote code execution", "command injection", "rce"),
        "file-read": ("path traversal", "local file inclusion", "lfi"),
        "repo-exposure": ("exposed git", "git repository", "source code exposure"),
    }
    for token, needles in rules.items():
        if any(needle in text for needle in needles):
            out.add(token)
    cwe_map = {
        "CWE-89": "sqli", "CWE-79": "xss", "CWE-918": "ssrf",
        "CWE-78": "rce", "CWE-22": "file-read", "CWE-200": "data-exposure",
        "CWE-798": "secret-exposure", "CWE-287": "auth-weakness",
    }
    out.update(cwe_map[cwe] for cwe in cwes if cwe in cwe_map)
    return out


def _eligible(finding: dict[str, Any]) -> bool:
    if finding.get("quarantined") or finding.get("status") == "false_positive":
        return False
    grade = str(finding.get("evidence_grade") or "E").upper()
    score = float(finding.get("evidence_score") or 0)
    has_proof = bool(
        finding.get("evidence") or finding.get("request_proof")
        or finding.get("response_proof") or finding.get("cve_ids")
    )
    return has_proof and grade in {"A", "B", "C"} and score >= 55


@dataclass(frozen=True)
class ChainRule:
    first: str
    second: str
    name: str
    impact: str


RULES = (
    ChainRule("repo-exposure", "secret-exposure", "Source exposure to credential compromise", "Leaked source material can expose reusable credentials."),
    ChainRule("file-read", "secret-exposure", "Arbitrary file read to credential compromise", "Readable application files can expose credentials or tokens."),
    ChainRule("secret-exposure", "auth-weakness", "Credential exposure to privileged access", "Exposed credentials combined with weak authentication can enable unauthorized access."),
    ChainRule("ssrf", "cloud-metadata", "SSRF to cloud identity compromise", "Server-side requests may reach instance metadata and expose cloud identity material."),
    ChainRule("sqli", "data-exposure", "SQL injection to sensitive-data compromise", "Database injection can turn an information exposure into direct data access."),
    ChainRule("xss", "session-weakness", "XSS to session compromise", "Script execution combined with weak session controls can increase account-takeover impact."),
    ChainRule("auth-weakness", "rce", "Authentication weakness to remote execution", "Unauthorized access can expose a verified code-execution path."),
)


def compile_attack_chains(findings: list[dict[str, Any]]) -> dict[str, Any]:
    candidates = [finding for finding in findings if _eligible(finding)]
    enriched = [(finding, _tokens(finding), evidence_ref(finding)) for finding in candidates]
    chains: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for rule in RULES:
        for first, first_tokens, first_ref in enriched:
            if rule.first not in first_tokens:
                continue
            for second, second_tokens, second_ref in enriched:
                if first_ref == second_ref or rule.second not in second_tokens:
                    continue
                first_host = str(first.get("target_host") or "").lower()
                second_host = str(second.get("target_host") or "").lower()
                if not first_host or first_host != second_host:
                    continue
                key = (rule.name, first_ref, second_ref)
                if key in seen:
                    continue
                seen.add(key)
                verified = all(
                    item.get("status") == "confirmed"
                    and float(item.get("evidence_score") or 0) >= 70
                    for item in (first, second)
                )
                chain_id = "chain_" + hashlib.sha256("|".join(key).encode()).hexdigest()[:16]
                chains.append({
                    "chain_id": chain_id,
                    "name": rule.name,
                    "target_host": first_host,
                    "status": "verified" if verified else "hypothesis",
                    "confidence": "high" if verified else "medium",
                    "impact": rule.impact,
                    "nodes": [
                        {"evidence_ref": first_ref, "title": first.get("title"), "severity": first.get("severity"), "role": rule.first},
                        {"evidence_ref": second_ref, "title": second.get("title"), "severity": second.get("severity"), "role": rule.second},
                    ],
                    "edges": [{
                        "source": first_ref,
                        "target": second_ref,
                        "relation": f"{rule.first}_enables_{rule.second}",
                        "evidence_refs": [first_ref, second_ref],
                    }],
                })

    return {
        "summary": {
            "total": len(chains),
            "verified": sum(1 for chain in chains if chain["status"] == "verified"),
            "hypotheses": sum(1 for chain in chains if chain["status"] == "hypothesis"),
        },
        "chains": chains,
    }
