"""Versioned internal control-evidence projection.

This is an assessment coverage view, not a certification engine. Controls are
supported only when the persisted evidence ledger contains the required
artifacts; the API deliberately uses ``evidenced`` instead of ``compliant``.
"""

from __future__ import annotations

from typing import Any


CONTROL_CATALOG = (
    ("VAPT-SCOPE-001", "Authorized scope recorded", "governance", "scope"),
    ("VAPT-SURFACE-001", "Attack surface inventory", "discovery", "assets"),
    ("VAPT-HTTP-001", "Live HTTP response validation", "dast", "http"),
    ("VAPT-INPUT-001", "Endpoint and input discovery", "dast", "inputs"),
    ("VAPT-VALIDATE-001", "Replayable vulnerability validation", "dast", "proofs"),
    ("VAPT-RECOVERY-001", "Durable execution and result recovery", "operations", "actions"),
    ("VAPT-REPORT-001", "Evidence-gated reporting", "governance", "report"),
)


def build_control_evidence(
    *,
    scan: dict[str, Any],
    coverage: dict[str, Any],
    findings: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    actions: list[dict[str, Any]],
) -> dict[str, Any]:
    asset_types: dict[str, int] = {}
    for asset in assets:
        key = str(asset.get("asset_type") or "unknown")
        asset_types[key] = asset_types.get(key, 0) + 1
    checks = {str(item.get("id") or ""): item for item in coverage.get("checks") or []}
    proof_findings = [
        item for item in findings
        if item.get("status") == "confirmed"
        and (item.get("request_proof") or item.get("response_proof"))
        and not item.get("quarantined")
    ]
    completed_actions = [item for item in actions if item.get("status") in {"completed", "partial"}]
    terminal = scan.get("status") in {"completed", "partial"}

    evidence = {
        "scope": (bool(scan.get("rules_of_engagement") or scan.get("scope")), ["rules-of-engagement"], "No persisted rules of engagement."),
        "assets": (bool(assets), [f"asset:{key}:{count}" for key, count in sorted(asset_types.items())], "No attack-surface objects were persisted."),
        "http": (
            bool(asset_types.get("url") or asset_types.get("technology")),
            [f"asset:url:{asset_types.get('url', 0)}", f"asset:technology:{asset_types.get('technology', 0)}"],
            "No body-verified HTTP surface evidence was persisted.",
        ),
        "inputs": (
            bool(asset_types.get("parameter") or asset_types.get("api_endpoint")),
            [f"asset:parameter:{asset_types.get('parameter', 0)}", f"asset:api_endpoint:{asset_types.get('api_endpoint', 0)}"],
            "No parameter or API endpoint inventory was captured.",
        ),
        "proofs": (
            bool(proof_findings),
            [f"finding:{item.get('title', 'proof')[:80]}" for item in proof_findings[:20]],
            "No replayable behavior proof was confirmed; this does not mean no vulnerability exists.",
        ),
        "actions": (
            bool(completed_actions),
            [f"action:{item.get('action_id')}:{item.get('status')}" for item in completed_actions[:30]],
            "No durable runner action has reached an evidence-producing state.",
        ),
        "report": (
            terminal and bool(checks.get("report_evidence_pack", {}).get("status") == "completed" or scan.get("report_base_name")),
            ["coverage:report_evidence_pack", f"scan-status:{scan.get('status', 'unknown')}"],
            "A terminal evidence-gated report has not been produced.",
        ),
    }

    controls: list[dict[str, Any]] = []
    for control_id, title, family, evidence_key in CONTROL_CATALOG:
        supported, refs, limitation = evidence[evidence_key]
        controls.append({
            "control_id": control_id,
            "title": title,
            "family": family,
            "status": "evidenced" if supported else "not_evidenced",
            "evidence_refs": refs if supported else [],
            "limitation": "" if supported else limitation,
            "scope": list(scan.get("targets") or []),
        })
    evidenced = sum(1 for item in controls if item["status"] == "evidenced")
    return {
        "catalog": "VAPT Internal Assessment Evidence Controls",
        "catalog_version": "1.0",
        "claim": "coverage_evidence_only",
        "summary": {
            "total": len(controls),
            "evidenced": evidenced,
            "not_evidenced": len(controls) - evidenced,
            "coverage_percent": round((evidenced / len(controls)) * 100) if controls else 0,
        },
        "controls": controls,
        "disclaimer": "Evidence coverage is not a certification or a compliance determination.",
    }
