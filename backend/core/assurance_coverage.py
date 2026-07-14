"""Evidence-backed OWASP testing coverage projection.

This is a test ledger, not a compliance or certification engine.  A category
is only marked tested when a persisted runner action produced evidence.
Discovery observations are shown separately and are never converted to pass.
"""

from __future__ import annotations

from typing import Any


WSTG_CATEGORIES = (
    ("WSTG-INFO", "Information Gathering", {"assetfinder", "subfinder", "amass", "httpx", "katana", "whatweb", "wappalyzer"}, {"domain", "subdomain", "url", "technology"}, set()),
    ("WSTG-CONF", "Configuration & Deployment", {"nmap", "nuclei", "nikto", "ffuf", "wafw00f"}, {"service", "url"}, set()),
    ("WSTG-IDNT", "Identity Management", set(), set(), set()),
    ("WSTG-ATHN", "Authentication", {"nuclei", "wpscan"}, set(), {"jwt_alg_none"}),
    ("WSTG-ATHZ", "Authorization", set(), set(), set()),
    ("WSTG-SESS", "Session Management", {"nuclei"}, set(), {"jwt_alg_none"}),
    ("WSTG-INPV", "Input Validation", {"sqlmap", "dalfox", "commix", "nuclei", "arjun"}, {"parameter", "api_endpoint"}, {"sqli_error_boolean", "nosqli_error", "xss_reflection", "ssti_arithmetic", "command_injection_timing", "lfi_known_file", "ssrf_http_oob"}),
    ("WSTG-ERRH", "Error Handling", {"nikto", "nuclei"}, set(), set()),
    ("WSTG-CRYP", "Weak Cryptography", {"testssl", "testssl.sh", "sslscan", "tlsx", "nuclei"}, {"service"}, {"jwt_alg_none"}),
    ("WSTG-BUSL", "Business Logic", set(), set(), set()),
    ("WSTG-CLNT", "Client-side", {"dalfox", "nuclei", "katana"}, {"js_file", "js_signal"}, {"xss_reflection", "sourcemap_exposure"}),
    ("WSTG-APIT", "API Testing", {"arjun", "nuclei", "graphql-cop"}, {"api_endpoint", "parameter"}, {"sqli_error_boolean", "nosqli_error", "ssrf_http_oob"}),
)


def build_assurance_coverage(
    *, scan: dict[str, Any], assets: list[dict[str, Any]], actions: list[dict[str, Any]], findings: list[dict[str, Any]],
    validation_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    asset_types = {str(item.get("asset_type") or "unknown") for item in assets}
    completed_tools = {
        str(item.get("tool") or "").lower()
        for item in actions
        if item.get("status") in {"completed", "partial"} and item.get("tool")
    }
    proof_count = sum(
        1 for item in findings
        if item.get("status") == "confirmed" and (item.get("request_proof") or item.get("response_proof")) and not item.get("quarantined")
    )
    validation_summary = validation_summary or {}
    validator_summary = validation_summary.get("validator_summary") or {}
    attempted_validators = {
        str(name).lower()
        for name, statuses in validator_summary.items()
        if isinstance(statuses, dict) and sum(int(value or 0) for value in statuses.values()) > 0
    }
    categories: list[dict[str, Any]] = []
    for category_id, title, tools, evidence_assets, validators in WSTG_CATEGORIES:
        executed = sorted(completed_tools.intersection({name.lower() for name in tools}))
        executed_validators = sorted(attempted_validators.intersection({name.lower() for name in validators}))
        observed = sorted(asset_types.intersection(evidence_assets))
        status = "tested" if executed or executed_validators else "observed" if observed else "not_tested"
        categories.append({
            "category_id": category_id,
            "title": title,
            "status": status,
            "executed_tools": executed,
            "executed_validators": executed_validators,
            "observed_assets": observed,
            "evidence_refs": [f"action:{name}" for name in executed] + [f"validator:{name}" for name in executed_validators] + [f"asset:{name}" for name in observed],
            "limitation": (
                "Persisted scanner evidence exists; review individual test artifacts before drawing a security conclusion."
                if status == "tested" else
                "Relevant attack-surface evidence exists, but no approved test action produced evidence."
                if status == "observed" else
                "No applicable evidence-producing test was executed."
            ),
        })
    tested = sum(1 for item in categories if item["status"] == "tested")
    observed = sum(1 for item in categories if item["status"] == "observed")
    return {
        "catalog": "OWASP Web Security Testing Guide",
        "catalog_version": "4.2 (stable)",
        "claim": "testing_coverage_only",
        "scope": list(scan.get("targets") or []),
        "summary": {
            "total": len(categories),
            "tested": tested,
            "observed": observed,
            "not_tested": len(categories) - tested - observed,
            "confirmed_proofs": proof_count,
        },
        "categories": categories,
        "dynamic_validation": {
            "hypotheses_planned": int(validation_summary.get("hypotheses_planned") or 0),
            "hypotheses_scheduled": int(validation_summary.get("hypotheses_scheduled") or 0),
            "hypotheses_tested": int(validation_summary.get("hypotheses_tested") or 0),
            "proofs_confirmed": int(validation_summary.get("proofs_confirmed") or 0),
            "validator_summary": validator_summary,
            "attempts": validation_summary.get("validation_attempts") or [],
        },
        "frameworks": [
            {"name": "OWASP WSTG", "version": "4.2", "purpose": "runtime security testing methodology", "url": "https://owasp.org/www-project-web-security-testing-guide/v42/"},
            {"name": "OWASP ASVS", "version": "5.0.0", "purpose": "application security verification requirements", "url": "https://owasp.org/www-project-application-security-verification-standard/"},
        ],
        "disclaimer": "Coverage records what was observed and tested. It is not a pass, compliance score, certification, or proof that untested vulnerabilities do not exist.",
    }
