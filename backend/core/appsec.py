"""Canonical AppSec findings produced by code and dependency scanners.

The adapters in this module are deliberately pure: they parse versioned tool
output into one evidence model without executing tools or asking an LLM to
reinterpret results.  This makes scanner upgrades regression-testable.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable


SEVERITY_ORDER = {
    "unknown": "informational",
    "info": "informational",
    "informational": "informational",
    "low": "low",
    "warning": "medium",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "error": "high",
    "critical": "critical",
}


def normalise_severity(value: Any) -> str:
    return SEVERITY_ORDER.get(str(value or "unknown").strip().lower(), "informational")


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable) and not isinstance(value, (dict, bytes)):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)]


def _identifiers(values: Any, pattern: str) -> list[str]:
    found: set[str] = set()
    for value in _strings(values):
        found.update(re.findall(pattern, value, flags=re.IGNORECASE))
    return sorted({item.upper() for item in found})


def finding_fingerprint(*parts: Any) -> str:
    material = "|".join(str(part or "").strip().lower() for part in parts)
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()


def _trace_locations(value: Any) -> list[str]:
    """Extract reproducible locations from a Semgrep data-flow trace.

    Trace payloads vary across releases. Walk the structure without retaining
    source snippets, credentials, or other raw code.
    """
    locations: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            path = node.get("path")
            start = node.get("start") if isinstance(node.get("start"), dict) else {}
            if path:
                label = f"{path}:{start.get('line') or '?'}"
                if label not in locations:
                    locations.append(label)
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(value)
    return locations[:12]


def _base_finding(
    *,
    source: str,
    category: str,
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    repository: str,
    path: str = "",
    start_line: int | None = None,
    end_line: int | None = None,
    evidence: str = "",
    remediation: str = "",
    cve_ids: list[str] | None = None,
    cwe_ids: list[str] | None = None,
    references: list[str] | None = None,
    package: str = "",
    installed_version: str = "",
    fixed_version: str = "",
    confidence: str = "high",
) -> dict[str, Any]:
    return {
        "fingerprint": finding_fingerprint(
            source, rule_id, repository, path, start_line, package, installed_version,
        ),
        "source": source,
        "category": category,
        "rule_id": rule_id,
        "title": title or rule_id or "Security finding",
        "description": description or "Scanner reported a security-relevant result.",
        "severity": normalise_severity(severity),
        "confidence": confidence,
        "status": "candidate",
        "repository": repository,
        "path": path,
        "start_line": start_line,
        "end_line": end_line,
        "package": package,
        "installed_version": installed_version,
        "fixed_version": fixed_version,
        "cve_ids": sorted(set(cve_ids or [])),
        "cwe_ids": sorted(set(cwe_ids or [])),
        "references": list(dict.fromkeys(references or []))[:20],
        "evidence": evidence[:8000],
        "remediation": remediation,
    }


def parse_semgrep(payload: dict[str, Any], repository: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in payload.get("results") or []:
        if not isinstance(result, dict):
            continue
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        start = result.get("start") if isinstance(result.get("start"), dict) else {}
        end = result.get("end") if isinstance(result.get("end"), dict) else {}
        rule_id = str(result.get("check_id") or "semgrep-rule")
        message = str(extra.get("message") or metadata.get("shortlink") or rule_id)
        references = _strings(metadata.get("references"))
        shortlink = metadata.get("shortlink")
        if shortlink:
            references.insert(0, str(shortlink))
        match_line = start.get("line") or "?"
        evidence = f"Rule {rule_id} matched {result.get('path') or 'source'}:{match_line}."
        trace = _trace_locations(extra.get("dataflow_trace"))
        if trace:
            evidence += f" Sanitized data-flow locations: {' -> '.join(trace)}."
        findings.append(_base_finding(
            source="semgrep",
            category="sast",
            rule_id=rule_id,
            title=message,
            description=message,
            severity=str(extra.get("severity") or metadata.get("impact") or "warning"),
            repository=repository,
            path=str(result.get("path") or ""),
            start_line=int(start.get("line")) if start.get("line") else None,
            end_line=int(end.get("line")) if end.get("line") else None,
            # Source text can contain credentials or customer data. Persist a
            # reproducible location, not the raw matched line, by default.
            evidence=evidence,
            remediation=str(metadata.get("fix") or metadata.get("remediation") or "Review the data flow and replace the unsafe pattern with the framework's secure API."),
            cve_ids=_identifiers(metadata, r"CVE-\d{4}-\d{4,}"),
            cwe_ids=_identifiers(metadata.get("cwe"), r"CWE-\d+"),
            references=references,
            confidence=str(metadata.get("confidence") or "medium").lower(),
        ))
    return findings


def parse_trivy(payload: dict[str, Any], repository: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in payload.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "")
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = str(vuln.get("VulnerabilityID") or "dependency-vulnerability")
            package = str(vuln.get("PkgName") or "")
            installed = str(vuln.get("InstalledVersion") or "")
            fixed = str(vuln.get("FixedVersion") or "")
            findings.append(_base_finding(
                source="trivy",
                category="sca",
                rule_id=vuln_id,
                title=str(vuln.get("Title") or f"{vuln_id} in {package}"),
                description=str(vuln.get("Description") or "A dependency vulnerability was identified."),
                severity=str(vuln.get("Severity") or "unknown"),
                repository=repository,
                path=target,
                evidence=f"Package {package} {installed}; fixed version: {fixed or 'not published'}.",
                remediation=(f"Upgrade {package} to {fixed}." if fixed else f"Review and replace or mitigate {package} {installed}; no fixed version was reported."),
                cve_ids=_identifiers(vuln_id, r"CVE-\d{4}-\d{4,}"),
                cwe_ids=_identifiers(vuln.get("CweIDs"), r"CWE-\d+"),
                references=_strings(vuln.get("References")) or _strings(vuln.get("PrimaryURL")),
                package=package,
                installed_version=installed,
                fixed_version=fixed,
                confidence="high",
            ))
        for item in result.get("Misconfigurations") or []:
            if not isinstance(item, dict):
                continue
            rule_id = str(item.get("ID") or item.get("AVDID") or "iac-misconfiguration")
            findings.append(_base_finding(
                source="trivy",
                category="iac",
                rule_id=rule_id,
                title=str(item.get("Title") or rule_id),
                description=str(item.get("Description") or "Infrastructure-as-code misconfiguration."),
                severity=str(item.get("Severity") or "medium"),
                repository=repository,
                path=str(item.get("CauseMetadata", {}).get("Resource") or target),
                start_line=(item.get("CauseMetadata", {}).get("StartLine")),
                end_line=(item.get("CauseMetadata", {}).get("EndLine")),
                evidence=str(item.get("Message") or item.get("Resolution") or "Configuration policy failed."),
                remediation=str(item.get("Resolution") or "Update the configuration to satisfy the referenced policy."),
                references=_strings(item.get("PrimaryURL")) or _strings(item.get("References")),
                confidence="high",
            ))
    return findings


def parse_gitleaks(payload: Any, repository: str) -> list[dict[str, Any]]:
    records = payload if isinstance(payload, list) else payload.get("findings", []) if isinstance(payload, dict) else []
    findings: list[dict[str, Any]] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("RuleID") or item.get("rule") or "secret")
        path = str(item.get("File") or item.get("file") or "")
        line = item.get("StartLine") or item.get("line")
        # Never retain Secret or Match. They are credentials, not evidence the
        # platform should copy into logs, databases, model prompts, or reports.
        findings.append(_base_finding(
            source="gitleaks",
            category="secret",
            rule_id=rule_id,
            title=str(item.get("Description") or f"Potential {rule_id} secret"),
            description="A secret pattern was detected. The secret value has been redacted by the platform.",
            severity="high",
            repository=repository,
            path=path,
            start_line=int(line) if line else None,
            end_line=int(item.get("EndLine")) if item.get("EndLine") else None,
            evidence=f"Secret detector {rule_id} matched {path}:{line or '?'}; value redacted.",
            remediation="Revoke or rotate the credential, remove it from source and history, and migrate it to an approved secrets manager.",
            confidence="high",
        ))
    return findings


def parse_trufflehog(output: str, repository: str) -> list[dict[str, Any]]:
    """Parse TruffleHog JSONL without retaining raw or redacted secrets."""
    import json

    findings: list[dict[str, Any]] = []
    for line in str(output or "").splitlines():
        try:
            item = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(item, dict):
            continue
        source_data = item.get("SourceMetadata", {}).get("Data", {})
        location: dict[str, Any] = {}
        if isinstance(source_data, dict):
            for key in ("Filesystem", "Git"):
                if isinstance(source_data.get(key), dict):
                    location = source_data[key]
                    break
        detector = str(item.get("DetectorName") or item.get("DetectorType") or "credential")
        path = str(location.get("file") or location.get("path") or "")
        line_no = location.get("line")
        try:
            parsed_line = int(line_no) if line_no not in (None, "") else None
        except (TypeError, ValueError):
            parsed_line = None
        verified = bool(item.get("Verified"))
        finding = _base_finding(
            source="trufflehog",
            category="secret",
            rule_id=f"trufflehog:{detector}",
            title=f"{'Verified' if verified else 'Potential'} {detector} credential",
            description=(
                "TruffleHog actively verified that this credential is accepted by its provider."
                if verified
                else "TruffleHog classified a potential credential; its value is redacted and validity is unconfirmed."
            ),
            severity="critical" if verified else "high",
            repository=repository,
            path=path,
            start_line=parsed_line,
            evidence=(
                f"Detector {detector} matched {path or 'repository'}:{line_no or '?'}; "
                f"provider verification={'confirmed' if verified else 'not confirmed'}; value redacted."
            ),
            remediation="Immediately revoke or rotate verified credentials, remove them from source/history, and store replacements in an approved secrets manager.",
            confidence="high" if verified else "medium",
        )
        if verified:
            finding["status"] = "verified"
        findings.append(finding)
    return findings


def merge_secret_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Prefer provider-verified TruffleHog evidence at the same location."""
    merged: dict[tuple[str, str, int | None], dict[str, Any]] = {}
    remainder: list[dict[str, Any]] = []
    for finding in findings:
        if finding.get("category") != "secret":
            remainder.append(finding)
            continue
        location_key = str(finding.get("path") or "")
        if not location_key and finding.get("start_line") is None:
            location_key = str(finding.get("fingerprint") or finding.get("rule_id") or "unknown")
        key = (
            str(finding.get("repository") or ""),
            location_key,
            finding.get("start_line"),
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            continue
        if finding.get("status") == "verified" or (
            finding.get("source") == "trufflehog" and existing.get("source") != "trufflehog"
        ):
            merged[key] = finding
    return [*remainder, *merged.values()]
