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
            evidence=f"Rule {rule_id} matched {result.get('path') or 'source'}:{start.get('line') or '?'}.",
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
