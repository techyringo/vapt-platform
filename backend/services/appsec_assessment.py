"""Durable repository assessment executed by ARQ workers."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from core.appsec import merge_secret_findings, parse_gitleaks, parse_semgrep, parse_trivy, parse_trufflehog
from core.config import AppConfig
from core.live_log import tool_log_context
from database.store import PersistenceStore
from tools.runner import CONTAINER_SHARED_DIR, DockerRunner, ensure_shared_dir


def validate_repository_url(value: str) -> str:
    parsed = urlparse(str(value or "").strip())
    allowed_hosts = {
        host.strip().lower()
        for host in os.environ.get("VAPT_APPSEC_GIT_HOSTS", "github.com,gitlab.com").split(",")
        if host.strip()
    }
    if parsed.scheme != "https" or not parsed.hostname or parsed.hostname.lower() not in allowed_hosts:
        raise ValueError(f"Repository must use HTTPS and an approved host: {', '.join(sorted(allowed_hosts))}")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Repository URLs cannot contain credentials, query parameters, or fragments")
    if not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?", parsed.path):
        raise ValueError("Repository URL must identify one owner and repository")
    return urlunparse(("https", parsed.hostname.lower(), parsed.path.rstrip("/"), "", "", ""))


def validate_ref(value: str) -> str:
    ref = str(value or "main").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", ref) or ".." in ref or "//" in ref:
        raise ValueError("Invalid repository ref")
    return ref


async def _clone(repository: str, ref: str, destination: Path) -> str:
    env = dict(os.environ)
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_LFS_SKIP_SMUDGE": "1",
    })
    proc = await asyncio.create_subprocess_exec(
        "git", "-c", "core.hooksPath=/dev/null", "clone", "--depth", "1",
        "--single-branch", "--no-tags", "--branch", ref,
        "--", repository, str(destination),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
    if proc.returncode != 0:
        message = stderr.decode("utf-8", errors="replace")[-2000:]
        raise RuntimeError(f"Repository clone failed: {message}")
    # A repository symlink could otherwise escape its workspace because the
    # approved scanner containers share a bounded host mount. Remove links and
    # scan regular files only; record full symlink support as a future runner
    # isolation capability rather than silently following them.
    paths = list(destination.rglob("*"))
    for path in paths:
        if path.is_symlink():
            path.unlink()
    max_bytes = int(os.environ.get("VAPT_APPSEC_MAX_REPO_MB", "512")) * 1024 * 1024
    size = sum(path.stat().st_size for path in destination.rglob("*") if path.is_file())
    if size > max_bytes:
        raise RuntimeError(f"Repository exceeds the {max_bytes // (1024 * 1024)} MB assessment limit")
    rev = await asyncio.create_subprocess_exec(
        "git", "-C", str(destination), "rev-parse", "HEAD",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    revision, _ = await rev.communicate()
    return revision.decode().strip()


def _json_payload(text: str):
    try:
        return json.loads(text or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Scanner returned invalid JSON: {exc}") from exc


_LANGUAGE_EXTENSIONS = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java",
    ".go": "Go", ".rb": "Ruby", ".php": "PHP", ".cs": "C#",
    ".c": "C/C++", ".cc": "C/C++", ".cpp": "C/C++", ".h": "C/C++",
    ".rs": "Rust", ".kt": "Kotlin", ".swift": "Swift", ".scala": "Scala",
}


def repository_inventory(workspace: Path) -> dict[str, object]:
    """Return a bounded, non-sensitive codebase inventory for scan coverage."""
    languages: Counter[str] = Counter()
    manifests: set[str] = set()
    manifest_names = {
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "requirements.txt", "poetry.lock", "pyproject.toml", "Pipfile.lock",
        "go.mod", "go.sum", "pom.xml", "build.gradle", "Cargo.lock",
        "Gemfile.lock", "composer.lock", "packages.lock.json",
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    }
    files_scanned = 0
    codeowners_path = ""
    codeowners: set[str] = set()
    for path in workspace.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        files_scanned += 1
        language = _LANGUAGE_EXTENSIONS.get(path.suffix.lower())
        if language:
            languages[language] += 1
        if path.name in manifest_names:
            manifests.add(path.name)
        if path.name == "CODEOWNERS" and not codeowners_path:
            codeowners_path = str(path.relative_to(workspace))
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[:2000]:
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                codeowners.update(token for token in line.split()[1:] if token.startswith("@"))
    return {
        "files": files_scanned,
        "languages": dict(languages.most_common(12)),
        "manifests": sorted(manifests),
        "ownership": {
            "codeowners_file": codeowners_path,
            "owners": sorted(codeowners)[:100],
            "configured": bool(codeowners_path),
        },
    }


def semgrep_rulepacks() -> list[str]:
    configured = os.environ.get("VAPT_SEMGREP_RULESETS", "p/default,p/security-audit,p/owasp-top-ten,p/secrets")
    return list(dict.fromkeys(value.strip() for value in configured.split(",") if value.strip()))[:8]


def semgrep_coverage(payload: dict, inventory: dict[str, object], duration: float) -> dict[str, object]:
    """Describe what Semgrep actually analyzed instead of equating exit 0 with coverage."""
    paths = payload.get("paths") if isinstance(payload.get("paths"), dict) else {}
    scanned = paths.get("scanned") if isinstance(paths.get("scanned"), list) else None
    skipped = paths.get("skipped") if isinstance(paths.get("skipped"), list) else []
    errors = payload.get("errors") if isinstance(payload.get("errors"), list) else []
    code_files = sum(int(value) for value in (inventory.get("languages") or {}).values())
    scanned_count = len(scanned) if scanned is not None else None
    coverage_percent = (
        round(min(100.0, (scanned_count / code_files) * 100), 1)
        if code_files and scanned_count is not None
        else (100.0 if not code_files else 0.0)
    )
    status = "completed"
    limitations: list[str] = []
    if errors:
        status = "partial"
        limitations.append(f"Semgrep reported {len(errors)} analysis error(s).")
    if code_files and scanned is None:
        status = "partial"
        limitations.append("Semgrep did not report its analyzed-file inventory.")
    elif code_files and scanned_count is not None and scanned_count < code_files:
        status = "partial"
        limitations.append(
            f"Semgrep reported {scanned_count} analyzed source file(s) out of {code_files} discovered."
        )
    evidence: dict[str, object] = {
        "status": status,
        "duration_seconds": round(float(duration), 2),
        "source_files": code_files,
        "analysis_coverage_percent": coverage_percent,
        "scanner_errors": len(errors),
        "skipped_files": len(skipped),
    }
    if scanned is not None:
        evidence["scanned_files"] = len(scanned)
    if limitations:
        evidence["limitation"] = " ".join(limitations)
    return evidence


def _deduplicate_findings(findings: list[dict]) -> list[dict]:
    return list({item["fingerprint"]: item for item in findings}.values())


async def run_assessment(assessment_id: str, repository: str, ref: str, config: AppConfig) -> dict:
    repository = validate_repository_url(repository)
    ref = validate_ref(ref)
    store = PersistenceStore(config.database.url)
    runner = DockerRunner(config, use_queue=False)
    workspace = ensure_shared_dir() / f"appsec_{assessment_id}"
    container_workspace = f"{CONTAINER_SHARED_DIR}/{workspace.name}"
    findings: list[dict] = []
    coverage: dict[str, dict] = {
        "sast": {"status": "planned", "tool": "semgrep", "findings": 0},
        "sca": {"status": "planned", "tool": "trivy", "findings": 0},
        "iac": {"status": "planned", "tool": "trivy", "findings": 0},
        "secrets": {"status": "planned", "tool": "gitleaks + trufflehog", "findings": 0},
    }
    store.update_appsec_assessment(assessment_id, {"status": "running", "phase": "checkout", "progress": 5})
    try:
        revision = await _clone(repository, ref, workspace)
        inventory = repository_inventory(workspace)
        rulepacks = semgrep_rulepacks()
        coverage["sast"].update({
            "languages": inventory["languages"],
            "files": inventory["files"],
            "rulepacks": rulepacks,
            "ownership": inventory["ownership"],
        })
        coverage["sca"].update({"manifests": inventory["manifests"]})
        coverage["iac"].update({"manifests": inventory["manifests"]})
        store.update_appsec_assessment(assessment_id, {"commit_sha": revision, "phase": "sast", "progress": 15})
        semgrep_configs = [value for rulepack in rulepacks for value in ("--config", rulepack)]
        scanners = [
            (
                "semgrep", "sast",
                ["semgrep", "scan", *semgrep_configs, "--json", "--time", "--metrics", "off", "--no-autofix", "--disable-version-check", container_workspace],
                parse_semgrep,
            ),
            (
                "trivy", "sca",
                ["fs", "--cache-dir", f"{CONTAINER_SHARED_DIR}/trivy-cache", "--format", "json", "--scanners", "vuln,misconfig", "--quiet", container_workspace],
                parse_trivy,
            ),
        ]
        for index, (tool, lane, args, parser) in enumerate(scanners, start=1):
            tool_log_context.set({"scan_id": assessment_id, "agent": "appsec", "phase": lane})
            coverage[lane]["status"] = "running"
            if lane == "sca":
                coverage["iac"]["status"] = "running"
            store.update_appsec_assessment(assessment_id, {"phase": lane, "progress": 15 + index * 20, "coverage": coverage})
            result = await runner.run_local(tool, args, timeout=900)
            scanner_stdout = result.read_stdout()
            store.append_appsec_run(assessment_id, lane, result.to_dict())
            if scanner_stdout.strip():
                payload = _json_payload(scanner_stdout)
                parsed = parser(payload, repository)
                findings.extend(parsed)
                findings = _deduplicate_findings(findings)
                lane_findings = [item for item in parsed if item.get("category") == lane]
                coverage[lane].update({"status": "completed", "findings": len(lane_findings) if lane == "sca" else len(parsed)})
                coverage[lane]["duration_seconds"] = round(result.duration, 2)
                if lane == "sast":
                    coverage[lane].update(semgrep_coverage(payload, inventory, result.duration))
                if lane == "sca":
                    iac_findings = [item for item in parsed if item.get("category") == "iac"]
                    coverage["iac"].update({
                        "status": "completed",
                        "findings": len(iac_findings),
                        "duration_seconds": round(result.duration, 2),
                        "manifests": inventory["manifests"],
                    })
            elif result.success:
                coverage[lane].update({
                    "status": "partial",
                    "duration_seconds": round(result.duration, 2),
                    "limitation": "Scanner exited successfully but produced no machine-readable evidence.",
                })
                if lane == "sca":
                    coverage["iac"].update(coverage[lane])
            else:
                coverage[lane].update({"status": "unavailable", "error": (result.stderr or "Scanner unavailable")[-500:]})
                if lane == "sca":
                    coverage["iac"].update({"status": "unavailable", "error": coverage[lane]["error"]})
            store.replace_appsec_findings(assessment_id, findings)
            unavailable_now = [name for name, state in coverage.items() if state["status"] in {"unavailable", "partial"}]
            store.update_appsec_assessment(assessment_id, {
                "coverage": coverage,
                "summary": _summary(findings, unavailable_now),
            })

        # Produce a complete CycloneDX inventory separately from the
        # vulnerability-only normalized finding set. This remains an artifact,
        # not a finding count, so a clean SBOM is never presented as proof that
        # dependencies are vulnerability-free.
        tool_log_context.set({"scan_id": assessment_id, "agent": "appsec", "phase": "sbom"})
        sbom_result = await runner.run_local(
            "trivy",
            [
                "fs", "--cache-dir", f"{CONTAINER_SHARED_DIR}/trivy-cache",
                "--format", "cyclonedx", "--scanners", "vuln", "--quiet",
                container_workspace,
            ],
            timeout=900,
        )
        sbom_state: dict[str, object] = {"status": "unavailable"}
        sbom_stdout = sbom_result.read_stdout()
        store.append_appsec_run(assessment_id, "sbom", sbom_result.to_dict())
        if sbom_stdout.strip():
            try:
                sbom_payload = _json_payload(sbom_stdout)
                if sbom_payload.get("bomFormat") == "CycloneDX":
                    artifact = store.save_appsec_artifact(
                        assessment_id,
                        kind="sbom",
                        format="cyclonedx-json",
                        filename=f"{assessment_id}.cdx.json",
                        content=json.dumps(sbom_payload, indent=2, ensure_ascii=True),
                    )
                    sbom_state = {
                        "status": "completed",
                        "components": len(sbom_payload.get("components") or []),
                        "format": "CycloneDX JSON",
                        "sha256": artifact["sha256"],
                        "size": artifact["size"],
                    }
            except Exception as exc:
                sbom_state = {"status": "partial", "limitation": f"Invalid CycloneDX output: {exc}"}
        elif sbom_result.success:
            sbom_state = {"status": "partial", "limitation": "Trivy returned no CycloneDX document."}
        else:
            sbom_state = {"status": "unavailable", "limitation": (sbom_result.stderr or "SBOM generation failed")[-500:]}
        coverage["sca"]["sbom"] = sbom_state

        lane = "secrets"
        report_path = workspace / "gitleaks.json"
        container_report = f"{container_workspace}/gitleaks.json"
        tool_log_context.set({"scan_id": assessment_id, "agent": "appsec", "phase": lane})
        coverage[lane]["status"] = "running"
        store.update_appsec_assessment(assessment_id, {"phase": lane, "progress": 70, "coverage": coverage})
        result = await runner.run_local(
            "gitleaks",
            [
                "detect", "--source", container_workspace, "--no-git",
                "--report-format", "json", "--report-path", container_report,
                "--exit-code", "0", "--no-banner",
            ],
            timeout=600,
        )
        store.append_appsec_run(assessment_id, lane, result.to_dict())
        gitleaks_completed = False
        if report_path.exists():
            parsed = parse_gitleaks(_json_payload(report_path.read_text(encoding="utf-8")), repository)
            findings.extend(parsed)
            gitleaks_completed = True
        elif result.success:
            gitleaks_completed = True

        # TruffleHog complements Gitleaks with broader classification and an
        # optional provider-verification pass. External verification is off by
        # default because it contacts credential providers; enable it only
        # under an engagement policy that permits those validation requests.
        active_verification = os.environ.get("VAPT_SECRET_ACTIVE_VERIFICATION", "false").lower() in {"1", "true", "yes"}
        truffle_args = ["filesystem", container_workspace, "--json", "--no-update"]
        if active_verification:
            truffle_args.extend(["--results=verified,unknown"])
        else:
            truffle_args.extend(["--no-verification", "--results=unverified,unknown"])
        truffle_result = await runner.run_local("trufflehog", truffle_args, timeout=900)
        truffle_stdout = truffle_result.read_stdout()
        store.append_appsec_run(assessment_id, lane, truffle_result.to_dict())
        findings.extend(parse_trufflehog(truffle_stdout, repository))
        findings = merge_secret_findings(findings)
        findings = _deduplicate_findings(findings)

        if gitleaks_completed or truffle_result.success:
            coverage[lane].update({
                "status": "completed",
                "findings": sum(1 for item in findings if item.get("category") == "secret"),
                "verification": "active" if active_verification else "classification-only",
                "detectors": {
                    "gitleaks": "completed" if gitleaks_completed else "unavailable",
                    "trufflehog": "completed" if truffle_result.success else "unavailable",
                },
            })
        else:
            errors = " | ".join(filter(None, [result.stderr, truffle_result.stderr]))
            coverage[lane].update({"status": "unavailable", "error": (errors or "Secret scanners unavailable")[-500:]})

        store.replace_appsec_findings(assessment_id, findings)
        unavailable = [lane for lane, state in coverage.items() if state["status"] in {"unavailable", "partial"}]
        status = "partial" if unavailable else "completed"
        baseline = store.load_previous_appsec_assessment(repository, ref=ref, exclude_id=assessment_id)
        summary = _summary(findings, unavailable)
        diff = assessment_diff(findings, (baseline or {}).get("findings") or [])
        baseline_revision = str((baseline or {}).get("commit_sha") or "")
        diff.update({
            "current_commit_sha": revision,
            "baseline_commit_sha": baseline_revision,
            "same_commit": bool(baseline_revision and baseline_revision == revision),
        })
        summary["diff"] = diff
        summary["baseline_assessment_id"] = (baseline or {}).get("assessment_id", "")
        store.update_appsec_assessment(assessment_id, {
            "status": status,
            "phase": "complete",
            "progress": 100,
            "coverage": coverage,
            "summary": summary,
        })
        return {"assessment_id": assessment_id, "status": status, "findings": len(findings)}
    except Exception as exc:
        store.update_appsec_assessment(assessment_id, {
            "status": "failed", "phase": "failed", "error": str(exc)[:2000],
            "coverage": coverage,
        })
        raise
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def _summary(findings: list[dict], unavailable: list[str]) -> dict:
    severities = {key: 0 for key in ("critical", "high", "medium", "low", "informational")}
    categories: dict[str, int] = {}
    for finding in findings:
        severity = finding.get("severity", "informational")
        severities[severity] = severities.get(severity, 0) + 1
        category = finding.get("category", "other")
        categories[category] = categories.get(category, 0) + 1
    return {"total": len(findings), "severities": severities, "categories": categories, "unavailable": unavailable}


def assessment_diff(current: list[dict], baseline: list[dict]) -> dict[str, object]:
    """Compare stable fingerprints without changing finding verification state."""
    current_ids = {str(item.get("fingerprint") or "") for item in current if item.get("fingerprint")}
    baseline_ids = {str(item.get("fingerprint") or "") for item in baseline if item.get("fingerprint")}
    return {
        "new": len(current_ids - baseline_ids),
        "unchanged": len(current_ids & baseline_ids),
        "resolved": len(baseline_ids - current_ids),
        "new_fingerprints": sorted(current_ids - baseline_ids)[:200],
        "resolved_fingerprints": sorted(baseline_ids - current_ids)[:200],
        "has_baseline": bool(baseline),
    }


def assessment_to_sarif(assessment: dict) -> dict:
    """Export normalized code findings as interoperable SARIF 2.1.0."""
    findings = assessment.get("findings") or []
    rules: dict[str, dict] = {}
    results: list[dict] = []
    level_map = {
        "critical": "error", "high": "error", "medium": "warning",
        "low": "note", "informational": "note",
    }
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "vapt-observation")
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": str(finding.get("title") or rule_id)[:1000]},
            "help": {"text": str(finding.get("remediation") or "Review and remediate the security observation.")[:4000]},
            "properties": {
                "source": finding.get("source", ""),
                "category": finding.get("category", ""),
                "cwe": finding.get("cwe_ids") or [],
            },
        })
        result: dict[str, object] = {
            "ruleId": rule_id,
            "level": level_map.get(str(finding.get("severity") or "informational"), "note"),
            "message": {"text": str(finding.get("description") or finding.get("title") or rule_id)[:4000]},
            "partialFingerprints": {"vaptFingerprint": finding.get("fingerprint", "")},
            "properties": {
                "severity": finding.get("severity", "informational"),
                "confidence": finding.get("confidence", "medium"),
                "verificationStatus": finding.get("status", "candidate"),
                "cve": finding.get("cve_ids") or [],
            },
        }
        if finding.get("path"):
            region: dict[str, int] = {}
            if finding.get("start_line"):
                region["startLine"] = int(finding["start_line"])
            if finding.get("end_line"):
                region["endLine"] = int(finding["end_line"])
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(finding["path"])},
                    **({"region": region} if region else {}),
                }
            }]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "VAPT Platform Unified AppSec",
                    "informationUri": "https://github.com/techyringo/vapt-platform",
                    "rules": list(rules.values()),
                }
            },
            "automationDetails": {"id": assessment.get("assessment_id", "")},
            "versionControlProvenance": [{
                "repositoryUri": assessment.get("repository", ""),
                "revisionId": assessment.get("commit_sha", ""),
                "branch": assessment.get("ref", ""),
            }],
            "results": results,
        }],
    }
