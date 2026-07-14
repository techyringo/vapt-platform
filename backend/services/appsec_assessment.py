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
    for path in workspace.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        files_scanned += 1
        language = _LANGUAGE_EXTENSIONS.get(path.suffix.lower())
        if language:
            languages[language] += 1
        if path.name in manifest_names:
            manifests.add(path.name)
    return {
        "files": files_scanned,
        "languages": dict(languages.most_common(12)),
        "manifests": sorted(manifests),
    }


def semgrep_rulepacks() -> list[str]:
    configured = os.environ.get("VAPT_SEMGREP_RULESETS", "p/default,p/security-audit")
    return list(dict.fromkeys(value.strip() for value in configured.split(",") if value.strip()))[:8]


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
        })
        coverage["sca"].update({"manifests": inventory["manifests"]})
        store.update_appsec_assessment(assessment_id, {"commit_sha": revision, "phase": "sast", "progress": 15})
        semgrep_configs = [value for rulepack in rulepacks for value in ("--config", rulepack)]
        scanners = [
            (
                "semgrep", "sast",
                ["semgrep", "scan", *semgrep_configs, "--json", "--metrics", "off", "--no-autofix", "--disable-version-check", container_workspace],
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
            store.update_appsec_assessment(assessment_id, {"phase": lane, "progress": 15 + index * 20, "coverage": coverage})
            result = await runner.run_local(tool, args, timeout=900)
            store.append_appsec_run(assessment_id, lane, result.to_dict())
            if result.stdout.strip():
                parsed = parser(_json_payload(result.stdout), repository)
                findings.extend(parsed)
                findings = _deduplicate_findings(findings)
                coverage[lane].update({"status": "completed", "findings": len(parsed)})
            elif result.success:
                coverage[lane]["status"] = "completed"
            else:
                coverage[lane].update({"status": "unavailable", "error": (result.stderr or "Scanner unavailable")[-500:]})
            store.replace_appsec_findings(assessment_id, findings)
            unavailable_now = [name for name, state in coverage.items() if state["status"] == "unavailable"]
            store.update_appsec_assessment(assessment_id, {
                "coverage": coverage,
                "summary": _summary(findings, unavailable_now),
            })

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
        store.append_appsec_run(assessment_id, lane, truffle_result.to_dict())
        findings.extend(parse_trufflehog(truffle_result.stdout, repository))
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
        unavailable = [lane for lane, state in coverage.items() if state["status"] == "unavailable"]
        status = "partial" if unavailable else "completed"
        store.update_appsec_assessment(assessment_id, {
            "status": status,
            "phase": "complete",
            "progress": 100,
            "coverage": coverage,
            "summary": _summary(findings, unavailable),
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
