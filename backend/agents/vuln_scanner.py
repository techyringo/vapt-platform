"""
VAPT Multi-Agent System — Vulnerability Scanner Agent

Template-based vulnerability detection:
  - nuclei (full template suite with severity/tag filtering)
  - nikto (web server misconfiguration scanner)
  - wpscan (WordPress vulnerability scanner)
  - Custom vulnerability checks
"""

import asyncio
import json
import tempfile
import os
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urljoin

from loguru import logger

from core.models import (
    AgentTask, AgentType, Finding, Severity, Target, ScanResult,
)
from core.scope import ScopeManager
from core.config import AppConfig
from agents.base import BaseAgent
from tools.runner import DockerRunner, OutputParser


class VulnScannerAgent(BaseAgent):
    """Template-based vulnerability scanning agent.

    Runs nuclei with the full template suite, nikto for web server
    misconfigurations, and CMS-specific scanners (wpscan, etc.)
    based on technology detection from earlier phases.
    Also uses LLM to identify context-aware vulnerabilities that
    template scanners miss (misconfigurations, logic issues, etc.).
    """

    def __init__(self, scope: ScopeManager, config: AppConfig) -> None:
        super().__init__(AgentType.VULN_SCANNER, scope, config)
        self._runner = DockerRunner(config)
        self._llm_client = None
        self._cve_resolver = None  # lazily built — see _get_cve_resolver
        self._warned_missing_nuclei_templates = False

    def _get_cve_resolver(self):
        """Lazily build the LLM+NVD resolver so nuclei-derived CVEs are
        verified against NVD (drops rejected / non-existent CVEs) and the
        LLM can propose additional CWEs grounded in the evidence.
        """
        if self._cve_resolver is not None:
            return self._cve_resolver
        try:
            from tools.llm_client import LLMClient
            from tools.cve_resolver import CVEResolver
            from services.nvd_service import NVDService
            if self._llm_client is None:
                self._llm_client = LLMClient(self.config)
            self._cve_resolver = CVEResolver(self._llm_client, NVDService())
        except Exception as exc:
            logger.debug("[VULN_SCAN] Could not init CVE resolver: {err}", err=exc)
            self._cve_resolver = None
        return self._cve_resolver

    async def execute(self, task: AgentTask) -> list[Finding]:
        """Execute vulnerability scanning against all discovered targets."""
        logger.info("[VULN_SCAN] Starting vulnerability scan")
        self.clear_findings()
        self.clear_tool_runs()

        recon_data = task.parameters.get("recon_data", task.result or {})
        enum_data = task.parameters.get("enum_data", {})
        existing_findings = task.parameters.get("existing_findings", [])
        live_urls = recon_data.get("live_urls", [])
        subdomains = recon_data.get("subdomains", [])
        historical_urls = recon_data.get("historical_urls", [])
        crawled_urls = recon_data.get("crawled_urls", [])
        technologies = self._normalize_technologies(
            recon_data.get("technologies", {}),
            live_urls,
            historical_urls,
            crawled_urls,
            existing_findings,
        )

        # Build target list
        targets = self._build_target_list(task.target, live_urls, subdomains, historical_urls, crawled_urls)
        if not targets:
            logger.warning("[VULN_SCAN] No targets to scan")
            return []

        logger.info("[VULN_SCAN] Scanning {count} targets", count=len(targets))

        evidence_tokens: frozenset[str] = frozenset(
            task.parameters.get("evidence_tokens") or set()
        )

        # Run scanners
        all_nuclei_findings = []
        nikto_findings = []
        cms_findings = []
        tech_nuclei_findings: list[dict] = []

        if self.config.tools.get("nuclei", AppConfig().get_tool_config("nuclei")).enabled:
            all_nuclei_findings = await self._run_nuclei(targets)

        web_roots = self._preferred_web_roots(self._web_roots(targets))

        await self._augment_cms_detection_from_targets(web_roots, technologies)

        if self.config.tools.get("nikto", AppConfig().get_tool_config("nikto")).enabled:
            nikto_findings = await self._run_nikto(web_roots[:5])
            nikto_findings = await self._validate_nikto_findings(nikto_findings)
            self._augment_cms_detection_from_nikto(nikto_findings, technologies)

        cms_findings = await self._run_cms_scanners(web_roots, technologies)

        # Evidence-driven pass: fire targeted nuclei for every detected tech /
        # service that has a matching entry in TECH_NUCLEI_TAGS and that was NOT
        # already handled by the dedicated CMS scanners above.
        tech_nuclei_findings = await self._run_tech_specific_nuclei(
            targets, evidence_tokens, technologies
        )

        # Convert all findings to Finding objects
        self._convert_nuclei_findings(all_nuclei_findings, task.target)
        self._convert_nikto_findings(nikto_findings, task.target)
        self._convert_cms_findings(cms_findings, task.target)
        self._convert_nuclei_findings(tech_nuclei_findings, task.target)

        # Run custom checks (async — uses httpx.AsyncClient)
        await self._run_custom_checks(web_roots, technologies, task.target)

        # Safe, non-destructive targeted web modules (P1): CORS, security
        # headers, open redirect, reflected-input. Each proves impact via
        # request/response replay without firing destructive payloads.
        await self._run_safe_web_modules(web_roots, task.target)

        # LLM-powered vulnerability analysis (context-aware)
        await self._run_llm_vuln_analysis(targets, technologies, task.target)

        # ── NVD verification + LLM-proposed CWE for every finding ──
        # nuclei / nikto / wpscan emit CVEs that may be stale, rejected, or
        # simply wrong. We route every finding through the resolver so:
        #   (a) CVEs NVD marks REJECTED / NOT_FOUND are dropped,
        #   (b) official CVSS scores + descriptions replace tool guesses,
        #   (c) the LLM proposes additional CWEs grounded in the evidence,
        #       validated against the CWE-NNN format.
        await self._verify_findings()

        task.result = {
            "nuclei_findings": all_nuclei_findings,
            "nikto_findings": nikto_findings,
            "cms_findings": cms_findings,
            "tech_nuclei_findings": tech_nuclei_findings,
            "technologies": technologies,
            "tool_runs": self.get_tool_runs(),
            "total_vulnerabilities": len(self._findings),
        }

        logger.info("[VULN_SCAN] Complete: {count} vulnerabilities found", count=len(self._findings))
        return self.get_findings()

    async def _run_safe_web_modules(self, web_roots: list[str], primary_target: Target) -> None:
        """Run the P1 safe web-validation modules against each in-scope web root.

        Findings carry request/response replay proof. Each is passed through the
        false-positive reducer's heuristic verdict to set a defensible status
        before it enters the pipeline.
        """
        from agents.modules import run_modules
        from core.fp_reducer import heuristic_verdict

        scope_config = getattr(self.scope, "_config", None)
        roots = [r for r in (web_roots or []) if r and self.is_in_scope(r)]
        if not roots:
            roots = [primary_target.base_url]

        seen: set[str] = set()
        for root in roots[:5]:  # bound the surface per scan
            canonical = self._canonical_root(root) or root
            if canonical in seen:
                continue
            seen.add(canonical)
            parsed = urlparse(canonical)
            target = Target(
                host=parsed.hostname or primary_target.host,
                port=parsed.port or (443 if parsed.scheme == "https" else 80),
                protocol=parsed.scheme or "https",
                url=canonical,
            )
            try:
                module_findings = await run_modules(target, scope_config)
            except Exception as exc:
                logger.warning("[VULN_SCAN] Safe modules failed for {root}: {err}", root=canonical, err=exc)
                continue
            for finding in module_findings:
                verdict = heuristic_verdict(finding.to_report_dict())
                if verdict.status == "false_positive":
                    logger.debug("[VULN_SCAN] Module finding demoted to FP: {t}", t=finding.title)
                    continue
                # Keep the stronger of the module's and the reducer's confidence.
                if verdict.status == "confirmed":
                    finding.status = "confirmed"
                self._add_finding(finding)

    async def _verify_findings(self) -> None:
        """Run the LLM+NVD CVE/CWE resolver over every finding produced so far."""
        resolver = self._get_cve_resolver()
        if resolver is None:
            logger.debug("[VULN_SCAN] CVE resolver unavailable — skipping NVD verification")
            return
        for f in self._findings:
            try:
                await resolver.enrich(f)
            except Exception as exc:
                logger.debug("[VULN_SCAN] Enrichment failed for '{t}': {err}",
                             t=f.title[:60], err=exc)

    def _build_target_list(
        self,
        primary_target: Target,
        live_urls: list[dict],
        subdomains: list[str],
        historical_urls: list[str] | None = None,
        crawled_urls: list[str] | None = None,
    ) -> list[str]:
        """Build a list of URLs to scan."""
        targets = []

        # Add primary target as a canonical web root.
        primary_root = self._canonical_root(primary_target.base_url) or primary_target.base_url
        targets.append(primary_root)

        # Add live URLs from recon
        for entry in live_urls:
            url = entry.get("url", "")
            if url and self.is_in_scope(url):
                targets.append(url)

        # Add subdomains (only https for speed)
        for sub in subdomains:
            url = f"https://{sub}"
            if self.is_in_scope(url):
                targets.append(url)

        # Add discovered endpoints from gau/wayback/katana. Cap the corpus so
        # VA scans stay responsive while still testing high-value paths.
        for url in (crawled_urls or [])[:150]:
            if url and self.is_in_scope(url):
                targets.append(url)
        for url in (historical_urls or [])[:150]:
            if url and self.is_in_scope(url):
                targets.append(url)

        return sorted({url for url in targets if url and self.is_in_scope(url)})

    @staticmethod
    def _adaptive_timeout(
        count: int,
        base_seconds: int,
        per_target_seconds: int,
        max_seconds: int,
    ) -> int:
        multiplier_raw = os.environ.get("VAPT_TOOL_TIMEOUT_MULTIPLIER", "1.0")
        try:
            multiplier = max(0.5, min(float(multiplier_raw), 3.0))
        except ValueError:
            multiplier = 1.0
        computed = base_seconds + max(1, count) * per_target_seconds
        return int(min(max_seconds, computed * multiplier))

    @staticmethod
    def _canonical_root(url: str) -> str:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            return ""
        host = parsed.hostname.lower()
        port = parsed.port
        default_port = (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)
        netloc = host if not port or default_port else f"{host}:{port}"
        return f"{parsed.scheme}://{netloc}"

    def _web_roots(self, targets: list[str]) -> list[str]:
        roots = []
        seen = set()
        for target in targets:
            root = self._canonical_root(target)
            if not root or root in seen or not self.is_in_scope(root):
                continue
            seen.add(root)
            roots.append(root)
        return sorted(roots)

    @staticmethod
    def _preferred_web_roots(roots: list[str]) -> list[str]:
        """Deduplicate web roots by host, preferring HTTPS over HTTP."""
        by_host: dict[str, str] = {}
        for root in roots:
            parsed = urlparse(root)
            host = (parsed.hostname or "").lower()
            if not host:
                continue
            current = by_host.get(host)
            if current is None or parsed.scheme == "https":
                by_host[host] = root
        return sorted(by_host.values())

    def _prioritize_nuclei_targets(self, targets: list[str]) -> list[str]:
        """Bound broad nuclei input so it cannot stall the whole vuln phase."""
        max_targets = int(os.environ.get("VAPT_NUCLEI_MAX_TARGETS", "8"))
        roots = self._preferred_web_roots(self._web_roots(targets))
        root_set = set(roots)
        high_value_markers = (
            "wp-", "admin", "login", "api", "swagger", "openapi", "graphql",
            ".env", ".git", "config", "backup", "debug", "phpinfo",
        )
        high_value = [
            target for target in targets
            if target not in root_set and any(marker in target.lower() for marker in high_value_markers)
        ]
        remainder = [target for target in targets if target not in root_set and target not in high_value]
        ordered = roots + high_value + remainder
        deduped = list(dict.fromkeys(target for target in ordered if target and self.is_in_scope(target)))
        return deduped[:max(1, max_targets)]

    @staticmethod
    def _batches(items: list[str], size: int) -> list[list[str]]:
        size = max(1, size)
        return [items[index:index + size] for index in range(0, len(items), size)]

    def _normalize_technologies(
        self,
        technologies: dict[str, list[str]],
        live_urls: list[dict],
        historical_urls: list[str],
        crawled_urls: list[str],
        existing_findings: list[Any],
    ) -> dict[str, list[str]]:
        """Merge technology signals from recon maps, URLs, and prior findings."""
        normalized: dict[str, set[str]] = {}

        def add(host: str, tech: str) -> None:
            if not host or not tech:
                return
            normalized.setdefault(host.lower(), set()).add(tech)

        for host, techs in (technologies or {}).items():
            for tech in techs or []:
                add(host, str(tech))

        for entry in live_urls or []:
            if not isinstance(entry, dict):
                continue
            url = entry.get("url") or entry.get("input") or ""
            parsed = urlparse(url)
            host = parsed.hostname or ""
            for tech in entry.get("tech") or []:
                add(host, str(tech))
            text = " ".join(str(entry.get(key, "")) for key in ("url", "title", "webserver", "server")).lower()
            self._add_cms_url_signals(host, text, add)

        for url in [*(historical_urls or []), *(crawled_urls or [])]:
            parsed = urlparse(str(url))
            self._add_cms_url_signals(parsed.hostname or "", str(url).lower(), add)

        for finding in existing_findings or []:
            title = getattr(finding, "title", "") or (finding.get("title", "") if isinstance(finding, dict) else "")
            evidence = getattr(finding, "evidence", "") or (finding.get("evidence", "") if isinstance(finding, dict) else "")
            target = getattr(finding, "target", None)
            host = getattr(target, "host", "") if target is not None else ""
            if isinstance(finding, dict):
                host = host or finding.get("target_host", "")
            text = f"{title} {evidence}".lower()
            self._add_cms_url_signals(host, text, add)

        return {host: sorted(values) for host, values in normalized.items()}

    @staticmethod
    def _add_cms_url_signals(host: str, text: str, add) -> None:
        if not host or not text:
            return
        if "wordpress" in text or "wp-content" in text or "wp-includes" in text or "/wp-json" in text:
            add(host, "WordPress")
        if "drupal" in text or "/sites/default/" in text:
            add(host, "Drupal")
        if "joomla" in text or "com_content" in text:
            add(host, "Joomla")

    async def _augment_cms_detection_from_targets(
        self,
        targets: list[str],
        technologies: dict[str, list[str]],
    ) -> None:
        """Add CMS tech signals from lightweight in-scope page probes.

        httpx fingerprints are useful, but they are not a contract. A site can
        expose obvious CMS paths without sending a technology header/title. This
        pass keeps CMS-specific scanners evidence-driven without depending on a
        single upstream tool.
        """
        if not targets:
            return

        import httpx as httpx_client

        def add(host: str, tech: str) -> None:
            if not host or not tech:
                return
            existing = {item.lower() for item in technologies.setdefault(host.lower(), [])}
            if tech.lower() not in existing:
                technologies[host.lower()].append(tech)

        async with httpx_client.AsyncClient(
            verify=False,
            timeout=12,
            follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0"},
        ) as client:
            for url in targets[:25]:
                if not self.is_in_scope(url):
                    continue
                parsed = urlparse(url)
                host = (parsed.hostname or "").lower()
                if not host:
                    continue
                try:
                    response = await client.get(url)
                except Exception as exc:
                    logger.debug("[VULN_SCAN] CMS probe failed for {url}: {err}", url=url, err=exc)
                    continue

                text = " ".join([
                    str(response.headers.get("server", "")),
                    str(response.headers.get("x-powered-by", "")),
                    str(response.headers.get("link", "")),
                    response.text[:250_000],
                ]).lower()
                before = set(technologies.get(host, []))
                self._add_cms_url_signals(host, text, add)
                detected = sorted(set(technologies.get(host, [])) - before)
                if detected:
                    logger.info(
                        "[VULN_SCAN] CMS detected by active probe on {host}: {tech}",
                        host=host,
                        tech=", ".join(detected),
                    )

    def _augment_cms_detection_from_nikto(
        self,
        nikto_findings: list[dict],
        technologies: dict[str, list[str]],
    ) -> None:
        """Promote CMS hints from Nikto output before CMS-specific scanners run."""
        if not nikto_findings:
            return

        def add(host: str, tech: str) -> None:
            if not host or not tech:
                return
            existing = {item.lower() for item in technologies.setdefault(host.lower(), [])}
            if tech.lower() not in existing:
                technologies[host.lower()].append(tech)

        for item in nikto_findings:
            host = str(item.get("host") or "").lower()
            text = f"{item.get('finding', '')} {item.get('raw', '')}".lower()
            before = set(technologies.get(host, []))
            self._add_cms_url_signals(host, text, add)
            detected = sorted(set(technologies.get(host, [])) - before)
            if detected:
                logger.info(
                    "[VULN_SCAN] CMS detected from Nikto evidence on {host}: {tech}",
                    host=host,
                    tech=", ".join(detected),
                )

    async def _run_nuclei(self, targets: list[str]) -> list[dict]:
        """Run nuclei with full template suite."""
        from tools.runner import shared_temp_path
        selected_targets = self._prioritize_nuclei_targets(targets)
        batch_size = int(os.environ.get("VAPT_NUCLEI_BATCH_SIZE", "8"))
        batch_timeout = int(os.environ.get("VAPT_NUCLEI_BATCH_TIMEOUT", "180"))
        total_budget = int(os.environ.get("VAPT_NUCLEI_TOTAL_BUDGET", "240"))
        started = time.monotonic()
        all_parsed: list[dict] = []

        nuc_config = self.config.tools.get("nuclei", AppConfig().get_tool_config("nuclei"))
        extra_args = nuc_config.extra_args if nuc_config else []

        # Build template tag filter from preserved tool settings (Bug #7 fix)
        tag_args: list[str] = []
        raw_nuc = self.config.tools.get("nuclei")
        template_tags = None
        if raw_nuc is not None:
            template_tags = getattr(raw_nuc, "settings", {}).get("template_tags")
            if not template_tags:
                template_tags = getattr(raw_nuc, "template_tags", None)
        if template_tags:
            tag_args = ["-tags", ",".join(template_tags)]
        template_args = self._nuclei_template_args()

        batches = self._batches(selected_targets, batch_size)
        logger.info(
            "[VULN_SCAN] nuclei broad pass: {targets}/{total} targets in {batches} batch(es)",
            targets=len(selected_targets),
            total=len(targets),
            batches=len(batches),
        )

        for index, batch in enumerate(batches, 1):
            remaining = total_budget - (time.monotonic() - started)
            if remaining <= 5:
                logger.warning(
                    "[VULN_SCAN] nuclei total budget exhausted after {elapsed:.1f}s; stopping broad pass",
                    elapsed=time.monotonic() - started,
                )
                break
            host_path = shared_temp_path(suffix=".txt")
            with open(host_path, "w") as f:
                f.write("\n".join(batch))

            try:
                result = await self._runner.run(
                    tool_name="nuclei",
                    args=[
                        "-l", host_path,
                        "-jsonl",
                        "-silent",
                        "-retries", "1",
                        "-timeout", "18",
                        "-c", "12",
                        "-rate-limit", "35",
                        "-max-host-error", "20",
                    ] + template_args + extra_args + tag_args,
                    timeout=max(5, min(int(remaining), batch_timeout, self._adaptive_timeout(len(batch), 90, 10, batch_timeout))),
                )
                self._record_tool_run(result, "vuln_scanning")
                if result.stdout.strip():
                    parsed = OutputParser.parse_nuclei(result.stdout)
                    all_parsed.extend(parsed)
                    logger.info(
                        "[VULN_SCAN] nuclei batch {idx}/{total}: {count} findings",
                        idx=index,
                        total=len(batches),
                        count=len(parsed),
                    )
                if result.timed_out:
                    logger.warning(
                        "[VULN_SCAN] nuclei batch {idx}/{total} timed out; continuing with remaining phases",
                        idx=index,
                        total=len(batches),
                    )
                    # Repeating the same broad template set against another
                    # batch after a timeout creates multi-minute cascades.
                    # Preserve partial output and let evidence-targeted passes
                    # continue instead.
                    break
            finally:
                try:
                    os.unlink(host_path)
                except OSError:
                    pass

        return all_parsed

    def _nuclei_template_args(self) -> list[str]:
        """Return a concrete nuclei template directory argument when available."""
        nuc_config = self.config.tools.get("nuclei", AppConfig().get_tool_config("nuclei"))
        settings = getattr(nuc_config, "settings", {}) if nuc_config else {}
        candidates = [
            os.environ.get("VAPT_NUCLEI_TEMPLATES", ""),
            settings.get("templates_path", ""),
            os.environ.get("NUCLEI_TEMPLATES_DIRECTORY", ""),
            "/nuclei-templates",
            "/root/nuclei-templates",
        ]
        for raw in candidates:
            if not raw:
                continue
            path = Path(str(raw))
            try:
                if path.exists() and any(path.rglob("*.yaml")):
                    return ["-templates", str(path)]
            except OSError:
                continue
        if not self._warned_missing_nuclei_templates:
            logger.warning(
                "[VULN_SCAN] nuclei templates not found. Expected /nuclei-templates "
                "or VAPT_NUCLEI_TEMPLATES; nuclei scans will fail until templates are installed."
            )
            self._warned_missing_nuclei_templates = True
        return []

    async def _run_nikto(self, targets: list[str]) -> list[dict]:
        """Run nikto on web targets."""
        all_findings = []
        max_time = int(os.environ.get("VAPT_NIKTO_MAXTIME", "90"))
        for target in targets:
            result = await self._runner.run(
                tool_name="nikto",
                args=["-h", target, "-nointeractive", "-maxtime", str(max_time)],
                timeout=max_time + 45,
            )
            self._record_tool_run(result, "vuln_scanning")
            if result.stdout.strip():
                findings = OutputParser.parse_nikto(result.stdout)
                parsed = urlparse(target)
                for item in findings:
                    item.setdefault("target_url", target)
                    item.setdefault("host", parsed.hostname or "")
                all_findings.extend(findings)
                logger.info("[VULN_SCAN] nikto on {t}: {c} findings", t=target, c=len(findings))
            elif not result.success:
                logger.warning(
                    "[VULN_SCAN] nikto failed on {t}: exit={code} stderr={err}",
                    t=target,
                    code=result.exit_code,
                    err=(result.stderr or "")[:500],
                )
        return all_findings

    async def _validate_nikto_findings(self, nikto_findings: list[dict]) -> list[dict]:
        """Replay and filter Nikto findings before they become report items.

        Nikto is useful as a discovery tool, but many lines are "potentially
        interesting" hints rather than vulnerabilities. For exposed file claims
        such as `/ai.pem`, require live HTTP proof and classify the actual
        content. Non-reproducible hints are kept in tool artifacts only.
        """
        if not nikto_findings:
            return []

        import httpx as httpx_client
        from core.http_evidence import fetch_missing_baseline

        validated: list[dict] = []
        async with httpx_client.AsyncClient(
            verify=False,
            timeout=10,
            follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0"},
        ) as client:
            baselines: dict[str, Any] = {}
            for item in nikto_findings:
                finding_text = str(item.get("finding") or "")
                lower = finding_text.lower()
                if self._nikto_requires_replay(lower):
                    target_url = str(item.get("target_url") or "")
                    if target_url not in baselines:
                        baselines[target_url] = await fetch_missing_baseline(client, target_url)
                    proof = await self._replay_nikto_path(client, item, baselines[target_url])
                    if not proof:
                        logger.info(
                            "[VULN_SCAN] Dropping weak Nikto hint without replay proof: {finding}",
                            finding=finding_text[:140],
                        )
                        continue
                    item.update(proof)
                validated.append(item)
        return validated

    @staticmethod
    def _nikto_requires_replay(finding_lower: str) -> bool:
        return any(token in finding_lower for token in (
            "potentially interesting",
            "backup",
            "cert file",
            "certificate",
            "private key",
            ".pem",
            ".key",
            ".bak",
            ".old",
            ".zip",
            ".tar",
            ".sql",
            ".env",
            "config file",
        ))

    async def _replay_nikto_path(
        self, client: Any, item: dict, baseline: Any = None
    ) -> dict[str, Any] | None:
        raw = str(item.get("finding") or item.get("raw") or "")
        target_url = str(item.get("target_url") or "")
        if not target_url:
            return None
        match = re.search(r"(?P<path>/[^\s:]+)", raw)
        if not match:
            return None
        path = match.group("path")
        url = urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
        if not self.is_in_scope(url):
            return None
        try:
            response = await client.get(url)
        except Exception as exc:
            logger.debug("[VULN_SCAN] Nikto replay failed for {url}: {err}", url=url, err=exc)
            return None
        if response.status_code not in {200, 206}:
            return None

        from core.http_evidence import equivalent_to_baseline, fingerprint_response
        candidate_fingerprint = fingerprint_response(response)
        if equivalent_to_baseline(candidate_fingerprint, baseline):
            logger.info("[VULN_SCAN] Dropping Nikto soft-404/SPA fallback: {url}", url=url)
            return None

        body = response.text[:80_000]
        body_lower = body.lower()
        content_type = response.headers.get("content-type", "")
        content_length = len(response.content or b"")
        if content_length < 16:
            return None

        is_private_key = any(marker in body for marker in (
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ))
        is_certificate = "-----BEGIN CERTIFICATE-----" in body
        looks_secret = any(marker in body_lower for marker in (
            "aws_access_key_id",
            "aws_secret_access_key",
            "password=",
            "secret_key",
            "api_key",
            "database_url",
            "db_password",
        ))
        generic_html = "text/html" in content_type.lower() and not (is_private_key or is_certificate or looks_secret)
        if generic_html and path.lower().endswith((".pem", ".key", ".env", ".sql", ".bak", ".old")):
            return None

        if is_private_key:
            severity = "critical"
            confidence = "high"
            finding_type = "exposed private key"
            remediation = "Remove the private key from the web root immediately, rotate the key/certificate, and review access logs for retrieval."
        elif looks_secret:
            severity = "high"
            confidence = "high"
            finding_type = "exposed secret/config content"
            remediation = "Remove the exposed file from the web root, rotate affected secrets, and restrict access to deployment artifacts."
        elif is_certificate:
            severity = "informational"
            confidence = "medium"
            finding_type = "public certificate file"
            remediation = "Move certificate artifacts out of the web root unless they are intentionally public. Confirm no private key is exposed."
        else:
            severity = "low"
            confidence = "medium"
            finding_type = "retrievable backup/config-like file"
            remediation = "Verify whether this file is intended to be public. Remove backup/config artifacts from the web root and block direct access."

        safe_sample = body[:600].replace("\x00", "\\0")
        return {
            "validated_url": url,
            "http_status": response.status_code,
            "content_type": content_type,
            "content_length": content_length,
            "finding_type": finding_type,
            "severity": severity,
            "confidence": confidence,
            "remediation": remediation,
            "request_proof": f"GET {url}",
            "response_proof": (
                f"HTTP {response.status_code}; content-type={content_type or 'unknown'}; "
                f"bytes={content_length}; sample={safe_sample}"
            ),
        }

    async def _run_cms_scanners(self, targets: list[str], technologies: dict[str, list[str]]) -> list[dict]:
        """Run CMS-specific vulnerability scanners based on detected technology."""
        cms_findings = []

        cms_hosts: dict[str, set[str]] = {"wordpress": set(), "joomla": set(), "drupal": set()}
        for host, techs in technologies.items():
            for tech in techs:
                tech_lower = tech.lower()
                if "wordpress" in tech_lower:
                    cms_hosts["wordpress"].add(host.lower())
                if "joomla" in tech_lower:
                    cms_hosts["joomla"].add(host.lower())
                if "drupal" in tech_lower:
                    cms_hosts["drupal"].add(host.lower())

        cms_targets = self._cms_targets_by_family(targets, cms_hosts)

        wp_hosts = cms_hosts["wordpress"]
        wp_targets = cms_targets["wordpress"]
        verified_wp_targets: list[str] = []
        if wp_hosts:
            verified_wp_targets = await self._verified_wordpress_targets(sorted(wp_targets))
            skipped = sorted(set(wp_targets) - set(verified_wp_targets))
            for url in skipped:
                logger.info(
                    "[VULN_SCAN] Skipping WordPress-specific scanners on {url}: active probe did not confirm WordPress",
                    url=url,
                )

        if wp_hosts and self.config.tools.get("wpscan", AppConfig().get_tool_config("wpscan")).enabled:
            from utils.env import first_env_value
            wpscan_token = first_env_value("WPSCAN_API_TOKEN")
            if not wpscan_token:
                logger.warning(
                    "[VULN_SCAN] WPSCAN_API_TOKEN not set — WPScan will enumerate "
                    "components and users but CANNOT report known CVEs. "
                    "Get a free token at https://wpscan.com/api"
                )

            if verified_wp_targets:
                logger.info(
                    "[VULN_SCAN] WordPress detected on {hosts}; starting WPScan on {count} target(s)",
                    hosts=", ".join(sorted(wp_hosts)),
                    count=len(verified_wp_targets),
                )

            for wp_url in verified_wp_targets:
                # WPScan treats "all" and "vulnerable-only" choices as mutually
                # exclusive (for example p cannot be combined with vp). Run a
                # broad component pass first, then a token-backed vulnerable-only
                # pass so we get both inventory and CVE-mapped findings.
                enum_passes = ["p,t,u,tt,cb,dbe"]
                if wpscan_token:
                    enum_passes.append("vp,vt")

                for enum_flags in enum_passes:
                    args = [
                        "--url", wp_url,
                        "--enumerate", enum_flags,
                        "--format", "json",
                        "--random-user-agent",
                        "--disable-tls-checks",
                        "--ignore-main-redirect",
                        "--no-update",
                        "--force",
                        "--request-timeout", "30",
                        "--connect-timeout", "30",
                    ]
                    if wpscan_token:
                        args += ["--api-token", wpscan_token]

                    result = await self._runner.run(
                        tool_name="wpscan",
                        args=args,
                        timeout=int(os.environ.get("VAPT_WPSCAN_TIMEOUT", "480")),
                    )
                    self._record_tool_run(result, "cms_scanning")
                    if result.stdout.strip():
                        findings = OutputParser.parse_wpscan(result.stdout)
                        findings = [item for item in findings if item.get("reportable") is not False]
                        cms_findings.extend(findings)
                        logger.info(
                            "[VULN_SCAN] wpscan on {url} ({flags}): exit={code} findings={c} token={has_token}",
                            url=wp_url,
                            flags=enum_flags,
                            code=result.exit_code,
                            c=len(findings),
                            has_token=bool(wpscan_token),
                        )
                        if not result.success:
                            logger.warning(
                                "[VULN_SCAN] wpscan returned non-zero on {url} ({flags}): exit={code} stderr={err} stdout={out}",
                                url=wp_url,
                                flags=enum_flags,
                                code=result.exit_code,
                                err=(result.stderr or "")[:800],
                                out=(result.stdout or "")[:800],
                            )
                    else:
                        logger.warning(
                            "[VULN_SCAN] wpscan failed/no output on {url} ({flags}): exit={code} stderr={err} stdout={out}",
                            url=wp_url,
                            flags=enum_flags,
                            code=result.exit_code,
                            err=(result.stderr or "")[:800],
                            out=(result.stdout or "")[:800],
                        )
        elif wp_hosts:
            logger.warning("[VULN_SCAN] WordPress detected but WPScan is disabled")

        if wp_hosts:
            cms_targets["wordpress"] = set(verified_wp_targets)

        for family, family_targets in cms_targets.items():
            if not family_targets:
                continue
            cms_findings.extend(await self._run_cms_nuclei(family, sorted(family_targets)))

        return cms_findings

    async def _verified_wordpress_targets(self, targets: list[str]) -> list[str]:
        """Return only targets with active, reproducible WordPress evidence."""
        verified: list[str] = []
        for url in targets:
            if await self._is_wordpress_target(url):
                verified.append(url)
        return verified

    async def _is_wordpress_target(self, root_url: str) -> bool:
        """Actively confirm WordPress before running WPScan.

        Historical URLs and generic scanner text are useful hints, but WPScan is
        noisy and slow when the site is not WordPress. Require current evidence:
        WP generator/meta, wp-content/wp-includes markers, wp-json, or login
        form markers.
        """
        if not root_url or not self.is_in_scope(root_url):
            return False
        import httpx as httpx_client

        checks = [
            root_url,
            urljoin(root_url.rstrip("/") + "/", "wp-json/"),
            urljoin(root_url.rstrip("/") + "/", "wp-login.php"),
        ]
        try:
            async with httpx_client.AsyncClient(
                verify=False,
                timeout=10,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"},
            ) as client:
                for url in checks:
                    response = await client.get(url)
                    text = (
                        response.text[:250_000]
                        + " "
                        + " ".join(f"{k}: {v}" for k, v in response.headers.items())
                    ).lower()
                    if any(marker in text for marker in (
                        "content=\"wordpress",
                        "wp-content/",
                        "wp-includes/",
                        "\"wp-json\"",
                        "/wp-json/",
                        "wp-submit",
                    )):
                        return True
                    if url.rstrip("/").endswith("wp-json") and response.status_code == 200:
                        ctype = response.headers.get("content-type", "").lower()
                        if "json" in ctype and any(marker in text for marker in ("namespaces", "routes", "wp/v2")):
                            return True
        except Exception as exc:
            logger.debug("[VULN_SCAN] WordPress probe failed for {url}: {err}", url=root_url, err=exc)
        return False

    async def _run_tech_specific_nuclei(
        self,
        targets: list[str],
        evidence_tokens: frozenset[str],
        technologies: dict[str, list[str]],
    ) -> list[dict]:
        """Fire targeted nuclei template passes for every detected technology.

        Converts accumulated evidence tokens + the raw technologies dict into
        nuclei `-tags` arguments using TECH_NUCLEI_TAGS from tool_registry.
        WordPress, Joomla, and Drupal are skipped here — _run_cms_scanners
        already handles them with dedicated tools and deeper nuclei passes.

        Groups all eligible tags into a single batched nuclei invocation per
        distinct tag set to avoid spawning dozens of containers.
        """
        from core.tool_registry import TECH_NUCLEI_TAGS, TECH_NUCLEI_SKIP_IN_GENERIC_PASS

        if not targets:
            return []
        if not self.config.tools.get("nuclei", AppConfig().get_tool_config("nuclei")).enabled:
            return []

        # Build evidence tokens from the raw technologies dict so we catch techs
        # that were discovered but not yet flushed into the orchestrator evidence set.
        computed_tokens: set[str] = set(evidence_tokens)
        for _host, techs in (technologies or {}).items():
            for tech in techs:
                token = f"tech_{tech.lower().replace(' ', '_').replace('-', '_')}"
                computed_tokens.add(token)

        # Collect matching nuclei tags, skip those with dedicated handlers.
        matched_tags: set[str] = set()
        for token, tag_string in TECH_NUCLEI_TAGS.items():
            if token in TECH_NUCLEI_SKIP_IN_GENERIC_PASS:
                continue
            if token in computed_tokens:
                for tag in tag_string.split(","):
                    matched_tags.add(tag.strip())

        if not matched_tags:
            logger.debug("[VULN_SCAN] No tech-specific nuclei tags matched — skipping targeted pass")
            return []

        # Deduplicate tags; cap to avoid nuclei template explosion on heavily
        # fingerprinted hosts. Core infra tags first, then the rest.
        priority = {"apache", "nginx", "iis", "php", "java", "spring", "redis",
                    "mysql", "mongodb", "elasticsearch", "ssh", "smb", "aws", "cloud"}
        sorted_tags = sorted(matched_tags, key=lambda t: (0 if t in priority else 1, t))
        tag_arg = ",".join(sorted_tags[:40])  # nuclei handles tag-OR logic internally

        logger.info(
            "[VULN_SCAN] Tech-specific nuclei pass: tags={tags} targets={count}",
            tags=tag_arg,
            count=len(targets),
        )

        from tools.runner import shared_temp_path
        host_path = shared_temp_path(suffix=".txt")
        with open(host_path, "w") as f:
            f.write("\n".join(targets))

        try:
            result = await self._runner.run(
                tool_name="nuclei",
                args=[
                    "-l", host_path,
                    "-jsonl",
                    "-silent",
                    "-retries", "2",
                    "-timeout", "30",
                    "-c", "20",
                    "-rate-limit", "35",
                    *self._nuclei_template_args(),
                    "-tags", tag_arg,
                ],
                timeout=self._adaptive_timeout(len(targets), 300, 15, 1200),
            )
            self._record_tool_run(result, "tech_specific_scanning")
            if result.stdout.strip():
                parsed = OutputParser.parse_nuclei(result.stdout)
                logger.info(
                    "[VULN_SCAN] Tech-specific nuclei ({tags}): {count} findings",
                    tags=tag_arg[:60],
                    count=len(parsed),
                )
                return parsed
            return []
        finally:
            try:
                os.unlink(host_path)
            except OSError:
                pass

    @staticmethod
    def _cms_targets_by_family(targets: list[str], cms_hosts: dict[str, set[str]]) -> dict[str, set[str]]:
        grouped: dict[str, set[str]] = {family: set() for family in cms_hosts}
        for family, hosts in cms_hosts.items():
            for target_url in targets:
                try:
                    parsed = urlparse(target_url)
                    if (parsed.hostname or "").lower() in hosts:
                        grouped[family].add(f"{parsed.scheme}://{parsed.netloc}")
                except Exception:
                    continue
            missing_hosts = {
                host.lower()
                for host in hosts
                if not any((urlparse(url).hostname or "").lower() == host.lower() for url in grouped[family])
            }
            for host in missing_hosts:
                grouped[family].add(f"https://{host}")
        for family, urls in list(grouped.items()):
            grouped[family] = {
                VulnScannerAgent._canonical_root(url) for url in urls
                if VulnScannerAgent._canonical_root(url)
            }
        return grouped

    async def _run_cms_nuclei(self, family: str, targets: list[str]) -> list[dict]:
        """Run CMS-focused nuclei templates for a detected CMS family."""
        if not targets or not self.config.tools.get("nuclei", AppConfig().get_tool_config("nuclei")).enabled:
            return []

        from tools.runner import shared_temp_path
        host_path = shared_temp_path(suffix=".txt")
        with open(host_path, "w") as f:
            f.write("\n".join(targets))

        tag_map = {
            "wordpress": "wordpress,wp,cms",
            "joomla": "joomla,cms",
            "drupal": "drupal,cms",
        }
        try:
            result = await self._runner.run(
                tool_name="nuclei",
                args=[
                    "-l", host_path,
                    "-jsonl",
                    "-silent",
                    "-retries", "2",
                    "-timeout", "30",
                    "-c", "20",
                    "-rate-limit", "35",
                    *self._nuclei_template_args(),
                    "-tags", tag_map.get(family, "cms"),
                ],
                timeout=self._adaptive_timeout(len(targets), 240, 20, 900),
            )
            self._record_tool_run(result, "cms_scanning")
            parsed = OutputParser.parse_nuclei(result.stdout) if result.stdout.strip() else []
            if parsed:
                logger.info("[VULN_SCAN] nuclei CMS {family}: {count} findings", family=family, count=len(parsed))
                return [self._cms_finding_from_nuclei(family, item) for item in parsed]
            if result.success:
                return [{
                    "finding": f"Nuclei CMS template scan completed for {family} with no findings",
                    "component": family,
                    "target_url": targets[0],
                    "informational": True,
                    "source_tool": "nuclei",
                }]
            return []
        finally:
            try:
                os.unlink(host_path)
            except OSError:
                pass

    @staticmethod
    def _cms_finding_from_nuclei(family: str, item: dict) -> dict:
        return {
            "finding": item.get("template_name") or item.get("template_id") or f"{family} CMS issue",
            "component": family,
            "target_url": item.get("url", ""),
            "severity": item.get("severity", "medium"),
            "cve": item.get("cve") or [],
            "cwe": item.get("cwe") or [],
            "references": item.get("reference") or [],
            "raw": item,
            "source_tool": "nuclei",
        }

    def _convert_nuclei_findings(self, nuclei_results: list[dict], target: Target) -> None:
        """Convert nuclei results to Finding objects."""
        for nuc in nuclei_results:
            severity_str = nuc.get("severity", "informational")
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "informational": Severity.INFORMATIONAL,
            }

            url = nuc.get("url", "")
            parsed_host = target.host
            try:
                from urllib.parse import urlparse
                p = urlparse(url)
                if p.hostname:
                    parsed_host = p.hostname
            except Exception:
                pass

            cvss = None
            if nuc.get("cvss_score"):
                try:
                    cvss = float(nuc["cvss_score"])
                except (ValueError, TypeError):
                    pass

            cve_ids = []
            if nuc.get("cve"):
                cve_ids = [nuc["cve"]] if isinstance(nuc["cve"], str) else nuc["cve"]

            cwe_ids = []
            if nuc.get("cwe"):
                cwe_ids = [nuc["cwe"]] if isinstance(nuc["cwe"], str) else nuc["cwe"]

            refs = nuc.get("reference", [])
            if isinstance(refs, str):
                refs = [refs]

            finding = Finding(
                title=nuc.get("template_name", nuc.get("template_id", "Unknown Vulnerability")),
                description=nuc.get("description", f"Vulnerability detected by nuclei template: {nuc.get('template_id', 'N/A')}"),
                severity=severity_map.get(severity_str, Severity.INFORMATIONAL),
                cvss_score=cvss,
                agent_source=AgentType.VULN_SCANNER,
                target=Target(host=parsed_host, url=url or target.base_url),
                evidence="\n".join(nuc.get("extracted_results", [])) or nuc.get("curl_command", ""),
                request_proof=nuc.get("curl_command", ""),
                remediation=nuc.get("remediation", "Review and patch the identified vulnerability."),
                references=refs,
                cve_ids=cve_ids,
                cwe_ids=cwe_ids,
                tags=nuc.get("tags", []) + ["nuclei", nuc.get("template_id", "")],
                confidence="high",
                status="confirmed",
                raw_tool_output=json.dumps(nuc, default=str),
            )
            self._add_finding(finding)

    def _convert_nikto_findings(self, nikto_findings: list[dict], target: Target) -> None:
        """Convert nikto results to Finding objects."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "informational": Severity.INFORMATIONAL,
            "info": Severity.INFORMATIONAL,
        }
        for nk in nikto_findings:
            if nk.get("reportable") is False:
                continue
            validated_url = nk.get("validated_url") or ""
            finding_type = nk.get("finding_type") or "web server issue"
            if self._nikto_requires_replay(str(nk.get("finding", "")).lower()) and not validated_url:
                continue
            severity = severity_map.get(str(nk.get("severity", "medium")).lower(), Severity.MEDIUM)
            host = target.host
            if validated_url:
                parsed = urlparse(validated_url)
                host = parsed.hostname or host
            evidence = nk.get("raw", nk.get("finding", ""))
            if validated_url:
                evidence = (
                    f"Nikto reported: {nk.get('finding', '')}\n"
                    f"Replay confirmed {validated_url} returned HTTP {nk.get('http_status')} "
                    f"with content-type={nk.get('content_type') or 'unknown'} and "
                    f"{nk.get('content_length')} bytes."
                )
            finding = Finding(
                title=(
                    f"Exposed {finding_type}: {validated_url}"
                    if validated_url else
                    f"Web Server Issue: {nk.get('finding', '')[:80]}"
                ),
                description=(
                    f"Nikto reported `{nk.get('finding', '')}` and replay validation "
                    f"confirmed the resource is currently retrievable."
                    if validated_url else
                    f"Nikto detected: {nk.get('finding', '')}"
                ),
                severity=severity,
                agent_source=AgentType.VULN_SCANNER,
                target=Target(host=host, url=validated_url or target.url or target.base_url),
                evidence=evidence,
                request_proof=nk.get("request_proof") or None,
                response_proof=nk.get("response_proof") or None,
                remediation=nk.get("remediation") or (
                    "Validate the Nikto signal manually and remove unnecessary exposed files or unsafe web-server behavior."
                ),
                tags=["nikto", "web-server", "scanner-evidence"] + (["replay-validated"] if validated_url else ["needs-validation"]),
                confidence=str(nk.get("confidence") or ("high" if validated_url else "medium")),
                status="confirmed" if validated_url else "suspected",
                raw_tool_output=json.dumps(nk, default=str),
            )
            self._add_finding(finding)

    def _convert_cms_findings(self, cms_findings: list[dict], target: Target) -> None:
        """Convert CMS scanner results to Finding objects."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "informational": Severity.INFORMATIONAL,
            "info": Severity.INFORMATIONAL,
        }
        for cms in cms_findings:
            informational = bool(cms.get("informational"))
            component = str(cms.get("component") or "cms").lower()
            cve_ids = cms.get("cve") or []
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            cwe_ids = cms.get("cwe") or []
            if isinstance(cwe_ids, str):
                cwe_ids = [cwe_ids]
            references = cms.get("references") or {}
            if isinstance(references, dict):
                refs: list[str] = []
                for value in references.values():
                    if isinstance(value, list):
                        refs.extend(str(item) for item in value)
                    elif value:
                        refs.append(str(value))
                references = refs
            elif isinstance(references, str):
                references = [references]

            finding = Finding(
                title=(
                    f"CMS Scan Evidence: {cms.get('finding', '')[:80]}"
                    if informational else
                    f"CMS Vulnerability: {cms.get('finding', '')[:80]}"
                ),
                description=cms.get("finding", ""),
                severity=Severity.INFORMATIONAL if informational else severity_map.get(str(cms.get("severity", "high")).lower(), Severity.HIGH),
                agent_source=AgentType.VULN_SCANNER,
                target=Target(host=urlparse(cms.get("target_url", "")).hostname or target.host, url=cms.get("target_url") or target.url),
                evidence=cms.get("finding", ""),
                remediation="Update the CMS and all plugins/themes to the latest versions. "
                            "Remove unused plugins and themes. Review security hardening guides.",
                references=references,
                cve_ids=cve_ids,
                cwe_ids=cwe_ids,
                tags=["cms", component, cms.get("source_tool", "cms-scanner"), "scanner-evidence" if informational else "vulnerability"],
                confidence="high",
                status="confirmed",
                raw_tool_output=json.dumps(cms, default=str),
            )
            self._add_finding(finding)

    async def _run_custom_checks(self, targets: list[str], technologies: dict, target: Target) -> None:
        """Run custom vulnerability checks beyond template scanners.

        Async — uses ``httpx.AsyncClient`` so we don't block the event loop.
        The previous sync ``httpx.get`` call timed out because it held the
        event loop hostage during the entire request.
        """
        import httpx as httpx_client
        async with httpx_client.AsyncClient(verify=False, timeout=15, follow_redirects=False,
                                            headers={"User-Agent": "Mozilla/5.0"}) as client:
            for url in targets[:15]:
                try:
                    resp = await client.get(url)
                    headers = resp.headers

                    missing_headers = []
                    header_checks = {
                        "X-Frame-Options": ("Clickjacking", Severity.MEDIUM, "CWE-1021"),
                        "X-Content-Type-Options": ("MIME Sniffing", Severity.LOW, "CWE-693"),
                        "X-XSS-Protection": ("XSS Protection", Severity.LOW, "CWE-79"),
                        "Strict-Transport-Security": ("HSTS Missing", Severity.MEDIUM, "CWE-319"),
                        "Content-Security-Policy": ("CSP Missing", Severity.MEDIUM, "CWE-1021"),
                        "Referrer-Policy": ("Referrer Leak", Severity.LOW, "CWE-200"),
                        "Permissions-Policy": ("Permissions Policy", Severity.LOW, "CWE-1021"),
                    }

                    for header, (name, severity, cwe) in header_checks.items():
                        if header not in headers:
                            missing_headers.append((header, name, severity, cwe))

                    if missing_headers:
                        try:
                            from urllib.parse import urlparse
                            host = urlparse(url).hostname or target.host
                        except Exception:
                            host = target.host

                        finding = Finding(
                            title=f"Missing Security Headers on {host}",
                            description=f"The following security headers are missing from {url}:\n\n"
                                        + "\n".join(f"  - {h[0]} ({h[1]})" for h in missing_headers)
                                        + "\n\nThese headers help protect against various web attacks "
                                        "including clickjacking, XSS, MIME sniffing, and information leakage.",
                            severity=Severity.MEDIUM,
                            agent_source=AgentType.VULN_SCANNER,
                            target=Target(host=host, url=url),
                            evidence="Response headers:\n" + "\n".join(
                                f"  {k}: {v}" for k, v in headers.items()
                                if k.startswith("X-") or k in ["Server", "Content-Security-Policy"]),
                            remediation="Implement all missing security headers. Use helmetjs (Node.js), "
                                        "django-security (Django), or equivalent middleware for your framework.",
                            cwe_ids=[h[3] for h in missing_headers],
                            tags=["security-headers", "misconfiguration", "hardening"],
                            confidence="high",
                            status="confirmed",
                        )
                        self._add_finding(finding)

                except Exception as exc:
                    logger.debug("[VULN_SCAN] Header check failed for {url}: {err}", url=url, err=exc)

    async def _run_llm_vuln_analysis(self, targets: list[str], technologies: dict, target: Target) -> None:
        """Use LLM to identify context-aware vulnerabilities from response headers, tech stack, and patterns.

        This catches misconfigurations and logic flaws that template scanners miss.
        """
        try:
            from tools.llm_client import LLMClient
            if self._llm_client is None:
                self._llm_client = LLMClient(self.config)

            available = self._llm_client.get_available_providers()
            if not available:
                logger.debug("[VULN_SCAN] No LLM provider available - skipping AI analysis")
                return

            # Collect response information from targets
            import httpx as httpx_client
            target_info = []
            for url in targets[:8]:
                try:
                    async with httpx_client.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
                        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                        host_key = url.split("//")[1].split("/")[0] if "//" in url else ""
                        target_info.append({
                            "url": url,
                            "status": resp.status_code,
                            "headers": dict(resp.headers),
                            "body_snippet": resp.text[:2000],
                            "tech": technologies.get(host_key, []),
                        })
                except Exception:
                    continue

            if not target_info:
                return

            prompt = (
                f"Analyze these HTTP responses for security vulnerabilities that automated scanners often miss.\n\n"
                f"Target: {target.host}\n\n"
                f"Responses:\n{json.dumps(target_info, indent=2, default=str)[:6000]}\n\n"
                f"Detected Technologies: {json.dumps(dict(list(technologies.items())[:5]), default=str)}\n\n"
                "Identify vulnerabilities in these categories:\n"
                "1. Security misconfigurations\n2. Information disclosure in headers/body\n"
                "3. Authentication/authorization weaknesses\n4. Session management issues\n"
                "5. API design flaws\n6. CORS misconfigurations\n7. Cache control issues\n"
                "8. Any business logic concerns\n\n"
                'Respond in JSON:\n{"findings": [{"title": "...", "description": "...", '
                '"severity": "critical|high|medium|low", "category": "misconfig|info-disclosure|auth|'
                'session|api|cors|cache|logic", "evidence": "specific header/value/pattern", '
                '"remediation": "..."}]}\n\n'
                "Only report findings you are confident about. Quality over quantity."
            )

            result = await self._llm_client.analyze(prompt, task="analysis")
            if result and "findings" in result:
                severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
                for f in result["findings"][:10]:
                    finding = Finding(
                        title=f"[AI] {f.get('title', 'Unknown')}",
                        description=f.get("description", ""),
                        severity=severity_map.get(f.get("severity", "medium"), Severity.MEDIUM),
                        agent_source=AgentType.VULN_SCANNER,
                        target=target,
                        evidence=f"AI Analysis - Category: {f.get('category', 'N/A')}\nEvidence: {f.get('evidence', 'N/A')}",
                        remediation=f.get("remediation", "Manual review required."),
                        tags=["llm", "ai-vuln", f.get("category", "other")],
                        confidence=f.get("confidence", "medium"),
                    )
                    self._add_finding(finding)
                logger.info("[VULN_SCAN] LLM analysis: {count} AI-identified findings", count=len(result["findings"]))

        except Exception as exc:
            logger.debug("[VULN_SCAN] LLM analysis error: {err}", err=exc)
