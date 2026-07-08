"""
VAPT Multi-Agent System — Intelligence/LLM Agent

Intelligent analysis layer:
  - JavaScript bundle analysis for secrets, API keys, tokens
  - CVE matching for discovered technology versions
  - Business logic flaw detection
  - Custom LLM-powered analysis
  - SecretFinder-style regex scanning
"""

import asyncio
import json
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import httpx as httpx_client
from loguru import logger

from core.models import AgentTask, AgentType, Finding, Severity, Target
from core.scope import ScopeManager
from core.config import AppConfig
from agents.base import BaseAgent


class IntelAgent(BaseAgent):
    """Intelligence agent powered by LLM and regex analysis.

    Performs deep analysis that template scanners cannot: logic flaws,
    secret hunting in JS bundles, CVE matching, and contextual vulnerability
    assessment.
    """

    # Regex patterns for secret detection (SecretFinder-inspired)
    SECRET_PATTERNS: list[dict[str, str]] = [
        {"name": "AWS Access Key", "pattern": r'(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}', "severity": "critical", "cwe": "CWE-798"},
        {"name": "AWS Secret Key", "pattern": r'(?:aws)?_?secret_?(?:access_)?key["\s]*[:=]["\s]*[A-Za-z0-9/+=]{40}', "severity": "critical", "cwe": "CWE-798"},
        {"name": "GitHub Token", "pattern": r'gh[pousr]_[A-Za-z0-9_]{36,}', "severity": "critical", "cwe": "CWE-798"},
        {"name": "Google API Key", "pattern": r'AIza[0-9A-Za-z\-_]{35}', "severity": "high", "cwe": "CWE-798"},
        {"name": "Google OAuth Token", "pattern": r'ya29\.[0-9A-Za-z\-_]+', "severity": "high", "cwe": "CWE-798"},
        {"name": "Slack Token", "pattern": r'xox[baprs]-[0-9]{10,13}-[0-9A-Za-z]{24,}', "severity": "high", "cwe": "CWE-798"},
        {"name": "Slack Webhook", "pattern": r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+', "severity": "high", "cwe": "CWE-798"},
        {"name": "Stripe API Key", "pattern": r'(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}', "severity": "critical", "cwe": "CWE-798"},
        {"name": "Twilio API Key", "pattern": r'SK[0-9a-fA-F]{32}', "severity": "high", "cwe": "CWE-798"},
        {"name": "SendGrid API Key", "pattern": r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}', "severity": "high", "cwe": "CWE-798"},
        {"name": "Mailgun API Key", "pattern": r'key-[A-Za-z0-9]{32}', "severity": "medium", "cwe": "CWE-798"},
        {"name": "Private Key", "pattern": r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "severity": "critical", "cwe": "CWE-312"},
        {"name": "JWT Secret", "pattern": r'(?:jwt[_\-]?secret|token[_\-]?secret)["\s]*[:=]["\s]*[A-Za-z0-9\-_]{20,}', "severity": "high", "cwe": "CWE-798"},
        {"name": "Generic Secret", "pattern": r'(?:password|passwd|pwd|secret|api[_\-]?key|auth[_\-]?token|access[_\-]?token)["\s]*[:=]["\s]*["\']?[A-Za-z0-9\-_!@#$%^&*]{8,}', "severity": "medium", "cwe": "CWE-798"},
        {"name": "Database Connection String", "pattern": r'(?:mongodb|postgres|mysql|redis|amqp)://[^\s\'"<]+:[^\s\'"<]+@[^\s\'"<]+', "severity": "critical", "cwe": "CWE-312"},
        {"name": "Heroku API Key", "pattern": r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "severity": "high", "cwe": "CWE-798"},
        {"name": "Discord Token", "pattern": r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}', "severity": "high", "cwe": "CWE-798"},
        {"name": "Telegram Bot Token", "pattern": r'[0-9]{9,10}:[A-Za-z0-9_-]{35}', "severity": "high", "cwe": "CWE-798"},
        {"name": "Firebase URL", "pattern": r'https://[a-z0-9-]+\.firebaseio\.com', "severity": "medium", "cwe": "CWE-200"},
        {"name": "Shopify Token", "pattern": r'shpat_[A-Za-z0-9]{32,}', "severity": "high", "cwe": "CWE-798"},
        {"name": "Square Access Token", "pattern": r'sq0atp-[A-Za-z0-9\-_]{22}', "severity": "high", "cwe": "CWE-798"},
        {"name": "Square Secret", "pattern": r'sq0csp-[A-Za-z0-9\-_]{43}', "severity": "high", "cwe": "CWE-798"},
    ]

    def __init__(self, scope: ScopeManager, config: AppConfig) -> None:
        super().__init__(AgentType.INTEL, scope, config)
        self._llm_client = None
        self._cve_resolver = None  # lazily built

    def _get_cve_resolver(self):
        """Lazily build the LLM+NVD resolver (tools/cve_resolver.py)."""
        if self._cve_resolver is not None:
            return self._cve_resolver
        try:
            from tools.llm_client import LLMClient
            from tools.cve_resolver import CVEResolver
            from services.nvd_service import NVDService
            if self._llm_client is None:
                self._llm_client = LLMClient(self.config)
            # Share a single NVDService instance so its cache + rate limiter
            # are reused across findings.
            self._cve_resolver = CVEResolver(self._llm_client, NVDService())
        except Exception as exc:
            logger.debug("[INTEL] Could not init CVE resolver: {err}", err=exc)
            self._cve_resolver = None
        return self._cve_resolver

    async def execute(self, task: AgentTask) -> list[Finding]:
        """Execute intelligent analysis.

        Replaces the previous hardcoded ``vuln_versions`` lookup table with
        LLM-proposed + NVD-verified CVE/CWE assignment (no hallucination):
        the LLM proposes candidates from concrete evidence, and every
        proposal is verified against NVD before being attached.
        """
        logger.info("[INTEL] Starting intelligent analysis")
        self.clear_findings()

        recon_data = self._merge_phase_context(task.parameters)
        live_urls = recon_data.get("live_urls", [])
        technologies = recon_data.get("technologies", {})
        all_findings_so_far = task.parameters.get("existing_findings", [])

        # Phase 1: JS bundle analysis for secrets, endpoints, and stale client
        # libraries. Use recon's already-discovered URLs as first-class inputs;
        # otherwise historical/crawler JS assets never reach the intel phase.
        js_analysis = await self._analyze_js_bundles(recon_data, live_urls)
        js_secrets = js_analysis["secrets"]
        self._generate_secret_findings(js_secrets, task.target)
        self._generate_js_library_findings(js_analysis["libraries"], task.target)

        # Phase 2: LLM+NVD-driven CVE/CWE enrichment of EXISTING findings.
        # The previous implementation matched a hardcoded version→CVE table;
        # we now ask the LLM to propose identifiers grounded in each finding's
        # evidence and verify them against NVD. Nothing is hardcoded.
        await self._enrich_existing_findings(all_findings_so_far)

        # Phase 3: LLM-powered contextual analysis (unchanged shape)
        try:
            from tools.llm_client import LLMClient
            if self._llm_client is None:
                self._llm_client = LLMClient(self.config)
            if self._llm_client.get_available_providers():
                await self._run_llm_analysis(live_urls, technologies, all_findings_so_far, task.target)
        except Exception:
            pass

        # Phase 4: attack-chain detection across existing findings (unchanged)
        self._enrich_findings(all_findings_so_far, task.target)

        task.result = {
            "secrets_found": len(js_secrets),
            "js_secrets": js_secrets,
            "js_files_scanned": js_analysis["files"],
            "js_endpoints": js_analysis["endpoints"],
            "js_libraries": js_analysis["libraries"],
            "existing_findings_enriched": len(all_findings_so_far),
            "llm_analysis": self._llm_client is not None
                             and bool(self._llm_client.get_available_providers()),
        }

        logger.info(
            "[INTEL] Complete: {files} JS files, {endpoints} JS endpoints, "
            "{libs} libraries, {secrets} secrets, {enr} findings enriched",
            files=len(js_analysis["files"]),
            endpoints=len(js_analysis["endpoints"]),
            libs=len(js_analysis["libraries"]),
            secrets=len(js_secrets),
            enr=len(all_findings_so_far),
        )
        return self.get_findings()

    @staticmethod
    def _merge_phase_context(parameters: dict[str, Any]) -> dict[str, Any]:
        """Merge prior phase output into a single analysis context."""
        merged: dict[str, Any] = {}
        for key in ("recon_data", "enum_data", "vuln_data", "fuzz_data", "intel_data"):
            value = parameters.get(key)
            if not isinstance(value, dict):
                continue
            for field, field_value in value.items():
                if isinstance(field_value, list):
                    merged.setdefault(field, [])
                    merged[field].extend(field_value)
                elif isinstance(field_value, dict):
                    merged.setdefault(field, {})
                    merged[field].update(field_value)
                else:
                    merged[field] = field_value
        if not merged and isinstance(parameters.get("scan_result"), dict):
            merged.update(parameters["scan_result"])
        return merged

    async def _enrich_existing_findings(self, findings: list[Finding]) -> None:
        """Run the LLM+NVD CVE/CWE resolver over every existing finding.

        This replaces the old hardcoded ``_match_cves`` table. Each finding is
        enriched in place; the resolver drops any LLM proposal that NVD does
        not confirm, so no hallucinated identifiers survive.
        """
        resolver = self._get_cve_resolver()
        if resolver is None:
            logger.debug("[INTEL] CVE resolver unavailable — skipping enrichment")
            return
        for f in findings:
            try:
                await resolver.enrich(f)
            except Exception as exc:
                logger.debug("[INTEL] Enrichment failed for '{t}': {err}",
                             t=f.title[:60], err=exc)

    async def _analyze_js_bundles(self, recon_data: dict[str, Any], live_urls: list[dict]) -> dict[str, list[dict]]:
        """Download and analyze JavaScript bundles for secrets and client-side signals."""
        secrets_found: list[dict] = []
        endpoints_found: list[dict] = []
        libraries_found: list[dict] = []
        files_scanned: list[dict] = []

        js_urls = self._collect_js_urls(recon_data, live_urls)
        async with httpx_client.AsyncClient(verify=False, timeout=15, follow_redirects=True) as client:
            js_urls = await self._discover_page_scripts(client, live_urls, js_urls)

            for js_url in js_urls[:60]:
                status_code: int | None = None
                body = ""
                try:
                    resp = await client.get(js_url, headers={"User-Agent": "Mozilla/5.0"})
                    status_code = resp.status_code
                    if resp.status_code == 200 and len(resp.text) > 50:
                        body = resp.text
                        secrets_found.extend(self._scan_for_secrets(body, js_url))
                        endpoints_found.extend(self._extract_js_endpoints(body, js_url))
                    libraries_found.extend(self._detect_js_libraries(body, js_url, status_code))
                except Exception as exc:
                    logger.debug("[INTEL] JS fetch failed for {url}: {err}", url=js_url, err=exc)
                    libraries_found.extend(self._detect_js_libraries("", js_url, status_code))

                files_scanned.append({
                    "url": js_url,
                    "status_code": status_code,
                    "bytes": len(body),
                })

        return {
            "secrets": self._dedupe_dicts(secrets_found, ("type", "source", "value")),
            "endpoints": self._dedupe_dicts(endpoints_found, ("source", "endpoint")),
            "libraries": self._dedupe_dicts(libraries_found, ("name", "version", "source")),
            "files": self._dedupe_dicts(files_scanned, ("url",)),
        }

    def _collect_js_urls(self, recon_data: dict[str, Any], live_urls: list[dict]) -> list[str]:
        """Collect in-scope JS URLs from recon, crawling, and probing output."""
        candidates: list[str] = []

        for entry in live_urls or []:
            url = entry.get("url") if isinstance(entry, dict) else str(entry)
            if self._looks_like_js_url(url):
                candidates.append(url)

        for key in ("historical_urls", "crawled_urls", "endpoints", "new_endpoints", "js_files", "js_endpoints"):
            for item in recon_data.get(key) or []:
                if isinstance(item, dict):
                    url = item.get("url") or item.get("source") or item.get("endpoint") or item.get("input") or ""
                else:
                    url = str(item)
                if self._looks_like_js_url(url):
                    candidates.append(url)

        deduped: list[str] = []
        seen: set[str] = set()
        for url in candidates:
            normalized = url.strip()
            if not normalized.startswith(("http://", "https://")):
                continue
            if not self.is_in_scope(normalized):
                continue
            key = normalized.split("#", 1)[0]
            if key in seen:
                continue
            seen.add(key)
            deduped.append(key)
        return deduped

    async def _discover_page_scripts(
        self,
        client: httpx_client.AsyncClient,
        live_urls: list[dict],
        js_urls: list[str],
    ) -> list[str]:
        """Add script src assets from live HTML pages."""
        seen = set(js_urls)
        for entry in (live_urls or [])[:20]:
            url = entry.get("url", "") if isinstance(entry, dict) else str(entry)
            if not url or self._looks_like_js_url(url) or not self.is_in_scope(url):
                continue
            try:
                resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code != 200:
                    continue
                for js_ref in re.findall(r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', resp.text, flags=re.I):
                    js_url = urljoin(url, js_ref)
                    key = js_url.split("#", 1)[0]
                    if key not in seen and self.is_in_scope(key):
                        seen.add(key)
                        js_urls.append(key)
            except Exception:
                continue
        return js_urls

    @staticmethod
    def _looks_like_js_url(value: str) -> bool:
        try:
            parsed = urlparse(str(value))
            return parsed.scheme in {"http", "https"} and ".js" in parsed.path.lower()
        except Exception:
            return False

    @staticmethod
    def _dedupe_dicts(items: list[dict], keys: tuple[str, ...]) -> list[dict]:
        deduped: list[dict] = []
        seen: set[tuple] = set()
        for item in items:
            marker = tuple(item.get(key) for key in keys)
            if marker in seen:
                continue
            seen.add(marker)
            deduped.append(item)
        return deduped

    def _extract_js_endpoints(self, content: str, source_url: str) -> list[dict]:
        """Extract likely API/route strings from JavaScript without fuzzing them."""
        endpoints: list[dict] = []
        patterns = [
            r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|open)\(\s*["']([^"']+)["']""",
            r"""["']((?:/api/|/v\d+/|/rest/|/graphql|/ajax/)[^"'\s<>]{1,180})["']""",
            r"""["'](https?://[^"'\s<>]+(?:api|graphql|ajax|rest)[^"'\s<>]*)["']""",
        ]
        for pattern in patterns:
            for match in re.findall(pattern, content, flags=re.I):
                endpoint = match.strip()
                if endpoint.startswith(("data:", "javascript:")):
                    continue
                endpoints.append({
                    "source": source_url,
                    "endpoint": endpoint,
                    "kind": "javascript-endpoint",
                })
        return endpoints[:100]

    def _detect_js_libraries(self, content: str, source_url: str, status_code: int | None) -> list[dict]:
        """Detect old client libraries from URL and file banner evidence."""
        libraries: list[dict] = []
        haystack = f"{source_url}\n{content[:2000]}"
        checks = [
            ("jquery", r"jquery(?:-|\.|/|%2d)(\d+\.\d+(?:\.\d+)?)", (3, 5, 0)),
            ("jquery", r"jQuery(?: JavaScript Library)? v(\d+\.\d+(?:\.\d+)?)", (3, 5, 0)),
        ]
        for name, pattern, safe_minimum in checks:
            for version in re.findall(pattern, haystack, flags=re.I):
                parsed = self._version_tuple(version)
                if parsed and parsed < safe_minimum:
                    libraries.append({
                        "name": name,
                        "version": version,
                        "source": source_url,
                        "status_code": status_code,
                        "safe_minimum": ".".join(str(part) for part in safe_minimum),
                        "confidence": "high" if status_code == 200 else "medium",
                    })
        return libraries

    @staticmethod
    def _version_tuple(version: str) -> tuple[int, int, int] | None:
        parts = re.findall(r"\d+", version)
        if not parts:
            return None
        nums = [int(part) for part in parts[:3]]
        while len(nums) < 3:
            nums.append(0)
        return tuple(nums)

    def _scan_for_secrets(self, content: str, source_url: str) -> list[dict]:
        """Scan content for secrets using regex patterns."""
        found = []

        for pattern_info in self.SECRET_PATTERNS:
            matches = re.findall(pattern_info["pattern"], content)
            for match in matches:
                # Filter obvious false positives
                match_str = match if isinstance(match, str) else match[0]
                if len(match_str) < 10:
                    continue
                # Skip example/test values
                if any(kw in match_str.lower() for kw in ["example", "test", "xxx", "your_", "replace_", "changeme"]):
                    continue

                found.append({
                    "type": pattern_info["name"],
                    "value": match_str[:50] + "..." if len(match_str) > 50 else match_str,
                    "source": source_url,
                    "severity": pattern_info["severity"],
                    "cwe": pattern_info["cwe"],
                })

        return found

    def _generate_secret_findings(self, secrets: list[dict], target: Target) -> None:
        """Generate Finding objects from discovered secrets."""
        severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}

        for secret in secrets:
            finding = Finding(
                title=f"Secret Exposed in JavaScript: {secret['type']}",
                description=f"A {secret['type']} was found embedded in JavaScript code at {secret['source']}. "
                            f"This secret is accessible to anyone who can access the page and could be used "
                            f"to compromise associated services, access sensitive data, or escalate privileges. "
                            f"Secrets should never be hardcoded in client-side code.",
                severity=severity_map.get(secret["severity"], Severity.HIGH),
                cvss_score=9.8 if secret["severity"] == "critical" else 7.5,
                agent_source=AgentType.INTEL,
                target=Target(host=target.host, url=secret["source"]),
                evidence=f"Type: {secret['type']}\nValue: {secret['value']}\nSource: {secret['source']}",
                remediation=f"Remove the {secret['type']} from the JavaScript bundle. Use environment variables "
                            f"or a secrets management service (e.g., HashiCorp Vault, AWS Secrets Manager). "
                            f"Rotate the exposed credential immediately.",
                cwe_ids=[secret["cwe"]],
                tags=["secret", "exposure", "javascript", "credential-leak"],
                confidence="high",
                status="confirmed",
            )
            self._add_finding(finding)

    def _generate_js_library_findings(self, libraries: list[dict], target: Target) -> None:
        """Generate findings for materially outdated client-side libraries."""
        for library in libraries:
            source = library.get("source") or target.base_url
            parsed = urlparse(source)
            host = parsed.hostname or target.host
            name = str(library.get("name", "JavaScript library")).title()
            version = library.get("version", "unknown")
            safe_minimum = library.get("safe_minimum", "current supported version")
            status_code = library.get("status_code")
            confirmed = status_code == 200

            finding = Finding(
                title=f"Outdated JavaScript Library: {name} {version}",
                description=(
                    f"The client-side asset {source} references {name} {version}, which is older than "
                    f"the configured safe baseline ({safe_minimum}). Outdated JavaScript libraries often "
                    "contain publicly documented security weaknesses and can increase client-side attack "
                    "surface when exploitable code paths are reachable."
                ),
                severity=Severity.MEDIUM,
                cvss_score=5.3 if confirmed else None,
                agent_source=AgentType.INTEL,
                target=Target(host=host, url=source, protocol=parsed.scheme or target.protocol),
                evidence=(
                    f"Library: {name}\nVersion: {version}\nSource: {source}\n"
                    f"HTTP status: {status_code if status_code is not None else 'not fetched'}"
                ),
                remediation=(
                    f"Upgrade {name} to a currently supported release, remove unused legacy assets, "
                    "and regression-test dependent client-side functionality."
                ),
                cwe_ids=["CWE-1104"],
                references=[
                    "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities",
                    "https://jquery.com/upgrade-guide/",
                ],
                tags=["javascript", "outdated-library", library.get("name", "library"), "client-side"],
                confidence="high" if confirmed else "medium",
                status="confirmed" if confirmed else "suspected",
            )
            self._add_finding(finding)

    def _match_cves(self, technologies: dict[str, list[str]], target: Target) -> list[Finding]:
        """DEPRECATED — kept only as a no-op for backward compatibility.

        The previous implementation hard-coded a ``{version_string: cve}``
        table. That approach is fundamentally unsound (versions drift, CVEs
        are added/withdrawn, and a static table cannot reflect NVD's current
        state). CVE/CWE assignment is now performed by the LLM+NVD resolver
        in ``_enrich_existing_findings`` above, which proposes identifiers
        from concrete evidence and verifies every proposal against NVD.
        """
        logger.debug("[INTEL] _match_cves is deprecated; CVE assignment now "
                     "flows through the LLM+NVD resolver.")
        return []

    async def _run_llm_analysis(
        self, live_urls: list[dict], technologies: dict, existing_findings: list, target: Target
    ) -> None:
        """Use LLM for intelligent vulnerability analysis (supports multiple providers)."""
        try:
            if self._llm_client is None:
                return

            # Build analysis prompt
            findings_summary = "\n".join(
                f"- [{f.severity.value}] {f.title}: {f.description[:200]}"
                for f in existing_findings[:20]
            )

            tech_summary = "\n".join(
                f"- {host}: {', '.join(techs)}"
                for host, techs in technologies.items()
            )

            prompt = (
                f"You are a senior penetration tester analyzing a target: {target.host}\n\n"
                f"Discovered Technologies:\n{tech_summary or 'None detected'}\n\n"
                f"Current Findings:\n{findings_summary or 'None yet'}\n\n"
                f"Live URLs: {[u.get('url', '') for u in live_urls[:10]]}\n\n"
                "As an expert pentester, identify:\n"
                "1. Business logic vulnerabilities that automated scanners miss\n"
                "2. Authentication/authorization flaws\n"
                "3. Data exposure risks\n"
                "4. Potential attack chains (how vulnerabilities could be combined)\n"
                "5. Any critical security issues based on the technology stack\n\n"
                'Respond in JSON:\n{"findings": [{"title": "...", "description": "...", '
                '"severity": "critical|high|medium|low", "category": "logic-flaw|auth-bypass|'
                'data-exposure|attack-chain|other", "confidence": "high|medium|low"}]}\n\n'
                "Only include findings you are confident about. Quality over quantity."
            )

            result = await self._llm_client.analyze(prompt)
            if result and "findings" in result:
                severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}

                for f in result["findings"]:
                    finding = Finding(
                        title=f"[LLM] {f.get('title', 'Unknown')}",
                        description=f.get("description", ""),
                        severity=severity_map.get(f.get("severity", "medium"), Severity.MEDIUM),
                        agent_source=AgentType.INTEL,
                        target=target,
                        evidence=f"LLM Analysis - Category: {f.get('category', 'N/A')}",
                        remediation="Manual review required. This finding was identified by AI analysis "
                                    "and should be validated by a security professional.",
                        tags=["llm", "ai-analysis", f.get("category", "other")],
                        confidence=f.get("confidence", "medium"),
                    )
                    self._add_finding(finding)
                logger.info("[INTEL] LLM analysis: {count} AI findings", count=len(result["findings"]))

        except Exception as exc:
            logger.warning("[INTEL] LLM analysis failed: {err}", err=exc)

    def _enrich_findings(self, existing_findings: list, target: Target) -> None:
        """Enrich existing findings with additional context."""
        # Group findings by target URL
        url_findings: dict[str, list] = {}
        for f in existing_findings:
            url = f.target.url or f.target.base_url
            url_findings.setdefault(url, []).append(f)

        # Check for potential attack chains
        for url, findings in url_findings.items():
            severities = [f.severity for f in findings]
            if Severity.HIGH in severities or Severity.CRITICAL in severities:
                if len(findings) >= 2:
                    chain_finding = Finding(
                        title=f"Potential Attack Chain on {url}",
                        description=f"Multiple vulnerabilities found on the same endpoint ({url}), which could "
                                    f"potentially be chained together for greater impact:\n\n"
                                    + "\n".join(f"  - [{f.severity.value}] {f.title}" for f in findings)
                                    + "\n\nAn attacker could combine these vulnerabilities to escalate privileges, "
                                    "access sensitive data, or achieve remote code execution.",
                        severity=Severity.CRITICAL,
                        cvss_score=9.5,
                        agent_source=AgentType.INTEL,
                        target=target,
                        evidence=f"{len(findings)} vulnerabilities on single endpoint: {url}",
                        remediation="Prioritize patching all vulnerabilities on this endpoint. "
                                    "Consider the combined attack surface when planning remediation.",
                        tags=["attack-chain", "chaining", "escalation"],
                        confidence="medium",
                    )
                    self._add_finding(chain_finding)
