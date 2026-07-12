"""
VAPT Multi-Agent System — Fuzzing Agent

Aggressive path, parameter, and value fuzzing:
  - ffuf (directory/path fuzzing with multiple wordlists)
  - wfuzz (parameter fuzzing)
  - Extension fuzzing (.bak, .old, .git, .env, .sql)
  - API versioning fuzzing (v1, v2, v3)
  - IDOR-style parameter fuzzing
"""

import asyncio
import json
import os
from typing import Any
from urllib.parse import urlparse, urljoin

from loguru import logger

from core.models import AgentTask, AgentType, Finding, Severity, Target
from core.scope import ScopeManager
from core.config import AppConfig
from agents.base import BaseAgent
from tools.runner import DockerRunner, OutputParser, WORDLIST_DIR


class FuzzingAgent(BaseAgent):
    """Fuzzing agent for discovering hidden endpoints and parameters.

    Runs multiple fuzzing strategies in parallel: path discovery,
    extension fuzzing, parameter fuzzing, and API version probing.
    """

    def __init__(self, scope: ScopeManager, config: AppConfig) -> None:
        super().__init__(AgentType.FUZZER, scope, config)
        self._runner = DockerRunner(config)
        self._llm_client = None

    async def execute(self, task: AgentTask) -> list[Finding]:
        """Execute multi-strategy fuzzing."""
        logger.info("[FUZZER] Starting fuzzing")
        self.clear_findings()
        self.clear_tool_runs()

        recon_data = task.parameters.get("recon_data", task.result or {})
        enum_data = task.parameters.get("enum_data", {})
        live_urls = recon_data.get("live_urls", [])
        historical_urls = recon_data.get("historical_urls", [])
        js_endpoints = enum_data.get("js_endpoints", [])

        all_new_endpoints: list[dict] = []
        fuzz_tasks = []

        # Strategy 1: Directory fuzzing on live targets
        for entry in live_urls[:10]:
            url = entry.get("url", "")
            if url and self.is_in_scope(url):
                fuzz_tasks.append(self._fuzz_directories(url))

        # Strategy 2: Extension fuzzing on discovered paths
        discovered_paths = self._extract_paths(historical_urls + js_endpoints)
        if discovered_paths and live_urls:
            base_url = live_urls[0].get("url", "")
            if base_url:
                fuzz_tasks.append(self._fuzz_extensions(base_url, discovered_paths[:20]))

        # Strategy 3: API version fuzzing
        api_endpoints = [u for u in (historical_urls + js_endpoints) if "/api/" in u]
        if api_endpoints:
            fuzz_tasks.append(self._fuzz_api_versions(api_endpoints[:10]))

        # Strategy 4: Backup and config file fuzzing
        if live_urls:
            base_url = live_urls[0].get("url", "")
            if base_url:
                fuzz_tasks.append(self._fuzz_sensitive_files(base_url))

        # Run all fuzzing tasks in parallel
        results = await asyncio.gather(*fuzz_tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                all_new_endpoints.extend(r)
            elif isinstance(r, Exception):
                logger.debug("[FUZZER] Task error: {err}", err=r)

        # Analyze results for findings
        self._analyze_fuzz_results(all_new_endpoints, task.target)

        # LLM-powered intelligent fuzzing analysis
        technologies = recon_data.get("technologies", {})
        await self._llm_analyze_fuzz_results(all_new_endpoints, technologies, task.target)

        task.result = {
            "new_endpoints": all_new_endpoints,
            "total_new_endpoints": len(all_new_endpoints),
            "tool_runs": self.get_tool_runs(),
        }

        logger.info("[FUZZER] Complete: {count} new endpoints found", count=len(all_new_endpoints))
        return self.get_findings()

    async def _fuzz_directories(self, base_url: str) -> list[dict]:
        """Fuzz directories and paths."""
        ffuf_cfg = self.config.tools.get("ffuf", AppConfig().get_tool_config("ffuf"))
        settings = getattr(ffuf_cfg, "settings", {}) if ffuf_cfg else {}
        wordlists = settings.get("wordlists") or [settings.get("wordlist") or f"{WORDLIST_DIR}/common-web.txt"]
        all_results: list[dict] = []
        seen_urls: set[str] = set()
        for wordlist in [str(item) for item in wordlists if item]:
            result = await self._runner.run(
                tool_name="ffuf",
                args=[
                    "-u", f"{base_url}/FUZZ",
                    "-w", wordlist,
                    "-fc", "404",
                    "-fs", "0",
                    "-t", "30",
                    "-mc", "all",
                    "-o", "/dev/stdout",
                    "-of", "json",
                    "-ac",  # Auto-calibration
                ],
                timeout=600,
            )
            self._record_tool_run(result, "fuzzing")

            if result.stdout.strip():
                parsed = OutputParser.parse_ffuf(result.stdout)
                for item in parsed:
                    url = item.get("url", "")
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        item["wordlist"] = wordlist
                        all_results.append(item)
                logger.info(
                    "[FUZZER] Directory fuzz on {url} with {wordlist}: {c} results",
                    url=base_url,
                    wordlist=wordlist,
                    c=len(parsed),
                )
        return all_results

    async def _fuzz_extensions(self, base_url: str, paths: list[str]) -> list[dict]:
        """Fuzz file extensions on discovered paths."""
        extensions = "php,html,js,json,txt,bak,old,zip,tar,gz,sql,conf,env,git,swp,inc,log,xml,yml,yaml,orig,save,asp,aspx,jsp"

        from tools.runner import shared_temp_path
        tmp_path = shared_temp_path(suffix=".txt")
        with open(tmp_path, "w") as f:
            f.write("\n".join(paths))

        try:
            result = await self._runner.run(
                tool_name="ffuf",
                args=[
                    "-u", f"{base_url}/FUZZ.EXT",
                    "-w", f"{tmp_path}:FUZZ,{extensions}:EXT",
                    "-fc", "404",
                    "-t", "20",
                    "-mc", "200,201,301,302,403,401",
                    "-o", "/dev/stdout",
                    "-of", "json",
                ],
                timeout=600,
            )
            self._record_tool_run(result, "fuzzing")

            if result.stdout.strip():
                parsed = OutputParser.parse_ffuf(result.stdout)
                logger.info("[FUZZER] Extension fuzz: {c} results", c=len(parsed))
                return parsed
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return []

    async def _fuzz_api_versions(self, api_endpoints: list[str]) -> list[dict]:
        """Fuzz API versioning patterns."""
        results = []
        versions = ["v1", "v2", "v3", "v4", "v5", "api/v1", "api/v2", "api/v3",
                     "v1.0", "v2.0", "v3.0", "rest/v1", "rest/v2", "graphql", "api/graphql"]

        for endpoint in api_endpoints[:5]:
            # Replace version in URL
            import re
            base = re.sub(r'/v\d+(?:\.\d+)?', '', endpoint)
            base = re.sub(r'/api/?', '/', base)
            if base.endswith("/"):
                base = base.rstrip("/")

            if not self.is_in_scope(base):
                continue

            try:
                import httpx as httpx_client
                async with httpx_client.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
                    for version in versions:
                        url = f"{base}/{version}"
                        try:
                            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                            if resp.status_code != 404:
                                results.append({
                                    "url": url,
                                    "status": resp.status_code,
                                    "length": len(resp.content),
                                    "source": "api_version_fuzz",
                                })
                        except Exception:
                            continue
            except Exception:
                pass

        logger.info("[FUZZER] API version fuzz: {c} results", c=len(results))
        return results

    async def _fuzz_sensitive_files(self, base_url: str) -> list[dict]:
        """Probe for sensitive files: .git, .env, backups, configs."""
        sensitive_paths = [
            ".git/HEAD", ".git/config", ".env", ".env.local", ".env.production",
            ".env.staging", ".htaccess", ".htpasswd", "web.config",
            "backup.sql", "backup.zip", "db.sql", "database.sql",
            "wp-config.php.bak", "config.php.bak", "configuration.php.bak",
            "phpinfo.php", "info.php", "server-status", "server-info",
            ".DS_Store", "Thumbs.db", ".svn/entries",
            "debug.log", "error.log", "access.log",
            "package.json", "composer.json", ".npmrc",
            "credentials.json", "service-account.json", "id_rsa",
            ".bash_history", ".mysql_history",
            "robots.txt", "sitemap.xml", "crossdomain.xml",
            "phpmyadmin/", "admin/", "administrator/", "wp-admin/",
            "api/docs", "swagger.json", "openapi.json", "api-schema.json",
            ".well-known/security.txt",
        ]

        results = []
        try:
            import httpx as httpx_client
            async with httpx_client.AsyncClient(verify=False, timeout=8, follow_redirects=True) as client:
                for path in sensitive_paths:
                    url = f"{base_url.rstrip('/')}/{path}"
                    if not self.is_in_scope(url):
                        continue
                    try:
                        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                        if resp.status_code == 200 and len(resp.content) > 0:
                            results.append({
                                "url": url,
                                "status": resp.status_code,
                                "length": len(resp.content),
                                "source": "sensitive_file_probe",
                                "sensitive": True,
                            })
                    except Exception:
                        continue
        except Exception as exc:
            logger.debug("[FUZZER] Sensitive file probe error: {err}", err=exc)

        logger.info("[FUZZER] Sensitive file probe: {c} files found", c=len(results))
        return results

    def _extract_paths(self, urls: list[str]) -> list[str]:
        """Extract unique paths from URLs."""
        paths = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.path and parsed.path != "/":
                    paths.add(parsed.path)
            except Exception:
                continue
        return list(paths)

    def _analyze_fuzz_results(self, results: list[dict], target: Target) -> None:
        """Generate findings from fuzzing results."""
        # Group sensitive file discoveries
        sensitive = [r for r in results if r.get("sensitive")]
        if sensitive:
            for s in sensitive[:10]:
                url = s.get("url", "")
                path = url.split("/")[-1] if "/" in url else url
                severity = Severity.CRITICAL if any(kw in path.lower() for kw in [".env", "credentials", "id_rsa", "service-account", "backup.sql", "database.sql", ".git"]) else Severity.HIGH

                finding = Finding(
                    title=f"Sensitive File Exposed: {path}",
                    description=f"A sensitive file was found accessible at {url}. This file may contain "
                                f"credentials, configuration data, database backups, or version control "
                                f"information that could aid an attacker in further compromising the system.",
                    severity=severity,
                    cvss_score=7.5 if severity == Severity.HIGH else 9.8,
                    agent_source=AgentType.FUZZER,
                    target=Target(
                        host=target.host,
                        url=url,
                    ),
                    evidence=f"HTTP {s.get('status', 'N/A')} — Content-Length: {s.get('length', 'N/A')}",
                    remediation=f"Remove the file from the web root or restrict access using server "
                                f"configuration. Add this path to your WAF rules.",
                    tags=["sensitive-file", "exposure", "information-disclosure"],
                    confidence="high",
                    status="confirmed",
                )
                self._add_finding(finding)

        # Check for admin panels
        admin_hits = [r for r in results if any(kw in r.get("url", "").lower() for kw in ["admin", "wp-admin", "phpmyadmin", "manager", "console", "dashboard"])]
        if admin_hits:
            for a in admin_hits[:5]:
                url = a.get("url", "")
                finding = Finding(
                    title=f"Admin Panel Discovered: {url}",
                    description=f"An administration interface was discovered at {url}. "
                                f"Admin panels are high-value targets for brute-force attacks "
                                f"and should be protected with strong authentication, MFA, "
                                f"and IP-based access restrictions.",
                    severity=Severity.MEDIUM,
                    agent_source=AgentType.FUZZER,
                    target=Target(host=target.host, url=url),
                    evidence=f"HTTP {a.get('status', 'N/A')} — Length: {a.get('length', 'N/A')}",
                    remediation="Protect admin interfaces with: IP whitelisting, MFA, rate limiting, "
                                "account lockout policies, and CAPTCHA. Consider moving admin to a "
                                "non-standard URL.",
                    tags=["admin-panel", "brute-force", "authentication"],
                    confidence="high",
                    status="confirmed",
                )
                self._add_finding(finding)

    async def _llm_analyze_fuzz_results(self, endpoints: list[dict], technologies: dict, target: Target) -> None:
        """Use LLM to analyze fuzzing results and identify patterns that automated rules miss.

        The AI can spot:
        - Naming conventions that reveal hidden functionality
        - Unusual status codes that suggest access control issues
        - Path patterns indicating framework-specific routes
        - API structure that suggests BOLA/IDOR potential
        """
        try:
            from tools.llm_client import LLMClient
            if self._llm_client is None:
                self._llm_client = LLMClient(self.config)

            available = self._llm_client.get_available_providers()
            if not available:
                return

            if not endpoints:
                return

            # Summarize endpoints by pattern
            endpoint_summary = []
            for ep in endpoints[:50]:
                url = ep.get("url", "")
                status = ep.get("status", "")
                source = ep.get("source", "")
                endpoint_summary.append(f"  {status} {url} (via {source})")

            prompt = (
                "You are a senior bug bounty hunter analyzing fuzzing results.\n\n"
                f"Target: {target.host}\n"
                f"Technologies: {technologies}\n\n"
                f"Discovered Endpoints ({len(endpoint_summary)} total):\n"
                + "\n".join(endpoint_summary[:50]) + "\n\n"
                "Analyze these results and identify:\n"
                "1. Endpoints that suggest IDOR/BOLA vulnerabilities (user IDs, resource IDs in paths)\n"
                "2. Hidden admin/debug/backup endpoints that are concerning\n"
                "3. API patterns that suggest broken access control\n"
                "4. Unusual path structures that might reveal framework-specific vulnerabilities\n"
                "5. Endpoints that should be tested for authentication bypass\n\n"
                'Respond in JSON:\n{"insights": [{"endpoint_pattern": "...", "risk": "critical|high|medium|low", '
                '"reasoning": "...", "recommended_test": "...", "category": "idor|auth-bypass|'
                'info-disclosure|debug-access|api-flaw|other"}]}'
            )

            result = await self._llm_client.analyze(prompt, task="triage")
            if result and "insights" in result:
                severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
                for insight in result["insights"][:8]:
                    finding = Finding(
                        title=f"[AI-Fuzz] {insight.get('endpoint_pattern', 'Unknown Pattern')}",
                        description=insight.get("reasoning", ""),
                        severity=severity_map.get(insight.get("risk", "medium"), Severity.MEDIUM),
                        agent_source=AgentType.FUZZER,
                        target=target,
                        evidence=f"Pattern: {insight.get('endpoint_pattern', '')}\nRecommended test: {insight.get('recommended_test', '')}",
                        remediation=insight.get("recommended_test", "Manual testing required."),
                        tags=["llm", "ai-fuzz", insight.get("category", "other")],
                        confidence="medium",
                        status="suspected",
                    )
                    self._add_finding(finding)
                logger.info("[FUZZER] LLM identified {count} patterns from fuzzing results", count=len(result["insights"]))

        except Exception as exc:
            logger.debug("[FUZZER] LLM analysis error: {err}", err=exc)
