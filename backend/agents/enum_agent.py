"""
VAPT Multi-Agent System — Enumeration Agent

Performs detailed enumeration:
  - nmap (port scanning, service detection, OS fingerprinting)
  - Directory bruteforcing with ffuf
  - Parameter discovery with arjun
  - Wappalyzer tech detection
  - API endpoint discovery from JS files
"""

import asyncio
import json
import re
import tempfile
import os
from typing import Any, Optional
from urllib.parse import urlparse, urljoin

from loguru import logger

from core.models import (
    AgentTask, AgentType, Finding, ScanPhase, Severity, Target,
)
from core.scope import ScopeManager
from core.config import AppConfig
from agents.base import BaseAgent
from tools.runner import DockerRunner, OutputParser, WORDLIST_DIR


class EnumAgent(BaseAgent):
    """Enumeration agent for deep service and endpoint discovery.

    Builds on recon results to map open ports, services, hidden
    directories, API parameters, and application structure.
    """

    def __init__(self, scope: ScopeManager, config: AppConfig) -> None:
        super().__init__(AgentType.ENUM, scope, config)
        self._runner = DockerRunner(config)

    async def execute(self, task: AgentTask) -> list[Finding]:
        """Execute enumeration against discovered targets."""
        logger.info("[ENUM] Starting enumeration for {target}", target=task.target.host)

        self.clear_findings()
        self.clear_tool_runs()
        target = task.target
        recon_data = task.parameters.get("recon_data", task.result or {})

        # Gather all hosts to enumerate — only real hostnames/IPs.
        # amass -passive emits graph relationship strings (e.g. "4755 (ASN) --> ...")
        # that are not valid scan targets; _is_valid_target() rejects them.
        raw_hosts: set[str] = {target.host}
        for sub in recon_data.get("subdomains", []):
            raw_hosts.add(str(sub))
        for url_entry in recon_data.get("live_urls", []):
            parsed = urlparse(url_entry.get("url", ""))
            if parsed.hostname:
                raw_hosts.add(parsed.hostname)

        hosts = sorted(
            h for h in raw_hosts
            if self._is_valid_target(h) and self._is_host_in_scope(h)
        )
        logger.info("[ENUM] Enumerating {count} hosts", count=len(hosts))

        # Results
        port_results: dict[str, list[dict]] = {}
        directory_results: list[dict] = []
        param_results: list[dict] = []
        js_endpoints: list[str] = []
        all_findings: list[Finding] = []

        # Run port scanning
        if self.config.tools.get("nmap", AppConfig().get_tool_config("nmap")).enabled:
            port_results = await self._run_nmap(hosts)
            all_findings.extend(self._analyze_ports(port_results, target))

        # Run directory bruteforcing on live URLs
        live_urls = self._unique_live_urls(recon_data.get("live_urls", []))
        if live_urls and self.config.tools.get("ffuf", AppConfig().get_tool_config("ffuf")).enabled:
            dir_tasks = []
            for entry in live_urls[:20]:  # Limit to top 20 hosts
                url = entry.get("url", "")
                if url and self.is_in_scope(url):
                    dir_tasks.append(self._run_ffuf_directories(url))

            dir_results_raw = await asyncio.gather(*dir_tasks, return_exceptions=True)
            for dr in dir_results_raw:
                if isinstance(dr, list):
                    directory_results.extend(dr)
                elif isinstance(dr, Exception):
                    logger.debug("[ENUM] Directory bruteforce error: {err}", err=dr)

        # Run parameter discovery on interesting URLs
        interesting_urls = self._get_interesting_urls(
            recon_data.get("historical_urls", []),
            live_urls,
        )
        if interesting_urls:
            # Arjun is request-intensive. A ranked six-endpoint batch gives it
            # time to finish and persist JSON instead of timing out midway
            # through a broad, low-value list.
            param_results = await self._run_param_discovery(interesting_urls[:6])

        # Discover JS endpoints
        for entry in live_urls:
            url = entry.get("url", "")
            if url and self.is_in_scope(url):
                endpoints = await self._discover_js_endpoints(url)
                js_endpoints.extend(endpoints)

        # Store everything in task result
        task.result = {
            "hosts_enumerated": hosts,
            "ports": port_results,
            "directories": directory_results,
            "parameters": param_results,
            "js_endpoints": list(set(js_endpoints)),
            "tool_runs": self.get_tool_runs(),
        }

        self._findings.extend(all_findings)

        logger.info(
            "[ENUM] Complete: {ports} port results, {dirs} directories, {params} params, {js} JS endpoints",
            ports=sum(len(v) for v in port_results.values()),
            dirs=len(directory_results),
            params=len(param_results),
            js=len(set(js_endpoints)),
        )

        return self.get_findings()

    def _unique_live_urls(self, live_urls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return in-scope live URL entries deduped by scheme/host/port."""
        unique: list[dict[str, Any]] = []
        seen: set[tuple[str, str, int | None]] = set()
        for entry in live_urls:
            url = entry.get("url", "")
            if not url or not self.is_in_scope(url):
                continue
            parsed = urlparse(url)
            key = (parsed.scheme, parsed.hostname or "", parsed.port)
            if key in seen:
                continue
            seen.add(key)
            unique.append(entry)
        return unique

    def _is_host_in_scope(self, host: str) -> bool:
        host = str(host or "").strip().lower().rstrip(".")
        if not host:
            return False
        return self.is_in_scope(f"https://{host}") or self.is_in_scope(f"http://{host}")

    @staticmethod
    def _is_valid_target(host: str) -> bool:
        """Return True only for real hostnames / IPs — reject amass graph strings.

        Amass passive mode emits human-readable relationship lines such as:
            "4755 (ASN) --> announces --> 121.242.22.0/23 (Netblock)"
        These are NOT hostnames.  Feeding them to nmap wastes minutes per line
        and produces zero useful results.
        """
        import re
        h = host.strip()
        if not h:
            return False
        # Amass relationship strings contain " --> "
        if "-->" in h:
            return False
        # Amass type annotations use parentheses: "121.242.23.195 (IPAddress)"
        if "(" in h or ")" in h:
            return False
        # Must only contain valid hostname/IP characters
        if not re.match(r'^[a-zA-Z0-9._\-\[\]:]+$', h):
            return False
        # Must have a dot (domain or IP) — rejects bare words
        if "." not in h:
            return False
        return True

    async def _run_nmap(self, hosts: list[str]) -> dict[str, list[dict]]:
        """Run nmap for port scanning — parallel across hosts with a semaphore cap."""
        # Filter out amass graph strings before wasting time on invalid targets.
        valid_hosts = [h for h in hosts if self._is_valid_target(h)]
        invalid = len(hosts) - len(valid_hosts)
        if invalid:
            logger.info(
                "[ENUM] Skipping {n} non-hostname strings (amass graph nodes)",
                n=invalid,
            )

        if not valid_hosts:
            return {}

        nmap_cfg = self.config.tools.get("nmap", AppConfig().get_tool_config("nmap"))
        ports = "1-10000"
        if nmap_cfg is not None:
            ports = getattr(nmap_cfg, "settings", {}).get("ports", ports)

        # Cap concurrent nmap processes — each nmap on /10000 ports can use ~100MB RAM.
        # 5 concurrent = reasonable on 2-4 core systems.
        concurrency = min(5, max(1, len(valid_hosts)))
        sem = asyncio.Semaphore(concurrency)
        results: dict[str, list[dict]] = {}

        async def _scan_one(host: str) -> None:
            async with sem:
                logger.info("[ENUM] Nmap scanning {host}", host=host)
                result = await self._runner.run(
                    tool_name="nmap",
                    args=[
                        "-sV", "-T4",
                        "-p", ports,
                        "--open",
                        "-oN", "/dev/stdout",
                        host,
                    ],
                    timeout=1200,
                )
                self._record_tool_run(result, "enumeration")
                if result.success or result.stdout.strip():
                    ports_found = OutputParser.parse_nmap(result.stdout)
                    if ports_found:
                        results[host] = ports_found
                        logger.info(
                            "[ENUM] {host}: {count} open ports",
                            host=host, count=len(ports_found),
                        )

        await asyncio.gather(*[_scan_one(h) for h in valid_hosts], return_exceptions=True)
        return results

    async def _run_ffuf_directories(self, base_url: str) -> list[dict]:
        """Run ffuf for directory/path discovery."""
        parsed = urlparse(base_url)
        if not parsed.scheme:
            base_url = f"https://{base_url}"

        # Wordlist path from config (Bug #7 — previously ignored)
        ffuf_cfg = self.config.tools.get("ffuf", AppConfig().get_tool_config("ffuf"))
        wordlists = [f"{WORDLIST_DIR}/common-web.txt"]
        if ffuf_cfg is not None:
            settings = getattr(ffuf_cfg, "settings", {})
            wordlists = settings.get("wordlists") or [settings.get("wordlist") or wordlists[0]]

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
                    "-t", "20",
                    "-mc", "all",
                    "-ac",
                    "-o", "/dev/stdout",
                    "-of", "json",
                ],
                timeout=600,
            )
            self._record_tool_run(result, "enumeration")

            if result.success and result.stdout.strip():
                parsed_results = OutputParser.parse_ffuf(result.stdout)
                for item in parsed_results:
                    url = item.get("url", "")
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        item["wordlist"] = wordlist
                        all_results.append(item)
                logger.info(
                    "[ENUM] ffuf on {url} with {wordlist}: {count} paths found",
                    url=base_url,
                    wordlist=wordlist,
                    count=len(parsed_results),
                )
        return all_results

    async def _run_param_discovery(self, urls: list[str]) -> list[dict]:
        """Run arjun for parameter discovery."""
        results = []

        if not urls:
            return results

        from tools.runner import shared_temp_path
        host_path = shared_temp_path(suffix=".txt")
        out_path = shared_temp_path(suffix=".json")
        with open(host_path, "w") as f:
            f.write("\n".join(urls))

        try:
            result = await self._runner.run(
                tool_name="arjun",
                args=["-i", host_path, "-o", out_path, "-t", "5"],
                timeout=max(60, int(os.environ.get("VAPT_ARJUN_TIMEOUT", "180"))),
            )
            self._record_tool_run(result, "enumeration")
            output = ""
            if os.path.exists(out_path):
                try:
                    with open(out_path) as f:
                        output = f.read()
                except OSError:
                    output = ""
            output = output or result.stdout
            if (result.success or result.partial) and output.strip():
                try:
                    data = json.loads(output)
                    for url, params in data.items():
                        results.append({"url": url, "parameters": params})
                except json.JSONDecodeError:
                    logger.debug("[ENUM] Arjun returned partial non-JSON output; artifact retained for operator review")
        finally:
            try:
                os.unlink(host_path)
            except OSError:
                pass
            try:
                os.unlink(out_path)
            except OSError:
                pass

        return results

    async def _discover_js_endpoints(self, base_url: str) -> list[str]:
        """Extract API endpoints from JavaScript files."""
        endpoints = []
        try:
            import httpx as httpx_client
            async with httpx_client.AsyncClient(verify=False, timeout=15, follow_redirects=True) as client:
                # Fetch the main page
                resp = await client.get(base_url, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code != 200:
                    return endpoints

                # Find JS file URLs
                js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', resp.text)

                for js_url in js_files:
                    if not js_url.startswith("http"):
                        js_url = urljoin(base_url, js_url)

                    if not self.is_in_scope(js_url):
                        continue

                    try:
                        js_resp = await client.get(js_url, timeout=10)
                        if js_resp.status_code == 200:
                            # Extract API paths
                            api_paths = re.findall(r'["\'](/api/[^"\']+)["\']', js_resp.text)
                            endpoints.extend(api_paths)

                            # Extract fetch/axios URLs
                            fetch_urls = re.findall(r'(?:fetch|axios|ajax|request|httpClient)\s*\(\s*["\']([^"\']+)["\']', js_resp.text)
                            endpoints.extend(fetch_urls)

                            # Extract route definitions
                            routes = re.findall(r'["\'](/[a-zA-Z0-9_\-/]+)["\']', js_resp.text)
                            interesting = [r for r in routes if len(r) > 3 and any(kw in r.lower() for kw in ["api", "user", "admin", "auth", "login", "data", "config", "upload", "download", "search", "query", "export", "import"])]
                            endpoints.extend(interesting)
                    except Exception:
                        continue
        except Exception as exc:
            logger.debug("[ENUM] JS endpoint discovery error: {err}", err=exc)

        return list(set(endpoints))

    def _get_interesting_urls(self, historical_urls: list[str], live_urls: list[dict]) -> list[str]:
        """Filter URLs that are worth parameter discovery."""
        interesting = []
        seen = set()

        # Prefer live URLs
        for entry in live_urls:
            url = entry.get("url", "")
            if url and url not in seen and self.is_in_scope(url):
                parsed = urlparse(url)
                # Focus on pages, not static assets
                if parsed.path and not any(parsed.path.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff", ".ttf"]):
                    interesting.append(url)
                    seen.add(url)

        # Add historical URLs
        for url in historical_urls:
            if url not in seen and self.is_in_scope(url):
                parsed = urlparse(url)
                if "?" in url or any(kw in parsed.path.lower() for kw in ["api", "search", "user", "admin", "login", "query"]):
                    interesting.append(url)
                    seen.add(url)

        return interesting[:20]

    def _analyze_ports(self, port_results: dict[str, list[dict]], target: Target) -> list[Finding]:
        """Generate findings from port scan results."""
        findings = []

        dangerous_services = {
            "ftp": {"severity": Severity.MEDIUM, "title": "FTP Service Exposed", "cwe": "CWE-16"},
            "telnet": {"severity": Severity.HIGH, "title": "Telnet Service Exposed", "cwe": "CWE-319"},
            "smtp": {"severity": Severity.LOW, "title": "SMTP Service Detected", "cwe": "CWE-319"},
            "ssh": {"severity": Severity.LOW, "title": "SSH Service Detected", "cwe": "CWE-16"},
            "redis": {"severity": Severity.CRITICAL, "title": "Redis Service Exposed", "cwe": "CWE-306"},
            "mongodb": {"severity": Severity.CRITICAL, "title": "MongoDB Exposed", "cwe": "CWE-306"},
            "mysql": {"severity": Severity.HIGH, "title": "MySQL Service Exposed", "cwe": "CWE-306"},
            "postgresql": {"severity": Severity.HIGH, "title": "PostgreSQL Service Exposed", "cwe": "CWE-306"},
            "rdp": {"severity": Severity.HIGH, "title": "RDP Service Exposed", "cwe": "CWE-284"},
            "smb": {"severity": Severity.HIGH, "title": "SMB Service Exposed", "cwe": "CWE-200"},
            "vnc": {"severity": Severity.CRITICAL, "title": "VNC Service Exposed", "cwe": "CWE-284"},
            "elasticsearch": {"severity": Severity.CRITICAL, "title": "Elasticsearch Exposed", "cwe": "CWE-306"},
        }

        for host, ports in port_results.items():
            for port_info in ports:
                service = port_info.get("service", "").lower()
                version = port_info.get("version", "")
                port = port_info.get("port", 0)

                # Check for dangerous services
                for svc_key, svc_info in dangerous_services.items():
                    if svc_key in service:
                        finding = Finding(
                            title=svc_info["title"],
                            description=f"A {service} service is running on {host}:{port} ({version}). "
                                        f"This service should not typically be exposed to the internet. "
                                        f"An attacker could attempt brute-force attacks, exploit known "
                                        f"vulnerabilities, or use it as an entry point for further compromise.",
                            severity=svc_info["severity"],
                            agent_source=AgentType.ENUM,
                            target=Target(host=host, port=port, url=f"{host}:{port}"),
                            evidence=f"Port {port}/tcp {port_info.get('state', '')} {service} {version}",
                            remediation=f"Restrict access to {service} using firewall rules. "
                                        f"Consider using VPN or SSH tunneling for remote access. "
                                        f"Ensure the service requires authentication.",
                            cwe_ids=[svc_info["cwe"]],
                            tags=["service", "exposed", svc_key],
                            confidence="high",
                            status="confirmed",
                        )
                        findings.append(finding)

                # Flag unusual high ports with known services
                if port > 10000 and service not in ("", "unknown"):
                    finding = Finding(
                        title=f"Unusual Service on High Port: {port}/{service}",
                        description=f"Service {service} detected on non-standard port {port} on host {host}. "
                                    f"This could indicate an attacker's backdoor, a misconfigured service, "
                                    f"or an intentionally obscured service that may have weaker security controls.",
                        severity=Severity.MEDIUM,
                        agent_source=AgentType.ENUM,
                        target=Target(host=host, port=port),
                        evidence=f"Port {port}/tcp {service} {version}",
                        remediation="Investigate why this service is running on a non-standard port. "
                                    "Ensure it is an authorized service and has appropriate security controls.",
                        tags=["unusual-port", "service"],
                        confidence="medium",
                    )
                    findings.append(finding)

        return findings
