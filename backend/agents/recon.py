"""
VAPT Multi-Agent System — Reconnaissance Agent

Discovers subdomains, URLs, technologies, and assets using:
  - subfinder (passive subdomain enumeration)
  - amass (deep subdomain enumeration)
  - httpx (live probe + tech detection)
  - crt.sh (certificate transparency)
  - waybackurls (historical URLs)
  - gau (GET all URLs from multiple sources)
  - katana (authenticated-capable web crawling/spidering)
"""

import asyncio
import ipaddress
import json
import os
import re
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse

import httpx as httpx_client
from loguru import logger

from core.models import (
    AgentTask, AgentType, Finding, ScanPhase, Severity, Target, ScanResult,
)
from core.scope import ScopeManager
from core.config import AppConfig
from agents.base import BaseAgent
from tools.runner import DockerRunner, OutputParser


class ReconAgent(BaseAgent):
    """Reconnaissance agent that discovers assets and maps the attack surface.

    This is the first active agent in the pipeline.  It enumerates
    subdomains, probes for live services, and collects URL histories.
    The output feeds directly into the enumeration and fuzzing phases.
    """

    def __init__(self, scope: ScopeManager, config: AppConfig) -> None:
        super().__init__(AgentType.RECON, scope, config)
        self._runner = DockerRunner(config)
        self._http_client: Optional[httpx_client.AsyncClient] = None

    async def _get_http_client(self) -> httpx_client.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx_client.AsyncClient(
                timeout=30,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
                verify=False,
            )
        return self._http_client

    async def execute(self, task: AgentTask) -> list[Finding]:
        """Execute full reconnaissance against the target.

        Runs subdomain enumeration, live probing, URL collection, and
        technology detection in parallel where possible.
        """
        logger.info("[RECON] Starting reconnaissance for {target}", target=task.target.host)

        self.clear_findings()
        self.clear_tool_runs()
        target = task.target
        domain = target.host
        target_url = target.url or target.base_url
        is_ip_target = self._is_ip_address(domain)
        expand_subdomains = (
            not is_ip_target and self.scope.allows_subdomain_expansion(domain)
        )

        # Results containers
        all_subdomains: set[str] = set()
        dns_records: list[dict[str, Any]] = []
        live_urls: list[dict[str, Any]] = []
        historical_urls: set[str] = set()
        crawled_urls: set[str] = set()
        technologies: dict[str, list[str]] = {}

        # Run subdomain enumeration tools in parallel for DNS names only.
        # IP/loopback targets do not benefit from CT/subdomain/archive lookups
        # and those calls can block the whole pipeline for minutes.
        subdomain_tasks = []
        if expand_subdomains:
            if self.config.tools.get("subfinder", AppConfig().get_tool_config("subfinder")).enabled:
                subdomain_tasks.append(self._run_subfinder(domain))
            if self.config.tools.get("amass", AppConfig().get_tool_config("amass")).enabled:
                subdomain_tasks.append(self._run_amass(domain))
            if self.config.tools.get("assetfinder", AppConfig().get_tool_config("assetfinder")).enabled:
                subdomain_tasks.append(self._run_assetfinder(domain))
            subdomain_tasks.append(self._query_crtsh(domain))
        elif not is_ip_target:
            logger.info(
                "[RECON] Exact-host scope for {domain}; child-host enumeration is not eligible. "
                "Use *.{domain} only when subdomains are explicitly authorised.",
                domain=domain,
            )

        sub_results = await asyncio.gather(*subdomain_tasks, return_exceptions=True)
        for result in sub_results:
            if isinstance(result, Exception):
                logger.warning("[RECON] Subdomain enumeration error: {err}", err=result)
                continue
            for candidate in result:
                candidate_host = str(candidate).strip().lower().rstrip(".")
                if self._is_host_discoverable(candidate_host):
                    all_subdomains.add(candidate_host)

        logger.info("[RECON] Found {count} unique subdomains", count=len(all_subdomains))

        active_subdomains = {
            sub for sub in all_subdomains if self._is_host_in_scope(sub)
        }
        passive_only_subdomains = all_subdomains - active_subdomains

        # Add only actively authorised discovered subdomains to scope.
        for sub in active_subdomains:
            self.scope.add_discovered_asset(sub)

        # Resolve discovered names before HTTP probing. This is important
        # attack-surface evidence in its own right and prevents "subdomain
        # found but never validated" blind spots.
        dns_inputs = sorted(active_subdomains | ({domain} if not is_ip_target else set()))
        dns_records = await self._run_dns_resolution(dns_inputs)

        # Probe live hosts with httpx
        domains_to_probe = [
            host for host in sorted(active_subdomains | {domain})
            if self._is_host_in_scope(host)
        ]
        probe_inputs = [target_url] if is_ip_target and target_url else domains_to_probe
        httpx_result = await self._run_httpx(probe_inputs)
        if httpx_result:
            live_urls = [entry for entry in httpx_result if self.is_in_scope(entry.get("url", ""))]
            # Extract technologies
            for entry in live_urls:
                tech = entry.get("tech", [])
                if tech:
                    url = entry.get("url", "")
                    parsed = urlparse(url)
                    host = parsed.hostname or ""
                    technologies[host] = tech
        else:
            # Fallback: direct HTTP probe when httpx tool is not available
            live_urls = await self._direct_http_probe(probe_inputs, technologies)

        # Never promote an unverified seed into a live application. Doing so
        # made every later phase look healthy even when httpx only resolved a
        # host or the Python body probe failed. Downstream web agents now run
        # only when a response body (including a legitimate auth/block page)
        # was actually retrieved.
        if not live_urls:
            logger.warning(
                "[RECON] No body-verified HTTP application response for {url}; "
                "web discovery and DAST will remain blocked",
                url=target.base_url,
            )

        # Collect historical URLs in parallel
        url_tasks = []
        if not is_ip_target and self.config.tools.get("waybackurls", AppConfig().get_tool_config("waybackurls")).enabled:
            url_tasks.append(self._run_waybackurls(domain))
        if not is_ip_target and self.config.tools.get("gau", AppConfig().get_tool_config("gau")).enabled:
            url_tasks.append(self._run_gau(domain))

        url_results = await asyncio.gather(*url_tasks, return_exceptions=True)
        for result in url_results:
            if isinstance(result, Exception):
                logger.debug("[RECON] URL collection error: {err}", err=result)
                continue
            historical_urls.update(result)
            max_urls = int(os.environ.get("VAPT_RECON_MAX_URL_CANDIDATES", "5000"))
            if len(historical_urls) > max_urls:
                historical_urls = set(sorted(historical_urls)[:max_urls])

        if self.config.tools.get("katana", AppConfig().get_tool_config("katana")).enabled:
            crawled_urls.update(await self._run_katana(live_urls))
            historical_urls.update(crawled_urls)

        # Filter collected URLs through scope
        scoped_urls = self.scope.filter_urls(list(historical_urls))
        scoped_crawled_urls = self.scope.filter_urls(list(crawled_urls))
        logger.info(
            "[RECON] Collected {total} URL candidates ({crawled} crawled), {scoped} in scope",
            total=len(historical_urls), crawled=len(crawled_urls), scoped=len(scoped_urls),
        )

        # Store results in task metadata
        task.result = {
            "subdomains": sorted(active_subdomains),
            "discovered_subdomains": sorted(all_subdomains),
            "passive_only_subdomains": sorted(passive_only_subdomains),
            "live_urls": [entry for entry in live_urls if self.is_in_scope(entry.get("url", ""))],
            "historical_urls": sorted(scoped_urls),
            "crawled_urls": sorted(scoped_crawled_urls),
            "technologies": technologies,
            "dns_records": dns_records,
            "total_subdomains": len(all_subdomains),
            "total_active_subdomains": len(active_subdomains),
            "total_passive_only_subdomains": len(passive_only_subdomains),
            "total_dns_records": len(dns_records),
            "total_live_urls": len(live_urls),
            "total_historical_urls": len(scoped_urls),
            "total_crawled_urls": len(scoped_crawled_urls),
            "target_health": {
                "status": "ready" if live_urls else "unreachable",
                "body_verified": bool(live_urls),
                "verified_urls": len(live_urls),
                "reason": (
                    "At least one in-scope HTTP response body was verified."
                    if live_urls
                    else "No in-scope HTTP response body could be retrieved."
                ),
            },
            "tool_runs": self.get_tool_runs(),
        }

        logger.info(
            "[RECON] Recon context captured: {tech_hosts} technology host(s), {live} live URL(s), "
            "{urls} historical URL(s). Technology fingerprints are scan context, not findings.",
            tech_hosts=len(technologies),
            live=len(live_urls),
            urls=len(scoped_urls),
        )

        logger.info(
            "[RECON] Complete: {subs} subdomains, {live} live, {urls} URLs, {crawled} crawled, {tech} tech stacks",
            subs=len(all_subdomains),
            live=len(live_urls),
            urls=len(scoped_urls),
            crawled=len(scoped_crawled_urls),
            tech=len(technologies),
        )

        # Close HTTP client
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()

        return self.get_findings()

    # ── Tool Execution Methods ─────────────────────────────────────

    def _is_host_in_scope(self, host: str) -> bool:
        host = str(host or "").strip().lower().rstrip(".")
        if not host:
            return False
        return self.is_in_scope(f"https://{host}") or self.is_in_scope(f"http://{host}")

    def _is_host_discoverable(self, host: str) -> bool:
        host = str(host or "").strip().lower().rstrip(".")
        if not host:
            return False
        checker = getattr(self.scope, "is_discoverable_host", None)
        if callable(checker):
            return bool(checker(host))
        return self._is_host_in_scope(host)

    @staticmethod
    def _is_ip_address(host: str) -> bool:
        try:
            ipaddress.ip_address(str(host or "").strip().strip("[]"))
            return True
        except ValueError:
            return False

    async def _run_subfinder(self, domain: str) -> list[str]:
        """Run subfinder for passive subdomain enumeration."""
        extra_args = self.config.tools.get("subfinder", AppConfig().get_tool_config("subfinder")).extra_args
        result = await self._runner.run(
            tool_name="subfinder",
            args=["-d", domain, "-silent", "-o", "/dev/stdout"] + extra_args,
            timeout=300,
        )
        self._record_tool_run(result, "recon")
        if result.success:
            subs = OutputParser.parse_subfinder(result.stdout)
            logger.info("[RECON] subfinder: {count} subdomains", count=len(subs))
            return subs
        logger.warning("[RECON] subfinder failed: {err}", err=result.stderr[:200])
        return []

    async def _run_amass(self, domain: str) -> list[str]:
        """Run amass for deep subdomain enumeration."""
        extra_args = self.config.tools.get("amass", AppConfig().get_tool_config("amass")).extra_args
        result = await self._runner.run(
            tool_name="amass",
            args=["enum", "-passive", "-d", domain, "-o", "/dev/stdout"] + extra_args,
            timeout=max(30, int(os.environ.get("VAPT_AMASS_TIMEOUT", "180"))),
        )
        self._record_tool_run(result, "recon")
        if result.stdout.strip():
            subs = OutputParser.parse_subfinder(result.stdout)
            logger.info("[RECON] amass: {count} subdomains", count=len(subs))
            return subs
        logger.warning("[RECON] amass failed: {err}", err=result.stderr[:200])
        return []

    async def _run_assetfinder(self, domain: str) -> list[str]:
        """Run assetfinder for passive subdomain enumeration."""
        result = await self._runner.run(
            tool_name="assetfinder",
            args=["--subs-only", domain],
            timeout=max(30, int(os.environ.get("VAPT_ASSETFINDER_TIMEOUT", "120"))),
        )
        self._record_tool_run(result, "recon")
        if result.stdout.strip():
            subs = OutputParser.parse_subfinder(result.stdout)
            logger.info("[RECON] assetfinder: {count} subdomains", count=len(subs))
            return subs
        logger.warning("[RECON] assetfinder failed: {err}", err=result.stderr[:200])
        return []

    async def _run_dns_resolution(self, domains: list[str]) -> list[dict[str, Any]]:
        """Resolve discovered domains with dnsx and return structured DNS evidence."""
        if not domains or not self.config.tools.get("dnsx", AppConfig().get_tool_config("dnsx")).enabled:
            return []

        from tools.runner import shared_temp_path
        host_path = shared_temp_path(suffix=".txt")
        with open(host_path, "w") as f:
            f.write("\n".join(sorted(set(domains))))

        try:
            result = await self._runner.run(
                tool_name="dnsx",
                args=[
                    "-l", host_path,
                    "-json",
                    "-silent",
                    "-a",
                    "-aaaa",
                    "-cname",
                    "-resp",
                ],
                timeout=300,
            )
            self._record_tool_run(result, "recon")
            if result.stdout.strip():
                records = self._parse_dnsx(result.stdout)
                logger.info("[RECON] dnsx: {count} resolved DNS records", count=len(records))
                return records
            if result.stderr:
                logger.debug("[RECON] dnsx stderr: {err}", err=result.stderr[:500])
            return []
        finally:
            try:
                import os
                os.unlink(host_path)
            except OSError:
                pass

    @staticmethod
    def _parse_dnsx(output: str) -> list[dict[str, Any]]:
        """Parse dnsx JSONL/plain output into DNS record dictionaries."""
        records: list[dict[str, Any]] = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                parts = line.split()
                if parts:
                    records.append({"host": parts[0], "raw": line})
                continue

            host = data.get("host") or data.get("input") or ""
            for record_type in ("a", "aaaa", "cname"):
                values = data.get(record_type) or []
                if isinstance(values, str):
                    values = [values]
                for value in values:
                    records.append({
                        "host": host,
                        "type": record_type.upper(),
                        "value": value,
                        "raw": data,
                    })
            if not any(data.get(key) for key in ("a", "aaaa", "cname")) and host:
                records.append({"host": host, "raw": data})
        return records

    async def _query_crtsh(self, domain: str) -> list[str]:
        """Query crt.sh for certificate transparency subdomains."""
        try:
            client = await self._get_http_client()
            response = await client.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=30,
            )
            if response.status_code == 200:
                data = response.json()
                domains = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for d in name.split("\n"):
                        d = d.strip().lstrip("*.")
                        if d and d.endswith(domain):
                            domains.add(d)
                logger.info("[RECON] crt.sh: {count} subdomains", count=len(domains))
                return list(domains)
        except Exception as exc:
            logger.warning("[RECON] crt.sh query failed: {err}", err=exc)
        return []

    async def _run_httpx(self, domains: list[str]) -> list[dict[str, Any]]:
        """Run httpx to probe live hosts and detect technologies."""
        if not domains:
            return []

        extra_args = self.config.tools.get("httpx", AppConfig().get_tool_config("httpx")).extra_args

        # Write domains to the SHARED temp dir so the httpx Docker container
        # can see the file (host /tmp is not visible inside containers).
        from tools.runner import shared_temp_path
        host_path = shared_temp_path(suffix=".txt")
        with open(host_path, "w") as f:
            f.write("\n".join(domains))

        try:
            result = await self._runner.run(
                tool_name="httpx",
                args=[
                    "-l", host_path,   # runner rewrites to container path
                    "-json",
                    "-silent",
                    "-retries", "2",
                    "-timeout", "10",
                ] + extra_args,
                timeout=300,
            )
            self._record_tool_run(result, "recon")
            if result.success:
                parsed = [
                    entry for entry in OutputParser.parse_httpx(result.stdout)
                    if self.is_in_scope(entry.get("url", ""))
                ]
                await self._verify_http_bodies(parsed)
                verified = [
                    entry for entry in parsed
                    if entry.get("body_verified") and entry.get("body_usable")
                ]
                rejected = len(parsed) - len(verified)
                logger.info(
                    "[RECON] httpx: {live} body-verified URLs ({rejected} rejected)",
                    live=len(verified), rejected=rejected,
                )
                return verified
            if result.stderr:
                logger.warning("[RECON] httpx failed: {err}", err=result.stderr[:500])
            return []
        finally:
            try:
                import os
                os.unlink(host_path)
            except OSError:
                pass

    async def _verify_http_bodies(self, entries: list[dict[str, Any]]) -> None:
        """Attach body proof and supplement header-only technology signals."""
        if not entries:
            return
        client = await self._get_http_client()
        semaphore = asyncio.Semaphore(5)

        async def verify(entry: dict[str, Any]) -> None:
            url = str(entry.get("url") or "")
            if not url or not self.is_in_scope(url):
                return
            async with semaphore:
                try:
                    response = await client.get(url, timeout=15)
                except Exception as exc:
                    entry["body_verified"] = False
                    entry["body_error"] = str(exc)[:200]
                    return
            from core.http_evidence import fingerprint_response
            fp = fingerprint_response(response)
            body = (response.text or "")[:100_000].lower()
            blocked = response.status_code in {401, 403, 407, 429}
            usable = fp.length > 0 and response.status_code < 500
            tech = {str(item) for item in (entry.get("tech") or []) if item}
            header_hints = (
                response.headers.get("server", ""),
                response.headers.get("x-powered-by", ""),
            )
            tech.update(item for item in header_hints if item)
            markers = (
                (("wp-content", "wordpress"), "WordPress"),
                (("drupal", "/sites/default/"), "Drupal"),
                (("joomla", "com_content"), "Joomla"),
                (("ng-version", "<app-root"), "Angular"),
                (("__next", "next.js"), "Next.js"),
                (("reactroot", "data-reactroot"), "React"),
                (("v-cloak", "vue.js"), "Vue.js"),
                (("swagger-ui", '"openapi"'), "OpenAPI"),
                (("jquery",), "jQuery"),
            )
            for needles, name in markers:
                if any(needle in body for needle in needles):
                    tech.add(name)
            entry.update({
                "status_code": response.status_code,
                "content_type": fp.content_type,
                "content_length": fp.length,
                "body_sha256": fp.digest,
                "body_verified": True,
                "body_usable": usable,
                "access_state": "restricted" if blocked else "available" if usable else "invalid",
                "tech": sorted(tech),
            })
            logger.info(
                "[RECON] Body verified {url}: status={status} type={ctype} bytes={length} sha256={digest}",
                url=url, status=fp.status, ctype=fp.content_type or "unknown",
                length=fp.length, digest=fp.digest[:16],
            )

        await asyncio.gather(*(verify(entry) for entry in entries[:20]))

    async def _run_waybackurls(self, domain: str) -> list[str]:
        """Collect historical URLs from Wayback Machine."""
        result = await self._runner.run(
            tool_name="waybackurls",
            args=[domain],
            timeout=max(30, int(os.environ.get("VAPT_WAYBACK_TIMEOUT", "90"))),
        )
        self._record_tool_run(result, "recon")
        if result.stdout.strip():
            urls = [u.strip() for u in result.stdout.strip().splitlines() if u.strip()]
            logger.info("[RECON] waybackurls: {count} URLs", count=len(urls))
            return urls
        return []

    async def _run_gau(self, domain: str) -> list[str]:
        """Collect root-domain archive URLs without stalling the scan.

        Subdomains are discovered by dedicated recon providers. Asking GAU to
        expand them again makes large public targets explode in size and the
        previous identical retry added another three minutes without changing
        the failure mode. Preserve partial output from one bounded request and
        let live crawling continue independently.
        """
        timeout = max(30, int(os.environ.get("VAPT_GAU_TIMEOUT", "90")))
        result = await self._runner.run(
            tool_name="gau",
            args=["--threads", "5", domain],
            timeout=timeout,
        )
        self._record_tool_run(result, "recon")
        urls = sorted({u.strip() for u in result.stdout.splitlines() if u.strip().startswith(("http://", "https://"))})
        # Provider fan-out can fail transiently even when GAU itself is healthy.
        # Retry once at one thread only when the first attempt produced no
        # usable evidence. Preserve partial output even when a provider keeps
        # the process exit code non-zero.
        if not urls and not result.success:
            retry = await self._runner.run(
                tool_name="gau",
                args=["--threads", "2", domain],
                timeout=max(timeout, int(os.environ.get("VAPT_GAU_RETRY_TIMEOUT", "180"))),
            )
            self._record_tool_run(retry, "recon")
            urls = sorted({
                value.strip()
                for value in retry.stdout.splitlines()
                if value.strip().startswith(("http://", "https://"))
            })
            result = retry
        if urls:
            logger.info(
                "[RECON] gau: {count} URLs ({outcome})",
                count=len(urls), outcome=result.outcome,
            )
            return urls
        return []

    async def _run_katana(self, live_urls: list[dict[str, Any]]) -> list[str]:
        """Crawl live web roots with katana and return discovered URLs."""
        seeds = []
        seen = set()
        for entry in live_urls:
            url = entry.get("url", "")
            if url and url not in seen and self.is_in_scope(url):
                seeds.append(url)
                seen.add(url)
        if not seeds:
            return []

        # Keep phase runtime bounded. Deep crawling every host belongs in a
        # future distributed worker pass; this gives VA mode broad signal now.
        seeds = seeds[:25]
        extra_args = self.config.tools.get("katana", AppConfig().get_tool_config("katana")).extra_args
        crawl_seconds = max(30, int(os.environ.get("VAPT_KATANA_CRAWL_DURATION", "240")))
        tool_timeout = max(crawl_seconds + 30, int(os.environ.get("VAPT_KATANA_TIMEOUT", "330")))
        if "-ct" not in extra_args and "-crawl-duration" not in extra_args:
            extra_args = list(extra_args) + ["-ct", f"{crawl_seconds}s"]

        from tools.runner import shared_temp_path
        host_path = shared_temp_path(suffix=".txt")
        with open(host_path, "w") as f:
            f.write("\n".join(seeds))

        try:
            # Recon needs canonical URLs, not response bodies. Plain silent
            # output is stable across Katana releases and avoids the previous
            # JSONL flag compatibility branch that visibly launched a second
            # full crawl (reported by operators as a Katana restart).
            result = await self._runner.run(
                tool_name="katana",
                args=["-list", host_path, "-silent"] + extra_args,
                timeout=tool_timeout,
            )
            self._record_tool_run(result, "recon")
            if result.stdout.strip():
                urls = self._parse_katana_urls(result.stdout)
                logger.info("[RECON] katana: {count} crawled URLs", count=len(urls))
                return urls
            if result.stderr:
                logger.debug("[RECON] katana stderr: {err}", err=result.stderr[:500])
            return []
        finally:
            try:
                os.unlink(host_path)
            except OSError:
                pass

    @staticmethod
    def _parse_katana_urls(output: str) -> list[str]:
        """Parse katana JSONL or plain URL output."""
        urls: set[str] = set()
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("http://") or line.startswith("https://"):
                urls.add(line)
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                for url in OutputParser.parse_urls_from_text(line):
                    urls.add(url)
                continue

            candidates = [
                data.get("url"),
                data.get("endpoint"),
                data.get("request", {}).get("endpoint") if isinstance(data.get("request"), dict) else None,
                data.get("response", {}).get("url") if isinstance(data.get("response"), dict) else None,
            ]
            for candidate in candidates:
                if isinstance(candidate, str) and candidate.startswith(("http://", "https://")):
                    urls.add(candidate)
        return sorted(urls)

    # ── Finding Generation ─────────────────────────────────────────

    def _check_tech_findings(self, technologies: dict[str, list[str]], target: Target) -> None:
        """Deprecated: technology fingerprints are context, not findings.

        Keep this no-op as a compatibility hook for older callers. Version/CVE
        intelligence belongs in the intel/vulnerability phases after evidence is
        tied to a verified vulnerable version or concrete misconfiguration.
        """
        return

    async def _direct_http_probe(self, hosts: list[str], technologies: dict) -> list[dict]:
        """Pure Python fallback: probe hosts directly with httpx when CLI tools are unavailable."""
        results = []
        client = await self._get_http_client()

        for host in hosts:
            raw = str(host or "").strip()
            candidates = [raw] if raw.startswith(("http://", "https://")) else [f"https://{raw}", f"http://{raw}"]
            for url in candidates:
                if not self.is_in_scope(url):
                    continue
                try:
                    resp = await client.get(
                        url,
                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
                        timeout=15,
                        follow_redirects=True,
                    )
                    # Extract title
                    title = ""
                    import re as _re
                    title_match = _re.search(r"<title[^>]*>(.*?)</title>", resp.text[:50000], _re.IGNORECASE | _re.DOTALL)
                    if title_match:
                        title = title_match.group(1).strip()[:100]

                    # Extract server and tech hints from headers
                    server = resp.headers.get("server", "")
                    powered_by = resp.headers.get("x-powered-by", "")
                    via = resp.headers.get("via", "")
                    generator = resp.headers.get("x-generator", "")

                    tech_hints = []
                    if server:
                        tech_hints.append(server)
                    if powered_by:
                        tech_hints.append(powered_by)
                    if via:
                        tech_hints.append(via)
                    if generator:
                        tech_hints.append(generator)

                    # Basic body-based tech detection
                    body_lower = resp.text[:10000].lower()
                    if "wordpress" in body_lower or "wp-content" in body_lower:
                        tech_hints.append("WordPress")
                    if "drupal" in body_lower:
                        tech_hints.append("Drupal")
                    if "joomla" in body_lower:
                        tech_hints.append("Joomla")
                    if "django" in body_lower or "csrfmiddleware" in body_lower:
                        tech_hints.append("Django")
                    if "laravel" in body_lower:
                        tech_hints.append("Laravel")
                    if "next.js" in body_lower or "__next" in body_lower:
                        tech_hints.append("Next.js")
                    if "react" in body_lower and "react" not in title.lower():
                        tech_hints.append("React")
                    if "angular" in body_lower or "ng-version" in body_lower:
                        tech_hints.append("Angular")
                    if "vue" in body_lower or "v-cloak" in body_lower:
                        tech_hints.append("Vue.js")
                    if "jquery" in body_lower:
                        tech_hints.append("jQuery")
                    if "bootstrap" in body_lower:
                        tech_hints.append("Bootstrap")
                    if "nginx" in server.lower():
                        tech_hints.append("Nginx")
                    if "apache" in server.lower():
                        tech_hints.append("Apache")

                    final_url = str(resp.url)
                    if not self.is_in_scope(final_url):
                        logger.warning(
                            "[RECON] Redirect left scope, dropping live URL: {source} -> {final}",
                            source=url,
                            final=final_url,
                        )
                        continue
                    from core.http_evidence import fingerprint_response

                    fp = fingerprint_response(resp)
                    final = urlparse(final_url)
                    usable = fp.length > 0 and resp.status_code < 500
                    entry = {
                        "url": final_url,
                        "status": resp.status_code,
                        "status_code": resp.status_code,
                        "title": title,
                        "content_type": fp.content_type,
                        "content_length": fp.length,
                        "body_sha256": fp.digest,
                        "body_verified": True,
                        "body_usable": usable,
                        "access_state": "restricted" if resp.status_code in {401, 403, 407, 429} else "available" if usable else "invalid",
                        "tech": tech_hints,
                        "server": server,
                        "scheme": final.scheme,
                    }
                    if usable:
                        results.append(entry)

                    if tech_hints:
                        hostname = final.hostname or urlparse(url).hostname or raw
                        technologies[hostname] = tech_hints

                    logger.info("[RECON] Direct probe: {status} {url} [{title}] tech={tech}", status=resp.status_code, url=final_url, title=title, tech=tech_hints)

                    # HTTPS worked, skip HTTP
                    if final.scheme == "https" and resp.status_code < 400:
                        break

                except Exception as exc:
                    logger.debug("[RECON] Direct probe failed for {url}: {err}", url=url, err=exc)
                    continue

        return results
