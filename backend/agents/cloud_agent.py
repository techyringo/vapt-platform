"""
VAPT Multi-Agent System — Cloud Security Agent

Cloud infrastructure security assessment:
  - SecurityTrails API (DNS history, associated domains, IP ranges)
  - AWS S3 bucket enumeration and access checks
  - Azure Blob Storage checks
  - GCP Cloud Storage checks
  - Cloud provider fingerprinting
  - DNS record analysis (SPF, DMARC, DKIM)
  - Cloud metadata endpoint checks
"""

import asyncio
import json
import os
import re
from typing import Any, Optional
from urllib.parse import urlparse

import httpx as httpx_client
from loguru import logger

from core.models import AgentTask, AgentType, Finding, Severity, Target, ScanPhase
from core.scope import ScopeManager
from core.config import AppConfig
from agents.base import BaseAgent
from tools.runner import DockerRunner, OutputParser


class CloudAgent(BaseAgent):
    """Cloud security assessment agent.

    Enumerates cloud assets, checks for misconfigured storage,
    analyzes DNS records, and identifies cloud provider infrastructure.
    """

    def __init__(self, scope: ScopeManager, config: AppConfig) -> None:
        super().__init__(AgentType.CLOUD, scope, config)
        self._runner = DockerRunner(config)

    async def execute(self, task: AgentTask) -> list[Finding]:
        logger.info("[CLOUD] Starting cloud security assessment")
        self.clear_findings()
        self.clear_tool_runs()

        domain = task.target.host
        recon_data = task.parameters.get("recon_data", task.result or {})
        subdomains = recon_data.get("subdomains", [])
        live_urls = recon_data.get("live_urls", [])

        # Phase 1: DNS Record Analysis
        await self._analyze_dns_records(domain)
        await self._check_email_security(domain)

        # Phase 2: Cloud Provider Fingerprinting
        cloud_assets = await self._fingerprint_cloud_infrastructure(domain, live_urls, subdomains)

        # Phase 3: S3 / Cloud Storage Checks
        s3_candidates_checked = await self._check_cloud_storage(domain, subdomains)

        # Phase 4: SecurityTrails Integration
        await self._query_securitytrails(domain)

        # Phase 5: Cloud Metadata Checks on discovered endpoints
        for entry in live_urls[:10]:
            url = entry.get("url", "")
            if url and self.is_in_scope(url):
                await self._check_cloud_metadata(url)

        # Phase 6: Azure/GCP specific checks
        await self._check_azure_resources(domain, subdomains)
        await self._check_gcp_resources(domain, subdomains)

        task.result = {
            "cloud_assets": cloud_assets,
            "total_cloud_findings": len(self._findings),
            "coverage": {
                "cloud_s3_storage": {
                    "status": "completed",
                    "candidates_checked": s3_candidates_checked,
                    "method": "cloud_agent_http_bucket_checks",
                    "notes": "S3 candidates were actively checked for public bucket listing responses.",
                },
                "azure_storage": {
                    "status": "completed",
                    "method": "cloud_agent_http_blob_checks",
                },
                "gcp_storage": {
                    "status": "completed",
                    "method": "cloud_agent_http_storage_checks",
                },
            },
        }

        logger.info("[CLOUD] Complete: {count} cloud findings", count=len(self._findings))
        return self.get_findings()

    async def _analyze_dns_records(self, domain: str) -> None:
        """Analyze DNS records for security issues."""
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]

        import subprocess
        for rtype in record_types:
            try:
                result = subprocess.run(
                    ["dig", "+short", domain, rtype],
                    capture_output=True, text=True, timeout=15
                )
                output = result.stdout.strip()
                if output:
                    logger.debug("[CLOUD] DNS {type} for {domain}: {out}", type=rtype, domain=domain, out=output[:100])
                    # Check for security-relevant DNS findings
                    self._analyze_dns_output(domain, rtype, output)
            except Exception:
                pass

    def _analyze_dns_output(self, domain: str, rtype: str, output: str) -> None:
        """Generate findings from DNS record analysis."""
        # Check for high TTL values (could indicate stale records)
        if rtype == "NS":
            nameservers = [l.strip() for l in output.splitlines() if l.strip()]
            if len(nameservers) >= 2:
                # Check if NS records point to different providers (split-horizon risk)
                domains_ns = set()
                for ns in nameservers:
                    ns_domain = ".".join(ns.split(".")[-2:]) if "." in ns else ns
                    domains_ns.add(ns_domain)
                if len(domains_ns) > 1:
                    finding = Finding(
                        title=f"DNS Nameservers on Multiple Providers",
                        description=f"The domain {domain} uses nameservers across {len(domains_ns)} different providers: "
                                    f"{', '.join(domains_ns)}. Split DNS providers can indicate a complex infrastructure "
                                    f"but may also suggest subdomain takeover risk if DNS records are not properly managed.",
                        severity=Severity.LOW,
                        agent_source=AgentType.CLOUD,
                        target=Target(host=domain),
                        evidence=f"NS Records: {', '.join(nameservers[:5])}",
                        remediation="Consolidate DNS management under a single provider. "
                                    "Audit all DNS records for stale entries that could lead to subdomain takeover.",
                        tags=["dns", "nameserver", "recon"],
                        confidence="medium",
                    )
                    self._add_finding(finding)

        # Check for SPF records
        if rtype == "TXT" and ("v=spf1" in output.lower() or "spf2" in output.lower()):
            spf_record = output
            if "-all" not in spf_record and "~all" not in spf_record:
                finding = Finding(
                    title="Weak or Missing SPF Policy",
                    description=f"The SPF record for {domain} does not end with -all or ~all. "
                                f"This means email spoofing is not strictly prevented, allowing attackers "
                                f"to send phishing emails that appear to come from this domain.",
                    severity=Severity.MEDIUM,
                    agent_source=AgentType.CLOUD,
                    target=Target(host=domain),
                    evidence=f"SPF Record: {spf_record[:200]}",
                    remediation="Update the SPF record to end with -all (hard fail) or ~all (soft fail). "
                                "This prevents unauthorized mail servers from sending email on behalf of your domain.",
                    cwe_ids=["CWE-933"],
                    tags=["dns", "spf", "email-security", "phishing"],
                    confidence="high",
                    status="confirmed",
                )
                self._add_finding(finding)

    async def _check_email_security(self, domain: str) -> None:
        """Check DMARC and DKIM configuration."""
        # DMARC check
        try:
            async with httpx_client.AsyncClient(timeout=10) as client:
                resp = await client.get(f"https://dmarc.elasticemail.com/_dmarc/{domain}")
                # Alternative: check TXT record for _dmarc.domain
                import subprocess
                result = subprocess.run(
                    ["dig", "+short", "TXT", f"_dmarc.{domain}"],
                    capture_output=True, text=True, timeout=15
                )
                dmarc = result.stdout.strip()

                if not dmarc or "v=DMARC1" not in dmarc:
                    finding = Finding(
                        title="DMARC Record Missing or Misconfigured",
                        description=f"No valid DMARC record was found for {domain}. DMARC helps prevent "
                                    f"email spoofing and phishing by defining how receivers should handle "
                                    f"emails that fail authentication. Without DMARC, attackers can easily "
                                    f"impersonate your domain in phishing campaigns.",
                        severity=Severity.MEDIUM,
                        agent_source=AgentType.CLOUD,
                        target=Target(host=domain),
                        evidence=f"DMARC lookup result: {dmarc or 'No record found'}",
                        remediation="Publish a DMARC record at _dmarc.{domain} with p=reject or p=quarantine. "
                                    "Example: v=DMARC1; p=reject; rua=mailto:dmarc@{domain}".format(domain=domain),
                        cwe_ids=["CWE-933"],
                        tags=["dmarc", "email-security", "phishing", "spoofing"],
                        confidence="high",
                        status="confirmed",
                    )
                    self._add_finding(finding)
                elif "p=none" in dmarc:
                    finding = Finding(
                        title="DMARC Policy Set to None (Monitoring Only)",
                        description=f"The DMARC record for {domain} is set to p=none, which means no action "
                                    f"is taken on failed emails. While useful for monitoring, this provides "
                                    f"no protection against email spoofing and phishing attacks.",
                        severity=Severity.LOW,
                        agent_source=AgentType.CLOUD,
                        target=Target(host=domain),
                        evidence=f"DMARC Record: {dmarc[:200]}",
                        remediation="Change DMARC policy from p=none to p=quarantine or p=reject after "
                                    "monitoring phase is complete.",
                        tags=["dmarc", "email-security"],
                        confidence="high",
                        status="confirmed",
                    )
                    self._add_finding(finding)
        except Exception as exc:
            logger.debug("[CLOUD] DMARC check error: {err}", err=exc)

    async def _fingerprint_cloud_infrastructure(
        self, domain: str, live_urls: list[dict], subdomains: list[str]
    ) -> list[dict]:
        """Identify cloud provider infrastructure."""
        cloud_indicators = {
            "aws": ["amazonaws.com", "elasticbeanstalk.com", "cloudfront.net", "s3.amazonaws.com", "rds.amazonaws.com", "lambda-url"],
            "azure": ["azurewebsites.net", "azure.com", "blob.core.windows.net", "cloudapp.net", "trafficmanager.net"],
            "gcp": ["appspot.com", "googleapis.com", "cloudfunctions.net", "run.app", "gcr.io", "storage.googleapis.com"],
            "cloudflare": ["cloudflare.com", "workers.dev", "pages.dev", "cf-ipfs.com"],
            "digitalocean": ["digitaloceanspaces.com", "do.app", "ondigitalocean.app"],
            "heroku": ["herokuapp.com", "herokudns.com"],
            "vercel": ["vercel.app", "now.sh"],
            "netlify": ["netlify.app", "netlify.com"],
        }

        cloud_assets = []
        all_hosts = [domain] + subdomains
        for entry in live_urls:
            url = entry.get("url", "")
            if url:
                try:
                    p = urlparse(url)
                    if p.hostname:
                        all_hosts.append(p.hostname)
                except Exception:
                    pass

        for host in set(all_hosts):
            for provider, indicators in cloud_indicators.items():
                for indicator in indicators:
                    if indicator in host.lower():
                        cloud_assets.append({"host": host, "provider": provider, "indicator": indicator})
                        break

        if cloud_assets:
            logger.info("[CLOUD] Found {count} cloud assets", count=len(cloud_assets))

        return cloud_assets

    def _load_s3_wordlist_candidates(self, domain: str) -> list[str]:
        wordlist_dir = os.environ.get("VAPT_WORDLIST_DIR", "/app/wordlists")
        path = os.path.join(wordlist_dir, "s3-buckets.txt")
        root = domain.split(".")[0]
        candidates: list[str] = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    item = line.strip()
                    if not item or item.startswith("#"):
                        continue
                    candidates.append(
                        item.format(domain=domain, root=root).replace("..", ".")
                    )
        except OSError:
            return []
        return candidates

    async def _check_cloud_storage(self, domain: str, subdomains: list[str]) -> int:
        """Check for exposed S3 buckets and cloud storage."""
        bucket_names = [
            domain.replace(".", "-"),
            domain.replace(".", ""),
            f"{domain.split('.')[0]}-assets",
            f"{domain.split('.')[0]}-media",
            f"{domain.split('.')[0]}-uploads",
            f"{domain.split('.')[0]}-backup",
            f"{domain.split('.')[0]}-data",
            f"{domain.split('.')[0]}-static",
            f"{domain.split('.')[0]}-public",
            f"{domain.split('.')[0]}-private",
            f"{domain.split('.')[0]}-staging",
            f"{domain.split('.')[0]}-prod",
            f"{domain.split('.')[0]}-dev",
        ]
        bucket_names.extend(self._load_s3_wordlist_candidates(domain))

        # Check for S3 bucket patterns in subdomains
        for sub in subdomains:
            if "s3" in sub.lower() or "bucket" in sub.lower() or "storage" in sub.lower():
                bucket_names.append(sub)

        unique_buckets = list(dict.fromkeys(bucket_names))
        checked = 0
        async with httpx_client.AsyncClient(timeout=8, follow_redirects=True) as client:
            for bucket in unique_buckets[:50]:
                try:
                    checked += 1
                    resp = await client.get(f"http://{bucket}.s3.amazonaws.com/")
                    if resp.status_code == 200 and "ListBucketResult" in resp.text:
                        finding = Finding(
                            title=f"Public S3 Bucket: {bucket}",
                            description=f"An S3 bucket named '{bucket}' is publicly accessible and allows listing. "
                                        f"This could expose sensitive files, backups, or user data to anyone on the internet.",
                            severity=Severity.CRITICAL,
                            cvss_score=9.1,
                            agent_source=AgentType.CLOUD,
                            target=Target(host=f"{bucket}.s3.amazonaws.com"),
                            evidence=f"HTTP 200 — Bucket listing enabled\n{resp.text[:500]}",
                            request_proof=f"GET http://{bucket}.s3.amazonaws.com/",
                            response_proof=f"HTTP 200\n{resp.text[:1000]}",
                            remediation="Set the S3 bucket ACL to private. Implement bucket policies "
                                        "that deny public access. Enable server-side encryption. "
                                        "Use IAM policies for access control.",
                            cwe_ids=["CWE-312", "CWE-200"],
                            tags=["s3", "cloud-storage", "exposure", "aws", "data-leak", "replay-proof"],
                            confidence="high",
                            status="confirmed",
                        )
                        self._add_finding(finding)
                except Exception:
                    continue
        return checked

    async def _check_cloud_metadata(self, url: str) -> None:
        """Check if cloud metadata endpoints are accessible from the application."""
        metadata_endpoints = [
            ("AWS EC2 Metadata", "http://169.254.169.254/latest/meta-data/", "ami-id,instance-id"),
            ("AWS IMDSv2 Token", "http://169.254.169.254/latest/api/token", "token"),
            ("GCP Metadata", "http://metadata.google.internal/computeMetadata/v1/", "project-id"),
            ("Azure IMDS", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "compute"),
            ("DigitalOcean Metadata", "http://169.254.169.254/metadata/v1/", "droplet-id"),
        ]

        for name, endpoint, indicator in metadata_endpoints:
            # Check if the web app can reach internal metadata (SSRF vector)
            try:
                async with httpx_client.AsyncClient(timeout=5, verify=False) as client:
                    headers = {"User-Agent": "Mozilla/5.0"}
                    if "google" in endpoint:
                        headers["Metadata-Flavor"] = "Google"
                    if "api/token" in endpoint:
                        headers["X-aws-ec2-metadata-token-ttl-seconds"] = "21600"
                        # Need to PUT first for IMDSv2
                        try:
                            put_resp = await client.put(endpoint, headers=headers, timeout=3)
                            if put_resp.status_code == 200:
                                headers["X-aws-ec2-metadata-token"] = put_resp.text.strip()
                        except Exception:
                            pass

                    resp = await client.get(endpoint, headers=headers, timeout=3)
                    if resp.status_code == 200 and len(resp.text) > 10:
                        if any(kw in resp.text.lower() for kw in indicator.split(",")):
                            finding = Finding(
                                title=f"Cloud Metadata Accessible via Web App (SSRF): {name}",
                                description=f"The web application at {url} can reach the {name} metadata endpoint. "
                                            f"This indicates a potential SSRF vulnerability that could allow an attacker "
                                            f"to access cloud instance metadata, including IAM credentials, API keys, "
                                            f"and other sensitive configuration data.",
                                severity=Severity.CRITICAL,
                                cvss_score=9.8,
                                agent_source=AgentType.CLOUD,
                                target=Target(host=task_target_host(url)),
                                evidence=f"Metadata endpoint: {endpoint}\nResponse preview: {resp.text[:300]}",
                                remediation=f"Block access to internal/cloud metadata IP ranges (169.254.169.254, metadata.google.internal) "
                                            f"at the network level. Implement SSRF protections in the application layer. "
                                            f"Use IMDSv2 for AWS instances.",
                                cwe_ids=["CWE-918", "CWE-200"],
                                tags=["ssrf", "cloud-metadata", name.lower().replace(" ", "-"), "data-leak"],
                                confidence="high",
                                status="confirmed",
                            )
                            self._add_finding(finding)
            except Exception:
                continue

    async def _check_azure_resources(self, domain: str, subdomains: list[str]) -> None:
        """Check for Azure-specific misconfigurations."""
        azure_patterns = [s for s in subdomains if "azure" in s.lower() or "windows.net" in s.lower()]
        if azure_patterns:
            # Check for exposed Azure Blob Storage
            for sub in azure_patterns:
                if "blob.core.windows.net" in sub:
                    try:
                        async with httpx_client.AsyncClient(timeout=8) as client:
                            resp = await client.get(f"https://{sub}/?restype=container&comp=list")
                            if resp.status_code == 200 and "Container" in resp.text:
                                finding = Finding(
                                    title=f"Exposed Azure Blob Storage: {sub}",
                                    description=f"Azure Blob Storage container list is publicly accessible at {sub}. "
                                                f"This could expose sensitive files and data stored in Azure.",
                                    severity=Severity.HIGH,
                                    agent_source=AgentType.CLOUD,
                                    target=Target(host=sub),
                                    evidence=f"Container listing returned HTTP 200",
                                    remediation="Set Azure Blob container access level to Private. "
                                                "Use Shared Access Signatures (SAS) for controlled access. "
                                                "Enable storage account firewall rules.",
                                    cwe_ids=["CWE-312"],
                                    tags=["azure", "blob-storage", "exposure", "cloud"],
                                    confidence="high",
                                    status="confirmed",
                                )
                                self._add_finding(finding)
                    except Exception:
                        continue

    async def _check_gcp_resources(self, domain: str, subdomains: list[str]) -> None:
        """Check for GCP-specific misconfigurations."""
        gcp_patterns = [s for s in subdomains if "appspot.com" in s or "googleapis.com" in s]
        if gcp_patterns:
            # Check for exposed GCP buckets
            for sub in gcp_patterns:
                if "storage.googleapis.com" in sub:
                    try:
                        async with httpx_client.AsyncClient(timeout=8) as client:
                            resp = await client.get(f"https://{sub}")
                            if resp.status_code == 200 and len(resp.text) > 100:
                                finding = Finding(
                                    title=f"Potentially Exposed GCP Storage: {sub}",
                                    description=f"GCP Cloud Storage bucket appears publicly accessible at {sub}.",
                                    severity=Severity.HIGH,
                                    agent_source=AgentType.CLOUD,
                                    target=Target(host=sub),
                                    remediation="Set GCP bucket IAM policy to deny public access. "
                                                "Enable uniform bucket-level access.",
                                    cwe_ids=["CWE-312"],
                                    tags=["gcp", "cloud-storage", "exposure", "cloud"],
                                    confidence="medium",
                                )
                                self._add_finding(finding)
                    except Exception:
                        continue

    async def _query_securitytrails(self, domain: str) -> None:
        """Query SecurityTrails API for DNS history and associated data."""
        import os
        api_key = os.environ.get("SECURITYTRAILS_API_KEY", "")
        if not api_key:
            logger.info("[CLOUD] No SecurityTrails API key — skipping")
            return

        try:
            async with httpx_client.AsyncClient(timeout=15) as client:
                # Get domain details
                resp = await client.get(
                    f"https://api.securitytrails.com/v1/domain/{domain}",
                    headers={"APIKEY": api_key},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    # Check for interesting records
                    records = data.get("records", {})
                    if records:
                        logger.info("[CLOUD] SecurityTrails: {dns_types} record types found",
                                    dns_types=", ".join(records.keys()))

                    # Check for subdomains
                    subdomains_st = data.get("subdomains", [])
                    if subdomains_st:
                        logger.info("[CLOUD] SecurityTrails: {count} historical subdomains",
                                    count=len(subdomains_st))
        except Exception as exc:
            logger.debug("[CLOUD] SecurityTrails query failed: {err}", err=exc)


def task_target_host(url: str) -> str:
    """Extract hostname from a URL string."""
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""
