"""
VAPT Platform — NVD (National Vulnerability Database) Verification Service

Every finding with a CVE ID is cross-verified against the NVD API to:
  1. Confirm the CVE exists and is published
  2. Pull the official CVSS v3.1 score and vector
  3. Pull the official description, references, and CPE matches
  4. Flag any CVE that is REJECTED or under analysis

Uses the NVD 2.0 REST API (api.nvd.nist.gov/vuln/v2.0).
Rate-limited to 5 requests/30 seconds (NVD API requirement).
Results are cached in-memory to avoid redundant lookups.

This is what separates a school project from an industry tool:
  - Faraday uses its own vuln DB but can cross-reference CVEs
  - OpenVAS/GVM uses the NVT feed + CVE data from NVD
  - We query NVD directly for every CVE we find
"""

import asyncio
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx
from loguru import logger


@dataclass
class NVDRecord:
    """A verified CVE record from NVD."""
    cve_id: str
    published: str = ""
    last_modified: str = ""
    description: str = ""
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: str = ""
    severity: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    cpe_matches: list[str] = field(default_factory=list)
    status: str = "PUBLISHED"  # PUBLISHED, REJECTED, UNDER_ANALYSIS
    nvd_url: str = ""
    verified: bool = False


class NVDService:
    """NVD 2.0 API client for CVE verification.

    Industry tools like OpenVAS maintain their own CVE databases,
    but they still cross-reference with NVD. We do the same —
    every finding that claims a CVE gets verified.

    Rate limiting: NVD allows 5 requests per 30 seconds without an API key.
    With an API key: 50 requests per 30 seconds.

    Args:
        api_key: Optional NVD API key for higher rate limits.
        cache_ttl: Time-to-live for cached records (seconds).
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    REQUEST_WINDOW = 30  # seconds
    MAX_REQUESTS_NO_KEY = 5
    MAX_REQUESTS_WITH_KEY = 50

    def __init__(self, api_key: Optional[str] = None, cache_ttl: int = 3600) -> None:
        self._api_key = api_key or os.environ.get("NVD_API_KEY") or os.environ.get("VAPT_NVD_API_KEY") or ""
        self._cache: dict[str, tuple[NVDRecord, float]] = {}
        self._cache_ttl = cache_ttl
        self._request_times: list[float] = []
        self._client: Optional[httpx.AsyncClient] = None
        self._semaphore = asyncio.Semaphore(3)  # Max 3 concurrent NVD requests
        self._stats = {"total_lookups": 0, "verified": 0, "rejected": 0, "failed": 0, "cached": 0}

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            headers = {"User-Agent": "VAPT-Platform/2.0 (https://github.com/vapt-platform)"}
            if self._api_key:
                headers["apiKey"] = self._api_key
            self._client = httpx.AsyncClient(
                base_url=self.BASE_URL,
                headers=headers,
                timeout=30,
                follow_redirects=True,
            )
        return self._client

    async def _rate_limit(self) -> None:
        """Enforce NVD API rate limits."""
        now = time.monotonic()
        max_reqs = self.MAX_REQUESTS_WITH_KEY if self._api_key else self.MAX_REQUESTS_NO_KEY

        # Clean old timestamps
        self._request_times = [t for t in self._request_times if now - t < self.REQUEST_WINDOW]

        if len(self._request_times) >= max_reqs:
            sleep_time = self.REQUEST_WINDOW - (now - self._request_times[0]) + 0.5
            logger.debug("[NVD] Rate limit reached, sleeping {t:.1f}s", t=sleep_time)
            await asyncio.sleep(sleep_time)

        self._request_times.append(time.monotonic())

    async def lookup_cve(self, cve_id: str) -> NVDRecord:
        """Look up a single CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-41773").

        Returns:
            An NVDRecord with verified data, or a stub if lookup fails.
        """
        cve_id = cve_id.upper().strip()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        self._stats["total_lookups"] += 1

        # Check cache
        cached = self._get_cached(cve_id)
        if cached:
            self._stats["cached"] += 1
            return cached

        async with self._semaphore:
            await self._rate_limit()
            try:
                client = await self._get_client()
                resp = await client.get(f"/?cveId={cve_id}")

                if resp.status_code == 403:
                    logger.warning("[NVD] Rate limit exceeded (403). Consider adding an API key.")
                    await asyncio.sleep(35)
                    return NVDRecord(cve_id=cve_id, status="RATE_LIMITED")

                if resp.status_code != 200:
                    logger.debug("[NVD] Lookup failed for {cve}: HTTP {status}", cve=cve_id, status=resp.status_code)
                    self._stats["failed"] += 1
                    return NVDRecord(cve_id=cve_id, status="LOOKUP_FAILED")

                data = resp.json()
                record = self._parse_response(cve_id, data)
                self._cache_record(cve_id, record)

                if record.verified:
                    self._stats["verified"] += 1
                elif record.status == "REJECTED":
                    self._stats["rejected"] += 1

                return record

            except httpx.TimeoutException:
                logger.debug("[NVD] Timeout for {cve}", cve=cve_id)
                self._stats["failed"] += 1
                return NVDRecord(cve_id=cve_id, status="TIMEOUT")
            except Exception as exc:
                logger.debug("[NVD] Error for {cve}: {err}", cve=cve_id, err=exc)
                self._stats["failed"] += 1
                return NVDRecord(cve_id=cve_id, status="ERROR")

    async def lookup_cves_batch(self, cve_ids: list[str]) -> dict[str, NVDRecord]:
        """Look up multiple CVEs, respecting rate limits.

        Args:
            cve_ids: List of CVE identifiers.

        Returns:
            Dict mapping CVE ID to NVDRecord.
        """
        results = {}
        for cve_id in cve_ids:
            record = await self.lookup_cve(cve_id)
            results[cve_id] = record
            # Small delay between requests to be polite
            await asyncio.sleep(0.1)
        return results

    async def verify_finding_cves(self, cve_ids: list[str]) -> list[dict]:
        """Verify a list of CVEs and return enriched data for reports.

        This is what makes reports audit-ready: every CVE is verified
        against NVD with official CVSS scores and descriptions.

        Returns:
            List of dicts with verified CVE data for report inclusion.
        """
        if not cve_ids:
            return []

        records = await self.lookup_cves_batch(cve_ids)
        results = []

        for cve_id, record in records.items():
            results.append({
                "cve_id": cve_id,
                "verified": record.verified,
                "status": record.status,
                "cvss_score": record.cvss_v3_score,
                "cvss_vector": record.cvss_v3_vector,
                "severity": record.severity,
                "description": record.description,
                "published": record.published,
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "cwe_ids": record.cwe_ids,
                "references": record.references[:5],
                "cpe_matches": record.cpe_matches[:3],
            })

        return results

    async def search_by_cpe(self, cpe_string: str) -> list[NVDRecord]:
        """Search for CVEs affecting a specific CPE (product/version).

        This is how OpenVAS works — it matches detected software against
        CPEs and then queries for known CVEs.

        Args:
            cpe_string: CPE 2.3 formatted string (e.g., "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")

        Returns:
            List of NVDRecords for matching CVEs.
        """
        self._stats["total_lookups"] += 1
        async with self._semaphore:
            await self._rate_limit()
            try:
                client = await self._get_client()
                resp = await client.get(f"/?cpeName={cpe_string}")

                if resp.status_code != 200:
                    self._stats["failed"] += 1
                    return []

                data = resp.json()
                records = []
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")
                    if cve_id:
                        record = self._parse_single_cve(cve_id, cve)
                        records.append(record)
                        self._cache_record(cve_id, record)
                        if record.verified:
                            self._stats["verified"] += 1
                        elif record.status == "REJECTED":
                            self._stats["rejected"] += 1

                return records

            except Exception as exc:
                logger.debug("[NVD] CPE search error: {err}", err=exc)
                self._stats["failed"] += 1
                return []

    def _parse_response(self, query_cve: str, data: dict) -> NVDRecord:
        """Parse NVD API response into NVDRecord."""
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return NVDRecord(cve_id=query_cve, status="NOT_FOUND")

        cve_data = vulnerabilities[0].get("cve", {})
        return self._parse_single_cve(query_cve, cve_data)

    def _parse_single_cve(self, cve_id: str, cve_data: dict) -> NVDRecord:
        """Parse a single CVE entry from NVD response."""
        record = NVDRecord(cve_id=cve_id)

        # Status
        record.status = cve_data.get("state", "PUBLISHED")
        record.verified = record.status == "PUBLISHED"

        # Published/Modified dates
        record.published = cve_data.get("published", "")
        record.last_modified = cve_data.get("lastModified", "")

        # Description (prefer English)
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                record.description = desc.get("value", "")
                break

        # CVSS v3.1 metrics
        metrics = cve_data.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            cvss = cvss_v31[0].get("cvssData", {})
            record.cvss_v3_score = cvss.get("baseScore")
            record.cvss_v3_vector = cvss.get("vectorString", "")
            record.severity = cvss.get("baseSeverity", "")
        elif metrics.get("cvssMetricV30"):
            cvss = metrics["cvssMetricV30"][0].get("cvssData", {})
            record.cvss_v3_score = cvss.get("baseScore")
            record.cvss_v3_vector = cvss.get("vectorString", "")
            record.severity = cvss.get("baseSeverity", "")
        elif metrics.get("cvssMetricV2"):
            cvss = metrics["cvssMetricV2"][0].get("cvssData", {})
            record.cvss_v3_score = cvss.get("baseScore")
            record.severity = cvss.get("baseSeverity", "")

        # CWE IDs
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                cwe_id = desc.get("value", "")
                if cwe_id.startswith("CWE-"):
                    record.cwe_ids.append(cwe_id)

        # References
        for ref in cve_data.get("references", []):
            record.references.append(ref.get("url", ""))

        # CPE Matches
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    if criteria:
                        record.cpe_matches.append(criteria)

        record.nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        return record

    def _get_cached(self, cve_id: str) -> Optional[NVDRecord]:
        """Get a cached record if it's still fresh."""
        key = cve_id.upper()
        if key in self._cache:
            record, timestamp = self._cache[key]
            if time.monotonic() - timestamp < self._cache_ttl:
                return record
            del self._cache[key]
        return None

    def _cache_record(self, cve_id: str, record: NVDRecord) -> None:
        """Cache a record."""
        self._cache[cve_id.upper()] = (record, time.monotonic())

    @property
    def stats(self) -> dict[str, int]:
        """Return NVD service statistics."""
        return dict(self._stats)

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
