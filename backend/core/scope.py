"""
VAPT Multi-Agent System — Scope Enforcer

Ensures all scanning activity stays within the authorised boundaries
defined by the engagement ``ScopeConfig``.  This is the critical safety
component that prevents accidental or intentional out-of-scope testing.

Features:
  - Domain and IP/CIDR matching with wildcard support
  - Path-level inclusion / exclusion rules
  - Crawl-depth enforcement
  - Global and per-second rate limiting
  - Hard request budget tracking
  - Dynamic asset addition during recon
"""

import ipaddress
import time
import threading
from urllib.parse import urlparse
from typing import Optional
from loguru import logger

from core.models import ScopeConfig


class ScopeManager:
    """Enforces scope boundaries for a VAPT engagement.

    Every outbound request, URL, or discovered asset must pass through
    this manager before it can be acted upon by an agent.

    Args:
        config: The ``ScopeConfig`` defining authorised boundaries.
    """

    def __init__(self, config: ScopeConfig) -> None:
        """Initialise the scope manager with the given configuration.

        Args:
            config: Scope configuration specifying authorised domains,
                IPs, rate limits, and exclusion rules.
        """
        self._config = config
        self._discovered_domains: set[str] = set()
        self._request_count: int = 0
        self._request_timestamps: list[float] = []
        self._lock = threading.Lock()

        # Pre-parse authorised IP networks for fast membership checks
        self._authorised_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._authorised_ips_parsed: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for entry in config.authorized_ips:
            self._add_ip_entry(entry)

        # Pre-parse out-of-scope networks and IPs
        self._oos_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._oos_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for entry in config.out_of_scope:
            self._add_oos_entry(entry)

        # Normalise authorised domains once
        self._authorised_domains_normalised: list[str] = [
            self._normalize_domain(d) for d in config.authorized_domains
        ]
        self._oos_domains_normalised: list[str] = [
            self._normalize_domain(d) for d in config.out_of_scope
            if not self._looks_like_ip(d)
        ]

        logger.info(
            "ScopeManager initialised: {doms} domains, {ips} IP ranges, "
            "rate_limit={rps}/s, max_requests={max_req}",
            doms=len(self._authorised_domains_normalised),
            ips=len(self._authorised_networks) + len(self._authorised_ips_parsed),
            rps=config.rate_limit,
            max_req=config.max_requests_total,
        )

    # ── Public API ─────────────────────────────────────────────────

    def is_in_scope(self, url: str) -> bool:
        """Determine whether a URL is within the authorised scope.

        The check proceeds through several layers:
        1. Parse the URL and extract the hostname.
        2. Check out-of-scope exclusions (reject immediately if matched).
        3. Check authorised domain list (including wildcards and
           dynamically discovered subdomains).
        4. Check authorised IP/CIDR ranges.
        5. Check path-level include/exclude rules.
        6. Check crawl depth.

        Args:
            url: The URL to validate.

        Returns:
            ``True`` if the URL is within scope, ``False`` otherwise.
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
        except Exception:
            logger.warning("Failed to parse URL for scope check: {url}", url=url)
            return False

        if not hostname:
            return False

        # Check out-of-scope first (hard reject)
        if self._is_out_of_scope(hostname, parsed.path or "/"):
            logger.debug("URL rejected (out of scope): {url}", url=url)
            return False

        normalised_host = self._normalize_domain(hostname)

        # Check domain-level authorisation. Exact domains are exact-only;
        # wildcard expansion must be explicit (for example: *.example.com).
        domain_ok = (
            self._matches_authorised_domain(normalised_host)
            or self._matches_discovered_domain(normalised_host)
        )

        # Check IP-level authorisation
        ip_ok = False
        try:
            ip_obj = ipaddress.ip_address(hostname)
            ip_ok = self._matches_authorised_ip(ip_obj)
        except ValueError:
            pass  # Not an IP — domain check already handled it

        if not domain_ok and not ip_ok:
            logger.debug("URL rejected (not authorised): {url}", url=url)
            return False

        # Check path-level include/exclude
        path = parsed.path or "/"
        if not self._check_path_rules(path):
            logger.debug("URL rejected (path rules): {url}", url=url)
            return False

        # Check depth
        if not self.check_depth(url):
            logger.debug("URL rejected (depth exceeded): {url}", url=url)
            return False

        return True

    def filter_urls(self, urls: list[str]) -> list[str]:
        """Filter a list of URLs to only those within the authorised scope.

        Args:
            urls: Candidate URLs to filter.

        Returns:
            A new list containing only in-scope URLs, preserving the
            original order.
        """
        in_scope: list[str] = []
        for url in urls:
            if self.is_in_scope(url):
                in_scope.append(url)
        if len(urls) != len(in_scope):
            logger.info(
                "Scope filter: {total} → {kept} URLs in scope ({dropped} dropped)",
                total=len(urls),
                kept=len(in_scope),
                dropped=len(urls) - len(in_scope),
            )
        return in_scope

    def validate_request(self, url: str, method: str = "GET") -> bool:
        """Check whether a specific HTTP request is allowed.

        Combines scope checking with rate-limit and budget validation.

        Args:
            url:    The target URL.
            method: HTTP method (used for potential future per-method
                    rate limiting — currently accepted as-is).

        Returns:
            ``True`` if the request should be allowed, ``False`` otherwise.
        """
        if not self.is_in_scope(url):
            return False

        with self._lock:
            if self._request_count >= self._config.max_requests_total:
                logger.warning(
                    "Request budget exhausted: {count}/{max}",
                    count=self._request_count,
                    max=self._config.max_requests_total,
                )
                return False

        if self.is_rate_limited():
            logger.debug("Rate limited — request deferred for: {url}", url=url)
            return False

        return True

    def add_discovered_asset(self, domain: str) -> None:
        """Dynamically add a discovered subdomain to the authorised scope.

        Assets are only added if they are directly authorised. This keeps
        passive discovery separate from active testing: an engagement for
        ``example.com`` can report ``app.example.com`` as discovered inventory,
        but only ``*.example.com`` authorises active testing of subdomains.

        Args:
            domain: The subdomain or domain to add.
        """
        normalised = self._normalize_domain(domain)

        # Verify the discovered domain falls under an authorised pattern
        parent_match = False
        for authorised in self._authorised_domains_normalised:
            if self._domain_matches_authorised_pattern(normalised, authorised):
                parent_match = True
                break

        if not parent_match:
            logger.debug(
                "Discovered domain '{dom}' does not fall under any "
                "authorised pattern — not adding to scope",
                dom=normalised,
            )
            return

        with self._lock:
            if normalised not in self._discovered_domains:
                self._discovered_domains.add(normalised)
                logger.info(
                    "Dynamically added discovered asset to scope: {dom}",
                    dom=normalised,
                )

    def is_rate_limited(self) -> bool:
        """Check whether the current request rate exceeds the configured limit.

        Uses a sliding window of the last second to determine if the
        rate limit has been hit.

        Returns:
            ``True`` if rate-limited (caller should back off), ``False``
            if requests may proceed.
        """
        now = time.monotonic()
        window_start = now - 1.0

        with self._lock:
            # Prune timestamps older than 1 second
            self._request_timestamps = [
                ts for ts in self._request_timestamps if ts > window_start
            ]

            if len(self._request_timestamps) >= self._config.rate_limit:
                return True

            # Record this check as a request timestamp
            self._request_timestamps.append(now)

        return False

    def check_depth(self, url: str) -> bool:
        """Check whether a URL's path depth is within the configured maximum.

        Depth is counted as the number of non-empty path segments after
        the hostname.  For example ``/a/b/c`` has depth 3.

        Args:
            url: The URL to check.

        Returns:
            ``True`` if the URL is within the allowed depth, ``False``
            otherwise.
        """
        try:
            parsed = urlparse(url)
            path = parsed.path or "/"
        except Exception:
            return False

        # Count path segments, ignoring empty strings from leading/trailing slashes
        segments = [s for s in path.split("/") if s]
        depth = len(segments)

        return depth <= self._config.max_depth

    def get_scope_summary(self) -> dict:
        """Return a human-readable summary of the current scope state.

        Returns:
            A dictionary containing counts and lists describing the
            current scope configuration and runtime state.
        """
        with self._lock:
            remaining = max(0, self._config.max_requests_total - self._request_count)

        return {
            "authorized_domains": list(self._authorised_domains_normalised),
            "authorized_ip_ranges": [
                str(n) for n in self._authorised_networks
            ] + [str(ip) for ip in self._authorised_ips_parsed],
            "discovered_domains": sorted(self._discovered_domains),
            "out_of_scope": list(self._oos_domains_normalised) + [
                str(n) for n in self._oos_networks
            ],
            "max_depth": self._config.max_depth,
            "max_pages": self._config.max_pages,
            "max_requests_total": self._config.max_requests_total,
            "requests_made": self._request_count,
            "requests_remaining": remaining,
            "rate_limit_per_second": self._config.rate_limit,
            "exclude_paths": self._config.exclude_paths,
            "include_paths": self._config.include_paths or [],
        }

    def increment_request_count(self) -> None:
        """Record that a request has been made against the global budget.

        Thread-safe.  The request budget is decremented by one each time
        this method is called.
        """
        with self._lock:
            self._request_count += 1

    def requests_remaining(self) -> int:
        """Return the number of requests remaining before the hard budget cap.

        Returns:
            Non-negative integer indicating remaining request budget.
        """
        with self._lock:
            return max(0, self._config.max_requests_total - self._request_count)

    # ── Domain Matching ────────────────────────────────────────────

    def _domain_matches_pattern(self, domain: str, pattern: str) -> bool:
        """Check whether *domain* is covered by *pattern* for discovery.

        This broad matcher is intentionally used for passive discovery and
        out-of-scope exclusions. Active authorisation uses
        ``_domain_matches_authorised_pattern`` below.

        Args:
            domain:  Normalised domain to test (lowercase, no trailing dot).
            pattern: Normalised pattern which may start with ``*.``.

        Returns:
            ``True`` if the domain matches the pattern.
        """
        if not pattern:
            return False

        # Exact match
        if domain == pattern:
            return True

        if pattern.startswith("*."):
            return self._domain_matches_authorised_pattern(domain, pattern)

        # Non-wildcard: domain must equal pattern or be a subdomain of it
        # e.g., pattern=example.com matches sub.example.com
        if domain == pattern:
            return True
        if domain.endswith(f".{pattern}"):
            return True

        return False

    def _domain_matches_authorised_pattern(self, domain: str, pattern: str) -> bool:
        """Check active testing authorisation for a domain pattern.

        ``example.com`` authorises only ``example.com``.
        ``*.example.com`` authorises ``example.com`` and its subdomains.
        """
        if not pattern:
            return False
        if domain == pattern:
            return True
        if pattern.startswith("*."):
            base = pattern[2:]
            return domain == base or domain.endswith(f".{base}")
        return False

    def _normalize_domain(self, domain: str) -> str:
        """Normalise a domain name for consistent comparison.

        Strips trailing dots, converts to lowercase, and removes any
        leading/trailing whitespace.

        Args:
            domain: The raw domain string.

        Returns:
            The normalised domain string.
        """
        return domain.strip().lower().rstrip(".")

    # ── Internal Helpers ───────────────────────────────────────────

    def _matches_authorised_domain(self, normalised_host: str) -> bool:
        """Check if a normalised hostname matches any authorised domain pattern.

        Args:
            normalised_host: Lowercase, normalised hostname.

        Returns:
            ``True`` if the host matches any authorised domain pattern.
        """
        for pattern in self._authorised_domains_normalised:
            if self._domain_matches_authorised_pattern(normalised_host, pattern):
                return True
        return False

    def is_discoverable_host(self, host: str) -> bool:
        """Return whether a host may be passively reported as related scope.

        Passive recon is allowed to keep discovered child hosts under an
        authorised domain for reporting, while active probing still requires
        ``is_in_scope`` to pass.
        """
        normalised = self._normalize_domain(str(host or ""))
        if not normalised or self._is_out_of_scope(normalised, "/"):
            return False
        return any(
            self._domain_matches_pattern(normalised, pattern)
            for pattern in self._authorised_domains_normalised
        )

    def _matches_discovered_domain(self, normalised_host: str) -> bool:
        """Check if a normalised hostname matches any dynamically discovered domain.

        Args:
            normalised_host: Lowercase, normalised hostname.

        Returns:
            ``True`` if the host is in the discovered domains set.
        """
        with self._lock:
            if normalised_host in self._discovered_domains:
                return True
        # Also check if it's a subdomain of a discovered domain
        for discovered in self._discovered_domains:
            if normalised_host == discovered or normalised_host.endswith(f".{discovered}"):
                return True
        return False

    def _matches_authorised_ip(
        self, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> bool:
        """Check if an IP address falls within any authorised IP/CIDR range.

        Args:
            ip_obj: A parsed ``ipaddress`` object.

        Returns:
            ``True`` if the IP is in any authorised range.
        """
        if ip_obj in self._authorised_ips_parsed:
            return True
        for network in self._authorised_networks:
            if ip_obj in network:
                return True
        return False

    def _is_out_of_scope(self, hostname: str, path: str) -> bool:
        """Check if a hostname or path is explicitly out of scope.

        Args:
            hostname: The hostname to check.
            path:     The URL path to check.

        Returns:
            ``True`` if the target is out of scope.
        """
        normalised = self._normalize_domain(hostname)

        # Check against out-of-scope domain patterns
        for oos_domain in self._oos_domains_normalised:
            if self._domain_matches_pattern(normalised, oos_domain):
                return True

        # Check against out-of-scope IP ranges
        if self._looks_like_ip(hostname):
            try:
                ip_obj = ipaddress.ip_address(hostname)
                if ip_obj in self._oos_ips:
                    return True
                for network in self._oos_networks:
                    if ip_obj in network:
                        return True
            except ValueError:
                pass

        # Check against out-of-scope path prefixes
        for oos_path in self._config.out_of_scope:
            # Distinguish path entries from domain entries
            if oos_path.startswith("/") and path.startswith(oos_path):
                return True

        return False

    def _check_path_rules(self, path: str) -> bool:
        """Evaluate include/exclude path rules against a URL path.

        If ``include_paths`` is configured, the path *must* match at
        least one include pattern.  If the path matches any exclude
        pattern, it is rejected.

        Args:
            path: The URL path component (e.g. ``/api/v1/users``).

        Returns:
            ``True`` if the path passes all rules.
        """
        # If include_paths is set, path must match at least one
        if self._config.include_paths:
            included = any(
                path.startswith(inc) for inc in self._config.include_paths
            )
            if not included:
                return False

        # Exclude takes precedence
        for exc in self._config.exclude_paths:
            if path.startswith(exc):
                return False

        return True

    def _add_ip_entry(self, entry: str) -> None:
        """Parse and store an authorised IP or CIDR entry.

        Args:
            entry: An IP address (e.g. ``10.0.0.1``) or CIDR range
                   (e.g. ``10.0.0.0/24``).
        """
        try:
            if "/" in entry:
                network = ipaddress.ip_network(entry, strict=False)
                self._authorised_networks.append(network)
            else:
                addr = ipaddress.ip_address(entry)
                self._authorised_ips_parsed.add(addr)
        except ValueError:
            logger.warning("Invalid IP/CIDR entry in authorised list: {entry}", entry=entry)

    def _add_oos_entry(self, entry: str) -> None:
        """Parse and store an out-of-scope IP or CIDR entry.

        Args:
            entry: An IP address or CIDR range to exclude.
        """
        if self._looks_like_ip(entry):
            try:
                if "/" in entry:
                    network = ipaddress.ip_network(entry, strict=False)
                    self._oos_networks.append(network)
                else:
                    addr = ipaddress.ip_address(entry)
                    self._oos_ips.add(addr)
            except ValueError:
                logger.debug("OOS entry is not a valid IP/CIDR, treating as domain: {entry}", entry=entry)
        # Non-IP entries are handled as domains in _oos_domains_normalised

    @staticmethod
    def _looks_like_ip(s: str) -> bool:
        """Quick heuristic to determine whether a string looks like an IP address.

        Args:
            s: String to test.

        Returns:
            ``True`` if the string contains only digits, dots, colons,
            and optionally a slash (CIDR notation).
        """
        cleaned = s.strip()
        if not cleaned:
            return False
        # Contains a colon → likely IPv6
        if ":" in cleaned:
            return True
        # Dotted quad pattern or CIDR
        parts = cleaned.split("/")
        if len(parts) > 2:
            return False
        octets = parts[0].split(".")
        if len(octets) != 4:
            return False
        return all(part.isdigit() and 0 <= int(part) <= 255 for part in octets)
