"""
Tool capability registry — the intelligence layer for evidence-driven planning.

Every tool declares:
  phases        — which pipeline phases it belongs to
  categories    — semantic groupings for query-based selection
  target_layers — what kind of target it operates on
  produces      — evidence tokens this tool emits when it succeeds
  consumes      — evidence tokens required before this tool makes sense to run
  safe_by_default / aggressive — safety classification
  requires_api_keys — external keys needed

The planner (plan_next_tools) uses produces/consumes to build a dynamic
execution graph: as soon as a tool's `consumes` set is satisfied by the
accumulated evidence, the tool is eligible to run.  This replaces
"always run everything in phase order" with evidence-driven selection.

Evidence token taxonomy
-----------------------
Network layer:   open_port, service_banner, service_version, os_hint, tls_service,
                 smb_open, ssh_open, rdp_open, snmp_open, rtsp_open
Domain layer:    subdomain, dns_record, dns_zone_transfer, ip_address
HTTP layer:      live_url, http_status, http_title, http_headers
Tech layer:      technology, tech_wordpress, tech_drupal, tech_joomla,
                 tech_php, tech_python, tech_java, tech_nginx, tech_apache,
                 waf_detected, cdn_detected
Web content:     discovered_path, directory_listing, backup_file, config_file
JS / secrets:    javascript_url, secret_candidate, api_key_candidate, endpoint
API layer:       api_endpoint, parameter, graphql_endpoint
Cloud layer:     cloud_asset, s3_bucket_hint, azure_blob_hint, gcp_bucket_hint,
                 origin_ip_candidate, cloudflare_detected
OSINT:           internet_exposure, historical_url, github_repo, leaked_credential
Vulnerability:   finding_cve, finding_xss, finding_sqli, finding_ssrf,
                 finding_rce, finding_lfi, finding_misconfig, finding_exposed_creds
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolCapability:
    name: str
    display_name: str
    phases: list[str]
    categories: list[str]
    target_layers: list[str]
    produces: list[str] = field(default_factory=list)
    consumes: list[str] = field(default_factory=list)
    safe_by_default: bool = True
    aggressive: bool = False
    requires_api_keys: list[str] = field(default_factory=list)
    run_when: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)   # legacy alias for produces
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────────────────────

TOOL_CAPABILITIES: dict[str, ToolCapability] = {

    # ── Passive subdomain / domain ───────────────────────────────────────────

    "subfinder": ToolCapability(
        name="subfinder",
        display_name="Subfinder",
        phases=["recon"],
        categories=["subdomain-enumeration", "passive-scanning", "osint-collection"],
        target_layers=["domain"],
        produces=["subdomain", "ip_address"],
        consumes=[],
        evidence=["subdomain"],
        notes="Fast passive subdomain enumeration via cert transparency + APIs.",
    ),
    "assetfinder": ToolCapability(
        name="assetfinder",
        display_name="Assetfinder",
        phases=["recon"],
        categories=["subdomain-enumeration", "passive-scanning", "osint-collection"],
        target_layers=["domain"],
        produces=["subdomain"],
        consumes=[],
        evidence=["subdomain"],
    ),
    "amass": ToolCapability(
        name="amass",
        display_name="Amass",
        phases=["recon"],
        categories=["subdomain-enumeration", "dns-enumeration", "osint-collection"],
        target_layers=["domain"],
        produces=["subdomain", "dns_record", "ip_address"],
        consumes=[],
        evidence=["subdomain", "dns_record"],
        notes="Run in passive mode for VA-safe scans; active mode adds DNS bruteforce.",
    ),
    "securitytrails": ToolCapability(
        name="securitytrails",
        display_name="SecurityTrails",
        phases=["recon"],
        categories=["dns-enumeration", "osint-collection"],
        target_layers=["domain"],
        produces=["subdomain", "dns_record", "historical_url"],
        consumes=[],
        requires_api_keys=["SECURITYTRAILS_API_KEY"],
        evidence=["subdomain", "dns_record"],
    ),
    "crobat": ToolCapability(
        name="crobat",
        display_name="Crobat",
        phases=["recon"],
        categories=["subdomain-enumeration", "passive-scanning"],
        target_layers=["domain"],
        produces=["subdomain"],
        consumes=[],
        evidence=["subdomain"],
    ),
    "theHarvester": ToolCapability(
        name="theHarvester",
        display_name="theHarvester",
        phases=["recon"],
        categories=["osint-collection", "email-harvesting"],
        target_layers=["domain"],
        produces=["subdomain", "internet_exposure", "leaked_credential"],
        consumes=[],
        evidence=["subdomain"],
        notes="OSINT aggregator: emails, subdomains, IPs from public sources.",
    ),

    # ── Active DNS ───────────────────────────────────────────────────────────

    "puredns": ToolCapability(
        name="puredns",
        display_name="PureDNS",
        phases=["recon"],
        categories=["dns-enumeration", "subdomain-bruteforcer"],
        target_layers=["domain"],
        produces=["subdomain", "dns_record", "dns_zone_transfer"],
        consumes=["subdomain"],   # resolves a list of candidates
        aggressive=True,
        evidence=["dns_resolution"],
        notes="Needs a large wordlist; resolves and deduplicates subdomains at scale.",
    ),
    "dnsx": ToolCapability(
        name="dnsx",
        display_name="dnsx",
        phases=["recon"],
        categories=["dns-enumeration", "dns-resolution"],
        target_layers=["domain"],
        produces=["ip_address", "dns_record"],
        consumes=["subdomain"],
        evidence=["dns_resolution"],
        notes="Resolves a list of subdomains; feeds IPs into port scanning.",
    ),

    # ── HTTP probing / tech detection ────────────────────────────────────────

    "httpx": ToolCapability(
        name="httpx",
        display_name="httpx",
        phases=["recon", "enumeration"],
        categories=["http-probing", "service-fingerprinting-tool", "tech-fingerprinting"],
        target_layers=["domain", "ip", "web"],
        produces=["live_url", "http_status", "http_title", "technology", "waf_detected"],
        consumes=["subdomain", "ip_address", "open_port"],
        evidence=["live_url", "status_code", "title", "technology"],
        notes="Core pivot: turns hostnames/IPs into confirmed live URLs + tech stack.",
    ),
    "httprobe": ToolCapability(
        name="httprobe",
        display_name="httprobe",
        phases=["recon"],
        categories=["http-probing", "http-probing-tool"],
        target_layers=["domain", "ip"],
        produces=["live_url"],
        consumes=["subdomain"],
        evidence=["live_url"],
    ),
    "wafw00f": ToolCapability(
        name="wafw00f",
        display_name="wafw00f",
        phases=["enumeration"],
        categories=["waf-detection", "tech-waf-cloudflare"],
        target_layers=["web"],
        produces=["waf_detected", "cdn_detected"],
        consumes=["live_url"],
        run_when=["live_http"],
        evidence=["waf_fingerprint"],
        notes="Identifies WAF/CDN — informs evasion strategy for later tools.",
    ),
    "whatweb": ToolCapability(
        name="whatweb",
        display_name="WhatWeb",
        phases=["enumeration"],
        categories=["cms-fingerprinting", "service-fingerprinting-tool", "tech-fingerprinting"],
        target_layers=["web"],
        produces=["technology", "tech_wordpress", "tech_drupal", "tech_joomla", "service_version"],
        consumes=["live_url"],
        run_when=["live_http"],
        evidence=["technology", "version"],
    ),
    "wappalyzer": ToolCapability(
        name="wappalyzer",
        display_name="Wappalyzer",
        phases=["enumeration"],
        categories=["cms-fingerprinting", "tech-fingerprinting"],
        target_layers=["web"],
        produces=["technology", "service_version"],
        consumes=["live_url"],
        run_when=["live_http"],
        evidence=["technology", "version"],
    ),

    # ── Port / service discovery ─────────────────────────────────────────────

    "naabu": ToolCapability(
        name="naabu",
        display_name="Naabu",
        phases=["enumeration"],
        categories=["port-scanning", "host-port-scanner"],
        target_layers=["domain", "ip"],
        produces=["open_port"],
        consumes=["ip_address", "subdomain"],
        evidence=["open_port"],
        notes="Fast SYN scanner; run before nmap for full-range discovery.",
    ),
    "nmap": ToolCapability(
        name="nmap",
        display_name="Nmap",
        phases=["enumeration"],
        categories=["port-scanning", "service-version-detection", "network-service-discovery"],
        target_layers=["domain", "ip"],
        produces=[
            "open_port", "service_banner", "service_version",
            "os_hint", "tls_service", "smb_open", "ssh_open", "rdp_open", "snmp_open",
        ],
        consumes=["ip_address", "open_port"],
        evidence=["open_port", "service_banner", "version"],
        notes="Run with -sV --script=vuln,safe against naabu-discovered ports for speed.",
    ),
    "masscan": ToolCapability(
        name="masscan",
        display_name="masscan",
        phases=["enumeration"],
        categories=["port-scanning", "mass-scanner"],
        target_layers=["ip"],
        produces=["open_port"],
        consumes=["ip_address"],
        aggressive=True,
        notes="Use only for large CIDRs (>256 hosts); feed results into nmap.",
    ),

    # ── TLS / certificate ────────────────────────────────────────────────────

    "tlsx": ToolCapability(
        name="tlsx",
        display_name="tlsx",
        phases=["enumeration", "vuln_scanning"],
        categories=["ssl-tls-assessment", "tech-fingerprinting"],
        target_layers=["web", "domain", "ip"],
        produces=["tls_service", "technology", "service_version"],
        consumes=["live_url", "open_port"],
        run_when=["tls_service"],
        evidence=["certificate", "tls_version", "cipher"],
    ),
    "testssl": ToolCapability(
        name="testssl",
        display_name="testssl.sh",
        phases=["vuln_scanning"],
        categories=["ssl-tls-assessment"],
        target_layers=["web", "domain", "ip"],
        produces=["finding_misconfig"],
        consumes=["tls_service"],
        run_when=["tls_service"],
        evidence=["tls_weakness", "certificate"],
        notes="Deep TLS audit: weak ciphers, BEAST, POODLE, Heartbleed, cert issues.",
    ),
    "sslscan": ToolCapability(
        name="sslscan",
        display_name="sslscan",
        phases=["vuln_scanning"],
        categories=["ssl-tls-assessment"],
        target_layers=["web", "domain", "ip"],
        produces=["finding_misconfig"],
        consumes=["tls_service"],
        run_when=["tls_service"],
        evidence=["tls_weakness", "certificate"],
    ),

    # ── URL / historical collection ──────────────────────────────────────────

    "gau": ToolCapability(
        name="gau",
        display_name="gau",
        phases=["recon"],
        categories=["url-collection", "parameter-discovery", "passive-scanning"],
        target_layers=["domain", "web"],
        produces=["historical_url", "parameter", "endpoint"],
        consumes=["subdomain"],
        evidence=["url", "parameter"],
        notes="Fetches URLs from Wayback Machine, Common Crawl, AlienVault OTX.",
    ),
    "waybackurls": ToolCapability(
        name="waybackurls",
        display_name="waybackurls",
        phases=["recon"],
        categories=["url-collection", "parameter-discovery", "passive-scanning"],
        target_layers=["domain", "web"],
        produces=["historical_url", "parameter"],
        consumes=["subdomain"],
        evidence=["url", "parameter"],
    ),
    "paramspider": ToolCapability(
        name="paramspider",
        display_name="ParamSpider",
        phases=["recon", "fuzzing"],
        categories=["parameter-discovery", "url-collection"],
        target_layers=["domain", "web"],
        produces=["parameter", "endpoint"],
        consumes=["subdomain"],
        evidence=["parameter", "url"],
    ),

    # ── Web crawling ─────────────────────────────────────────────────────────

    "katana": ToolCapability(
        name="katana",
        display_name="Katana",
        phases=["recon", "fuzzing"],
        categories=["web-crawling", "parameter-discovery", "js-recon"],
        target_layers=["web", "api", "javascript"],
        produces=["endpoint", "javascript_url", "parameter", "api_endpoint"],
        consumes=["live_url"],
        run_when=["live_http", "spa_detected", "api_detected"],
        evidence=["url", "endpoint", "javascript_url"],
        notes="Headless-capable crawler; best for SPAs and JS-heavy apps.",
    ),
    "hakrawler": ToolCapability(
        name="hakrawler",
        display_name="hakrawler",
        phases=["recon", "fuzzing"],
        categories=["web-crawling", "js-recon"],
        target_layers=["web", "javascript"],
        produces=["endpoint", "javascript_url"],
        consumes=["live_url"],
        run_when=["live_http"],
        evidence=["url", "javascript_url"],
    ),
    "gospider": ToolCapability(
        name="gospider",
        display_name="GoSpider",
        phases=["recon", "fuzzing"],
        categories=["web-crawling", "js-recon"],
        target_layers=["web"],
        produces=["endpoint", "javascript_url", "parameter"],
        consumes=["live_url"],
        run_when=["live_http"],
        evidence=["url"],
    ),
    "meg": ToolCapability(
        name="meg",
        display_name="meg",
        phases=["enumeration", "fuzzing"],
        categories=["web-content-discovery"],
        target_layers=["web"],
        produces=["discovered_path", "backup_file"],
        consumes=["live_url"],
        run_when=["live_http"],
        evidence=["discovered_path"],
        notes="Fetches many paths across many hosts — efficient bulk discovery.",
    ),

    # ── JS / secret analysis ─────────────────────────────────────────────────

    "jssecrets": ToolCapability(
        name="jssecrets",
        display_name="jssecrets",
        phases=["recon", "vuln_scanning"],
        categories=["js-recon", "secrets-detection"],
        target_layers=["javascript", "web"],
        produces=["secret_candidate", "api_key_candidate", "endpoint"],
        consumes=["javascript_url"],
        run_when=["javascript_urls_discovered"],
        evidence=["secret_candidate", "javascript_url"],
    ),
    "jsfscan": ToolCapability(
        name="jsfscan",
        display_name="JSFScan",
        phases=["recon", "vuln_scanning"],
        categories=["js-recon", "secrets-detection", "endpoint-discovery"],
        target_layers=["javascript", "web"],
        produces=["secret_candidate", "endpoint", "api_key_candidate"],
        consumes=["javascript_url"],
        run_when=["javascript_urls_discovered"],
        evidence=["endpoint", "secret_candidate", "javascript_url"],
    ),
    "secretfinder": ToolCapability(
        name="secretfinder",
        display_name="SecretFinder",
        phases=["recon", "vuln_scanning"],
        categories=["js-recon", "secrets-detection"],
        target_layers=["javascript", "web"],
        produces=["secret_candidate", "api_key_candidate"],
        consumes=["javascript_url"],
        run_when=["javascript_urls_discovered"],
        evidence=["secret_candidate"],
        notes="Internal regex scanner works without the external command.",
    ),
    "trufflehog": ToolCapability(
        name="trufflehog",
        display_name="TruffleHog",
        phases=["recon", "vuln_scanning"],
        categories=["secrets-detection", "exposed-repository"],
        target_layers=["repository", "web", "cloud"],
        produces=["leaked_credential", "secret_candidate", "finding_exposed_creds"],
        consumes=["github_repo"],
        run_when=["exposed_git", "repository_url", "downloaded_artifacts"],
        evidence=["verified_secret", "secret_candidate", "repository_path"],
        notes="Verifies secrets against APIs — produces confirmed findings.",
    ),
    "gitleaks": ToolCapability(
        name="gitleaks",
        display_name="Gitleaks",
        phases=["recon", "vuln_scanning"],
        categories=["secrets-detection", "exposed-repository"],
        target_layers=["repository", "web"],
        produces=["secret_candidate", "leaked_credential"],
        consumes=["github_repo"],
        run_when=["exposed_git", "repository_url", "downloaded_artifacts"],
        evidence=["secret_candidate", "repository_path"],
    ),

    # ── Vulnerability scanning ────────────────────────────────────────────────

    "nuclei": ToolCapability(
        name="nuclei",
        display_name="Nuclei",
        phases=["vuln_scanning"],
        categories=[
            "network-vulnerability-scanning",
            "web-vulnerability-scanning",
            "vuln-templates",
            "exposure-detection",
            "js-recon",
        ],
        target_layers=["web", "domain", "ip", "api", "javascript"],
        produces=[
            "finding_cve", "finding_misconfig", "finding_exposed_creds",
            "finding_xss", "finding_sqli", "finding_ssrf", "finding_rce", "finding_lfi",
        ],
        consumes=["live_url"],
        run_when=["live_http", "service_detected", "javascript_urls_discovered"],
        evidence=["template_match", "http_request", "http_response", "cve"],
        notes="Primary VA engine. Use cve+misconfig+exposure tags for safe scans.",
    ),
    "nikto": ToolCapability(
        name="nikto",
        display_name="Nikto",
        phases=["vuln_scanning"],
        categories=["web-vulnerability-scanning", "web-misconfiguration"],
        target_layers=["web"],
        produces=["finding_misconfig", "discovered_path", "backup_file", "config_file"],
        consumes=["live_url"],
        run_when=["live_http"],
        evidence=["http_finding"],
    ),

    # ── Web fuzzing / content discovery ──────────────────────────────────────

    "ffuf": ToolCapability(
        name="ffuf",
        display_name="ffuf",
        phases=["fuzzing"],
        categories=["web-content-discovery", "web-fuzzing", "directory-bruteforcer"],
        target_layers=["web", "api"],
        produces=["discovered_path", "backup_file", "config_file", "api_endpoint"],
        consumes=["live_url"],
        aggressive=True,
        run_when=["live_http"],
        evidence=["discovered_path", "status_code"],
        notes="Fast fuzzer; also used for vhost enumeration and parameter bruteforce.",
    ),
    "feroxbuster": ToolCapability(
        name="feroxbuster",
        display_name="Feroxbuster",
        phases=["fuzzing"],
        categories=["web-content-discovery", "directory-bruteforcer"],
        target_layers=["web"],
        produces=["discovered_path", "backup_file"],
        consumes=["live_url"],
        aggressive=True,
        run_when=["live_http"],
        evidence=["discovered_path", "status_code"],
        notes="Recursive content discovery; good for deep directory structures.",
    ),
    "gobuster": ToolCapability(
        name="gobuster",
        display_name="Gobuster",
        phases=["fuzzing"],
        categories=["web-content-discovery", "directory-bruteforcer"],
        target_layers=["web"],
        produces=["discovered_path", "subdomain"],
        consumes=["live_url"],
        aggressive=True,
        run_when=["live_http"],
        evidence=["discovered_path", "status_code"],
        notes="Also supports DNS subdomain fuzzing mode.",
    ),
    "wfuzz": ToolCapability(
        name="wfuzz",
        display_name="wfuzz",
        phases=["fuzzing"],
        categories=["web-fuzzing", "parameter-discovery"],
        target_layers=["web", "api"],
        produces=["parameter", "discovered_path", "api_endpoint"],
        consumes=["live_url"],
        aggressive=True,
        run_when=["live_http"],
        evidence=["discovered_path"],
    ),
    "arjun": ToolCapability(
        name="arjun",
        display_name="Arjun",
        phases=["fuzzing"],
        categories=["parameter-discovery"],
        target_layers=["web", "api"],
        produces=["parameter"],
        consumes=["live_url"],
        run_when=["live_http", "api_detected"],
        evidence=["parameter"],
        notes="Discovers hidden GET/POST parameters — critical before SQLi/XSS testing.",
    ),
    "gf": ToolCapability(
        name="gf",
        display_name="gf",
        phases=["recon", "fuzzing"],
        categories=["parameter-discovery", "url-collection"],
        target_layers=["web"],
        produces=["parameter"],
        consumes=["historical_url", "endpoint"],
        evidence=["parameter"],
        notes="Grep patterns over URLs to find injection candidates (sqli, xss, ssrf…).",
    ),
    "qsreplace": ToolCapability(
        name="qsreplace",
        display_name="qsreplace",
        phases=["fuzzing"],
        categories=["parameter-discovery"],
        target_layers=["web"],
        produces=["parameter"],
        consumes=["historical_url"],
        evidence=["parameter"],
    ),

    # ── CMS / tech-specific scanners ─────────────────────────────────────────

    "wpscan": ToolCapability(
        name="wpscan",
        display_name="WPScan",
        phases=["vuln_scanning"],
        categories=["cms-specific-scanner", "tech-wordpress"],
        target_layers=["web"],
        produces=["finding_cve", "finding_exposed_creds", "service_version"],
        consumes=["tech_wordpress"],
        aggressive=True,
        run_when=["tech_wordpress"],
        evidence=["wordpress_vulnerability", "plugin_version", "theme_version"],
        notes="Only fires when WordPress is detected in the tech stack.",
    ),

    # ── Exploitation ──────────────────────────────────────────────────────────

    "sqlmap": ToolCapability(
        name="sqlmap",
        display_name="sqlmap",
        phases=["exploitation"],
        categories=["sql-injection", "exploitation"],
        target_layers=["web", "api"],
        produces=["finding_sqli", "finding_exposed_creds"],
        consumes=["parameter"],   # runs against parameterised URLs only
        aggressive=True,
        run_when=["parameterized_url", "sqli_candidate"],
        evidence=["sql_injection_evidence"],
        notes="Run ONLY against parameters surfaced by arjun/gf — never blindly.",
    ),
    "dalfox": ToolCapability(
        name="dalfox",
        display_name="dalfox",
        phases=["exploitation"],
        categories=["xss-scanner", "exploitation"],
        target_layers=["web"],
        produces=["finding_xss"],
        consumes=["parameter"],
        aggressive=True,
        run_when=["parameterized_url", "xss_candidate"],
        evidence=["xss_evidence"],
        notes="XSS scanner; run after Arjun finds reflected-parameter candidates.",
    ),
    "commix": ToolCapability(
        name="commix",
        display_name="commix",
        phases=["exploitation"],
        categories=["command-injection", "exploitation"],
        target_layers=["web"],
        produces=["finding_rce"],
        consumes=["parameter"],
        aggressive=True,
        run_when=["command_injection_candidate"],
        evidence=["rce_evidence"],
    ),

    # ── OSINT / internet exposure ─────────────────────────────────────────────

    "shodan": ToolCapability(
        name="shodan",
        display_name="Shodan",
        phases=["recon"],
        categories=["osint-collection", "cloud-recon"],
        target_layers=["domain", "ip", "cloud"],
        produces=["internet_exposure", "service_banner", "open_port", "technology"],
        consumes=[],
        requires_api_keys=["SHODAN_API_KEY"],
        evidence=["internet_exposure", "service_banner"],
        notes="Returns historical + live internet-wide scan data; no active probing.",
    ),
    "censys": ToolCapability(
        name="censys",
        display_name="Censys",
        phases=["recon"],
        categories=["osint-collection", "cloud-recon"],
        target_layers=["domain", "ip", "cloud"],
        produces=["internet_exposure", "tls_service", "service_banner", "open_port"],
        consumes=[],
        requires_api_keys=["CENSYS_API_ID", "CENSYS_API_SECRET"],
        evidence=["internet_exposure", "certificate", "service_banner"],
    ),
    "uncover": ToolCapability(
        name="uncover",
        display_name="uncover",
        phases=["recon"],
        categories=["osint-collection", "cloud-recon"],
        target_layers=["domain", "ip"],
        produces=["internet_exposure", "open_port"],
        consumes=[],
        requires_api_keys=["SHODAN_API_KEY"],
        evidence=["internet_exposure"],
        notes="Meta-search across Shodan, Censys, FOFA, Hunter, Zoomeye.",
    ),

    # ── Cloud ─────────────────────────────────────────────────────────────────

    "s3scanner": ToolCapability(
        name="s3scanner",
        display_name="S3Scanner",
        phases=["recon", "vuln_scanning"],
        categories=["cloud-recon", "tech-s3-bucket", "cloud-misconfiguration"],
        target_layers=["cloud"],
        produces=["cloud_asset", "finding_misconfig", "finding_exposed_creds"],
        consumes=["s3_bucket_hint", "cloud_asset"],
        run_when=["s3_bucket_hint"],
        evidence=["bucket_exposure"],
    ),
    "cloud_enum": ToolCapability(
        name="cloud_enum",
        display_name="cloud_enum",
        phases=["recon"],
        categories=["cloud-recon"],
        target_layers=["cloud"],
        produces=["cloud_asset", "s3_bucket_hint", "azure_blob_hint", "gcp_bucket_hint"],
        consumes=[],
        evidence=["cloud_asset"],
        notes="Enumerates AWS, Azure, GCP resources by common naming patterns.",
    ),
    "cloudfail": ToolCapability(
        name="cloudfail",
        display_name="CloudFail",
        phases=["recon"],
        categories=["cloud-recon", "cdn-origin-discovery"],
        target_layers=["cloud", "web"],
        produces=["origin_ip_candidate"],
        consumes=["cloudflare_detected"],
        run_when=["cloudflare_detected"],
        evidence=["origin_ip_candidate"],
        notes="Attempts to find the real origin IP behind Cloudflare.",
    ),

    # ── CMS — additional scanners ─────────────────────────────────────────────

    "droopescan": ToolCapability(
        name="droopescan",
        display_name="droopescan",
        phases=["vuln_scanning"],
        categories=["cms-specific-scanner", "tech-drupal", "tech-joomla"],
        target_layers=["web"],
        produces=["finding_cve", "service_version"],
        consumes=["tech_drupal", "tech_joomla"],
        aggressive=False,
        run_when=["tech_drupal", "tech_joomla"],
        evidence=["cms_vulnerability", "plugin_version"],
        notes="Plugin/theme/version scanner for Drupal and Joomla. Fires only when those CMSes are detected.",
    ),

    # ── DevOps / infrastructure scanners ─────────────────────────────────────

    "jwt_tool": ToolCapability(
        name="jwt_tool",
        display_name="jwt_tool",
        phases=["vuln_scanning", "exploitation"],
        categories=["api-security", "authentication"],
        target_layers=["web", "api"],
        produces=["finding_misconfig", "finding_exposed_creds"],
        consumes=["api_endpoint"],
        run_when=["jwt_in_response", "api_detected"],
        evidence=["jwt_weakness"],
        notes="Tests JWT alg:none, weak secrets, RS256→HS256 confusion.",
    ),
    "graphql_cop": ToolCapability(
        name="graphql_cop",
        display_name="GraphQL Cop",
        phases=["vuln_scanning"],
        categories=["api-security", "graphql"],
        target_layers=["api"],
        produces=["finding_misconfig", "finding_rce"],
        consumes=["graphql_endpoint"],
        run_when=["graphql_endpoint"],
        evidence=["graphql_weakness"],
        notes="GraphQL security audit: introspection, batching, CSRF, etc.",
    ),
    "ssh_audit": ToolCapability(
        name="ssh-audit",
        display_name="ssh-audit",
        phases=["vuln_scanning"],
        categories=["network-vulnerability-scanning", "service-audit"],
        target_layers=["ip"],
        produces=["finding_misconfig"],
        consumes=["ssh_open"],
        run_when=["ssh_open"],
        evidence=["ssh_weakness", "weak_cipher"],
        notes="SSH configuration and cipher audit; fires only when port 22 is open.",
    ),
    "redis_cli_check": ToolCapability(
        name="redis_cli_check",
        display_name="Redis Unauth Check",
        phases=["vuln_scanning"],
        categories=["network-vulnerability-scanning", "service-audit"],
        target_layers=["ip"],
        produces=["finding_misconfig", "finding_exposed_creds"],
        consumes=["service_redis"],
        run_when=["service_redis"],
        evidence=["redis_unauthenticated"],
        notes="Checks for unauthenticated Redis; fires only when Redis is detected.",
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Evidence token → nuclei tag mapping
#
# Used by VulnScannerAgent to convert accumulated evidence into targeted nuclei
# `-tags` arguments so every detected technology gets its own template pass
# without hardcoding per-tech logic in the agent.
#
# Keys are evidence tokens produced by orchestrator._ingest_evidence_from_phase_context().
# Values are comma-joined nuclei tag strings passed directly to `-tags`.
# ─────────────────────────────────────────────────────────────────────────────

TECH_NUCLEI_TAGS: dict[str, str] = {
    # CMS — handled by dedicated scanners too, but nuclei adds CVE coverage
    "tech_wordpress":       "wordpress,wp,cms",
    "tech_joomla":          "joomla,cms",
    "tech_drupal":          "drupal,cms",
    "tech_magento":         "magento,cms",
    "tech_shopify":         "shopify",
    "tech_typo3":           "typo3,cms",
    "tech_prestashop":      "prestashop,cms",
    # Web servers
    "tech_apache":          "apache,http",
    "tech_nginx":           "nginx,http",
    "tech_iis":             "iis,windows",
    "tech_tomcat":          "apache-tomcat,java",
    "tech_jetty":           "jetty,java",
    # Languages / frameworks
    "tech_php":             "php",
    "tech_laravel":         "laravel,php",
    "tech_symfony":         "symfony,php",
    "tech_codeigniter":     "codeigniter,php",
    "tech_django":          "django,python",
    "tech_flask":           "flask,python",
    "tech_spring":          "spring,java",
    "tech_springboot":      "springboot,spring,java",
    "tech_struts":          "struts,java",
    "tech_rails":           "rails,ruby",
    "tech_node_js":         "nodejs,node",
    "tech_express":         "express,nodejs",
    # DevOps / CI / monitoring
    "tech_jenkins":         "jenkins,ci-cd",
    "tech_gitlab":          "gitlab",
    "tech_jira":            "jira,atlassian",
    "tech_confluence":      "confluence,atlassian",
    "tech_bitbucket":       "bitbucket,atlassian",
    "tech_grafana":         "grafana",
    "tech_kibana":          "kibana,elastic",
    "tech_prometheus":      "prometheus",
    "tech_zabbix":          "zabbix",
    "tech_nagios":          "nagios",
    "tech_sonarqube":       "sonarqube",
    "tech_nexus":           "nexus",
    "tech_artifactory":     "artifactory",
    "tech_rancher":         "rancher,kubernetes",
    # Cloud / storage
    "s3_bucket_hint":       "aws-s3,s3,aws,cloud",
    "azure_blob_hint":      "azure,cloud",
    "gcp_bucket_hint":      "gcp,cloud",
    "cloud_asset":          "aws,azure,gcp,cloud",
    # Network services (populated by per-service token extraction)
    "service_redis":        "redis",
    "service_mysql":        "mysql",
    "service_postgresql":   "postgresql",
    "service_mongodb":      "mongodb",
    "service_elasticsearch":"elasticsearch,elastic",
    "service_memcached":    "memcached",
    "service_rabbitmq":     "rabbitmq",
    "service_smtp":         "smtp,email",
    "service_ftp":          "ftp",
    "service_jenkins":      "jenkins,ci-cd",
    "service_docker":       "docker",
    "service_kubernetes":   "kubernetes,k8s",
    "service_consul":       "consul,hashicorp",
    "service_etcd":         "etcd",
    "service_prometheus":   "prometheus",
    "service_grafana_candidate": "grafana",
    "service_kibana":       "kibana,elastic",
    "service_activemq":     "activemq,java",
    # Network protocol findings
    "ssh_open":             "ssh,network",
    "smb_open":             "smb,network",
    "rdp_open":             "rdp,network",
    "snmp_open":            "snmp,network",
    "rtsp_open":            "rtsp,iot",
    "tls_service":          "ssl,tls",
    # API / web features
    "graphql_endpoint":     "graphql",
    "api_endpoint":         "api,exposure",
    "waf_detected":         "waf-bypass",
    # Secrets / exposure
    "secret_candidate":     "exposure,token,secret",
    "leaked_credential":    "exposure,credential",
}

# Evidence tokens that should be SKIPPED in the generic tech-specific nuclei
# pass because they have dedicated agent methods that handle them more thoroughly
# (wpscan for WordPress, droopescan for Joomla/Drupal, etc.).
TECH_NUCLEI_SKIP_IN_GENERIC_PASS: frozenset[str] = frozenset({
    "tech_wordpress",
    "tech_joomla",
    "tech_drupal",
})


# ─────────────────────────────────────────────────────────────────────────────
# Query API
# ─────────────────────────────────────────────────────────────────────────────

def get_tool_capability(tool_name: str) -> ToolCapability | None:
    return TOOL_CAPABILITIES.get(tool_name)


def all_tool_capabilities() -> dict[str, dict[str, Any]]:
    return {name: public_tool_capability(cap) for name, cap in TOOL_CAPABILITIES.items()}


def public_tool_capability(capability: ToolCapability) -> dict[str, Any]:
    """Return capability metadata safe for product/API display.

    Exact environment variable names are internal deployment details. Expose
    only whether credentials are required and how many, not their names.
    """
    data = capability.to_dict()
    required = data.pop("requires_api_keys", []) or []
    data["requires_credentials"] = bool(required)
    data["required_credentials_count"] = len(required)
    return data


def select_tools(
    *,
    phase: str | None = None,
    target_layer: str | None = None,
    categories: list[str] | None = None,
    detected_tech: list[str] | None = None,
    include_aggressive: bool = False,
) -> list[ToolCapability]:
    """Select tools matching a phase/layer/category/tech request."""
    requested_categories = {item.lower() for item in categories or []}
    tech_tokens = {
        item.lower().replace(" ", "_").replace("-", "_") for item in detected_tech or []
    }

    selected: list[ToolCapability] = []
    for cap in TOOL_CAPABILITIES.values():
        if phase and phase not in cap.phases:
            continue
        if target_layer and target_layer not in cap.target_layers:
            continue
        if requested_categories and not requested_categories.intersection(cap.categories):
            continue
        if tech_tokens:
            haystack = {
                item.lower().replace("-", "_")
                for item in cap.categories + cap.run_when
            }
            if not tech_tokens.intersection(haystack):
                continue
        if cap.aggressive and not include_aggressive:
            continue
        selected.append(cap)

    return sorted(selected, key=lambda c: (c.aggressive, c.name))


def plan_next_tools(
    available_evidence: set[str],
    already_run: set[str] | None = None,
    *,
    phase: str | None = None,
    include_aggressive: bool = False,
    available_tools: set[str] | None = None,
    target_layers: set[str] | None = None,
) -> list[ToolCapability]:
    """Evidence-driven tool planner.

    Returns tools whose `consumes` requirements are fully satisfied by
    `available_evidence` and that haven't been run yet.

    A tool with an empty `consumes` list is always eligible (it runs on
    the raw target without needing prior evidence).

    Args:
        available_evidence: Set of evidence tokens accumulated so far.
        already_run:        Tool names that have already executed — excluded.
        phase:              If given, only consider tools in this phase.
        include_aggressive: Allow aggressive tools in the result.
        available_tools:    If given, only consider tools in this set
                            (e.g. those whose Docker image is available).
        target_layers:      If given, only consider tools that operate on at
                            least one relevant target layer.

    Returns:
        Sorted list of eligible ToolCapability objects.
    """
    done = already_run or set()
    eligible: list[ToolCapability] = []

    for name, cap in TOOL_CAPABILITIES.items():
        if name in done:
            continue
        if phase and phase not in cap.phases:
            continue
        if cap.aggressive and not include_aggressive:
            continue
        if available_tools is not None and name not in available_tools:
            continue
        if target_layers is not None and not set(cap.target_layers).intersection(target_layers):
            continue
        # All consumes requirements must be present in evidence.
        if cap.consumes and not set(cap.consumes).issubset(available_evidence):
            continue
        eligible.append(cap)

    return sorted(eligible, key=lambda c: (c.aggressive, c.name))


def target_layers_from_evidence(available_evidence: set[str]) -> set[str]:
    """Infer target layers represented by the current evidence set."""
    layers: set[str] = set()
    if available_evidence.intersection({"target_domain", "subdomain", "dns_record"}):
        layers.add("domain")
    if available_evidence.intersection({"target_ip", "ip_address", "ip_range", "open_port"}):
        layers.add("ip")
    if available_evidence.intersection({"target_url", "live_url", "http_status", "http_headers"}):
        layers.add("web")
    if available_evidence.intersection({"target_api", "api_endpoint", "graphql_endpoint"}):
        layers.add("api")
    if available_evidence.intersection({"javascript_url", "secret_candidate", "api_key_candidate"}):
        layers.add("javascript")
    if available_evidence.intersection({"target_cloud_asset", "cloud_asset", "s3_bucket_hint", "azure_blob_hint", "gcp_bucket_hint"}):
        layers.add("cloud")
    if available_evidence.intersection({"github_repo", "repository_url"}):
        layers.add("repository")
    return layers


def tools_producing(evidence_token: str) -> list[str]:
    """Return tool names that produce a given evidence token."""
    return [
        name for name, cap in TOOL_CAPABILITIES.items()
        if evidence_token in cap.produces
    ]


def build_evidence_chain(
    target_evidence: str,
    available_evidence: set[str] | None = None,
    max_depth: int = 6,
) -> list[list[str]]:
    """Return ordered tool chains that eventually produce `target_evidence`.

    Useful for the AI planner to explain *why* a chain of tools is needed.
    Performs a simple BFS — not guaranteed to be shortest but deterministic.

    Returns:
        List of chains (each chain is an ordered list of tool names).
    """
    available = available_evidence or set()
    chains: list[list[str]] = []

    def _dfs(wanted: str, path: list[str], depth: int) -> None:
        if depth > max_depth:
            return
        producers = tools_producing(wanted)
        for tool_name in producers:
            if tool_name in path:
                continue
            cap = TOOL_CAPABILITIES[tool_name]
            new_path = [tool_name] + path
            # If all consumes are already in available evidence → complete chain.
            if not cap.consumes or set(cap.consumes).issubset(available):
                chains.append(new_path)
            else:
                for dep in cap.consumes:
                    if dep not in available:
                        _dfs(dep, new_path, depth + 1)

    _dfs(target_evidence, [], 0)
    return chains
