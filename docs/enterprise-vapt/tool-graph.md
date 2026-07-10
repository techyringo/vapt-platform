# Tool Selection Graph

This document describes when tools should run. The platform should select tools based on evidence, not run every tool blindly.

## Full Tool Decision Graph

```mermaid
flowchart TD
    TARGET[Target] --> SCOPE[Scope Manager]
    SCOPE --> TYPE{Target Type}

    TYPE -->|Domain| DOMAIN[Domain Recon]
    TYPE -->|IP / CIDR| NETWORK[Network Enumeration]
    TYPE -->|URL| WEB[Web Recon]
    TYPE -->|Cloud hint| CLOUD[Cloud Checks]

    DOMAIN --> SUB[subfinder / assetfinder]
    DOMAIN --> DNS[dnsx / DNS records]
    DOMAIN --> HIST[waybackurls / gau]
    SUB --> HTTPX[httpx live probing]
    HIST --> URLS[Historical URLs]
    DNS --> HTTPX

    WEB --> HTTPX
    HTTPX --> LIVE{Live HTTP?}
    LIVE -->|Yes| CRAWL[katana]
    LIVE -->|Yes| TECH[Technology Context]
    LIVE -->|Yes| NUCLEI[nuclei safe templates]
    LIVE -->|Yes| NIKTO[Nikto filtered and replayed]

    TECH --> CMS{CMS proven?}
    CMS -->|WordPress| WPSCAN[WPScan]
    CMS -->|Joomla / Drupal| CMSNUC[CMS-specific nuclei]
    CMS -->|No| SKIPCMS[Skip CMS scanners]

    CRAWL --> PARAMS{Parameters / forms / APIs?}
    URLS --> PARAMS
    PARAMS --> FUZZ[ffuf / gobuster / parameter discovery]
    PARAMS --> DAST[DAST proof engine]

    NETWORK --> NAABU[naabu]
    NAABU --> NMAP[nmap service/version/safe scripts]
    NMAP --> SERVICE{Service detected?}
    SERVICE -->|TLS| TLS[tlsx / TLS checks]
    SERVICE -->|HTTP| HTTPX
    SERVICE -->|SSH/Redis/etc| SERVICECHECK[Service-specific safe checks]

    CLOUD --> SHODAN[Shodan passive intel]
    CLOUD --> CENSYS[Censys passive intel]
    CLOUD --> S3[S3/bucket checks if hints exist]

    NUCLEI --> CANDIDATES[Candidate findings]
    NIKTO --> CANDIDATES
    WPSCAN --> CANDIDATES
    CMSNUC --> CANDIDATES
    SERVICECHECK --> CANDIDATES
    DAST --> PROOF[Confirmed proof findings]

    CANDIDATES --> VERIFY[Replay / CVE / quality validation]
    VERIFY -->|Strong evidence| FINDINGS[Reportable findings]
    VERIFY -->|Weak evidence| QUARANTINE[Quarantine / leads]
    PROOF --> FINDINGS
```

## Tool Categories

| Category | Tools | Expected output |
|---|---|---|
| Subdomain discovery | subfinder, assetfinder | Subdomains |
| DNS resolution | dnsx | Resolved hosts, DNS records |
| HTTP probing | httpx, httprobe | Live URLs, titles, status codes, technologies |
| Crawling | katana, hakrawler | URLs, JS files, APIs, parameters |
| URL archives | waybackurls, gau | Historical URLs and parameters |
| Port scanning | naabu, nmap | Open ports, services, versions |
| Vulnerability templates | nuclei | Template evidence, CVEs, exposures |
| Web checks | Nikto | Candidate misconfigurations, replay required |
| CMS checks | WPScan and CMS nuclei | CMS-specific candidate findings |
| Content discovery | ffuf, gobuster | Hidden paths and endpoints |
| DAST proof | internal validators | Confirmed replayable vulnerabilities |
| Passive intel | Shodan, Censys, NVD | Exposure and CVE intelligence |

## Important Guardrails

```text
Technology detected != vulnerability.
Port open != vulnerability.
AI suspicion != vulnerability.
Scanner weak signal != final report finding.
Replay proof or verified CVE or confirmed misconfiguration = reportable.
```

## Current DAST Validators

| Validator | Example signal | Report condition |
|---|---|---|
| XSS reflection | `q` parameter reflects payload | Payload marker returned unencoded |
| SSTI arithmetic | `{{7*7}}` | Response evaluates to `49` not in baseline |
| SQLi error proof | quote payload | SQL error appears only after payload |
| NoSQLi error proof | Mongo operator payload | NoSQL error appears only after payload |
| LFI/path traversal | file/path parameter | Known file marker returned |
| Open redirect | redirect parameter | `Location` points to external proof URL |
| Command injection timing | host/cmd parameter | Stable timing delta from sleep probe |
