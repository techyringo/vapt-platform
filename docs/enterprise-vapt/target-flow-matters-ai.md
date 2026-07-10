# Example Target Flow: matters.ai

This is the expected behavior when an operator enters:

```text
matters.ai
```

## End-to-End Flow

```mermaid
flowchart TD
    A[Input: matters.ai] --> B[Scope Manager]
    B --> C[Scan Orchestrator]

    C --> R[Recon Agent]
    R --> R1[Subdomain discovery]
    R --> R2[DNS resolution]
    R --> R3[Live URL probing]
    R --> R4[Historical URL collection]
    R --> R5[Crawling]
    R --> R6[Technology context]

    R6 --> CTX[Context only: Nginx, React, Cloudflare, etc.]
    CTX --> TGT[Tool targeting]

    C --> E[Enumeration Agent]
    E --> E1[Port discovery]
    E --> E2[Service/version detection]
    E --> E3[TLS/WAF checks]

    C --> V[Vulnerability Scanner Agent]
    V --> V1[nuclei]
    V --> V2[Nikto filtered/replayed]
    V --> V3[CMS checks only if CMS proven]

    C --> F[Fuzzer Agent]
    F --> F1[Hidden paths]
    F --> F2[Parameters]
    F --> F3[API and JS endpoints]
    F --> F4[AI lead analysis]

    C --> P[Exploit / Proof Agent]
    P --> P1[Build hypotheses]
    P1 --> P2[LLM ranks hypotheses]
    P2 --> P3[Safe DAST validators]
    P3 --> P4[Replayable proof findings]

    C --> I[Intelligence Agent]
    I --> I1[CVE / NVD validation]
    I --> I2[Passive exposure intel]

    P4 --> Q[Quality Gate]
    I1 --> Q
    V --> Q
    Q --> REP[Reporter Agent]
    REP --> FINAL[Final report]
```

## Step 1: Scope

The scanner creates an authorized scope for `matters.ai`.

Expected in-scope examples:

```text
matters.ai
app.matters.ai
demo.matters.ai
payu.matters.ai
groww.matters.ai
https://app.matters.ai/*
```

Out-of-scope examples:

```text
third-party payment provider domains
analytics domains
CDN domains not explicitly allowed
external links discovered in JS
```

## Step 2: Recon

Recon should collect:

```text
Subdomains
DNS records
Live URLs
Historical URLs
Crawled URLs
Technology context
```

Example context:

```text
app.matters.ai -> HTTPS live, Nginx, React
demo.matters.ai -> HTTPS live, Nginx
payu.matters.ai -> HTTPS live
```

This must not become a finding:

```text
Nginx detected on app.matters.ai
```

It is stored only as context for targeting.

## Step 3: Enumeration

Enumeration should answer:

```text
Which services are exposed?
Which ports are open?
Which TLS/cert configuration exists?
Which service versions are actually visible?
```

Example:

```text
app.matters.ai:443 https
demo.matters.ai:443 https
```

Open `443` is not a vulnerability. It is asset context.

## Step 4: Vulnerability Scanning

Nuclei and similar scanners run against live targets.

Good candidate:

```text
/.git/config exposed
```

Weak candidate:

```text
/ai.pem potentially interesting file
```

Weak candidates must be replayed before they become findings.

## Step 5: Fuzzing and API Discovery

Fuzzing discovers paths and parameters such as:

```text
https://app.matters.ai/search?q=test
https://app.matters.ai/redirect?next=/dashboard
https://api.matters.ai/user?id=123
https://demo.matters.ai/debug
```

AI may generate leads:

```text
/user?id=123 may need IDOR validation.
/redirect?next= may need open redirect validation.
/search?q= may need XSS/SSTI validation.
```

These are leads, not findings.

## Step 6: DAST Proof

The proof engine creates hypotheses and validates them safely.

```mermaid
flowchart LR
    A[/search?q=test/] --> XSS[XSS hypothesis]
    A --> SSTI[SSTI hypothesis]
    B[/redirect?next=/dashboard/] --> OR[Open redirect hypothesis]
    C[/user?id=123/] --> SQL[SQLi / NoSQLi hypothesis]
    D[/ping?host=127.0.0.1/] --> CMD[Command injection timing hypothesis]

    XSS --> V[Validator]
    SSTI --> V
    OR --> V
    SQL --> V
    CMD --> V

    V -->|Proof| F[Confirmed finding]
    V -->|No proof| Q[No report finding]
```

## Step 7: Intelligence

CVE findings require strong version evidence.

Bad:

```text
Nginx detected, may have vulnerabilities.
```

Good:

```text
Product and version are detected, CVE is verified, and the affected version range matches.
```

## Step 8: Report

Report should include:

```text
Confirmed vulnerabilities
Verified misconfigurations
Replayable DAST proof
Verified CVE/version issues
Exposed sensitive files confirmed by HTTP replay
```

Report should not include:

```text
Nginx detected
React detected
Cloudflare detected
Recon completed
Port 443 open
AI thinks endpoint may be risky
```

Those belong in attack surface or leads, not findings.
