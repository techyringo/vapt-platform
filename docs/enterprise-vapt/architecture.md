# Dockerized Multi-Agent VAPT Architecture

## Goal

Build a commercial VAPT platform that finds real vulnerabilities, minimizes false positives, preserves evidence, and produces audit-grade reports.

The product should not be a wrapper around many tools. The product should be an evidence system.

```text
Tools are replaceable.
Evidence is the product.
```

## High-Level System

```mermaid
flowchart TD
    U[User / Operator] --> P[Nginx Reverse Proxy]
    P --> FE[Next.js Frontend]
    P --> API[FastAPI Backend]

    API --> DB[(Scan DB)]
    API --> RQ[(Redis Tool Queue)]
    API --> EV[(Redis Event Bus)]
    API --> ART[(Artifacts, Reports, Logs)]

    RQ --> W1[Worker 1]
    RQ --> W2[Worker 2]
    RQ --> WN[Worker N]

    API --> ORCH[Scan Orchestrator]
    W1 --> RUNNER[Docker Tool Runner]
    W2 --> RUNNER
    WN --> RUNNER

    ORCH --> RECON[Recon Agent]
    ORCH --> ENUM[Enumeration Agent]
    ORCH --> VULN[Vulnerability Scanner Agent]
    ORCH --> FUZZ[Fuzzer Agent]
    ORCH --> EXP[Exploit / Proof Agent]
    ORCH --> INTEL[Intelligence Agent]
    ORCH --> CLOUD[Cloud Agent]
    ORCH --> REPORT[Reporter Agent]

    RECON --> CTX[Asset Context]
    ENUM --> CTX
    VULN --> EVID[Evidence Store]
    FUZZ --> LEADS[Leads and Parameters]
    EXP --> PROOF[Replayable Proof]
    INTEL --> CVE[CVE / Version Intelligence]
    CLOUD --> CLOUDCTX[Cloud Context]

    CTX --> GRAPH[Evidence Graph]
    LEADS --> GRAPH
    EVID --> GRAPH
    PROOF --> GRAPH
    CVE --> GRAPH
    CLOUDCTX --> GRAPH

    GRAPH --> QG[Quality Gate]
    QG --> REPORT
```

## Docker Runtime

```mermaid
flowchart LR
    HOST[Host Machine] --> PROXY[proxy: nginx]
    HOST --> FRONT[frontend: Next.js]
    HOST --> BACK[backend: FastAPI]
    HOST --> WORKERS[worker x N]
    HOST --> REDISQ[redis-queue]
    HOST --> REDIS[redis-events/cache]
    HOST --> SOCK[/var/run/docker.sock/]

    BACK --> DATA[(backend/data)]
    BACK --> REPORTS[(backend/reports)]
    BACK --> LOGS[(backend/logs)]
    BACK --> ARTIFACTS[(backend/artifacts)]
    BACK --> SHARED[(.vapt-shared)]

    WORKERS --> DATA
    WORKERS --> LOGS
    WORKERS --> ARTIFACTS
    WORKERS --> SHARED
    WORKERS --> SOCK

    SOCK --> T1[Tool Container: nuclei]
    SOCK --> T2[Tool Container: nmap]
    SOCK --> T3[Tool Container: katana]
    SOCK --> T4[Tool Container: nikto]
    SOCK --> T5[Tool Container: wpscan]
    SOCK --> T6[Tool Container: other tools]
```

## Agent Responsibilities

| Agent | Main job | Output type |
|---|---|---|
| Recon Agent | Find subdomains, live URLs, historical URLs, crawled URLs, DNS, technology context | Asset context |
| Enumeration Agent | Ports, services, TLS, WAF, service banners | Service context |
| Vulnerability Scanner Agent | Run evidence-based scanners like nuclei, Nikto, CMS checks | Candidate findings |
| Fuzzer Agent | Hidden paths, parameters, API patterns, JS endpoints | Leads |
| Exploit / Proof Agent | Safely validate DAST hypotheses | Confirmed findings |
| Intelligence Agent | CVE, version, internet exposure enrichment | Verified or suspected intelligence |
| Cloud Agent | Cloud provider, bucket, public exposure checks | Cloud context / findings |
| Reporter Agent | Quality gate, dual review, remediation, report generation | Customer report |

## Evidence Lifecycle

```mermaid
flowchart LR
    RAW[Raw tool output] --> PARSE[Parser / Normalizer]
    PARSE --> CLASSIFY{Classification}

    CLASSIFY -->|Technology, banner, port| CONTEXT[Context]
    CLASSIFY -->|Weak scanner signal| LEAD[Lead]
    CLASSIFY -->|AI idea| LEAD
    CLASSIFY -->|Verified CVE| FINDING[Finding]
    CLASSIFY -->|Replay proof| FINDING
    CLASSIFY -->|Confirmed exposure| FINDING

    LEAD --> PROOF[Proof Engine]
    PROOF -->|Confirmed| FINDING
    PROOF -->|Not confirmed| QUARANTINE[Quarantine]

    CONTEXT --> TARGETING[Tool targeting and asset graph]
    FINDING --> QUALITY[Quality Gate]
    QUALITY --> REPORT[Report]
    QUALITY -->|Weak| QUARANTINE
```

## LLM Placement

LLM is a reasoning layer around evidence. It must not directly create customer-facing vulnerabilities.

```mermaid
flowchart TD
    LLM[LLM Gateway] --> P1[Prioritize tools]
    LLM --> P2[Rank DAST hypotheses]
    LLM --> P3[Cluster duplicate findings]
    LLM --> P4[Write remediation]
    LLM --> P5[Write executive summary]
    LLM --> P6[Second-model review]

    P1 --> GUARD[Evidence guardrails]
    P2 --> GUARD
    P3 --> GUARD
    P4 --> GUARD
    P5 --> GUARD
    P6 --> GUARD

    GUARD --> RULE[No proof, no report finding]
```

Current configured chain:

1. Primary: `openai_compat` using local vLLM Qwen.
2. Fallback: `ollama` qwen through ngrok.
3. Fallback: `http_basic_chat` llama3.2 through Basic Auth endpoint.

## Enterprise Target State

```mermaid
flowchart TD
    UI[Operator UI] --> API[Control Plane API]
    API --> QUEUE[Queue]
    API --> DB[(Postgres)]
    API --> OBJ[(Object Storage)]
    API --> EVENTS[Event Stream]

    QUEUE --> SCHED[Scheduler]
    SCHED --> WP[Worker Pool]
    WP --> AGENTS[Agents]
    AGENTS --> RUNNER[Sandboxed Tool Runner]
    RUNNER --> TOOLS[Ephemeral Tool Containers]

    AGENTS --> LLM[LLM Gateway]
    LLM --> M1[Primary GPU Model]
    LLM --> M2[Fallback Model]
    LLM --> M3[Reviewer Model]

    AGENTS --> EVIDENCE[Evidence Graph]
    EVIDENCE --> QUALITY[Quality Engine]
    QUALITY --> REPORT[Report Engine]
    REPORT --> CUSTOMER[Customer Report]
    EVIDENCE --> AUDIT[Audit Trail]
```
