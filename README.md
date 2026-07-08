# VAPT Platform — AI-Augmented Vulnerability Assessment & Penetration Testing

> **Industry-grade** multi-agent VAPT platform with NVD-verified findings, real-time agent orchestration, and audit-ready reports.

## How This Differs From School Projects

| Feature | School Project | This Platform |
|---------|--------------|---------------|
| CVE Verification | None | NVD API 2.0 cross-reference |
| Findings | Same vulns on every target | Deduplicated per (title, target_host) |
| Completion Time | 1 second (fake) | Real tool execution (minutes-hours) |
| Agent Status | Always "idle" | Real-time: running/completed/failed/tools/progress |
| Reports | No download button | Download HTML/PDF/Markdown/JSON |
| Scan Modes | One mode | VA-Only, Full VAPT, Web App, API, Cloud, IoT |
| AI Integration | None | 8 LLM providers with fallback chain |
| Evidence | Empty | Tool output, HTTP headers, NVD links |

## Architecture (How Real Tools Work)

### Faraday's Approach
Faraday uses Python/Flask + PostgreSQL, normalizes findings from 80+ tools, and provides workspace-based vulnerability management. We follow the same pattern:
- **Normalization**: All tool outputs → standard `Finding` model
- **Deduplication**: (title, target_host) uniqueness check
- **Workspace/Scan management**: Create, start, stop, track scans
- **REST API + Web UI**: Separated backend/frontend

### OpenVAS/GVM's Approach
OpenVAS uses NVT (Network Vulnerability Tests) feed + CVE data. We do the same but simpler:
- **NVD 2.0 API**: Every CVE is cross-verified against NIST
- **CVSS v3.1 scores**: Pulled from NVD, not hardcoded
- **REJECTED CVEs**: Flagged as potential false positives
- **Template-based scanning**: nuclei with 14+ template tags

### Where AI Is Used
AI is NOT used for fake findings. It's used where automation falls short:

1. **Vulnerability Scanner Agent** (`_run_llm_vuln_analysis`): LLM analyzes HTTP responses for misconfigurations, auth flaws, CORS issues that template scanners miss
2. **Fuzzing Agent** (`_llm_analyze_fuzz_results`): LLM identifies IDOR patterns, auth bypass endpoints, attack chains from fuzzing results
3. **Exploit Agent** (`_llm_enhance_findings`): LLM improves PoC steps, suggests attack chains, assesses real-world impact
4. **Intel Agent** (`_run_llm_analysis`): LLM identifies business logic flaws, data exposure risks, and potential attack chains
5. **Report Generation** (future): LLM writes executive summary, prioritizes remediation

## Quick Start

### With Docker (Recommended)

```bash
# Start everything (backend on 8443, frontend on 3000)
docker-compose up -d

# Backend API docs
open http://localhost:8443/api/docs

# Frontend dashboard
open http://localhost:3000
```

### Without Docker

**Backend:**
```bash
cd backend
pip install -r requirements.txt

# Optionally install tools (Docker is used by default)
# apt install nmap
# Docker: subfinder, nuclei, httpx, nikto, ffuf, sqlmap, etc.

python -m uvicorn web.app:create_app:app --host 0.0.0.0 --port 8443 --factory
```

**Frontend:**
```bash
cd frontend
npm install
NEXT_PUBLIC_API_URL=http://localhost:8443 npm run dev
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scans/start` | Start scan (returns scan_id immediately) |
| GET | `/api/scans` | List all scans |
| GET | `/api/scans/{id}` | Full scan with agent status |
| GET | `/api/scans/{id}/findings` | Findings (filter by severity/agent/status) |
| GET | `/api/scans/{id}/agents` | Real-time agent status |
| POST | `/api/scans/{id}/stop` | Stop/cancel scan |
| GET | `/api/scans/{id}/report?format=html` | Download audit report |
| GET | `/api/modes` | Available scan modes |
| GET | `/api/stream` | SSE real-time events |
| GET | `/api/health` | Health + NVD stats |
| GET | `/api/tools/status` | Tool availability check |
| GET | `/api/nvd/stats` | NVD verification statistics |

## Scan Modes

| Mode | Exploitation | Agents | Use Case |
|------|-------------|--------|----------|
| `va_only` | **No** | recon, enum, vuln_scanner, reporter | Non-intrusive compliance assessment |
| `full_vapt` | **Yes** | All 7 agents | Complete penetration test |
| `web_app` | **Yes** | All 7 agents | Deep web app testing (XSS, SQLi, SSRF) |
| `api` | **Yes** | All 7 agents | API security (BOLA, injection, rate limits) |
| `cloud` | **No** | recon, cloud, vuln_scanner, intel, reporter | Cloud misconfigurations (S3, IAM) |
| `iot_cctv` | **Yes** | recon, iot_cctv, vuln_scanner, exploit, reporter | IoT/CCTV devices |

## Project Structure

```
vapt-platform/
├── backend/                    # Python FastAPI backend
│   ├── core/                   # Orchestrator, state machine, models, scope
│   ├── agents/                 # 9 specialized agents
│   │   ├── recon.py            # Subdomain enumeration (subfinder, amass, httpx)
│   │   ├── enum_agent.py       # Port scanning (nmap), JS endpoint discovery
│   │   ├── vuln_scanner.py     # Template scanning (nuclei, nikto, wpscan) + LLM
│   │   ├── fuzzer.py           # Path/param fuzzing (ffuf, wfuzz) + LLM
│   │   ├── exploit.py          # Validation (sqlmap, dalfox, commix) + LLM
│   │   ├── intel.py            # Secret hunting, CVE matching, LLM analysis
│   │   ├── cloud_agent.py      # Cloud misconfigurations (Shodan, Censys)
│   │   ├── iot_agent.py        # IoT/CCTV (default creds, RTSP, firmware)
│   │   └── reporter.py         # HTML/PDF/Markdown/JSON reports
│   ├── services/
│   │   ├── nvd_service.py     # NVD 2.0 API verification
│   │   └── scan_manager.py    # Scan lifecycle, dedup, events
│   ├── tools/
│   │   ├── runner.py           # Docker tool execution
│   │   └── llm_client.py       # 8-provider LLM with fallback
│   ├── web/app.py              # Production API (all endpoints)
│   └── config.yaml             # Tool configs, modes, LLM settings
│
├── frontend/                   # Next.js 16 dashboard
│   ├── src/app/page.tsx        # Dark hacker aesthetic dashboard
│   ├── src/hooks/useSSE.ts     # Real-time SSE hook
│   ├── src/lib/api.ts          # API client
│   ├── src/types/index.ts      # TypeScript types
│   └── prisma/schema.prisma    # Database schema
│
├── docker-compose.yml          # One-command deployment
└── README.md                   # This file
```

## NVD Verification

Every finding with a CVE ID is verified against the NVD 2.0 API:
- Confirms the CVE exists and is PUBLISHED
- Pulls official CVSS v3.1 score and vector string
- Pulls official NVD description and references
- Flags REJECTED CVEs as potential false positives
- Caches results to respect rate limits (5 req/30s without key)

## Selling Points (CEO Mindset)

1. **AI-augmented, not AI-generated**: AI enhances real tool output, doesn't fake it
2. **NVD-verified**: Every CVE cross-checked against NIST — audit-ready
3. **Multi-agent architecture**: 9 specialized agents, not just tool wrappers
4. **Real tool integration**: 40+ security tools via Docker isolation
5. **Scan mode enforcement**: VA-only truly skips exploitation — legal compliance
6. **Real-time visibility**: SSE events, agent status, live log feed
7. **Audit-ready reports**: Evidence, CVSS, PoC steps, remediation, NVD links
8. **Professional UI**: Dark theme, real-time updates, report download
9. **Extensible**: Plugin architecture for new agents and tools
10. **Deployable**: Docker Compose, one command