# Source File Map

This document maps the architecture to implementation files.

## Control Plane

| Area | File |
|---|---|
| FastAPI app and runtime endpoints | `backend/web/app.py` |
| API key middleware | `backend/web/auth.py` |
| Scan manager and API scan state | `backend/services/scan_manager.py` |
| Orchestrator | `backend/core/orchestrator.py` |
| Data models | `backend/core/models.py` |
| Config loader | `backend/core/config.py` |
| Runtime LLM settings | `backend/core/runtime_config.py` |

## Agents

| Agent | File |
|---|---|
| Recon | `backend/agents/recon.py` |
| Enumeration | `backend/agents/enum_agent.py` |
| Vulnerability scanner | `backend/agents/vuln_scanner.py` |
| Fuzzer | `backend/agents/fuzzer.py` |
| Exploit / proof | `backend/agents/exploit.py` |
| Intelligence | `backend/agents/intel.py` |
| Cloud | `backend/agents/cloud_agent.py` |
| Reporter | `backend/agents/reporter.py` |

## Tooling

| Area | File |
|---|---|
| Docker tool runner | `backend/tools/runner.py` |
| Tool registry | `backend/core/tool_registry.py` |
| LLM client | `backend/tools/llm_client.py` |
| CVE resolver | `backend/tools/cve_resolver.py` |
| Wordlists | `backend/wordlists/` |

## Evidence and Quality

| Area | File |
|---|---|
| Finding quality gate | `backend/core/quality.py` |
| DAST planner | `backend/core/dast_planner.py` |
| DAST validators | `backend/core/dast_validators.py` |
| DAST evidence gate | `backend/core/evidence_gate.py` |
| Dual model review | `backend/core/dual_review.py` |
| LLM context budgeting | `backend/core/llm_budget.py` |
| Asset graph | `backend/core/asset_graph.py` |

## Frontend

| Area | File |
|---|---|
| Main UI | `frontend/src/app/page.tsx` |
| LLM configuration panel | `frontend/src/components/features/LLMConfigPanel.tsx` |
| API client | `frontend/src/lib/api.ts` |
| Shared types | `frontend/src/types/index.ts` |

## Runtime

| Area | File |
|---|---|
| Compose stack | `docker-compose.yml` |
| Reverse proxy | `proxy/nginx.conf` |
| Backend Dockerfile | `backend/Dockerfile` |
| Runtime logs | `backend/logs/` |
| Reports | `backend/reports/` |
| Artifacts | `backend/artifacts/` |

## Recent Quality Changes To Validate

| Change | File |
|---|---|
| Stop recon from emitting technology findings | `backend/agents/recon.py` |
| Quarantine inventory-only records | `backend/core/quality.py` |
| Regression test for tech-only findings | `backend/tests/test_quality_gate.py` |
| Proof-gated DAST engine | `backend/agents/exploit.py`, `backend/core/dast_*`, `backend/core/evidence_gate.py` |
| Multi-provider LLM runtime config | `backend/tools/llm_client.py`, `backend/web/app.py`, `backend/core/runtime_config.py` |
