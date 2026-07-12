# Investor demo runbook

This demo is designed to show verified security findings, an evidence-backed attack narrative, and an executive report without fabricating results.

## Before the meeting

1. Obtain written authorization for the exact target host(s), paths, time window, and allowed test intensity. Use a staging asset you control whenever possible.
2. Start the stack with `docker compose up -d --build` and confirm `/api/health`, Redis, and workers are healthy.
3. In **Settings → LLM Endpoints**, configure and test all three sources:
   - **Report/reasoning:** `openai_compat`, GPU base URL, `Qwen/Qwen2.5-32B-Instruct-AWQ`.
   - **Analysis/triage:** `ollama`, Mac/ngrok base URL, `qwen3:8b`.
   - **Independent review:** `http_basic_chat`, CPU base URL, `llama3.2`; keep Basic Auth in `MANTHAN_BASIC_AUTH`, never source control.
4. Select those exact model names in the analysis, report, and review role fields. Enable fallbacks. Test every endpoint from the dashboard.
5. Create a narrow scope for one authorized web application. Start with VA mode and conservative request limits. Confirm excluded hosts and paths.
6. Run once before the meeting. Review evidence and quarantine anything not reproducible. Export HTML/PDF/JSON reports and retain the scan ID.

## Live story (8 minutes)

1. **Scope and authorization:** show the target boundary and safety controls.
2. **Live progress:** show durable tool jobs, discovered assets, coverage, and evidence as it arrives.
3. **Verified finding:** open one finding and walk through request/response or tool proof, confidence, CVE/CWE mapping, and remediation.
4. **Attack narrative:** connect only evidence-supported findings. Label any unverified link as a hypothesis and show the next validation step.
5. **Model resilience:** show endpoint health and explain that each model has a role; an unavailable endpoint falls back to the next configured endpoint using that endpoint's native model.
6. **Executive output:** export the customer-ready report and show evidence provenance and independent review status.

## Guardrails

- Do not scan an arbitrary public domain for the presentation.
- Do not claim a vulnerability, exploit, or business impact that the stored evidence does not support.
- Never demonstrate destructive exploitation, persistence, credential access, data modification, denial of service, or scope expansion.
- If a model is unavailable, deterministic tools continue; AI enrichment is degraded, not authoritative. Record that coverage gap in the report.

## Known MVP limitation

Individual tool executions use Redis/ARQ workers, but whole-scan orchestration still begins in the API process. An API restart can interrupt orchestration. The enterprise follow-up is a persisted workflow/state machine with resumable checkpoints; do not restart the API during the live scan.
