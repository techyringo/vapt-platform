# VAPT Platform contributor guide

## Build and verify

- Backend: `cd backend && python -m compileall -q . && pytest -q`
- Frontend: `cd frontend && npm ci && npm run lint && npm run build`
- Full stack: `docker compose config && docker compose build`

## Security invariants

- Run active scans only against targets the operator explicitly owns or is authorized to test.
- Never commit credentials, tokens, target secrets, raw session cookies, or customer evidence.
- Findings are evidence-gated: distinguish confirmed, suspected, and untested claims. Never invent tool output, CVEs, exploitability, impact, or attack chains.
- Exploit validation must be non-destructive, scoped, rate-limited, logged, and reproducible. Stop when the configured proof threshold is met.
- Keep model reasoning advisory. Scope enforcement, tool arguments, evidence validation, severity policy, and state transitions remain deterministic code.
- Long-running work belongs in durable queues with persisted checkpoints; API-process background tasks are not durable.

## Pull requests

- Include the threat/risk addressed, tests run, and any remaining blind spots.
- Preserve audit logs and tenant/scan boundaries. Redact sensitive evidence in UI, logs, and reports.
