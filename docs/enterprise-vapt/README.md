# Enterprise VAPT Architecture Pack

This folder is a validation pack for the current VAPT platform architecture.

Files:

- `architecture.md` - dockerized multi-agent system architecture and data flow.
- `tool-graph.md` - tool selection graph by target evidence and scan phase.
- `target-flow-matters-ai.md` - example end-to-end flow for `matters.ai`.
- `finding-quality-policy.md` - what is reportable, what is a lead, and what is context.
- `source-file-map.md` - important implementation files to review.

Design principle:

```text
Target -> Assets -> Services -> Endpoints -> Parameters -> Evidence -> Hypotheses -> Proof -> Findings -> Report
```

Commercial rule:

```text
No proof, no customer-facing vulnerability finding.
```
