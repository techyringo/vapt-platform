"""Bounded agentic planner for evidence-driven capability selection.

The model may rank approved candidates and describe hypotheses.  Deterministic
policy defines the candidate set; model output can never introduce an
executable tool, command, image, or out-of-scope target.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from core.tool_registry import plan_next_tools, target_layers_from_evidence


class AdaptivePlanner:
    def __init__(self, config: Any) -> None:
        self.config = config
        self._llm = None

    async def plan(
        self,
        *,
        scan_id: str,
        phase: str,
        evidence_tokens: set[str],
        already_run: set[str],
    ) -> dict[str, Any]:
        layers = target_layers_from_evidence(evidence_tokens)
        eligible = plan_next_tools(
            available_evidence=evidence_tokens,
            already_run=already_run,
            phase=phase,
            include_aggressive=False,
            target_layers=layers or None,
        )
        candidates = [
            {
                "tool": cap.name,
                "capability": cap.display_name,
                "consumes": cap.consumes,
                "produces": cap.produces,
                "target_layers": cap.target_layers,
                "reason": self._deterministic_reason(cap.name, cap.consumes, evidence_tokens),
            }
            for cap in eligible
        ]
        # Evidence-specific capabilities outrank baseline scanners.  This is
        # the key adaptive behavior: WordPress evidence promotes WPScan, an
        # API endpoint promotes parameter/API checks, and so on.
        candidates.sort(key=lambda item: (0 if item["consumes"] else 1, item["tool"]))
        selected = list(candidates[:8])
        hypotheses: list[str] = []
        coverage_gaps: list[str] = []
        model_trace: dict[str, Any] = {
            "used": False,
            "provider": "",
            "model": "",
            "error": "",
        }

        if candidates:
            try:
                from tools.llm_client import LLMClient

                if self._llm is None:
                    self._llm = LLMClient(self.config)
                if self._llm.get_available_providers():
                    prompt = self._prompt(phase, evidence_tokens, candidates)
                    response = await self._llm.complete(
                        prompt,
                        system_prompt=(
                            "You are a security assessment planner. Rank only the supplied approved tools. "
                            "Never invent commands, tools, exploits, targets, CVEs, or findings. "
                            "Unknown needs must be returned as coverage gaps, not executable actions."
                        ),
                        task="reason",
                        json_mode=True,
                        max_tokens=700,
                        use_fallback=False,
                    )
                    model_trace = {
                        "used": bool(response.content and not response.error),
                        "provider": response.provider,
                        "model": response.model,
                        "error": response.error or "",
                    }
                    parsed = response.json_content() if response and not response.error else None
                    if isinstance(parsed, dict):
                        allowed = {item["tool"]: item for item in candidates}
                        ranked: list[dict[str, Any]] = []
                        for proposal in parsed.get("selected") or []:
                            if not isinstance(proposal, dict):
                                continue
                            tool = str(proposal.get("tool") or "")
                            if tool not in allowed or any(item["tool"] == tool for item in ranked):
                                continue
                            item = dict(allowed[tool])
                            if proposal.get("reason"):
                                item["reason"] = str(proposal["reason"])[:500]
                            ranked.append(item)
                        if ranked:
                            selected = ranked[:8]
                        hypotheses = [str(value)[:500] for value in (parsed.get("hypotheses") or []) if str(value).strip()][:8]
                        coverage_gaps = [str(value)[:300] for value in (parsed.get("coverage_gaps") or []) if str(value).strip()][:8]
            except Exception as exc:
                model_trace["error"] = f"{type(exc).__name__}: {exc}"

        return {
            "decision_id": f"decision_{uuid4().hex[:16]}",
            "scan_id": scan_id,
            "phase": phase,
            "decision_type": "adaptive_capability_plan",
            "status": "proposed",
            "created_at": datetime.utcnow().isoformat(),
            "policy": {
                "candidate_source": "deterministic_registry",
                "aggressive_tools_allowed": False,
                "arbitrary_commands_allowed": False,
                "automatic_install_allowed": False,
            },
            "input_evidence": sorted(evidence_tokens),
            "target_layers": sorted(layers),
            "candidate_count": len(candidates),
            "selected": selected,
            "hypotheses": hypotheses,
            "coverage_gaps": coverage_gaps,
            "model_trace": model_trace,
        }

    @staticmethod
    def _deterministic_reason(tool: str, consumes: list[str], evidence: set[str]) -> str:
        if consumes:
            matched = sorted(set(consumes).intersection(evidence))
            return f"{tool} is eligible because required evidence is present: {', '.join(matched)}."
        return f"{tool} is a baseline capability for this phase and target layer."

    @staticmethod
    def _prompt(phase: str, evidence: set[str], candidates: list[dict[str, Any]]) -> str:
        compact = [
            {"tool": item["tool"], "consumes": item["consumes"], "produces": item["produces"]}
            for item in candidates[:30]
        ]
        return (
            f"Phase: {phase}\n"
            f"Evidence tokens: {sorted(evidence)}\n"
            f"Approved candidates: {compact}\n\n"
            "Return JSON: {\"selected\":[{\"tool\":\"approved-name\",\"reason\":\"grounded reason\"}],"
            "\"hypotheses\":[\"non-factual test hypothesis\"],"
            "\"coverage_gaps\":[\"missing capability, credential, or evidence\"]}."
        )
