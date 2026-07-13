"""Hypothesis-driven DAST planning.

This module turns discovered URLs and parameters into a small, ranked queue of
testable hypotheses. It does not produce findings. It only answers:
"what should we safely validate next, and why?"
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse


@dataclass(frozen=True)
class InputCandidate:
    id: str
    url: str
    method: str
    parameter: str
    value: str
    source: str
    reason: str = ""


@dataclass(frozen=True)
class DASTHypothesis:
    id: str
    vuln_type: str
    validator: str
    candidate: InputCandidate
    reason: str
    confidence: str = "medium"
    priority: int = 50

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["candidate"] = asdict(self.candidate)
        return data


class DASTPlanner:
    """Build and rank DAST validation hypotheses from scan context."""

    MAX_CANDIDATES = 80
    MAX_HYPOTHESES = 120

    SQLI_PARAMS = {
        "id", "uid", "user", "userid", "product", "productid", "item",
        "cat", "category", "page", "sort", "order", "filter", "search", "q",
        "query", "keyword", "where",
    }
    NOSQLI_PARAMS = {"id", "user", "username", "email", "filter", "where", "query", "q"}
    XSS_PARAMS = {"q", "s", "search", "query", "keyword", "name", "message", "comment", "callback", "return"}
    SSTI_PARAMS = {"name", "template", "tpl", "view", "preview", "message", "content", "email", "subject"}
    CMD_PARAMS = {"host", "ip", "domain", "cmd", "command", "exec", "ping", "lookup", "dns", "url", "target"}
    LFI_PARAMS = {"file", "path", "page", "template", "include", "download", "doc", "document", "view"}
    REDIRECT_PARAMS = {"next", "redirect", "redirect_uri", "return", "returnurl", "url", "continue", "destination"}

    def collect_candidates(
        self,
        *,
        recon_data: dict[str, Any] | None = None,
        enum_data: dict[str, Any] | None = None,
        fuzz_data: dict[str, Any] | None = None,
        vuln_data: dict[str, Any] | None = None,
        existing_findings: list[Any] | None = None,
    ) -> list[InputCandidate]:
        urls: list[tuple[str, str]] = []

        base_urls = [
            str(entry.get("url") or "")
            for entry in (recon_data or {}).get("live_urls") or []
            if isinstance(entry, dict) and str(entry.get("url") or "").startswith(("http://", "https://"))
        ]

        def add_url(value: Any, source: str) -> None:
            if isinstance(value, dict):
                value = value.get("url") or value.get("target_url") or value.get("input") or ""
            text = str(value or "").strip()
            if text.startswith("/") and base_urls:
                text = urljoin(base_urls[0], text)
            if text.startswith(("http://", "https://")):
                urls.append((text, source))

        for entry in (recon_data or {}).get("live_urls") or []:
            add_url(entry, "live_url")
        for entry in (recon_data or {}).get("historical_urls") or []:
            add_url(entry, "historical_url")
        for entry in (recon_data or {}).get("crawled_urls") or []:
            add_url(entry, "crawled_url")
        for entry in (enum_data or {}).get("directories") or []:
            add_url(entry, "content_discovery")
        for entry in (enum_data or {}).get("js_endpoints") or []:
            add_url(entry, "javascript_endpoint")
        # Arjun emits explicit parameter names separately from URLs. Convert
        # those observations into testable URLs so the proof engine does not
        # depend on a crawler having already seen the parameter in a query.
        for result in (enum_data or {}).get("parameters") or []:
            if not isinstance(result, dict):
                continue
            base = str(result.get("url") or "").strip()
            if base.startswith("/") and base_urls:
                base = urljoin(base_urls[0], base)
            if not base.startswith(("http://", "https://")):
                continue
            for parameter in result.get("parameters") or []:
                name = str(parameter or "").strip()
                if name:
                    urls.append((self.ensure_parameter(base, name), "parameter_discovery"))
        for entry in (fuzz_data or {}).get("new_endpoints") or []:
            add_url(entry, "fuzzer")
        for key in ("nuclei_findings", "nikto_findings", "cms_findings", "tech_nuclei_findings"):
            for entry in (vuln_data or {}).get(key) or []:
                add_url(entry, f"vuln:{key}")
        for finding in existing_findings or []:
            target = getattr(finding, "target", None)
            add_url(getattr(target, "url", "") if target is not None else "", "finding")

        candidates: list[InputCandidate] = []
        seen: set[tuple[str, str]] = set()
        for url, source in urls:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                continue
            resource_key = (url, "__resource__")
            if parsed.path.lower().endswith(".js") and resource_key not in seen:
                seen.add(resource_key)
                candidates.append(InputCandidate(
                    id=f"inp_{len(candidates) + 1:04d}",
                    url=url,
                    method="GET",
                    parameter="__resource__",
                    value="",
                    source=source,
                    reason=f"Discovered JavaScript resource in {source}.",
                ))
                if len(candidates) >= self.MAX_CANDIDATES:
                    return candidates

            response_key = (urlunparse(parsed._replace(query="")), "__response__")
            if response_key not in seen:
                seen.add(response_key)
                candidates.append(InputCandidate(
                    id=f"inp_{len(candidates) + 1:04d}",
                    url=urlunparse(parsed._replace(query="")),
                    method="GET",
                    parameter="__response__",
                    value="",
                    source=source,
                    reason=f"Discovered response surface in {source}.",
                ))
                if len(candidates) >= self.MAX_CANDIDATES:
                    return candidates

            if not parsed.query:
                continue
            for name, value in parse_qsl(parsed.query, keep_blank_values=True):
                key = (self._normalise_param_url(url, name), name.lower())
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(InputCandidate(
                    id=f"inp_{len(candidates) + 1:04d}",
                    url=url,
                    method="GET",
                    parameter=name,
                    value=value,
                    source=source,
                    reason=f"Discovered parameter `{name}` in {source}.",
                ))
                if len(candidates) >= self.MAX_CANDIDATES:
                    return candidates
        return candidates

    def build_hypotheses(self, candidates: list[InputCandidate]) -> list[DASTHypothesis]:
        hypotheses: list[DASTHypothesis] = []
        for candidate in candidates:
            name = candidate.parameter.lower()
            specs: list[tuple[str, str, int, str]] = []
            if name == "__resource__" and urlparse(candidate.url).path.lower().endswith(".js"):
                specs.append(("source_map_exposure", "sourcemap_exposure", 18, "JavaScript resource may expose source maps."))
            elif name == "__response__":
                specs.append(("jwt", "jwt_alg_none", 45, "Response may expose JWTs with unsafe header configuration."))
            if name.startswith("__"):
                for vuln_type, validator, priority, reason in specs:
                    hypotheses.append(DASTHypothesis(
                        id=f"hyp_{len(hypotheses) + 1:04d}",
                        vuln_type=vuln_type,
                        validator=validator,
                        candidate=candidate,
                        reason=reason,
                        confidence="high" if priority <= 25 else "medium",
                        priority=priority,
                    ))
                    if len(hypotheses) >= self.MAX_HYPOTHESES:
                        return self.rank(hypotheses)
                continue

            if name in self.REDIRECT_PARAMS:
                specs.append(("open_redirect", "open_redirect", 10, "Parameter commonly controls redirects."))
            if name in self.CMD_PARAMS:
                specs.append(("command_injection", "command_injection_timing", 15, "Parameter name suggests OS/network command sink."))
            if name in self.SSTI_PARAMS:
                specs.append(("ssti", "ssti_arithmetic", 20, "Parameter may be rendered inside a template."))
            if name in self.XSS_PARAMS:
                specs.append(("xss", "xss_reflection", 25, "Parameter commonly reflects into HTML/JS output."))
            if name in self.SQLI_PARAMS:
                specs.append(("sqli", "sqli_error_boolean", 30, "Parameter commonly reaches SQL query logic."))
            if name in self.NOSQLI_PARAMS:
                specs.append(("nosqli", "nosqli_error", 35, "Parameter may reach document/query filtering logic."))
            if name in self.LFI_PARAMS:
                specs.append(("lfi", "lfi_known_file", 40, "Parameter commonly controls file/path selection."))

            # Unknown parameters still get cheap reflection/SSTI checks, but low priority.
            if not specs and len(name) >= 2:
                specs.extend([
                    ("xss", "xss_reflection", 70, "Generic parameter can be checked for safe reflection."),
                    ("ssti", "ssti_arithmetic", 75, "Generic parameter can be checked for template evaluation."),
                ])

            for vuln_type, validator, priority, reason in specs:
                hypotheses.append(DASTHypothesis(
                    id=f"hyp_{len(hypotheses) + 1:04d}",
                    vuln_type=vuln_type,
                    validator=validator,
                    candidate=candidate,
                    reason=reason,
                    confidence="high" if priority <= 25 else "medium",
                    priority=priority,
                ))
                if len(hypotheses) >= self.MAX_HYPOTHESES:
                    return self.rank(hypotheses)
        return self.rank(hypotheses)

    @staticmethod
    def rank(hypotheses: list[DASTHypothesis]) -> list[DASTHypothesis]:
        return sorted(hypotheses, key=lambda item: (item.priority, item.candidate.source, item.id))

    async def rank_with_llm(self, hypotheses: list[DASTHypothesis], llm_client: Any) -> list[DASTHypothesis]:
        """Let the local LLM reprioritise, without letting it create findings."""
        if not hypotheses or llm_client is None:
            return self.rank(hypotheses)
        try:
            compact = [
                {
                    "id": h.id,
                    "type": h.vuln_type,
                    "param": h.candidate.parameter,
                    "url": h.candidate.url[:180],
                    "source": h.candidate.source,
                    "reason": h.reason,
                }
                for h in self.rank(hypotheses)[:60]
            ]
            prompt = (
                "You are the VAPT proof-planning reviewer in an enterprise security agent workflow. "
                "Your job is only to rank safe validation hypotheses; validators, not the LLM, create proof. "
                "Prefer replayable evidence over fingerprints. Never promote technology detection, server banners, "
                "or generic scanner text as vulnerabilities. Do not invent IDs. "
                "Return JSON only: {\"ordered_ids\": [\"hyp_0001\", ...]}.\n\n"
                f"Hypotheses:\n{json.dumps(compact, ensure_ascii=True)}"
            )
            result = await llm_client.analyze(prompt, task="triage")
            ordered = result.get("ordered_ids") if isinstance(result, dict) else None
            if not isinstance(ordered, list):
                return self.rank(hypotheses)
            by_id = {h.id: h for h in hypotheses}
            selected = [by_id[item] for item in ordered if isinstance(item, str) and item in by_id]
            remainder = [h for h in self.rank(hypotheses) if h.id not in {item.id for item in selected}]
            return selected + remainder
        except Exception:
            return self.rank(hypotheses)

    @staticmethod
    def replace_param(url: str, parameter: str, value: str) -> str:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = [(name, value if name == parameter else current) for name, current in pairs]
        return urlunparse(parsed._replace(query=urlencode(replaced, doseq=True)))

    @staticmethod
    def ensure_parameter(url: str, parameter: str, value: str = "vapt-baseline") -> str:
        """Return ``url`` with a stable parameter added when it is absent."""
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not any(name == parameter for name, _current in pairs):
            pairs.append((parameter, value))
        return urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))

    @staticmethod
    def _normalise_param_url(url: str, parameter: str) -> str:
        parsed = urlparse(url)
        pairs = [(name, "") for name, _value in parse_qsl(parsed.query, keep_blank_values=True)]
        return urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))
