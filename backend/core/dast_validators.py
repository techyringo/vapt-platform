"""Safe DAST validators.

Validators perform small, bounded probes and return proof objects. They do not
decide reporting policy and they do not mutate scan state.
"""

from __future__ import annotations

import asyncio
import base64
import difflib
import json
import os
import re
import statistics
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urljoin, urlparse
from uuid import uuid4

import httpx

from core.dast_planner import DASTHypothesis, DASTPlanner


@dataclass
class ValidationProof:
    hypothesis_id: str
    vuln_type: str
    validator: str
    url: str
    parameter: str
    confirmed: bool
    confidence: str
    severity: str
    title: str
    evidence: str
    request_proof: str = ""
    response_proof: str = ""
    remediation: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DASTValidator:
    """Run safe validators for DAST hypotheses."""

    SQL_ERRORS = (
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "postgresql query failed",
        "sqlite error",
        "ora-01756",
        "microsoft ole db",
        "sqlstate",
    )
    NOSQL_ERRORS = (
        "mongoerror",
        "bson",
        "mongodb",
        "cast to objectid failed",
        "unknown operator",
        "$where",
    )

    def __init__(
        self,
        *,
        scope: Any = None,
        timeout: float = 12.0,
        oob_store: Any = None,
        oob_base_url: str = "",
    ) -> None:
        self.scope = scope
        self.timeout = timeout
        self.oob_store = oob_store
        self.oob_base_url = (oob_base_url or os.environ.get("VAPT_OOB_BASE_URL", "")).rstrip("/")
        self.attempts: list[dict[str, Any]] = []

    async def validate_many(
        self,
        hypotheses: list[DASTHypothesis],
        *,
        max_checks: int = 40,
        concurrency: int = 4,
    ) -> list[ValidationProof]:
        sem = asyncio.Semaphore(max(1, concurrency))
        selected = hypotheses[:max(1, max_checks)]

        self.attempts = []

        async def run_one(hypothesis: DASTHypothesis) -> ValidationProof | None:
            async with sem:
                prerequisite = self._prerequisite_failure(hypothesis)
                if prerequisite:
                    self.attempts.append(self._attempt_record(hypothesis, "skipped", prerequisite))
                    return None
                try:
                    proof = await self.validate(hypothesis)
                except Exception as exc:
                    self.attempts.append(self._attempt_record(
                        hypothesis,
                        "error",
                        f"{type(exc).__name__}: {str(exc)[:240]}",
                    ))
                    return None
                if proof is not None:
                    self.attempts.append(self._attempt_record(hypothesis, "confirmed", "Evidence threshold met."))
                    return proof
                self.attempts.append(self._attempt_record(
                    hypothesis,
                    "not_confirmed",
                    "Validator completed; the issue-specific proof threshold was not met.",
                ))
                return None

        results = await asyncio.gather(*(run_one(item) for item in selected), return_exceptions=True)
        proofs: list[ValidationProof] = []
        for item in results:
            if isinstance(item, ValidationProof):
                proofs.append(item)
        return proofs

    def _prerequisite_failure(self, hypothesis: DASTHypothesis) -> str:
        if not self._in_scope(hypothesis.candidate.url):
            return "Candidate is outside the authorised engagement scope."
        if hypothesis.validator == "ssrf_http_oob" and (
            self.oob_store is None or not self.oob_base_url.startswith(("http://", "https://"))
        ):
            return "OOB callback receiver is not configured; SSRF was not tested."
        return ""

    @staticmethod
    def _attempt_record(hypothesis: DASTHypothesis, status: str, reason: str) -> dict[str, Any]:
        return {
            "hypothesis_id": hypothesis.id,
            "validator": hypothesis.validator,
            "vuln_type": hypothesis.vuln_type,
            "url": hypothesis.candidate.url,
            "parameter": hypothesis.candidate.parameter,
            "source": hypothesis.candidate.source,
            "status": status,
            "reason": reason,
        }

    async def validate(self, hypothesis: DASTHypothesis) -> ValidationProof | None:
        if not self._in_scope(hypothesis.candidate.url):
            return None
        validator = hypothesis.validator
        if validator == "open_redirect":
            return await self._validate_open_redirect(hypothesis)
        if validator == "ssrf_http_oob":
            return await self._validate_ssrf_oob(hypothesis)
        if validator == "xss_reflection":
            return await self._validate_xss_reflection(hypothesis)
        if validator == "ssti_arithmetic":
            return await self._validate_ssti(hypothesis)
        if validator == "command_injection_timing":
            return await self._validate_command_timing(hypothesis)
        if validator == "sqli_error_boolean":
            return await self._validate_sqli(hypothesis)
        if validator == "nosqli_error":
            return await self._validate_nosqli(hypothesis)
        if validator == "lfi_known_file":
            return await self._validate_lfi(hypothesis)
        if validator == "sourcemap_exposure":
            return await self._validate_sourcemap_exposure(hypothesis)
        if validator == "jwt_alg_none":
            return await self._validate_jwt_alg_none(hypothesis)
        return None

    async def _validate_ssrf_oob(self, hypothesis: DASTHypothesis) -> ValidationProof | None:
        """Confirm server-side HTTP fetches using a single-use callback token."""
        if self.oob_store is None or not self.oob_base_url.startswith(("http://", "https://")):
            return None
        token = uuid4().hex
        try:
            from core.job_tracker import current_scan_id

            scan_id = current_scan_id.get()
        except Exception:
            scan_id = ""
        self.oob_store.register_oob_token(token, {
            "scan_id": scan_id,
            "hypothesis_id": hypothesis.id,
            "interaction_type": "http",
            "expires_at": (datetime.utcnow() + timedelta(minutes=10)).isoformat(),
        })
        callback = f"{self.oob_base_url}/api/oob/c/{token}"
        test_url = DASTPlanner.replace_param(
            hypothesis.candidate.url,
            hypothesis.candidate.parameter,
            callback,
        )
        async with self._client(follow_redirects=True) as client:
            try:
                await client.get(test_url)
            except httpx.HTTPError:
                # The target may close its client response after dispatching a
                # background fetch. The callback remains the source of truth.
                pass
        interaction: dict[str, Any] = {}
        for _ in range(16):
            record = await asyncio.to_thread(self.oob_store.load_oob_token, token)
            if record and record.get("interacted_at"):
                interaction = record
                break
            await asyncio.sleep(0.5)
        if not interaction:
            return None
        observed = interaction.get("interaction") or {}
        return ValidationProof(
            hypothesis_id=hypothesis.id,
            vuln_type="ssrf",
            validator=hypothesis.validator,
            url=test_url,
            parameter=hypothesis.candidate.parameter,
            confirmed=True,
            confidence="high",
            severity="high",
            title="Server-Side Request Forgery With OOB HTTP Proof",
            evidence=(
                f"The target triggered the single-use HTTP callback token at "
                f"{interaction.get('interacted_at')}; source fingerprint "
                f"{observed.get('source_sha256', 'recorded')}."
            ),
            request_proof=f"GET {test_url}",
            response_proof=(
                f"OOB callback observed: method={observed.get('method', 'unknown')} "
                f"token={token[:8]}… timestamp={interaction.get('interacted_at')}"
            ),
            remediation=(
                "Allowlist outbound destinations, reject private/link-local addresses after DNS resolution, "
                "disable unnecessary redirects, and route required fetches through a constrained egress proxy."
            ),
            cwe_ids=["CWE-918"],
            tags=["dast-proof", "ssrf", "oob-http", "safe-validation"],
            metadata={"callback_token_prefix": token[:8], "interaction": observed},
        )

    async def _validate_open_redirect(self, hypothesis: DASTHypothesis) -> ValidationProof | None:
        payload = "https://example.invalid/vapt-open-redirect-proof"
        test_url = DASTPlanner.replace_param(hypothesis.candidate.url, hypothesis.candidate.parameter, payload)
        async with self._client(follow_redirects=False) as client:
            resp = await client.get(test_url)
        location = resp.headers.get("location", "")
        confirmed = location.startswith(payload)
        if not confirmed:
            return None
        return ValidationProof(
            hypothesis_id=hypothesis.id,
            vuln_type="open_redirect",
            validator=hypothesis.validator,
            url=test_url,
            parameter=hypothesis.candidate.parameter,
            confirmed=True,
            confidence="high",
            severity="medium",
            title="Open Redirect With External Location Proof",
            evidence=f"HTTP {resp.status_code} returned Location: {location}",
            request_proof=f"GET {test_url}",
            response_proof=f"HTTP {resp.status_code}\nLocation: {location}",
            remediation="Validate redirect destinations against an allowlist and prefer relative redirect paths.",
            cwe_ids=["CWE-601"],
            tags=["dast-proof", "open-redirect", "safe-validation"],
        )

    async def _validate_xss_reflection(self, hypothesis: DASTHypothesis) -> ValidationProof | None:
        marker = f"vaptxss{hypothesis.id.replace('_', '')}"
        payload = f'"><svg data-vapt="{marker}">'
        test_url = DASTPlanner.replace_param(hypothesis.candidate.url, hypothesis.candidate.parameter, payload)
        async with self._client(follow_redirects=True) as client:
            resp = await client.get(test_url)
        body = resp.text or ""
        confirmed = payload in body or f'data-vapt="{marker}"' in body
        if not confirmed:
            return None
        return ValidationProof(
            hypothesis_id=hypothesis.id,
            vuln_type="xss",
            validator=hypothesis.validator,
            url=test_url,
            parameter=hypothesis.candidate.parameter,
            confirmed=True,
            confidence="high",
            severity="medium",
            title="Reflected XSS Payload Returned Unencoded",
            evidence=f"Payload marker `{marker}` was reflected into the HTML response without encoding.",
            request_proof=f"GET {test_url}",
            response_proof=self._excerpt(body, marker),
            remediation="Contextually encode reflected user input and apply a restrictive Content Security Policy.",
            cwe_ids=["CWE-79"],
            tags=["dast-proof", "xss", "reflected", "safe-validation"],
        )

    async def _validate_ssti(self, hypothesis: DASTHypothesis) -> ValidationProof | None:
        payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]
        async with self._client(follow_redirects=True) as client:
            baseline = await client.get(hypothesis.candidate.url)
            baseline_text = baseline.text or ""
            for payload in payloads:
                test_url = DASTPlanner.replace_param(hypothesis.candidate.url, hypothesis.candidate.parameter, payload)
                resp = await client.get(test_url)
                body = resp.text or ""
                if "49" in body and "49" not in baseline_text:
                    return ValidationProof(
                        hypothesis_id=hypothesis.id,
                        vuln_type="ssti",
                        validator=hypothesis.validator,
                        url=test_url,
                        parameter=hypothesis.candidate.parameter,
                        confirmed=True,
                        confidence="high",
                        severity="high",
                        title="Server-Side Template Injection Arithmetic Proof",
                        evidence=f"Template payload `{payload}` evaluated to `49` in the response.",
                        request_proof=f"GET {test_url}",
                        response_proof=self._excerpt(body, "49"),
                        remediation="Avoid rendering user-controlled input as templates. Use sandboxing and strict allowlists for template variables.",
                        cwe_ids=["CWE-1336"],
                        tags=["dast-proof", "ssti", "safe-validation"],
                    )
        return None

    async def _validate_command_timing(self, hypothesis: DASTHypothesis) -> ValidationProof | None:
        # Timing-only proof; no command output retrieval.
        delay = 4.0
        payloads = [f"127.0.0.1;sleep {int(delay)}", f"127.0.0.1&&sleep {int(delay)}"]
        async with self._client(follow_redirects=True, timeout=max(self.timeout, delay + 6)) as client:
            baseline_samples = []
            for _ in range(2):
                started = time.monotonic()
                await client.get(hypothesis.candidate.url)
                baseline_samples.append(time.monotonic() - started)
            baseline = statistics.mean(baseline_samples)

            for payload in payloads:
                test_url = DASTPlanner.replace_param(hypothesis.candidate.url, hypothesis.candidate.parameter, payload)
                samples = []
                for _ in range(2):
                    started = time.monotonic()
                    try:
                        await client.get(test_url)
                    except httpx.ReadTimeout:
                        samples.append(delay + 2)
                        continue
                    samples.append(time.monotonic() - started)
                observed = statistics.mean(samples)
                if observed >= baseline + 3.0 and observed >= delay - 0.5:
                    return ValidationProof(
                        hypothesis_id=hypothesis.id,
                        vuln_type="command_injection",
                        validator=hypothesis.validator,
                        url=test_url,
                        parameter=hypothesis.candidate.parameter,
                        confirmed=True,
                        confidence="high",
                        severity="critical",
                        title="OS Command Injection Timing Proof",
                        evidence=(
                            f"Baseline avg response time {baseline:.2f}s; timing payload avg "
                            f"{observed:.2f}s using a non-output `sleep` probe."
                        ),
                        request_proof=f"GET {test_url}",
                        response_proof=f"Timing delta observed: baseline={baseline:.2f}s delayed={observed:.2f}s",
                        remediation="Never concatenate user input into shell commands. Use safe library APIs and strict allowlists for host/domain parameters.",
                        cwe_ids=["CWE-78"],
                        tags=["dast-proof", "command-injection", "timing-proof", "safe-validation"],
                    )
        return None

    async def _validate_sqli(self, hypothesis: DASTHypothesis) -> ValidationProof | None:
        payloads = ["'", "\"", "' OR '1'='1", "' AND '1'='2"]
        async with self._client(follow_redirects=True) as client:
            baseline = await client.get(hypothesis.candidate.url)
            baseline_text = (baseline.text or "").lower()
            for payload in payloads[:2]:
                test_url = DASTPlanner.replace_param(hypothesis.candidate.url, hypothesis.candidate.parameter, payload)
                resp = await client.get(test_url)
                text = (resp.text or "").lower()
                matched = next((err for err in self.SQL_ERRORS if err in text and err not in baseline_text), "")
                if matched:
                    return ValidationProof(
                        hypothesis_id=hypothesis.id,
                        vuln_type="sqli",
                        validator=hypothesis.validator,
                        url=test_url,
                        parameter=hypothesis.candidate.parameter,
                        confirmed=True,
                        confidence="high",
                        severity="high",
                        title="SQL Injection Error-Based Proof",
                        evidence=f"SQL error signature `{matched}` appeared only after injecting a quote payload.",
                        request_proof=f"GET {test_url}",
                        response_proof=self._excerpt(resp.text or "", matched),
                        remediation="Use parameterized queries/prepared statements and avoid building SQL from user-controlled strings.",
                        cwe_ids=["CWE-89"],
                        tags=["dast-proof", "sqli", "error-based", "safe-validation"],
                    )

            # Error messages are often suppressed. Use a paired true/false
            # negative control and require a strong response
            # relationship before creating proof. A single length change or
            # status code is never enough to confirm SQL injection.
            true_url = DASTPlanner.replace_param(
                hypothesis.candidate.url,
                hypothesis.candidate.parameter,
                payloads[2],
            )
            false_url = DASTPlanner.replace_param(
                hypothesis.candidate.url,
                hypothesis.candidate.parameter,
                payloads[3],
            )
            true_resp = await client.get(true_url)
            false_resp = await client.get(false_url)
            baseline_true = self._response_similarity(baseline.text or "", true_resp.text or "")
            baseline_false = self._response_similarity(baseline.text or "", false_resp.text or "")
            true_false = self._response_similarity(true_resp.text or "", false_resp.text or "")
            boolean_proof = (
                baseline.status_code == true_resp.status_code
                and baseline_true >= 0.92
                and baseline_false <= 0.72
                and true_false <= 0.72
            )
            if boolean_proof:
                return ValidationProof(
                    hypothesis_id=hypothesis.id,
                    vuln_type="sqli",
                    validator=hypothesis.validator,
                    url=true_url,
                    parameter=hypothesis.candidate.parameter,
                    confirmed=True,
                    confidence="high",
                    severity="high",
                    title="SQL Injection Boolean Differential Proof",
                    evidence=(
                        "A paired SQL boolean control produced a response differential: "
                        f"baseline↔true={baseline_true:.2f}, baseline↔false={baseline_false:.2f}, "
                        f"true↔false={true_false:.2f}."
                    ),
                    request_proof=f"GET {true_url}\nNEGATIVE CONTROL GET {false_url}",
                    response_proof=(
                        f"baseline status={baseline.status_code} bytes={len(baseline.content)}\n"
                        f"true status={true_resp.status_code} bytes={len(true_resp.content)} similarity={baseline_true:.2f}\n"
                        f"false status={false_resp.status_code} bytes={len(false_resp.content)} similarity={baseline_false:.2f}"
                    ),
                    remediation="Use parameterized queries/prepared statements and avoid building SQL from user-controlled strings.",
                    cwe_ids=["CWE-89"],
                    tags=["dast-proof", "sqli", "boolean-differential", "negative-control", "safe-validation"],
                    metadata={
                        "baseline_true_similarity": baseline_true,
                        "baseline_false_similarity": baseline_false,
                        "true_false_similarity": true_false,
                    },
                )
        return None

    async def _validate_nosqli(self, hypothesis: DASTHypothesis) -> ValidationProof | None:
        payloads = ['{"$ne":null}', '{"$gt":""}', '[$ne]=null']
        async with self._client(follow_redirects=True) as client:
            baseline = await client.get(hypothesis.candidate.url)
            baseline_text = (baseline.text or "").lower()
            for payload in payloads:
                test_url = DASTPlanner.replace_param(hypothesis.candidate.url, hypothesis.candidate.parameter, payload)
                resp = await client.get(test_url)
                text = (resp.text or "").lower()
                matched = next((err for err in self.NOSQL_ERRORS if err in text and err not in baseline_text), "")
                if matched:
                    return ValidationProof(
                        hypothesis_id=hypothesis.id,
                        vuln_type="nosqli",
                        validator=hypothesis.validator,
                        url=test_url,
                        parameter=hypothesis.candidate.parameter,
                        confirmed=True,
                        confidence="high",
                        severity="high",
                        title="NoSQL Injection Error-Based Proof",
                        evidence=f"NoSQL/database error signature `{matched}` appeared after operator-style input.",
                        request_proof=f"GET {test_url}",
                        response_proof=self._excerpt(resp.text or "", matched),
                        remediation="Parse and validate typed input server-side; do not pass user-controlled objects/operators directly into NoSQL queries.",
                        cwe_ids=["CWE-943"],
                        tags=["dast-proof", "nosqli", "error-based", "safe-validation"],
                    )
        return None

    async def _validate_lfi(self, hypothesis: DASTHypothesis) -> ValidationProof | None:
        payloads = ["../../../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd"]
        async with self._client(follow_redirects=True) as client:
            for payload in payloads:
                test_url = DASTPlanner.replace_param(hypothesis.candidate.url, hypothesis.candidate.parameter, payload)
                resp = await client.get(test_url)
                body = resp.text or ""
                if "root:x:0:0:" in body:
                    return ValidationProof(
                        hypothesis_id=hypothesis.id,
                        vuln_type="lfi",
                        validator=hypothesis.validator,
                        url=test_url,
                        parameter=hypothesis.candidate.parameter,
                        confirmed=True,
                        confidence="high",
                        severity="high",
                        title="Local File Inclusion / Path Traversal Proof",
                        evidence="The response contained `/etc/passwd` content marker `root:x:0:0:`.",
                        request_proof=f"GET {test_url}",
                        response_proof=self._excerpt(body, "root:x:0:0:"),
                        remediation="Canonicalize paths, enforce a strict file allowlist, and block traversal sequences before file access.",
                        cwe_ids=["CWE-22"],
                        tags=["dast-proof", "lfi", "path-traversal", "safe-validation"],
                    )
        return None

    async def _validate_sourcemap_exposure(self, hypothesis: DASTHypothesis) -> ValidationProof | None:
        js_url = hypothesis.candidate.url
        candidates: list[str] = []
        async with self._client(follow_redirects=True) as client:
            try:
                js_resp = await client.get(js_url)
            except Exception:
                return None
            body = js_resp.text or ""
            for match in re.finditer(r"sourceMappingURL=([^\s*]+)", body, re.I):
                value = match.group(1).strip().strip("'\"")
                if value and not value.startswith("data:"):
                    candidates.append(urljoin(js_url, value))
            if js_url.endswith(".js"):
                candidates.append(f"{js_url}.map")

            seen: set[str] = set()
            for map_url in candidates:
                if map_url in seen or not self._in_scope(map_url):
                    continue
                seen.add(map_url)
                try:
                    resp = await client.get(map_url)
                except Exception:
                    continue
                if resp.status_code != 200:
                    continue
                try:
                    payload = resp.json()
                except json.JSONDecodeError:
                    continue
                sources = payload.get("sources")
                if not isinstance(sources, list) or not sources:
                    continue
                if "mappings" not in payload and "sourcesContent" not in payload:
                    continue
                sample_sources = [str(item) for item in sources[:5]]
                return ValidationProof(
                    hypothesis_id=hypothesis.id,
                    vuln_type="source_map_exposure",
                    validator=hypothesis.validator,
                    url=map_url,
                    parameter=hypothesis.candidate.parameter,
                    confirmed=True,
                    confidence="high",
                    severity="medium",
                    title="Exposed JavaScript Source Map",
                    evidence=(
                        f"Source map is publicly reachable and references {len(sources)} source file(s): "
                        + ", ".join(sample_sources)
                    ),
                    request_proof=f"GET {map_url}",
                    response_proof=json.dumps({
                        "version": payload.get("version"),
                        "file": payload.get("file"),
                        "sources_sample": sample_sources,
                        "has_sources_content": bool(payload.get("sourcesContent")),
                    }, ensure_ascii=True),
                    remediation="Do not publish production source maps unless intentionally required. Restrict access or omit sourcesContent from public builds.",
                    cwe_ids=["CWE-540"],
                    tags=["dast-proof", "source-map", "javascript", "safe-validation"],
                )
        return None

    async def _validate_jwt_alg_none(self, hypothesis: DASTHypothesis) -> ValidationProof | None:
        url = hypothesis.candidate.url
        async with self._client(follow_redirects=True) as client:
            try:
                resp = await client.get(url)
            except Exception:
                return None
        haystacks = [resp.text or ""]
        haystacks.extend(str(value) for value in resp.headers.values())
        for text in haystacks:
            for token in re.findall(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b", text):
                header = self._decode_jwt_header(token)
                if not header:
                    continue
                alg = str(header.get("alg") or "").lower()
                if alg != "none":
                    continue
                redacted = f"{token[:18]}...{token[-8:]}" if len(token) > 32 else token
                return ValidationProof(
                    hypothesis_id=hypothesis.id,
                    vuln_type="jwt",
                    validator=hypothesis.validator,
                    url=url,
                    parameter=hypothesis.candidate.parameter,
                    confirmed=True,
                    confidence="high",
                    severity="high",
                    title="JWT Uses alg=none",
                    evidence=f"A JWT returned by the application declares alg=none. Token sample: {redacted}",
                    request_proof=f"GET {url}",
                    response_proof=json.dumps({"jwt_header": header, "token_sample": redacted}, ensure_ascii=True),
                    remediation="Reject unsigned JWTs, enforce an explicit signing algorithm allowlist, and verify signatures server-side on every request.",
                    cwe_ids=["CWE-347"],
                    tags=["dast-proof", "jwt", "alg-none", "safe-validation"],
                )
        return None

    def _client(self, *, follow_redirects: bool, timeout: float | None = None) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            verify=False,
            timeout=timeout or self.timeout,
            follow_redirects=follow_redirects,
            headers={"User-Agent": "Mozilla/5.0 VAPT-ProofEngine"},
        )

    def _in_scope(self, url: str) -> bool:
        if self.scope is None:
            return True
        try:
            return bool(self.scope.is_in_scope(url))
        except Exception:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)

    @staticmethod
    def _excerpt(text: str, marker: str, radius: int = 450) -> str:
        if not text:
            return ""
        lower = text.lower()
        marker_l = marker.lower()
        idx = lower.find(marker_l)
        if idx < 0:
            return text[: radius * 2]
        start = max(0, idx - radius)
        end = min(len(text), idx + len(marker) + radius)
        return text[start:end]

    @staticmethod
    def _response_similarity(left: str, right: str, limit: int = 200_000) -> float:
        """Compare bounded, whitespace-normalized bodies for negative controls."""
        left_normalized = " ".join((left or "")[:limit].split())
        right_normalized = " ".join((right or "")[:limit].split())
        if not left_normalized and not right_normalized:
            return 1.0
        if not left_normalized or not right_normalized:
            return 0.0
        return round(difflib.SequenceMatcher(None, left_normalized, right_normalized).ratio(), 4)

    @staticmethod
    def _decode_jwt_header(token: str) -> dict[str, Any] | None:
        try:
            raw_header = token.split(".", 1)[0]
            padded = raw_header + "=" * (-len(raw_header) % 4)
            decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
            payload = json.loads(decoded.decode("utf-8", errors="strict"))
            return payload if isinstance(payload, dict) else None
        except Exception:
            return None
