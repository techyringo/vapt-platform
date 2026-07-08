"""Concrete safe web-validation modules.

Every probe is non-destructive: it re-observes a signal (missing headers,
origin reflection, unencoded reflection, off-site redirect) and never sends a
payload that alters state or executes. Impact is proven via request/response
proof captured for the evidence chain.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

from loguru import logger

from core.models import Finding, Severity, Target
from agents.modules.base import SafeModule, make_finding, register

# A unique, benign canary — angle brackets prove the sink does not encode output
# but the string is not a working script, so nothing executes.
XSS_CANARY = "vapt7canary<x>"
REDIRECT_MARKER = "vapt-redirect.example.com"
COMMON_REDIRECT_PARAMS = ["next", "url", "redirect", "return", "returnUrl", "dest", "destination"]

SECURITY_HEADERS = {
    "content-security-policy": ("Content-Security-Policy", Severity.LOW, "CWE-693"),
    "strict-transport-security": ("Strict-Transport-Security", Severity.LOW, "CWE-319"),
    "x-frame-options": ("X-Frame-Options", Severity.LOW, "CWE-1021"),
    "x-content-type-options": ("X-Content-Type-Options", Severity.INFORMATIONAL, "CWE-693"),
}


def _fmt_request(method: str, url: str, headers: dict[str, str]) -> str:
    lines = [f"{method} {url}"]
    lines.extend(f"{k}: {v}" for k, v in headers.items())
    return "\n".join(lines)


def _fmt_response(status: int, headers: Any, body: str = "") -> str:
    head = "\n".join(f"{k}: {v}" for k, v in dict(headers).items())
    out = f"HTTP {status}\n{head}"
    if body:
        out += f"\n\n{body[:400]}"
    return out


@register
class SecurityHeadersModule(SafeModule):
    name = "security_headers"
    category = "hardening"

    async def run(self, target: Target, scope_config: Any, client: Any) -> list[Finding]:
        url = target.base_url
        resp = await client.get(url)
        present = {k.lower() for k in resp.headers.keys()}
        missing = [meta for key, meta in SECURITY_HEADERS.items() if key not in present]
        if not missing:
            return []
        names = ", ".join(m[0] for m in missing)
        worst = min((m[1] for m in missing), key=lambda s: list(Severity).index(s))
        return [make_finding(
            title=f"Missing security headers: {names}",
            description=(
                "The response is missing recommended security headers. These "
                "reduce defence-in-depth against clickjacking, MIME sniffing, "
                "and transport downgrade attacks."
            ),
            severity=worst,
            target=target,
            evidence=f"Missing: {names}",
            request_proof=_fmt_request("GET", url, {}),
            response_proof=_fmt_response(resp.status_code, resp.headers),
            remediation="Add the missing headers at the web server / framework layer.",
            cwe_ids=[m[2] for m in missing],
            tags=["security-headers"],
            confidence="high",
            status="confirmed",
        )]


@register
class CorsModule(SafeModule):
    name = "cors"
    category = "access-control"

    async def run(self, target: Target, scope_config: Any, client: Any) -> list[Finding]:
        url = target.base_url
        probe_origin = "https://vapt-cors-probe.example.com"
        resp = await client.get(url, headers={"Origin": probe_origin})
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()
        reflected = acao == probe_origin or acao == "*"
        if not reflected:
            return []
        credentialed = acac == "true" and acao == probe_origin
        severity = Severity.HIGH if credentialed else Severity.MEDIUM
        return [make_finding(
            title="Permissive CORS policy reflects arbitrary origin",
            description=(
                "The server reflects an attacker-supplied Origin in "
                "Access-Control-Allow-Origin"
                + (" together with Allow-Credentials: true, enabling cross-origin "
                   "reads of authenticated responses." if credentialed else ".")
            ),
            severity=severity,
            target=target,
            evidence=f"Origin: {probe_origin} → Access-Control-Allow-Origin: {acao}"
                     + (f"; Allow-Credentials: {acac}" if acac else ""),
            request_proof=_fmt_request("GET", url, {"Origin": probe_origin}),
            response_proof=_fmt_response(resp.status_code, resp.headers),
            remediation="Validate the Origin against an allowlist; never reflect it "
                        "with credentials enabled.",
            cwe_ids=["CWE-942"],
            tags=["cors"],
            confidence="high",
            status="confirmed",
        )]


@register
class OpenRedirectModule(SafeModule):
    name = "open_redirect"
    category = "redirection"

    async def run(self, target: Target, scope_config: Any, client: Any) -> list[Finding]:
        base = target.base_url
        findings: list[Finding] = []
        for param in COMMON_REDIRECT_PARAMS:
            test_url = f"{base}?{urlencode({param: 'https://' + REDIRECT_MARKER})}"
            try:
                resp = await client.get(test_url)  # follow_redirects=False on client
            except Exception:
                continue
            location = resp.headers.get("location", "")
            if 300 <= resp.status_code < 400 and REDIRECT_MARKER in location:
                findings.append(make_finding(
                    title=f"Open redirect via '{param}' parameter",
                    description=(
                        "A user-controlled parameter is used as the redirect "
                        "destination without validation, allowing redirection to "
                        "an arbitrary external site (phishing / token theft vector)."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=f"{param}=https://{REDIRECT_MARKER} → Location: {location}",
                    request_proof=_fmt_request("GET", test_url, {}),
                    response_proof=_fmt_response(resp.status_code, resp.headers),
                    remediation="Validate redirect targets against an allowlist of "
                                "internal paths; reject absolute external URLs.",
                    cwe_ids=["CWE-601"],
                    tags=["open-redirect"],
                    confidence="high",
                    status="confirmed",
                ))
                break  # one is enough to prove the class
        return findings


@register
class ReflectedInputModule(SafeModule):
    name = "reflected_xss"
    category = "injection"

    async def run(self, target: Target, scope_config: Any, client: Any) -> list[Finding]:
        # Inject a benign canary into existing query params (or a probe param)
        # and check whether angle brackets are reflected UNENCODED. The canary
        # is not a working script, so nothing executes — we only prove the sink
        # fails to encode, which is the XSS precondition.
        parsed = urlparse(target.base_url)
        query = dict(parse_qsl(parsed.query))
        params_to_test = list(query.keys()) or ["q"]
        for param in params_to_test[:5]:
            test_query = dict(query)
            test_query[param] = XSS_CANARY
            test_url = urlunparse(parsed._replace(query=urlencode(test_query)))
            try:
                resp = await client.get(test_url)
            except Exception:
                continue
            body = resp.text or ""
            if XSS_CANARY in body:  # reflected with angle brackets intact/unencoded
                snippet_at = body.find(XSS_CANARY)
                snippet = body[max(0, snippet_at - 60):snippet_at + 80]
                return [make_finding(
                    title=f"Unencoded reflection of '{param}' (reflected XSS precondition)",
                    description=(
                        "User input is reflected into the response without output "
                        "encoding — the angle-bracket canary survived intact. This "
                        "is the precondition for reflected XSS. A benign canary was "
                        "used; no script was executed."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=f"Reflected canary '{XSS_CANARY}' unencoded near: …{snippet}…",
                    request_proof=_fmt_request("GET", test_url, {}),
                    response_proof=_fmt_response(resp.status_code, resp.headers, snippet),
                    remediation="Context-aware output encoding for all reflected input; "
                                "add a Content-Security-Policy as defence-in-depth.",
                    cwe_ids=["CWE-79"],
                    tags=["reflected-xss"],
                    confidence="medium",
                    status="suspected",
                )]
        return []
