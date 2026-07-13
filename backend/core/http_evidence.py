"""HTTP response evidence helpers for soft-404 and SPA fallback rejection.

Discovery tools produce *candidates*.  A 2xx status alone is not proof that a
candidate exists: single-page applications commonly return the same HTML shell
for every path.  These helpers compare a candidate with a randomized missing
path and require content appropriate for the claimed resource type.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urljoin
from uuid import uuid4


@dataclass(frozen=True)
class ResponseFingerprint:
    status: int
    content_type: str
    length: int
    digest: str
    text_sample: str


@dataclass(frozen=True)
class ValidationOutcome:
    confirmed: bool
    category: str
    reason: str
    evidence: str = ""


def fingerprint_response(response: Any) -> ResponseFingerprint:
    body = bytes(response.content or b"")
    content_type = str(response.headers.get("content-type", "")).split(";", 1)[0].lower()
    text = ""
    if not body or "text" in content_type or any(
        marker in content_type for marker in ("json", "xml", "javascript", "html")
    ):
        text = (response.text or "")[:80_000]
    normalized = re.sub(r"\b[0-9a-f]{12,}\b", "<token>", text, flags=re.IGNORECASE)
    normalized = re.sub(r"\b\d{2,}\b", "<number>", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return ResponseFingerprint(
        status=int(response.status_code),
        content_type=content_type,
        length=len(body),
        digest=hashlib.sha256(body).hexdigest(),
        text_sample=normalized,
    )


async def fetch_missing_baseline(client: Any, base_url: str) -> ResponseFingerprint | None:
    marker = f".vapt-missing-{uuid4().hex}"
    url = urljoin(base_url.rstrip("/") + "/", marker)
    try:
        return fingerprint_response(await client.get(url))
    except Exception:
        return None


def equivalent_to_baseline(candidate: ResponseFingerprint, baseline: ResponseFingerprint | None) -> bool:
    if baseline is None or candidate.status != baseline.status:
        return False
    if candidate.digest == baseline.digest:
        return True
    if candidate.content_type != baseline.content_type:
        return False
    length_delta = abs(candidate.length - baseline.length)
    if length_delta > max(96, int(max(candidate.length, baseline.length) * 0.05)):
        return False
    if candidate.text_sample and baseline.text_sample:
        similarity = SequenceMatcher(
            None, candidate.text_sample[:40_000], baseline.text_sample[:40_000], autojunk=False
        ).ratio()
        return similarity >= 0.96
    return False


def _proof(fp: ResponseFingerprint) -> str:
    return (
        f"HTTP {fp.status}; content-type={fp.content_type or 'unknown'}; "
        f"bytes={fp.length}; sha256={fp.digest[:16]}"
    )


def validate_sensitive_response(
    path: str,
    response: Any,
    baseline: ResponseFingerprint | None,
) -> ValidationOutcome:
    """Require both a distinct response and resource-specific body evidence."""
    fp = fingerprint_response(response)
    lower_path = path.lower().split("?", 1)[0].rstrip("/")
    body = bytes(response.content or b"")
    text = (response.text or "")[:100_000]
    lower = text.lower()

    if fp.status not in {200, 206} or fp.length == 0:
        return ValidationOutcome(False, "rejected", "non-success or empty response", _proof(fp))
    if equivalent_to_baseline(fp, baseline):
        return ValidationOutcome(False, "soft_404", "response matches randomized missing-path baseline", _proof(fp))

    public_discovery = (
        "robots.txt", "sitemap.xml", "crossdomain.xml", ".well-known/security.txt",
    )
    if lower_path.endswith(public_discovery):
        return ValidationOutcome(True, "public_metadata", "distinct public metadata resource", _proof(fp))

    endpoint_markers = ("admin", "administrator", "phpmyadmin", "wp-admin")
    if any(token in lower_path for token in endpoint_markers):
        return ValidationOutcome(True, "admin_endpoint", "distinct administration endpoint", _proof(fp))

    if lower_path.endswith(("swagger.json", "openapi.json", "api-schema.json")):
        try:
            payload = json.loads(text)
        except Exception:
            payload = {}
        if isinstance(payload, dict) and any(key in payload for key in ("swagger", "openapi", "paths")):
            return ValidationOutcome(True, "api_schema", "valid API schema body", _proof(fp))
        return ValidationOutcome(False, "rejected", "body is not an API schema", _proof(fp))

    if lower_path.endswith(".git/head") and re.search(r"(?m)^ref:\s+refs/", text):
        return ValidationOutcome(True, "source_control", "Git HEAD reference present", _proof(fp))
    if lower_path.endswith(".git/config") and "[core]" in lower and "repositoryformatversion" in lower:
        return ValidationOutcome(True, "source_control", "Git repository configuration present", _proof(fp))
    if lower_path.endswith(".svn/entries") and (re.search(r"(?m)^\d+$", text) or "svn" in lower):
        return ValidationOutcome(True, "source_control", "SVN metadata present", _proof(fp))
    if ".env" in lower_path:
        assignments = re.findall(r"(?m)^[A-Za-z_][A-Za-z0-9_]{1,80}\s*=.+$", text)
        if assignments and "text/html" not in fp.content_type:
            return ValidationOutcome(True, "environment", "environment assignments present", _proof(fp))
        return ValidationOutcome(False, "rejected", "no environment-file body signature", _proof(fp))
    if lower_path.endswith(("id_rsa", ".pem", ".key")):
        if re.search(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", body):
            return ValidationOutcome(True, "private_key", "private-key PEM marker present", _proof(fp))
        return ValidationOutcome(False, "rejected", "no private-key body signature", _proof(fp))
    if lower_path.endswith((".sql", ".sql.bak")):
        if re.search(r"(?i)(create\s+table|insert\s+into|sql\s+dump|--\s+(mysql|postgresql))", text):
            return ValidationOutcome(True, "database_backup", "SQL dump statements present", _proof(fp))
        return ValidationOutcome(False, "rejected", "no SQL dump body signature", _proof(fp))
    if lower_path.endswith((".zip", ".jar")):
        return ValidationOutcome(body.startswith(b"PK\x03\x04"), "archive", "ZIP magic present" if body.startswith(b"PK\x03\x04") else "no ZIP magic", _proof(fp))
    if lower_path.endswith((".gz", ".tgz")):
        return ValidationOutcome(body.startswith(b"\x1f\x8b"), "archive", "gzip magic present" if body.startswith(b"\x1f\x8b") else "no gzip magic", _proof(fp))
    if lower_path.endswith(("package.json", "composer.json", "credentials.json", "service-account.json")):
        try:
            payload = json.loads(text)
        except Exception:
            payload = None
        if isinstance(payload, dict):
            expected = {
                "package.json": {"name", "dependencies", "scripts"},
                "composer.json": {"require", "autoload", "name"},
                "credentials.json": {"client_id", "client_secret", "type"},
                "service-account.json": {"private_key", "client_email", "type"},
            }
            name = lower_path.rsplit("/", 1)[-1]
            if set(payload).intersection(expected.get(name, set())):
                return ValidationOutcome(True, "json_config", "expected JSON keys present", _proof(fp))
        return ValidationOutcome(False, "rejected", "no expected JSON configuration keys", _proof(fp))

    if "text/html" in fp.content_type:
        return ValidationOutcome(False, "rejected", "generic HTML is not proof of a sensitive file", _proof(fp))
    secret_markers = re.search(
        r"(?i)(password\s*[:=]|secret(?:_key)?\s*[:=]|api[_-]?key\s*[:=]|database_url\s*=)", text
    )
    if secret_markers or fp.length >= 32:
        return ValidationOutcome(True, "candidate_file", "distinct non-HTML file body", _proof(fp))
    return ValidationOutcome(False, "rejected", "insufficient resource-specific body evidence", _proof(fp))


def validate_api_response(response: Any, baseline: ResponseFingerprint | None) -> ValidationOutcome:
    fp = fingerprint_response(response)
    if fp.status >= 400 or fp.length == 0:
        return ValidationOutcome(False, "rejected", "API candidate did not return a successful body", _proof(fp))
    if equivalent_to_baseline(fp, baseline):
        return ValidationOutcome(False, "soft_404", "API candidate matches missing-path baseline", _proof(fp))
    text = (response.text or "").lstrip()
    is_json = "json" in fp.content_type or text.startswith(("{", "["))
    if not is_json:
        return ValidationOutcome(False, "rejected", "API candidate did not return structured JSON", _proof(fp))
    try:
        json.loads(text)
    except Exception:
        return ValidationOutcome(False, "rejected", "API candidate returned invalid JSON", _proof(fp))
    return ValidationOutcome(True, "api", "distinct structured API response", _proof(fp))
