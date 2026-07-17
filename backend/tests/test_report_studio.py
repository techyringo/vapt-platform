import json

import pytest

from core.config import AppConfig
from database.store import PersistenceStore
from services.report_studio import (
    _markdown,
    _parse_labelled_text,
    _redact_model_bound_text,
    run_report_studio_job,
)


def test_labelled_text_import_preserves_observed_status_and_source():
    findings = _parse_labelled_text(
        """
Title: SQL injection candidate
Severity: High
Target: https://example.test/items?id=1
Evidence: A quote changed the response body.
Status: suspected

Title: Missing HSTS
Severity: Low
Target: https://example.test
Status: confirmed
Evidence: Strict-Transport-Security header absent in captured response.
""",
        "manual-notes.txt",
    )

    assert len(findings) == 2
    assert findings[0]["status"] == "observed"
    assert findings[1]["status"] == "confirmed"
    assert all(item["source_file"] == "manual-notes.txt" for item in findings)


def test_model_bound_evidence_redacts_common_credentials():
    source = (
        "Authorization: Bearer live-token\n"
        "Cookie: session=live-session\n"
        "api_key=super-secret\n"
        "AWS AKIA1234567890ABCDEF"
    )
    redacted = _redact_model_bound_text(source)

    assert "live-token" not in redacted
    assert "live-session" not in redacted
    assert "super-secret" not in redacted
    assert "AKIA1234567890ABCDEF" not in redacted


def test_executive_template_omits_technical_finding_evidence():
    payload = {
        "report_metadata": {
            "name": "Board brief", "client_name": "Example", "assessment_type": "VAPT",
            "template_id": "executive_brief", "generated_at": "2026-07-17T00:00:00Z",
        },
        "engagement_metadata": {}, "scope": ["example.test"],
        "summary": {
            "severities": {"critical": 0, "high": 1, "medium": 0, "low": 0, "informational": 0},
            "confirmed": 0, "observed": 1, "source_count": 1, "limitations": ["Evidence only"],
        },
        "narrative": {
            "executive_summary": "One material observation.", "risk_statement": "Review required.",
            "key_recommendations": ["Validate and remediate."], "methodology_note": "Imported evidence.",
        },
        "findings": [{
            "severity": "high", "title": "Sensitive technical finding", "target": "example.test",
            "status": "observed", "source_file": "raw.txt", "description": "technical-only-detail",
            "evidence": "secret-proof", "business_impact": "", "remediation": "Validate and remediate.",
        }],
    }

    report = _markdown(payload)
    assert "Executive Summary" in report
    assert "Prioritised Remediation" in report
    assert "Technical Findings" not in report
    assert "secret-proof" not in report


@pytest.mark.asyncio
async def test_report_studio_generates_auditable_artifacts_without_scan(tmp_path, monkeypatch):
    monkeypatch.setenv("VAPT_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("VAPT_LLM_ENABLED", "false")
    config = AppConfig()
    config.database.url = f"sqlite:///{tmp_path / 'data' / 'vapt.db'}"
    config.llm.enabled = False
    store = PersistenceStore(config.database.url)
    report_id = "report_test"
    store.create_report_studio_job(report_id, {
        "name": "Imported evidence audit",
        "client_name": "Example Client",
        "assessment_type": "Web VAPT",
        "template_id": "vapt_standard",
        "scope": ["example.test"],
    })
    source_payload = {
        "findings": [
            {
                "title": "Exposed administration endpoint",
                "severity": "high",
                "target": "https://example.test/admin",
                "status": "observed",
                "evidence": "HTTP 200 response captured by analyst.",
            },
            {
                "title": "Verified obsolete TLS protocol",
                "severity": "medium",
                "target": "example.test:443",
                "status": "verified",
                "evidence": "TLS 1.0 handshake succeeded.",
                "remediation": "Disable TLS 1.0 and TLS 1.1.",
            },
        ]
    }
    manifest = store.save_report_studio_source(
        report_id,
        filename="findings.json",
        media_type="application/json",
        content=json.dumps(source_payload),
    )
    store.update_report_studio_job(report_id, {"source_manifest": [manifest]})

    result = await run_report_studio_job(report_id, config)
    saved = store.load_report_studio_job(report_id)

    assert result == {"report_id": report_id, "status": "completed", "findings": 2}
    assert saved is not None
    assert saved["summary"]["confirmed"] == 1
    assert saved["summary"]["observed"] == 1
    assert saved["narrative"]["llm_used"] is False
    assert "no active scanning" in " ".join(saved["summary"]["limitations"]).lower()
    artifact_kinds = {item["kind"] for item in saved["artifacts"]}
    assert {"json", "markdown", "html"}.issubset(artifact_kinds)

    json_artifact = store.load_report_studio_artifact(report_id, "json")
    payload = json.loads(open(json_artifact["path"], encoding="utf-8").read())
    assert payload["report_metadata"]["claim"] == "report_generated_from_supplied_evidence; no_scan_performed"
    assert payload["source_manifest"][0]["sha256"] == manifest["sha256"]
    assert {item["status"] for item in payload["findings"]} == {"confirmed", "observed"}

    history = store.load_report_studio_jobs()
    assert "findings" not in history[0]
    assert {artifact["kind"] for artifact in history[0]["artifacts"]} >= {"json", "markdown", "html"}
