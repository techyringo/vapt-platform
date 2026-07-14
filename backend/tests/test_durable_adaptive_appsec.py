from database.store import PersistenceStore
from core.control_evidence import build_control_evidence
from services.appsec_assessment import assessment_diff, assessment_to_sarif
from web.auth import _is_public


def test_durable_action_survives_result_channel_loss(tmp_path):
    store = PersistenceStore(f"sqlite:///{tmp_path / 'durable.db'}")
    store.create_durable_action({
        "action_id": "action_test",
        "scan_id": "scan_test",
        "phase": "recon",
        "capability": "Live HTTP probing",
        "tool": "httpx",
        "idempotency_key": "action_test",
        "input_hash": "sha256",
    })
    store.update_durable_action("action_test", {
        "status": "completed",
        "result": {"tool": "httpx", "success": True, "exit_code": 0, "stdout": "evidence"},
        "checkpoint": {"evidence_captured": True},
    })

    recovered = store.load_durable_action("action_test")

    assert recovered is not None
    assert recovered["status"] == "completed"
    assert recovered["result"]["stdout"] == "evidence"
    assert recovered["checkpoint"]["evidence_captured"] is True


def test_event_sequence_supports_reconnect_replay(tmp_path):
    store = PersistenceStore(f"sqlite:///{tmp_path / 'events.db'}")
    first = store.append_event({"scan_id": "scan_test", "event": "phase_change", "phase": "recon"})
    second = store.append_event({"scan_id": "scan_test", "event": "phase_complete", "phase": "recon"})

    replay = store.load_events_after(first)

    assert second > first
    assert [item["sequence"] for item in replay] == [second]
    assert replay[0]["event"] == "phase_complete"


def test_oob_token_records_only_registered_unexpired_interaction(tmp_path):
    store = PersistenceStore(f"sqlite:///{tmp_path / 'oob.db'}")
    store.register_oob_token("a" * 32, {
        "scan_id": "scan_test",
        "hypothesis_id": "hyp_0001",
        "expires_at": "2999-01-01T00:00:00+00:00",
    })

    assert store.record_oob_interaction("a" * 32, {"method": "GET"}) is True
    assert store.record_oob_interaction("b" * 32, {"method": "GET"}) is False
    record = store.load_oob_token("a" * 32)
    assert record is not None
    assert record["interaction"]["method"] == "GET"


def test_appsec_diff_and_sarif_preserve_stable_identity():
    old = [{"fingerprint": "same"}, {"fingerprint": "fixed"}]
    current = [{
        "fingerprint": "same",
        "rule_id": "python.sql-injection",
        "title": "SQL constructed from input",
        "description": "Untrusted input reaches a SQL construction sink.",
        "severity": "high",
        "confidence": "high",
        "status": "candidate",
        "source": "semgrep",
        "category": "sast",
        "path": "app/db.py",
        "start_line": 42,
        "cwe_ids": ["CWE-89"],
        "cve_ids": [],
        "remediation": "Use parameterized queries.",
    }, {"fingerprint": "new"}]

    diff = assessment_diff(current, old)
    sarif = assessment_to_sarif({
        "assessment_id": "appsec_test",
        "repository": "https://github.com/example/repo",
        "ref": "main",
        "commit_sha": "abc123",
        "findings": current[:1],
    })

    assert diff["new"] == 1
    assert diff["unchanged"] == 1
    assert diff["resolved"] == 1
    result = sarif["runs"][0]["results"][0]
    assert sarif["version"] == "2.1.0"
    assert result["partialFingerprints"]["vaptFingerprint"] == "same"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 42


def test_control_evidence_never_claims_compliance_without_artifacts():
    projection = build_control_evidence(
        scan={"scan_id": "scan_test", "status": "running", "targets": ["example.test"]},
        coverage={"checks": []},
        findings=[],
        assets=[],
        actions=[],
    )

    assert projection["claim"] == "coverage_evidence_only"
    assert projection["summary"]["evidenced"] == 0
    assert all(control["status"] == "not_evidenced" for control in projection["controls"])
    assert "not a certification" in projection["disclaimer"]


def test_control_evidence_links_real_proof_and_runner_artifacts():
    projection = build_control_evidence(
        scan={
            "scan_id": "scan_test",
            "status": "completed",
            "targets": ["example.test"],
            "rules_of_engagement": {"authorization_confirmed": True},
            "report_base_name": "scan-test",
        },
        coverage={"checks": [{"id": "report_evidence_pack", "status": "completed"}]},
        findings=[{
            "title": "Reflected XSS",
            "status": "confirmed",
            "request_proof": "GET /?q=probe",
            "response_proof": "marker reflected in text/html",
        }],
        assets=[
            {"asset_type": "url"},
            {"asset_type": "technology"},
            {"asset_type": "parameter"},
        ],
        actions=[{"action_id": "action_1", "status": "completed"}],
    )

    statuses = {item["control_id"]: item["status"] for item in projection["controls"]}
    assert projection["summary"]["evidenced"] == projection["summary"]["total"]
    assert statuses["VAPT-VALIDATE-001"] == "evidenced"
    assert statuses["VAPT-RECOVERY-001"] == "evidenced"


def test_oob_receiver_is_public_but_status_remains_authenticated():
    assert _is_public("/api/oob/c/" + ("a" * 32)) is True
    assert _is_public("/api/oob/status/" + ("a" * 32)) is False
