from database.store import PersistenceStore


def _finding():
    return {
        "title": "Replayable SQL injection",
        "description": "Differential response was reproduced.",
        "severity": "high",
        "target_host": "example.test",
        "target_port": 443,
        "target_url": "https://example.test/search?q=1",
        "status": "confirmed",
        "confidence": "high",
        "agent_source": "vuln_scanner",
    }


def test_analyst_disposition_is_audited_and_survives_scanner_upsert(tmp_path):
    store = PersistenceStore(f"sqlite:///{tmp_path / 'triage.db'}")
    store.upsert_scan("scan", {"name": "scan", "targets": ["example.test"]})
    store.upsert_finding("scan", _finding())
    finding = store.load_findings("scan")[0]

    updated = store.triage_finding(
        "scan", finding["finding_id"], "false_positive", "alice", "WAF replay artifact",
    )
    assert updated["status"] == "false_positive"
    assert updated["triage_status"] == "false_positive"
    assert updated["quarantined"] is True

    # Scanner replays may enrich evidence, but cannot overwrite an analyst
    # disposition or silently re-add the finding to a report.
    store.upsert_finding("scan", {**_finding(), "evidence": "new scanner evidence"})
    reloaded = store.load_findings("scan")[0]
    assert reloaded["status"] == "false_positive"
    assert reloaded["triage_status"] == "false_positive"
    assert store.load_finding_triage("scan", finding["finding_id"])[0]["actor"] == "alice"

