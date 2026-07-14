from core.appsec import merge_secret_findings, parse_gitleaks, parse_semgrep, parse_trivy, parse_trufflehog
from services.appsec_assessment import repository_inventory, semgrep_coverage, semgrep_rulepacks, validate_ref, validate_repository_url
from database.store import PersistenceStore


REPO = "https://github.com/acme/example"


def test_semgrep_parser_preserves_location_and_weakness() -> None:
    payload = {
        "results": [{
            "check_id": "python.lang.security.audit.eval-detected",
            "path": "app.py",
            "start": {"line": 12},
            "end": {"line": 12},
            "extra": {
                "message": "Use of eval detected",
                "severity": "ERROR",
                "lines": "eval(user_input)",
                "metadata": {"cwe": ["CWE-95"], "confidence": "HIGH"},
            },
        }],
    }
    finding = parse_semgrep(payload, REPO)[0]
    assert finding["category"] == "sast"
    assert finding["severity"] == "high"
    assert finding["path"] == "app.py"
    assert finding["start_line"] == 12
    assert finding["cwe_ids"] == ["CWE-95"]


def test_semgrep_parser_preserves_sanitized_dataflow_locations() -> None:
    payload = {"results": [{
        "check_id": "python.sql-injection",
        "path": "app.py",
        "start": {"line": 20},
        "extra": {
            "message": "SQL injection data flow",
            "severity": "ERROR",
            "dataflow_trace": {
                "taint_source": ["request.args", {"path": "app.py", "start": {"line": 5}}],
                "taint_sink": ["cursor.execute", {"path": "db.py", "start": {"line": 42}}],
            },
        },
    }]}
    finding = parse_semgrep(payload, REPO)[0]
    assert "app.py:5" in finding["evidence"]
    assert "db.py:42" in finding["evidence"]
    assert "request.args" not in finding["evidence"]


def test_trivy_parser_emits_real_cve_and_fix() -> None:
    payload = {"Results": [{
        "Target": "package-lock.json",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2025-12345",
            "PkgName": "example-lib",
            "InstalledVersion": "1.0.0",
            "FixedVersion": "1.0.1",
            "Severity": "CRITICAL",
            "Title": "Example vulnerability",
        }],
    }]}
    finding = parse_trivy(payload, REPO)[0]
    assert finding["category"] == "sca"
    assert finding["cve_ids"] == ["CVE-2025-12345"]
    assert finding["fixed_version"] == "1.0.1"
    assert finding["severity"] == "critical"


def test_gitleaks_parser_never_persists_secret_value() -> None:
    secret = "super-secret-api-key"
    finding = parse_gitleaks([{
        "RuleID": "generic-api-key",
        "Description": "Generic API key",
        "File": "settings.py",
        "StartLine": 3,
        "Secret": secret,
        "Match": f"API_KEY={secret}",
    }], REPO)[0]
    assert secret not in str(finding)
    assert "redacted" in finding["evidence"].lower()


def test_trufflehog_parser_redacts_and_marks_verified_secret() -> None:
    output = '{"DetectorName":"AWS","Verified":true,"Raw":"DO-NOT-STORE","Redacted":"ALSO-NO","SourceMetadata":{"Data":{"Filesystem":{"file":"config.env","line":7}}}}'
    finding = parse_trufflehog(output, REPO)[0]

    assert finding["status"] == "verified"
    assert finding["severity"] == "critical"
    assert finding["path"] == "config.env"
    assert "DO-NOT-STORE" not in str(finding)
    assert "ALSO-NO" not in str(finding)


def test_verified_secret_replaces_same_location_pattern_candidate() -> None:
    gitleaks = parse_gitleaks([{"RuleID": "generic", "File": "config.env", "StartLine": 7}], REPO)[0]
    trufflehog = parse_trufflehog('{"DetectorName":"AWS","Verified":true,"SourceMetadata":{"Data":{"Filesystem":{"file":"config.env","line":7}}}}', REPO)[0]

    merged = merge_secret_findings([gitleaks, trufflehog])
    assert len(merged) == 1
    assert merged[0]["source"] == "trufflehog"


def test_repository_validation_rejects_credentials_and_unapproved_hosts() -> None:
    assert validate_repository_url(REPO) == REPO
    for value in (
        "http://github.com/acme/example",
        "https://user:token@github.com/acme/example",
        "https://example.com/acme/example",
        "https://github.com/acme/example/extra",
    ):
        try:
            validate_repository_url(value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Expected repository URL to be rejected: {value}")


def test_ref_validation_rejects_revision_traversal() -> None:
    assert validate_ref("release/1.0") == "release/1.0"
    for value in ("../main", "main..evil", "feature//branch", " main "):
        if value == " main ":
            assert validate_ref(value) == "main"
            continue
        try:
            validate_ref(value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Expected ref to be rejected: {value}")


def test_repository_inventory_reports_languages_and_manifests(tmp_path) -> None:
    (tmp_path / "api.py").write_text("print('ok')")
    (tmp_path / "ui.tsx").write_text("export default 1")
    (tmp_path / "package-lock.json").write_text("{}")
    inventory = repository_inventory(tmp_path)
    assert inventory["languages"] == {"Python": 1, "TypeScript": 1}
    assert inventory["manifests"] == ["package-lock.json"]
    assert inventory["files"] == 3


def test_semgrep_rulepacks_are_configurable_and_deduplicated(monkeypatch) -> None:
    monkeypatch.setenv("VAPT_SEMGREP_RULESETS", "p/default,p/security-audit,p/default")
    assert semgrep_rulepacks() == ["p/default", "p/security-audit"]


def test_semgrep_coverage_rejects_false_success_with_zero_scanned_files() -> None:
    evidence = semgrep_coverage(
        {"paths": {"scanned": [], "skipped": []}, "errors": []},
        {"languages": {"Python": 4}, "files": 5, "manifests": []},
        0.8,
    )
    assert evidence["status"] == "partial"
    assert evidence["source_files"] == 4
    assert evidence["scanned_files"] == 0
    assert "zero analyzed" in str(evidence["limitation"])


def test_semgrep_coverage_records_scanned_skipped_and_errors() -> None:
    evidence = semgrep_coverage(
        {"paths": {"scanned": ["a.py", "b.py"], "skipped": [{"path": "vendor.js"}]}, "errors": [{"message": "parse"}]},
        {"languages": {"Python": 2}, "files": 3, "manifests": []},
        2.25,
    )
    assert evidence["status"] == "partial"
    assert evidence["scanned_files"] == 2
    assert evidence["skipped_files"] == 1
    assert evidence["scanner_errors"] == 1


def test_appsec_store_round_trip(tmp_path) -> None:
    store = PersistenceStore(f"sqlite:///{tmp_path / 'appsec.db'}")
    store.create_appsec_assessment("appsec_test", {
        "name": "Example", "repository": REPO, "ref": "main",
        "coverage": {"sast": {"status": "planned", "tool": "semgrep"}},
    })
    finding = parse_trivy({"Results": [{
        "Target": "requirements.txt",
        "Vulnerabilities": [{"VulnerabilityID": "CVE-2025-22222", "PkgName": "demo", "InstalledVersion": "1", "Severity": "HIGH"}],
    }]}, REPO)[0]
    store.replace_appsec_findings("appsec_test", [finding])
    store.update_appsec_assessment("appsec_test", {"status": "completed", "progress": 100})
    assessment = store.load_appsec_assessment("appsec_test")
    assert assessment is not None
    assert assessment["status"] == "completed"
    assert assessment["progress"] == 100
    assert assessment["findings"][0]["cve_ids"] == ["CVE-2025-22222"]
