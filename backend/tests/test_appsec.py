from core.appsec import parse_gitleaks, parse_semgrep, parse_trivy
from services.appsec_assessment import validate_ref, validate_repository_url
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
