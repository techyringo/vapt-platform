from core.attack_chain import compile_attack_chains


def finding(title: str, *, tags=None, status="confirmed", score=82, grade="B"):
    return {
        "title": title,
        "description": title,
        "severity": "high",
        "target_host": "app.example.test",
        "target_url": "https://app.example.test",
        "evidence": f"tool evidence for {title}",
        "tags": tags or [],
        "cwe_ids": [],
        "cve_ids": [],
        "status": status,
        "evidence_score": score,
        "evidence_grade": grade,
        "quarantined": False,
        "created_at": title,
    }


def test_unrelated_findings_do_not_become_attack_chain():
    result = compile_attack_chains([
        finding("Missing security header", tags=["misconfiguration"]),
        finding("Outdated JavaScript library", tags=["dependency"]),
    ])
    assert result["summary"]["total"] == 0


def test_compatible_confirmed_findings_create_evidence_backed_chain():
    result = compile_attack_chains([
        finding("Exposed Git repository", tags=["repo-exposure"]),
        finding("API key exposed in source", tags=["secret-exposure"]),
    ])
    assert result["summary"] == {"total": 1, "verified": 1, "hypotheses": 0}
    chain = result["chains"][0]
    assert chain["status"] == "verified"
    assert len(chain["edges"][0]["evidence_refs"]) == 2
    assert all(ref.startswith("ev_") for ref in chain["edges"][0]["evidence_refs"])


def test_suspected_chain_remains_hypothesis():
    result = compile_attack_chains([
        finding("SSRF behavior", tags=["ssrf"], status="suspected", score=60, grade="C"),
        finding("Cloud metadata exposed", tags=["cloud-metadata"], status="suspected", score=60, grade="C"),
    ])
    assert result["summary"]["hypotheses"] == 1
    assert result["chains"][0]["status"] == "hypothesis"
