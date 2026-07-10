from core.quality import assess_finding_quality


def test_technology_detection_is_quarantined_without_vulnerability_evidence():
    finding = {
        "title": "Technology Detected: Nginx",
        "description": "Nginx was detected on several hosts.",
        "severity": "low",
        "evidence": "Technology: Nginx detected on hosts: app.example.com",
        "tags": ["technology", "recon", "nginx"],
        "confidence": "high",
        "status": "confirmed",
        "cwe_ids": ["CWE-933"],
    }

    quality = assess_finding_quality(finding)

    assert quality["quarantined"] is True
    assert quality["evidence_score"] < 40
    assert any("Inventory/fingerprint context only" in note for note in quality["validation_notes"])


def test_proven_dast_finding_is_not_quarantined():
    finding = {
        "title": "Reflected XSS Payload Returned Unencoded",
        "description": "A reflected XSS payload was returned unencoded in the HTTP response.",
        "severity": "medium",
        "evidence": "Payload marker was reflected into the HTML response.",
        "request_proof": "GET https://example.com/search?q=payload",
        "response_proof": "<svg data-vapt=\"marker\">",
        "tags": ["dast-proof", "xss", "replay-proof", "confirmed"],
        "confidence": "high",
        "status": "confirmed",
        "cwe_ids": ["CWE-79"],
    }

    quality = assess_finding_quality(finding)

    assert quality["quarantined"] is False
    assert quality["evidence_score"] >= 40
