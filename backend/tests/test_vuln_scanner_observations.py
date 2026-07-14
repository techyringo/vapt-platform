from agents.vuln_scanner import VulnScannerAgent
from core.models import Target


def _agent() -> VulnScannerAgent:
    agent = VulnScannerAgent.__new__(VulnScannerAgent)
    agent._findings = []
    agent._observations = []
    return agent


def test_informational_nuclei_detection_is_observation_not_finding() -> None:
    agent = _agent()
    agent._convert_nuclei_findings(
        [{
            "template_id": "wordpress-detect",
            "template_name": "WordPress Detection",
            "severity": "info",
            "url": "https://example.test",
            "tags": ["tech", "wordpress"],
        }],
        Target(host="example.test", url="https://example.test"),
    )

    assert agent._findings == []
    assert agent._observations[0]["category"] == "technology_or_inventory"


def test_informational_cms_template_is_observation_not_finding() -> None:
    agent = _agent()
    agent._convert_cms_findings(
        [{
            "finding": "WordPress readme found",
            "component": "wordpress",
            "target_url": "https://example.test/readme.html",
            "severity": "info",
            "source_tool": "nuclei",
        }],
        Target(host="example.test", url="https://example.test"),
    )

    assert agent._findings == []
    assert agent._observations[0]["category"] == "cms_inventory"
