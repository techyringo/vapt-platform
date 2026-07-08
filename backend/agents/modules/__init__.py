"""
VAPT Platform — Safe Web-Validation Modules (P1)

Targeted, non-destructive web vulnerability checks that prove impact via HTTP
request/response replay without firing destructive payloads. Each module returns
Finding objects carrying request_proof/response_proof so the evidence chain and
false-positive reducer have concrete artifacts to work with.
"""

from agents.modules.base import SafeModule, make_finding, run_modules, MODULE_REGISTRY

__all__ = ["SafeModule", "make_finding", "run_modules", "MODULE_REGISTRY"]
