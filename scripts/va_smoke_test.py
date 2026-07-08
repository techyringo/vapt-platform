#!/usr/bin/env python3
"""API-driven VA smoke test for the VAPT platform.

This test proves the operational flow, not vulnerability quality:
  1. optionally start a VA scan for an authorized target,
  2. wait for terminal status,
  3. verify required VA agents ran,
  4. verify real tool names were recorded,
  5. verify SSE/event history and report download.

Usage:
  python scripts/va_smoke_test.py --target example.com
  python scripts/va_smoke_test.py --scan-id latest
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


TERMINAL_STATUSES = {"completed", "failed", "cancelled"}
REQUIRED_AGENTS = ("recon", "enum", "vuln_scanner", "reporter")
EXPECTED_TOOLS = {
    "recon": {"subfinder", "assetfinder", "amass", "dnsx", "httpx", "waybackurls", "gau", "katana"},
    "enum": {"nmap", "ffuf", "arjun"},
    "vuln_scanner": {"nuclei", "nikto", "wpscan"},
}


class ApiClient:
    def __init__(self, base_url: str, api_key: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def request(self, method: str, path: str, body: Any = None, raw: bool = False) -> Any:
        headers = {}
        data = None
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
        try:
            with urlopen(req, timeout=30) as res:
                payload = res.read()
                if raw:
                    return res.status, payload
                text = payload.decode() if payload else "{}"
                return json.loads(text)
        except HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"{method} {path} failed HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"{method} {path} failed: {exc}") from exc

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, body: Any) -> Any:
        return self.request("POST", path, body)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run or inspect a VAPT VA smoke scan.")
    parser.add_argument("--api-url", default="http://localhost:8443", help="Backend API base URL")
    parser.add_argument("--api-key", default="", help="Optional X-API-Key value")
    parser.add_argument("--target", action="append", help="Authorized target to scan; repeat for multiple")
    parser.add_argument("--scan-id", default="", help="Existing scan id to inspect, or 'latest'")
    parser.add_argument("--mode", default="va_only", help="Scan mode to start")
    parser.add_argument("--name", default="VA smoke test", help="Scan name when starting a new scan")
    parser.add_argument("--timeout", type=int, default=1200, help="Seconds to wait for terminal scan status")
    parser.add_argument("--poll", type=int, default=5, help="Polling interval in seconds")
    parser.add_argument("--no-wait", action="store_true", help="Do not wait if an existing scan is still running")
    parser.add_argument("--skip-report", action="store_true", help="Do not verify report download")
    return parser.parse_args()


def latest_scan_id(api: ApiClient) -> str:
    scans = api.get("/api/scans")
    if not scans:
        raise RuntimeError("No scans exist; pass --target to start one.")
    return scans[0]["scan_id"]


def start_scan(api: ApiClient, targets: list[str], mode: str, name: str) -> str:
    result = api.post("/api/scans/start", {"targets": targets, "mode": mode, "name": name})
    scan_id = result.get("scan_id")
    if not scan_id:
        raise RuntimeError(f"Start scan returned no scan_id: {result}")
    print(f"started scan: {scan_id}")
    return scan_id


def wait_for_scan(api: ApiClient, scan_id: str, timeout: int, poll: int) -> dict[str, Any]:
    deadline = time.time() + timeout
    last_line = ""
    while True:
        scan = api.get(f"/api/scans/{scan_id}")
        status = scan.get("status", "")
        phase = scan.get("current_phase", "")
        findings = scan.get("total_findings", 0)
        line = f"status={status} phase={phase} findings={findings}"
        if line != last_line:
            print(line)
            last_line = line
        if status in TERMINAL_STATUSES:
            return scan
        if time.time() > deadline:
            health = api.get("/api/health")
            queue = health.get("worker_queue", {})
            raise RuntimeError(
                f"Timed out waiting for {scan_id}; last {line}; "
                f"worker_queue={json.dumps(queue, sort_keys=True)}"
            )
        time.sleep(max(1, poll))


def verify(api: ApiClient, scan_id: str, scan: dict[str, Any], skip_report: bool) -> int:
    failures: list[str] = []
    agents_payload = api.get(f"/api/scans/{scan_id}/agents")
    agents: dict[str, dict[str, Any]] = agents_payload.get("agents", {})
    events = api.get(f"/api/events?{urlencode({'scan_id': scan_id, 'limit': 500})}").get("events", [])

    if scan.get("status") != "completed":
        queue = api.get("/api/health").get("worker_queue", {})
        failures.append(
            f"scan did not complete successfully: {scan.get('status')} {scan.get('error', '')}; "
            f"worker_queue={json.dumps(queue, sort_keys=True)}"
        )

    missing_agents = [agent for agent in REQUIRED_AGENTS if agent not in agents]
    if missing_agents:
        failures.append(f"missing required agents: {', '.join(missing_agents)}")

    for agent in REQUIRED_AGENTS:
        status = agents.get(agent, {})
        if status and status.get("status") != "completed":
            failures.append(f"agent {agent} status is {status.get('status')}")

    observed_tools = {
        agent: set(agents.get(agent, {}).get("tools_run") or [])
        for agent in REQUIRED_AGENTS
    }
    for agent, expected_any in EXPECTED_TOOLS.items():
        seen_real_tools = observed_tools.get(agent, set()) & expected_any
        if not seen_real_tools:
            failures.append(
                f"agent {agent} recorded no expected real tools; saw {sorted(observed_tools.get(agent, []))}"
            )

    event_types = {event.get("type") or event.get("event") for event in events}
    for required_event in ("scan_started", "phase_change", "agent_status"):
        if required_event not in event_types:
            failures.append(f"missing event type: {required_event}")
    if "scan_complete" not in event_types and scan.get("status") == "completed":
        failures.append("missing scan_complete event")

    if not skip_report and scan.get("status") == "completed":
        status_code, payload = api.request(
            "GET",
            f"/api/scans/{scan_id}/report?format=html",
            raw=True,
        )
        if status_code != 200 or len(payload) < 500:
            failures.append(f"report download suspicious: status={status_code} bytes={len(payload)}")

    print("\nsummary")
    print(json.dumps({
        "scan_id": scan_id,
        "status": scan.get("status"),
        "phase": scan.get("current_phase"),
        "findings": scan.get("total_findings"),
        "agents": {name: {
            "status": data.get("status"),
            "tools_run": data.get("tools_run", []),
            "findings_count": data.get("findings_count"),
        } for name, data in agents.items()},
        "event_types": sorted(t for t in event_types if t),
    }, indent=2))

    if failures:
        print("\nFAIL")
        for item in failures:
            print(f"- {item}")
        return 1
    print("\nPASS")
    return 0


def main() -> int:
    args = parse_args()
    api = ApiClient(args.api_url, args.api_key)

    health = api.get("/api/health")
    print(f"api={args.api_url} status={health.get('status')} marker={health.get('runtime_marker', 'old-image')}")

    if args.scan_id:
        scan_id = latest_scan_id(api) if args.scan_id == "latest" else args.scan_id
        scan = api.get(f"/api/scans/{scan_id}")
        if scan.get("status") not in TERMINAL_STATUSES and not args.no_wait:
            print(f"scan {scan_id} is {scan.get('status')} — waiting for terminal status")
            scan = wait_for_scan(api, scan_id, args.timeout, args.poll)
    else:
        targets = args.target or []
        if not targets:
            print("error: pass --target for an authorized target, or --scan-id to inspect an existing scan", file=sys.stderr)
            return 2
        scan_id = start_scan(api, targets, args.mode, args.name)
        scan = wait_for_scan(api, scan_id, args.timeout, args.poll)

    return verify(api, scan_id, scan, args.skip_report)


if __name__ == "__main__":
    raise SystemExit(main())
