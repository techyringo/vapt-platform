"""
VAPT Multi-Agent System — IoT/CCTV Security Agent

IoT and CCTV device security assessment:
  - Shodan API (device discovery, banner analysis)
  - Censys API (TLS/HTTP fingerprinting)
  - Default credential testing
  - RTSP probe
  - Firmware analysis hints
  - UPnP discovery
  - Common IoT protocol checks (MQTT, CoAP)
"""

import asyncio
import json
import re
from typing import Any, Optional
from urllib.parse import urlparse

import httpx as httpx_client
from loguru import logger

from core.models import AgentTask, AgentType, Finding, Severity, Target
from core.scope import ScopeManager
from core.config import AppConfig
from agents.base import BaseAgent
from tools.runner import DockerRunner


# Common default credentials for IoT devices
DEFAULT_CREDS = {
    "admin": ["admin", "password", "12345", "", "admin123", "root", "default", "pass", "guest", "user"],
    "root": ["root", "toor", "admin", "password", "12345", "", "default"],
    "user": ["user", "password", "12345", "", "user123"],
    "guest": ["guest", "password", "12345", ""],
    "support": ["support", "support", "password"],
    "service": ["service", "service", "password"],
    "ubnt": ["ubnt", "ubnt"],
    "pi": ["pi", "raspberry"],
    "camera": ["camera", "camera", "12345"],
    "operator": ["operator", "operator", "password"],
}


class IoTAgent(BaseAgent):
    """IoT and CCTV security assessment agent.

    Discovers IoT devices, tests for default credentials, probes
    RTSP streams, and checks for common IoT vulnerabilities.
    """

    def __init__(self, scope: ScopeManager, config: AppConfig) -> None:
        super().__init__(AgentType.IOT_CCTV, scope, config)
        self._runner = DockerRunner(config)

    async def execute(self, task: AgentTask) -> list[Finding]:
        logger.info("[IOT] Starting IoT/CCTV security assessment")
        self.clear_findings()

        domain = task.target.host
        recon_data = task.parameters.get("recon_data", task.result or {})
        subdomains = recon_data.get("subdomains", [])
        enum_data = task.parameters.get("enum_data", {})
        ports = enum_data.get("ports", {})

        # Phase 1: Shodan discovery
        shodan_devices = await self._query_shodan(domain, ports)
        self._analyze_shodan_results(shodan_devices)

        # Phase 2: Censys discovery
        censys_devices = await self._query_censys(domain)

        # Phase 3: RTSP probing on discovered hosts
        iot_hosts = self._identify_iot_hosts(subdomains, ports)
        await self._probe_rtsp(iot_hosts)

        # Phase 4: Default credential testing on web interfaces
        await self._test_default_creds(iot_hosts)

        # Phase 5: UPnP and IoT protocol checks
        await self._check_upnp(iot_hosts)
        await self._check_iot_protocols(iot_hosts)

        # Phase 6: Common IoT web interface fingerprinting
        await self._fingerprint_iot_web(iot_hosts)

        task.result = {
            "shodan_devices": shodan_devices,
            "censys_devices": censys_devices,
            "iot_hosts": iot_hosts,
            "total_iot_findings": len(self._findings),
        }

        logger.info("[IOT] Complete: {count} IoT findings", count=len(self._findings))
        return self.get_findings()

    async def _query_shodan(self, domain: str, ports: dict) -> list[dict]:
        """Query Shodan API for IoT devices."""
        import os
        api_key = os.environ.get("SHODAN_API_KEY", "")
        if not api_key:
            logger.info("[IOT] No Shodan API key — skipping Shodan query")
            return []

        devices = []
        try:
            async with httpx_client.AsyncClient(timeout=20) as client:
                # Search for devices on the target domain/IP
                query = f"hostname:{domain}"
                resp = await client.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={"key": api_key, "query": query},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    devices = data.get("matches", [])
                    logger.info("[IOT] Shodan: {count} devices found", count=len(devices))

                    # Also check specific IPs from port scan
                    for host in list(ports.keys())[:5]:
                        resp2 = await client.get(
                            f"https://api.shodan.io/shodan/host/{host}",
                            params={"key": api_key},
                        )
                        if resp2.status_code == 200:
                            host_data = resp2.json()
                            if host_data.get("ports"):
                                devices.append(host_data)
        except Exception as exc:
            logger.debug("[IOT] Shodan query error: {err}", err=exc)

        return devices

    def _analyze_shodan_results(self, devices: list[dict]) -> None:
        """Analyze Shodan device results for security issues."""
        iot_signatures = {
            "Hikvision": {"type": "CCTV", "severity": Severity.HIGH, "cwe": "CWE-798"},
            "Dahua": {"type": "CCTV", "severity": Severity.HIGH, "cwe": "CWE-798"},
            "Axis": {"type": "CCTV", "severity": Severity.MEDIUM, "cwe": "CWE-16"},
            "DVR": {"type": "DVR", "severity": Severity.HIGH, "cwe": "CWE-798"},
            "NVR": {"type": "NVR", "severity": Severity.HIGH, "cwe": "CWE-798"},
            "camera": {"type": "Camera", "severity": Severity.MEDIUM, "cwe": "CWE-798"},
            "rtsp": {"type": "RTSP Stream", "severity": Severity.HIGH, "cwe": "CWE-284"},
            "mqtt": {"type": "MQTT Broker", "severity": Severity.HIGH, "cwe": "CWE-306"},
            "UPnP": {"type": "UPnP Device", "severity": Severity.MEDIUM, "cwe": "CWE-933"},
            "router": {"type": "Router", "severity": Severity.MEDIUM, "cwe": "CWE-16"},
            "printer": {"type": "Printer", "severity": Severity.LOW, "cwe": "CWE-16"},
            "smart": {"type": "Smart Device", "severity": Severity.MEDIUM, "cwe": "CWE-306"},
            "IoT": {"type": "IoT Device", "severity": Severity.MEDIUM, "cwe": "CWE-306"},
            "webcam": {"type": "Webcam", "severity": Severity.HIGH, "cwe": "CWE-798"},
            "NetBus": {"type": "Remote Access", "severity": Severity.CRITICAL, "cwe": "CWE-284"},
            "VNC": {"type": "VNC", "severity": Severity.CRITICAL, "cwe": "CWE-284"},
            "RDP": {"type": "RDP", "severity": Severity.HIGH, "cwe": "CWE-284"},
            "Telnet": {"type": "Telnet", "severity": Severity.HIGH, "cwe": "CWE-319"},
        }

        for device in devices:
            host = device.get("ip_str", device.get("hostname", "unknown"))
            port = device.get("port", 0)
            product = device.get("product", "")
            banner = device.get("data", "")
            vulns = device.get("vulns", {})

            # Check for known vulnerable devices
            for sig, info in iot_signatures.items():
                if sig.lower() in (product + banner).lower():
                    finding = Finding(
                        title=f"{info['type']} Device Exposed: {product or sig} ({host}:{port})",
                        description=f"A {info['type']} device ({product or sig}) was found exposed on {host}:{port}. "
                                    f"IoT/CCTV devices are frequently targeted due to weak default credentials, "
                                    f"unpatched firmware, and minimal security controls. {banner[:200]}",
                        severity=info["severity"],
                        agent_source=AgentType.IOT_CCTV,
                        target=Target(host=host, port=port, url=f"http://{host}:{port}"),
                        evidence=f"Product: {product}\nPort: {port}\nBanner: {banner[:500]}",
                        remediation=f"Restrict access to the {info['type']} device using firewall rules. "
                                    f"Change default credentials. Update firmware to the latest version. "
                                    f"Place IoT devices on an isolated network segment (VLAN).",
                        cwe_ids=[info["cwe"]],
                        tags=["iot", info["type"].lower().replace(" ", "-"), "exposed", "device"],
                        confidence="high",
                        status="confirmed",
                    )
                    self._add_finding(finding)
                    break

            # Check for known vulnerabilities
            if vulns:
                for vuln_id, vuln_data in vulns.items():
                    finding = Finding(
                        title=f"Known Vulnerability on IoT Device: {vuln_id} ({host}:{port})",
                        description=f"Shodan detected known vulnerability {vuln_id} on {host}:{port}. "
                                    f"This device has a known security flaw that could allow remote exploitation. "
                                    f"CVSS: {vuln_data.get('cvss', 'N/A')} — {vuln_data.get('summary', 'No summary available')}",
                        severity=Severity.CRITICAL if vuln_data.get("cvss", 0) >= 9.0 else Severity.HIGH,
                        cvss_score=vuln_data.get("cvss"),
                        agent_source=AgentType.IOT_CCTV,
                        target=Target(host=host, port=port),
                        evidence=f"Vuln: {vuln_id}\nCVSS: {vuln_data.get('cvss', 'N/A')}\n{vuln_data.get('summary', '')}",
                        remediation=f"Apply the vendor patch for {vuln_id} immediately. If no patch is available, "
                                    f"isolate the device on a restricted network segment.",
                        cve_ids=[vuln_id],
                        tags=["iot", "known-vuln", "shodan"],
                        confidence="high",
                        status="confirmed",
                    )
                    self._add_finding(finding)

    async def _query_censys(self, domain: str) -> list[dict]:
        """Query Censys API for device information."""
        import os
        api_id = os.environ.get("CENSYS_API_ID", "")
        api_secret = os.environ.get("CENSYS_API_SECRET", "")
        if not api_id or not api_secret:
            logger.info("[IOT] No Censys API credentials — skipping")
            return []

        devices = []
        try:
            async with httpx_client.AsyncClient(
                timeout=20,
                auth=httpx_client.BasicAuth(api_id, api_secret),
            ) as client:
                resp = await client.post(
                    "https://search.censys.io/api/v2/hosts/search",
                    json={"q": f"services.tls.certificate.parsed.names: {domain}"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    devices = data.get("result", {}).get("hits", [])
                    logger.info("[IOT] Censys: {count} hosts found", count=len(devices))
        except Exception as exc:
            logger.debug("[IOT] Censys query error: {err}", err=exc)

        return devices

    def _identify_iot_hosts(self, subdomains: list[str], ports: dict) -> list[dict]:
        """Identify hosts that are likely IoT devices from port scan data."""
        iot_ports = {
            80, 443, 554, 8080, 8443,  # Web / RTSP / Admin
            1883, 8883,  # MQTT
            5683, 5684,  # CoAP
            502,  # Modbus
            161, 162,  # SNMP
            23, 2323,  # Telnet
            21,  # FTP
            5900,  # VNC
            3389,  # RDP
            49152, 49153, 49154, 49155,  # UPnP
        }

        iot_hosts = []
        for host, port_list in ports.items():
            host_ports = [p.get("port", 0) for p in port_list]
            iot_port_overlap = set(host_ports) & iot_ports
            if len(iot_port_overlap) >= 2:
                iot_hosts.append({
                    "host": host,
                    "ports": host_ports,
                    "iot_ports": list(iot_port_overlap),
                    "is_likely_iot": True,
                })

        # Also check subdomains for IoT indicators
        iot_keywords = ["camera", "cctv", "iot", "sensor", "device", "monitor", "dvr", "nvr", "hik", "dahua", "axis", "printer", "smart"]
        for sub in subdomains:
            if any(kw in sub.lower() for kw in iot_keywords):
                iot_hosts.append({"host": sub, "ports": [], "iot_ports": [], "is_likely_iot": True})

        return iot_hosts

    async def _probe_rtsp(self, iot_hosts: list[dict]) -> None:
        """Probe for accessible RTSP streams."""
        rtsp_paths = [
            "/stream1", "/stream2", "/live", "/ch1", "/ch01",
            "/video1", "/cam/realmonitor", "/Media/Live/Channel/1",
            "/h264/ch1/main/av_stream", "/mpeg4/ch1/main/av_stream",
        ]

        for host_info in iot_hosts[:10]:
            host = host_info["host"]
            for path in rtsp_paths:
                rtsp_url = f"rtsp://{host}:554{path}"
                try:
                    # Use subprocess for RTSP since httpx doesn't support rtsp://
                    import subprocess
                    result = subprocess.run(
                        ["timeout", "5", "curl", "-s", "-I", rtsp_url],
                        capture_output=True, text=True, timeout=8,
                    )
                    if "200 OK" in result.stdout or "RTSP/1.0" in result.stdout:
                        finding = Finding(
                            title=f"Accessible RTSP Stream: {host}:554{path}",
                            description=f"An RTSP video stream is publicly accessible at {rtsp_url}. "
                                        f"This allows unauthorized viewing of CCTV footage, potentially "
                                        f"revealing sensitive areas, activities, and personnel.",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            agent_source=AgentType.IOT_CCTV,
                            target=Target(host=host, port=554, url=rtsp_url),
                            evidence=f"RTSP URL: {rtsp_url}\nResponse: {result.stdout[:300]}",
                            remediation="Restrict RTSP access to authorized IP ranges using firewall rules. "
                                        "Enable RTSP authentication. Consider using HTTPS/SSL for camera "
                                        "management interfaces. Place cameras on isolated network segments.",
                            cwe_ids=["CWE-284", "CWE-306"],
                            tags=["rtsp", "cctv", "camera", "exposure", "video"],
                            confidence="high",
                            status="confirmed",
                        )
                        self._add_finding(finding)
                        break  # One hit per host is enough
                except Exception:
                    continue

    async def _test_default_creds(self, iot_hosts: list[dict]) -> None:
        """Test for default credentials on IoT web interfaces."""
        for host_info in iot_hosts[:5]:
            host = host_info["host"]
            for port in [80, 443, 8080, 8443]:
                url = f"https://{host}:{port}" if port in (443, 8443) else f"http://{host}:{port}"

                if not self.is_in_scope(url):
                    continue

                try:
                    async with httpx_client.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
                        # Check for login pages
                        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                        if resp.status_code != 200:
                            continue

                        # Detect login form
                        if any(kw in resp.text.lower() for kw in ["login", "password", "sign in", "auth"]):
                            # Test a few default credential pairs
                            tested = 0
                            for username, passwords in DEFAULT_CREDS.items():
                                if tested >= 3:  # Limit tests per host
                                    break
                                for password in passwords[:2]:
                                    if tested >= 3:
                                        break
                                    try:
                                        login_data = self._build_login_data(resp.text, username, password)
                                        if not login_data:
                                            continue
                                        login_resp = await client.post(
                                            url + "/login",
                                            data=login_data,
                                            follow_redirects=False,
                                            timeout=8,
                                        )
                                        # Check for successful login
                                        if (login_resp.status_code in (200, 302, 303)
                                            and "invalid" not in login_resp.text.lower()
                                            and "incorrect" not in login_resp.text.lower()
                                            and "failed" not in login_resp.text.lower()):
                                            finding = Finding(
                                                title=f"Default Credentials Working: {username}/{password} on {host}:{port}",
                                                description=f"Default credentials ({username}:{password}) successfully authenticated "
                                                            f"to the IoT device management interface at {url}. This allows "
                                                            f"full administrative access to the device.",
                                                severity=Severity.CRITICAL,
                                                cvss_score=9.8,
                                                agent_source=AgentType.IOT_CCTV,
                                                target=Target(host=host, port=port, url=url),
                                                evidence=f"Username: {username}\nPassword: {password}\nResponse: HTTP {login_resp.status_code}",
                                                remediation="Change all default credentials immediately. Enforce strong "
                                                            "password policies. Disable default accounts. Implement "
                                                            "account lockout after failed attempts.",
                                                cwe_ids=["CWE-798", "CWE-521"],
                                                tags=["default-creds", "iot", "authentication", "brute-force"],
                                                confidence="high",
                                                status="confirmed",
                                            )
                                            self._add_finding(finding)
                                        tested += 1
                                    except Exception:
                                        tested += 1
                                        continue
                except Exception:
                    continue

    def _build_login_data(self, html: str, username: str, password: str) -> Optional[dict]:
        """Build login form data based on HTML form fields."""
        # Find form field names
        user_fields = re.findall(r'<input[^>]*name=["\']([\w\-\.]+)["\'][^>]*(?:type=["\'](?:text|email|hidden)["\'])?[^>]*>', html, re.I)
        pass_fields = re.findall(r'<input[^>]*name=["\']([\w\-\.]+)["\'][^>]*type=["\']password["\']', html, re.I)
        csrf_fields = re.findall(r'<input[^>]*name=["\'](csrf[\w\-\.]*)["\']', html, re.I)

        if not user_fields or not pass_fields:
            return None

        data = {user_fields[0]: username, pass_fields[0]: password}
        if csrf_fields:
            data[csrf_fields[0]] = "test"
        return data

    async def _check_upnp(self, iot_hosts: list[dict]) -> None:
        """Check for UPnP services that could expose internal services."""
        for host_info in iot_hosts[:5]:
            host = host_info["host"]
            try:
                async with httpx_client.AsyncClient(verify=False, timeout=8) as client:
                    # UPnP description URL
                    resp = await client.get(
                        f"http://{host}:49152/description.xml",
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                    if resp.status_code == 200 and "UPnP" in resp.text:
                        finding = Finding(
                            title=f"UPnP Service Exposed: {host}",
                            description=f"A UPnP service is running on {host}:49152. UPnP can be exploited "
                                        f"to open ports on the firewall, potentially exposing internal services "
                                        f"to the internet or allowing NAT traversal attacks.",
                            severity=Severity.MEDIUM,
                            agent_source=AgentType.IOT_CCTV,
                            target=Target(host=host, port=49152),
                            evidence=f"UPnP description XML accessible",
                            remediation="Disable UPnP on the device or network. Use manual port forwarding "
                                        "instead. Implement firewall rules to block UPnP traffic from the internet.",
                            cwe_ids=["CWE-933"],
                            tags=["upnp", "iot", "nat-traversal"],
                            confidence="high",
                            status="confirmed",
                        )
                        self._add_finding(finding)
            except Exception:
                continue

    async def _check_iot_protocols(self, iot_hosts: list[dict]) -> None:
        """Check for exposed IoT-specific protocols (MQTT, CoAP, etc.)."""
        for host_info in iot_hosts[:5]:
            host = host_info["host"]

            # MQTT broker check
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((host, 1883))
                if result == 0:
                    finding = Finding(
                        title=f"MQTT Broker Exposed: {host}:1883",
                        description=f"An MQTT broker is accessible on {host}:1883 without TLS. MQTT brokers "
                                    f"without authentication can be abused to subscribe to sensitive topics, "
                                    f"publish malicious messages, or disrupt IoT device operations.",
                        severity=Severity.HIGH,
                        agent_source=AgentType.IOT_CCTV,
                        target=Target(host=host, port=1883),
                        remediation="Enable MQTT authentication (username/password or TLS client certificates). "
                                    "Use MQTT over TLS (port 8883). Implement topic-level ACLs. "
                                    "Restrict broker access to authorized IPs.",
                        cwe_ids=["CWE-306", "CWE-319"],
                        tags=["mqtt", "iot", "broker", "exposed"],
                        confidence="high",
                        status="suspected",
                    )
                    self._add_finding(finding)
                sock.close()
            except Exception:
                pass

    async def _fingerprint_iot_web(self, iot_hosts: list[dict]) -> None:
        """Fingerprint IoT device web interfaces for known vulnerabilities."""
        iot_fingerprints = {
            "Hikvision": {
                "indicators": ["Hikvision", "iVMS", "webVideoCtrl", "ISAPI"],
                "severity": Severity.HIGH,
                "cwe": "CWE-798",
                "remediation": "Update Hikvision firmware to latest version. Change default credentials. "
                               "Disable UPnP. Restrict web interface access to authorized IPs.",
            },
            "Dahua": {
                "indicators": ["Dahua", "dmr", "digital-protector", "x109"],
                "severity": Severity.HIGH,
                "cwe": "CWE-798",
                "remediation": "Update Dahua firmware immediately. Change default credentials. "
                               "Disable Telnet and UPnP services.",
            },
            "Axis": {
                "indicators": ["Axis", "axis-cgi", "VAPIX", "vapix"],
                "severity": Severity.MEDIUM,
                "cwe": "CWE-16",
                "remediation": "Update Axis firmware. Enable HTTPS. Configure strong authentication.",
            },
            "TP-Link": {
                "indicators": ["TP-LINK", "tplink", "tplinklogin"],
                "severity": Severity.MEDIUM,
                "cwe": "CWE-798",
                "remediation": "Update TP-Link firmware. Change default admin password.",
            },
        }

        for host_info in iot_hosts[:10]:
            host = host_info["host"]
            for port in [80, 443, 8080]:
                url = f"https://{host}:{port}" if port == 443 else f"http://{host}:{port}"
                if not self.is_in_scope(url):
                    continue

                try:
                    async with httpx_client.AsyncClient(verify=False, timeout=8, follow_redirects=True) as client:
                        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                        if resp.status_code != 200:
                            continue

                        title_match = re.search(r'<title>(.*?)</title>', resp.text, re.I)
                        title = title_match.group(1) if title_match else ""
                        content = title + " " + resp.text[:3000]

                        for vendor, fp_info in iot_fingerprints.items():
                            if any(ind.lower() in content.lower() for ind in fp_info["indicators"]):
                                finding = Finding(
                                    title=f"{vendor} Device Identified: {host}:{port}",
                                    description=f"A {vendor} device was identified at {url} based on web "
                                                f"fingerprinting. {vendor} devices have known vulnerabilities "
                                                f"including default credentials, authentication bypass, and "
                                                f"remote code execution in older firmware versions.",
                                    severity=fp_info["severity"],
                                    agent_source=AgentType.IOT_CCTV,
                                    target=Target(host=host, port=port, url=url),
                                    evidence=f"Title: {title}\nPage indicators: {[i for i in fp_info['indicators'] if i.lower() in content.lower()]}",
                                    remediation=fp_info["remediation"],
                                    cwe_ids=[fp_info["cwe"]],
                                    tags=["iot", vendor.lower(), "fingerprint", "device"],
                                    confidence="high",
                                    status="confirmed",
                                )
                                self._add_finding(finding)
                                break
                except Exception:
                    continue