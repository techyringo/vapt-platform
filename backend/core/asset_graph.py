"""Attack-surface asset graph primitives and extraction helpers."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class AssetNode:
    asset_type: str
    value: str
    source: str
    confidence: str = "medium"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        raw = f"{self.asset_type}|{self.value.lower().strip()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    def to_record(self) -> dict[str, Any]:
        return {"asset_key": self.key, **asdict(self)}


@dataclass(frozen=True)
class AssetEdge:
    source_key: str
    target_key: str
    relation: str
    evidence: str = ""

    @property
    def key(self) -> str:
        raw = f"{self.source_key}|{self.relation}|{self.target_key}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    def to_record(self) -> dict[str, Any]:
        return {"edge_key": self.key, **asdict(self)}


def infer_host_type(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        return "domain"


def normalize_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme:
        return value.strip().rstrip("/")
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme.lower()}://{netloc}{path}{query}"


class AssetGraphBuilder:
    """Collect graph nodes/edges from scan targets, findings, and agent output."""

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        self.assets: dict[str, AssetNode] = {}
        self.edges: dict[str, AssetEdge] = {}

    def add_asset(
        self,
        asset_type: str,
        value: str,
        source: str,
        confidence: str = "medium",
        metadata: dict[str, Any] | None = None,
    ) -> AssetNode | None:
        value = normalize_url(str(value or "").strip())
        if not value:
            return None
        node = AssetNode(
            asset_type=asset_type,
            value=value,
            source=source,
            confidence=confidence,
            metadata=metadata or {},
        )
        existing = self.assets.get(node.key)
        if existing:
            merged = dict(existing.metadata)
            merged.update(node.metadata)
            node = AssetNode(
                asset_type=existing.asset_type,
                value=existing.value,
                source=existing.source if existing.source == source else f"{existing.source},{source}",
                confidence=existing.confidence if existing.confidence == "high" else confidence,
                metadata=merged,
            )
        self.assets[node.key] = node
        return node

    def add_edge(self, source: AssetNode | None, target: AssetNode | None, relation: str, evidence: str = "") -> None:
        if not source or not target or source.key == target.key:
            return
        edge = AssetEdge(source_key=source.key, target_key=target.key, relation=relation, evidence=evidence[:1000])
        self.edges[edge.key] = edge

    def add_target(self, host: str, source: str = "target") -> AssetNode | None:
        return self.add_asset(infer_host_type(host), host, source, "high", {"scope_seed": source == "target"})

    def add_url(self, url: str, source: str, parent: AssetNode | None = None, metadata: dict[str, Any] | None = None) -> AssetNode | None:
        parsed_input = urlparse(str(url))
        if parsed_input.scheme and parsed_input.scheme not in {"http", "https"}:
            return None
        node = self.add_asset("js_file" if ".js" in urlparse(url).path.lower() else "url", url, source, "high", metadata)
        parsed = urlparse(normalize_url(url))
        host = parsed.hostname
        if host:
            host_node = self.add_asset(infer_host_type(host), host, source, "high")
            self.add_edge(host_node, node, "hosts")
            if parent:
                self.add_edge(parent, node, "discovered")
        return node

    def ingest_finding(self, finding: dict[str, Any]) -> None:
        host = finding.get("target_host") or ""
        host_node = self.add_target(host, finding.get("agent_source") or "finding") if host else None
        url = finding.get("target_url") or ""
        if url and urlparse(str(url)).scheme in {"http", "https"}:
            self.add_url(url, finding.get("agent_source") or "finding", host_node, {"finding": finding.get("title")})
        elif host and finding.get("target_port"):
            service = self.add_asset(
                "service",
                f"{host}:{finding.get('target_port')}",
                finding.get("agent_source") or "finding",
                "medium",
                {"finding": finding.get("title"), "port": finding.get("target_port")},
            )
            self.add_edge(host_node, service, "exposes_service", finding.get("title", ""))
        for cve in finding.get("cve_ids") or []:
            cve_node = self.add_asset("vulnerability", cve, "finding", "high", {"kind": "cve"})
            self.add_edge(host_node, cve_node, "has_vulnerability", finding.get("title", ""))
        for tag in finding.get("tags") or []:
            if str(tag).lower() in {"exposure", "token", "secret", "api", "js", "javascript"}:
                tag_node = self.add_asset("signal", str(tag), "finding", "medium")
                self.add_edge(host_node, tag_node, "has_signal", finding.get("title", ""))

    def ingest_task_result(self, result: Any, source: str, target_host: str = "") -> None:
        if not isinstance(result, dict):
            return
        target_node = self.add_target(target_host, source) if target_host else None

        for sub in result.get("subdomains") or []:
            node = self.add_asset("subdomain", sub, source, "high")
            self.add_edge(target_node, node, "discovered_subdomain")

        for record in result.get("dns_records") or []:
            if not isinstance(record, dict):
                continue
            host = record.get("host") or ""
            value = record.get("value") or record.get("raw") or ""
            record_type = str(record.get("type") or "DNS").upper()
            host_node = self.add_asset(infer_host_type(host), host, source, "high") if host else target_node
            dns_node = self.add_asset(
                "dns_record",
                f"{host} {record_type} {value}".strip(),
                source,
                "high",
                record,
            )
            self.add_edge(host_node, dns_node, "has_dns_record")

        for entry in result.get("live_urls") or []:
            if isinstance(entry, dict):
                url = entry.get("url") or entry.get("input") or ""
                node = self.add_url(url, source, target_node, entry)
                for tech in entry.get("tech") or []:
                    tech_node = self.add_asset("technology", str(tech), source, "medium")
                    self.add_edge(node, tech_node, "uses_technology")

        for key in ("historical_urls", "crawled_urls", "endpoints", "new_endpoints"):
            for item in result.get(key) or []:
                if isinstance(item, dict):
                    url = item.get("url") or item.get("input") or item.get("path") or ""
                    metadata = item
                else:
                    url = str(item)
                    metadata = {"source_list": key}
                node = self.add_url(url, source, target_node, metadata) if url else None
                parsed = urlparse(normalize_url(url))
                if parsed.path.startswith("/api") or "/api/" in parsed.path:
                    api_node = self.add_asset("api_endpoint", normalize_url(url), source, "medium", metadata)
                    self.add_edge(node, api_node, "api_endpoint")

        for host, techs in (result.get("technologies") or {}).items():
            host_node = self.add_asset(infer_host_type(host), host, source, "high")
            for tech in techs or []:
                tech_node = self.add_asset("technology", str(tech), source, "medium")
                self.add_edge(host_node, tech_node, "uses_technology")

        for host, ports in (result.get("port_results") or result.get("services") or {}).items():
            host_node = self.add_asset(infer_host_type(host), host, source, "high")
            for port in ports or []:
                if not isinstance(port, dict):
                    continue
                service_name = port.get("service") or "unknown"
                port_no = port.get("port") or port.get("target_port")
                service_value = f"{host}:{port_no}/{service_name}"
                service_node = self.add_asset("service", service_value, source, "high", port)
                self.add_edge(host_node, service_node, "exposes_service")

        for item in result.get("param_results") or result.get("parameters") or []:
            if not isinstance(item, dict):
                continue
            url = item.get("url") or ""
            url_node = self.add_url(url, source, target_node, item) if url else target_node
            for param in item.get("parameters") or []:
                param_node = self.add_asset("parameter", f"{url}::{param}", source, "medium", {"url": url, "name": param})
                self.add_edge(url_node, param_node, "has_parameter")

        for item in result.get("js_files_scanned") or []:
            if isinstance(item, dict):
                url = item.get("url") or ""
                node = self.add_url(url, source, target_node, item) if url else None
                self.add_edge(target_node, node, "javascript_asset")

        js_items = [*(result.get("js_endpoints") or []), *(result.get("js_secrets") or [])]
        for item in js_items:
            if isinstance(item, dict):
                value = item.get("url") or item.get("source") or item.get("endpoint") or item.get("value") or ""
                metadata = item
            else:
                value = str(item)
                metadata = {}
            node_type = "secret" if isinstance(item, dict) and item.get("type") else "api_endpoint" if str(value).startswith("/") else "js_signal"
            node = self.add_asset(node_type, value, source, "medium", metadata)
            self.add_edge(target_node, node, "javascript_signal")

    def records(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        return (
            [asset.to_record() for asset in self.assets.values()],
            [edge.to_record() for edge in self.edges.values()],
        )


def summarize_assets(assets: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for asset in assets:
        asset_type = asset.get("asset_type", "unknown")
        summary[asset_type] = summary.get(asset_type, 0) + 1
    return dict(sorted(summary.items()))
