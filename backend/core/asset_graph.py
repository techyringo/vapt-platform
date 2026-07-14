"""Attack-surface asset graph primitives and extraction helpers."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit


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


_TRACKING_PARAMETERS = {
    "fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source",
    "utm_campaign", "utm_content", "utm_medium", "utm_source", "utm_term",
}
_UUID_OR_HASH = re.compile(r"^(?:[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{24,}|\d{4,})$", re.I)


def normalize_url(value: str) -> str:
    """Return a canonical endpoint identity, not a crawler-observation URL.

    Query values, fragments and tracking parameters are intentionally excluded
    from identity. Dynamic path identifiers are templated. The original sample
    remains in node metadata for evidence and replay.
    """

    raw = str(value or "").strip()
    if not raw or "\\" in raw:
        return ""
    parsed = urlsplit(raw)
    if not parsed.scheme:
        return raw.rstrip("/")
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower().rstrip(".")
    port = parsed.port
    netloc = hostname if not port or (scheme == "http" and port == 80) or (scheme == "https" and port == 443) else f"{hostname}:{port}"
    segments = ["{id}" if _UUID_OR_HASH.fullmatch(segment) else segment for segment in parsed.path.split("/")]
    path = "/".join(segments).rstrip("/") or "/"
    names = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True) if name.lower() not in _TRACKING_PARAMETERS})
    query = urlencode([(name, "{value}") for name in names])
    return urlunsplit((scheme, netloc, path, query, ""))


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
        raw_value = str(value or "").strip()
        value = normalize_url(raw_value) if asset_type in {"url", "api_endpoint", "js_file"} else raw_value
        if not value:
            return None
        normalized_metadata = dict(metadata or {})
        if asset_type in {"url", "api_endpoint", "js_file"}:
            normalized_metadata.setdefault("raw_samples", [raw_value][:1])
            normalized_metadata.setdefault("observation_count", 1)
        node = AssetNode(
            asset_type=asset_type,
            value=value,
            source=source,
            confidence=confidence,
            metadata=normalized_metadata,
        )
        existing = self.assets.get(node.key)
        if existing:
            merged = dict(existing.metadata)
            merged.update(node.metadata)
            if asset_type in {"url", "api_endpoint", "js_file"}:
                samples = list(dict.fromkeys([*(existing.metadata.get("raw_samples") or []), raw_value]))[:5]
                merged["raw_samples"] = samples
                merged["observation_count"] = int(existing.metadata.get("observation_count") or 1) + 1
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

        # EnumAgent persists Nmap records under ``ports``.  Older result
        # producers used ``port_results``/``services``; accept all three so the
        # graph preserves Nmap's service/product/version evidence instead of
        # falling back to a finding-only ``host:port`` node with an unknown
        # service label.
        service_results = (
            result.get("ports")
            or result.get("port_results")
            or result.get("services")
            or {}
        )
        for host, ports in service_results.items():
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


def canonical_graph_projection(
    assets: list[dict[str, Any]], edges: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Collapse legacy/raw URL rows into canonical assets for API projection."""

    projected: dict[str, dict[str, Any]] = {}
    key_map: dict[str, str] = {}
    for item in assets:
        asset_type = str(item.get("asset_type") or "unknown")
        raw_value = str(item.get("value") or "")
        value = normalize_url(raw_value) if asset_type in {"url", "api_endpoint", "js_file"} else raw_value.strip()
        if not value:
            continue
        node = AssetNode(asset_type, value, str(item.get("source") or "unknown"), str(item.get("confidence") or "medium"))
        key_map[str(item.get("asset_key") or "")] = node.key
        current = projected.get(node.key)
        metadata = dict(item.get("metadata") or {})
        metadata.setdefault("raw_samples", [raw_value] if value != raw_value else [])
        metadata["observation_count"] = max(1, int(metadata.get("observation_count") or 1))
        if current:
            previous = current.get("metadata") or {}
            metadata["observation_count"] += int(previous.get("observation_count") or 1)
            metadata["raw_samples"] = list(dict.fromkeys([*(previous.get("raw_samples") or []), *(metadata.get("raw_samples") or [])]))[:5]
            current["metadata"] = metadata
            current["source"] = ",".join(dict.fromkeys([*str(current.get("source") or "").split(","), *str(item.get("source") or "").split(",")]))
        else:
            projected[node.key] = {**item, "asset_key": node.key, "value": value, "metadata": metadata}

    projected_edges: dict[str, dict[str, Any]] = {}
    for item in edges:
        source = key_map.get(str(item.get("source_key") or ""))
        target = key_map.get(str(item.get("target_key") or ""))
        if not source or not target or source == target:
            continue
        edge = AssetEdge(source, target, str(item.get("relation") or "related"), str(item.get("evidence") or ""))
        projected_edges[edge.key] = {**item, **edge.to_record()}
    return list(projected.values()), list(projected_edges.values())
