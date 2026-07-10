"""Target classification and seed-evidence helpers.

The platform accepts loose user input: URLs, domains, IPs, CIDRs, API
endpoints, and cloud resource names. This module normalises those inputs once
so scope enforcement, the asset graph, and the evidence planner all start from
the same interpretation.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse


API_PATH_HINTS = (
    "/api",
    "/graphql",
    "/swagger",
    "/openapi",
    "/v1/",
    "/v2/",
    "/v3/",
)

CLOUD_HOST_HINTS: tuple[tuple[str, str, str], ...] = (
    ("s3.amazonaws.com", "aws", "s3_bucket_hint"),
    (".s3.", "aws", "s3_bucket_hint"),
    (".s3-", "aws", "s3_bucket_hint"),
    ("cloudfront.net", "aws", "cdn_detected"),
    ("storage.googleapis.com", "gcp", "gcp_bucket_hint"),
    ("appspot.com", "gcp", "cloud_asset"),
    ("blob.core.windows.net", "azure", "azure_blob_hint"),
    ("azurewebsites.net", "azure", "cloud_asset"),
)

TECH_TOKEN_HINTS: tuple[tuple[str, str], ...] = (
    ("wordpress", "tech_wordpress"),
    ("wp-", "tech_wordpress"),
    ("drupal", "tech_drupal"),
    ("joomla", "tech_joomla"),
    ("graphql", "graphql_endpoint"),
)


@dataclass(frozen=True)
class TargetClassification:
    raw: str
    normalized: str
    target_type: str
    host: str = ""
    scheme: str = ""
    port: int | None = None
    path: str = ""
    scope_domain: str = ""
    scope_ip: str = ""
    asset_type: str = "target"
    provider: str = ""
    evidence_tokens: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["evidence_tokens"] = sorted(self.evidence_tokens)
        return data


def _strip_single_host_port(value: str) -> tuple[str, int | None]:
    if value.count(":") != 1:
        return value, None
    host, port_text = value.rsplit(":", 1)
    if not host or not port_text.isdigit():
        return value, None
    port = int(port_text)
    if 1 <= port <= 65535:
        return host, port
    return value, None


def _looks_like_domain(value: str) -> bool:
    return bool(re.match(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", value, re.I))


def _default_port(scheme: str) -> int | None:
    if scheme == "http":
        return 80
    if scheme == "https":
        return 443
    return None


def _api_tokens(host: str, path: str) -> set[str]:
    lowered = f"{host}{path}".lower()
    tokens: set[str] = set()
    if host.lower().startswith("api.") or any(hint in lowered for hint in API_PATH_HINTS):
        tokens.update({"api_endpoint", "target_api"})
    if "graphql" in lowered:
        tokens.update({"graphql_endpoint", "api_endpoint", "target_api"})
    return tokens


def _cloud_tokens(host: str) -> tuple[set[str], str]:
    lowered = host.lower()
    tokens: set[str] = set()
    provider = ""
    for hint, cloud_provider, token in CLOUD_HOST_HINTS:
        if hint in lowered:
            tokens.update({"cloud_asset", "target_cloud_asset", token})
            provider = provider or cloud_provider
    return tokens, provider


def _tech_hint_tokens(value: str) -> set[str]:
    lowered = value.lower()
    return {token for hint, token in TECH_TOKEN_HINTS if hint in lowered}


def classify_target(raw_target: str) -> TargetClassification:
    raw = str(raw_target or "").strip()
    if not raw:
        return TargetClassification(raw="", normalized="", target_type="empty")

    parsed = urlparse(raw if "://" in raw else "")
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        host = parsed.hostname.lower()
        port = parsed.port or _default_port(parsed.scheme)
        path = parsed.path or "/"
        normalized = raw.rstrip("/")
        tokens = {
            "target_url",
            "live_url",
            "http_service",
        }
        scope_domain = host
        scope_ip = ""
        try:
            scope_ip = str(ipaddress.ip_address(host))
            scope_domain = ""
            tokens.update({"ip_address", "target_ip"})
        except ValueError:
            tokens.add("subdomain")
        if parsed.scheme == "https":
            tokens.add("tls_service")
        cloud_tokens, provider = _cloud_tokens(host)
        tokens.update(cloud_tokens)
        tokens.update(_api_tokens(host, path))
        tokens.update(_tech_hint_tokens(raw))
        if path.lower().endswith(".js"):
            tokens.add("javascript_url")

        return TargetClassification(
            raw=raw,
            normalized=normalized,
            target_type="url",
            host=host,
            scheme=parsed.scheme,
            port=port,
            path=path,
            scope_domain=scope_domain,
            scope_ip=scope_ip,
            asset_type="url",
            provider=provider,
            evidence_tokens=tokens,
            metadata={
                "query": parsed.query,
                "seed_url": True,
                "seed_liveness": "assumed_user_input",
            },
        )

    host_candidate, port = _strip_single_host_port(raw.strip().strip("/"))
    host_candidate = host_candidate.lower().strip("[]")

    if host_candidate.startswith("*."):
        base_host = host_candidate[2:].rstrip(".")
        if _looks_like_domain(base_host):
            cloud_tokens, provider = _cloud_tokens(base_host)
            tokens = {"target_domain", "subdomain", "wildcard_scope"}
            tokens.update(cloud_tokens)
            tokens.update(_api_tokens(base_host, ""))
            tokens.update(_tech_hint_tokens(base_host))
            return TargetClassification(
                raw=raw,
                normalized=f"*.{base_host}",
                target_type="domain_wildcard",
                host=base_host,
                port=port,
                scope_domain=f"*.{base_host}",
                asset_type="domain",
                provider=provider,
                evidence_tokens=tokens,
                metadata={
                    "seed_port": port,
                    "wildcard_scope": True,
                    "execution_seed": base_host,
                } if port else {"wildcard_scope": True, "execution_seed": base_host},
            )

    try:
        network = ipaddress.ip_network(host_candidate, strict=False)
        tokens = {"ip_address", "target_ip"}
        target_type = "cidr" if network.prefixlen != network.max_prefixlen else "ip"
        if target_type == "cidr":
            tokens.update({"target_cidr", "ip_range"})
        return TargetClassification(
            raw=raw,
            normalized=str(network) if target_type == "cidr" else str(network.network_address),
            target_type=target_type,
            host=str(network.network_address),
            port=port,
            scope_ip=str(network),
            asset_type="cidr" if target_type == "cidr" else "ip",
            evidence_tokens=tokens,
            metadata={"seed_network": str(network), "seed_port": port},
        )
    except ValueError:
        pass

    host = host_candidate.rstrip(".")
    cloud_tokens, provider = _cloud_tokens(host)
    tokens = {"target_domain", "subdomain"}
    tokens.update(cloud_tokens)
    tokens.update(_api_tokens(host, ""))
    tokens.update(_tech_hint_tokens(host))

    target_type = "domain" if _looks_like_domain(host) else "hostname"
    if provider:
        target_type = "cloud_asset"
    return TargetClassification(
        raw=raw,
        normalized=host,
        target_type=target_type,
        host=host,
        port=port,
        scope_domain=host,
        asset_type="cloud_asset" if provider else target_type,
        provider=provider,
        evidence_tokens=tokens,
        metadata={"seed_port": port} if port else {},
    )


def classify_targets(targets: list[str]) -> list[TargetClassification]:
    return [item for item in (classify_target(target) for target in targets) if item.target_type != "empty"]


def scope_from_classifications(classifications: list[TargetClassification]) -> tuple[list[str], list[str]]:
    domains: list[str] = []
    ips: list[str] = []
    for item in classifications:
        if item.scope_domain and item.scope_domain not in domains:
            domains.append(item.scope_domain)
        if item.scope_ip and item.scope_ip not in ips:
            ips.append(item.scope_ip)
    return domains, ips


def evidence_from_classifications(classifications: list[TargetClassification]) -> set[str]:
    tokens: set[str] = set()
    for item in classifications:
        tokens.update(item.evidence_tokens)
    return tokens


def evidence_from_asset_records(assets: list[dict[str, Any]]) -> set[str]:
    tokens: set[str] = set()
    for asset in assets:
        asset_type = str(asset.get("asset_type") or "").lower()
        value = str(asset.get("value") or "").lower()
        metadata = asset.get("metadata") if isinstance(asset.get("metadata"), dict) else {}

        if asset_type in {"domain", "hostname", "subdomain"}:
            tokens.update({"subdomain", "target_domain"})
        elif asset_type in {"ip", "cidr"}:
            tokens.add("ip_address")
        elif asset_type == "url":
            tokens.update({"live_url", "target_url"})
            parsed = urlparse(value)
            tokens.update(_api_tokens(parsed.hostname or "", parsed.path or ""))
            if parsed.path.lower().endswith(".js"):
                tokens.add("javascript_url")
        elif asset_type == "js_file":
            tokens.add("javascript_url")
        elif asset_type == "api_endpoint":
            tokens.update({"api_endpoint", "target_api"})
            if "graphql" in value:
                tokens.add("graphql_endpoint")
        elif asset_type == "technology":
            tokens.add("technology")
            tokens.update(_tech_hint_tokens(value))
        elif asset_type == "service":
            tokens.update({"open_port", "service_banner"})
            service_name = str(metadata.get("service") or value).lower()
            for hint, token in (
                ("ssh", "ssh_open"),
                ("redis", "service_redis"),
                ("mysql", "service_mysql"),
                ("postgres", "service_postgresql"),
                ("mongodb", "service_mongodb"),
                ("elasticsearch", "service_elasticsearch"),
                ("rtsp", "rtsp_open"),
                ("rdp", "rdp_open"),
                ("smb", "smb_open"),
            ):
                if hint in service_name:
                    tokens.add(token)
        elif asset_type == "cloud_asset":
            cloud_tokens, _ = _cloud_tokens(value)
            tokens.update(cloud_tokens or {"cloud_asset"})
        elif asset_type == "repository":
            tokens.add("github_repo")

        cloud_tokens, _ = _cloud_tokens(value)
        tokens.update(cloud_tokens)

    return tokens
