"""Typed asset schema for ReconX.

This module defines the canonical graph entities handled by the orchestration
engine. The core design goal is deterministic identity and reproducible merges:
the same real-world fact should map to the same ID regardless of scanner source.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar, Iterable, Type, Union
from urllib.parse import urlsplit

from reconx.core.evidence import Evidence, EvidenceBag, utc_now_iso
from reconx.utils.hashing import deterministic_id, stable_json
from reconx.utils.normalization import (
    CanonicalHost,
    canonical_host,
    choose_higher_severity,
    clamp_confidence,
    extract_port_from_url,
    extract_scheme_from_url,
    normalize_cve_id,
    normalize_hostname,
    normalize_path,
    normalize_protocol,
    normalize_severity,
    normalize_service_name,
    normalize_tech_list,
    normalize_url,
)


FINDING_TIER_ORDER: dict[str, int] = {
    "raw": 0,
    "probable": 1,
    "validated": 2,
}


def normalize_tier(value: str | None) -> str:
    """Normalize finding output tier into a known finite set."""

    if not value:
        return "raw"
    cleaned = value.strip().lower()
    if cleaned in FINDING_TIER_ORDER:
        return cleaned
    return "raw"


def stronger_tier(first: str | None, second: str | None) -> str:
    """Return the stronger of two finding tiers."""

    first_norm = normalize_tier(first)
    second_norm = normalize_tier(second)
    if FINDING_TIER_ORDER[first_norm] >= FINDING_TIER_ORDER[second_norm]:
        return first_norm
    return second_norm


def _merge_metadata(current: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    """Merge metadata while preferring existing non-empty values.

    This strategy protects higher quality values collected from earlier modules
    while still allowing sparse fields to be filled by later evidence.
    """

    merged = dict(current)
    for key, value in incoming.items():
        if key not in merged or merged[key] in (None, "", [], {}):
            merged[key] = value
            continue
        if isinstance(merged[key], dict) and isinstance(value, dict):
            nested = dict(merged[key])
            nested.update(value)
            merged[key] = nested
    return merged


@dataclass(kw_only=True)
class BaseAsset:
    """Base class for all assets in the graph."""

    first_seen: str = field(default_factory=utc_now_iso)
    last_seen: str = field(default_factory=utc_now_iso)
    confidence: float = 0.5
    evidence: EvidenceBag = field(default_factory=EvidenceBag)
    tags: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(init=False)
    canonical_key: str = field(init=False)

    ASSET_TYPE: ClassVar[str] = "asset"

    def __post_init__(self) -> None:
        self.confidence = clamp_confidence(self.confidence)
        self.tags = {tag.strip().lower() for tag in self.tags if tag and tag.strip()}
        self.metadata = dict(self.metadata)
        self.canonical_key = self.compute_canonical_key()
        self.id = deterministic_id(self.ASSET_TYPE, self.canonical_key)
        self._recompute_confidence()

    @property
    def asset_type(self) -> str:
        """Stable string identifier for event routing and persistence."""

        return self.ASSET_TYPE

    @classmethod
    def event_topic(cls) -> str:
        """Event topic for this asset class in the event bus."""

        return f"asset.{cls.ASSET_TYPE}"

    def canonical_parts(self) -> tuple[str, ...]:
        """Subclass override point for deterministic identity fields."""

        raise NotImplementedError

    def compute_canonical_key(self) -> str:
        """Compute canonical key string from type-specific identity fields."""

        return stable_json(self.canonical_parts())

    def add_evidence(self, evidence: Evidence) -> bool:
        """Attach evidence and recompute confidence when inserted."""

        inserted = self.evidence.add(evidence)
        if inserted:
            self._recompute_confidence()
            self.last_seen = max(self.last_seen, evidence.timestamp)
            if self.first_seen > evidence.timestamp:
                self.first_seen = evidence.timestamp
        return inserted

    def merge_from(self, incoming: "BaseAsset") -> bool:
        """Merge another asset with the same concrete type and identity.

        Returns True when any field changed.
        """

        if type(self) is not type(incoming):
            raise TypeError(f"Cannot merge {type(incoming)} into {type(self)}")

        changed = False
        if incoming.first_seen < self.first_seen:
            self.first_seen = incoming.first_seen
            changed = True
        if incoming.last_seen > self.last_seen:
            self.last_seen = incoming.last_seen
            changed = True

        before_tags = set(self.tags)
        self.tags.update(incoming.tags)
        if self.tags != before_tags:
            changed = True

        merged_metadata = _merge_metadata(self.metadata, incoming.metadata)
        if merged_metadata != self.metadata:
            self.metadata = merged_metadata
            changed = True

        inserted = self.evidence.extend(incoming.evidence.items)
        if inserted:
            changed = True

        if incoming.confidence > self.confidence:
            self.confidence = incoming.confidence
            changed = True

        before_confidence = self.confidence
        self._recompute_confidence()
        if self.confidence != before_confidence:
            changed = True

        return changed

    def _recompute_confidence(self) -> None:
        """Update confidence using evidence corroboration logic.

        We model confidence as the complement of independent failure across
        evidence items. A small source-diversity bonus rewards corroboration
        from independent tools without making confidence explode to 1.0 too fast.
        """

        if not self.evidence.items:
            self.confidence = clamp_confidence(self.confidence)
            return

        complement = 1.0
        for item in self.evidence.items:
            contribution = clamp_confidence(item.confidence) * 0.9
            complement *= 1.0 - contribution

        source_bonus = min(0.20, 0.04 * max(0, self.evidence.source_count() - 1))
        merged_confidence = 1.0 - complement + source_bonus
        self.confidence = clamp_confidence(max(self.confidence, merged_confidence))

    def to_dict(self) -> dict[str, Any]:
        """Serialize as JSON-safe dict for storage/export."""

        return {
            "asset_type": self.asset_type,
            "id": self.id,
            "canonical_key": self.canonical_key,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "confidence": self.confidence,
            "tags": sorted(self.tags),
            "metadata": self.metadata,
            "evidence": self.evidence.dump(),
            **self._type_payload(),
        }

    def _type_payload(self) -> dict[str, Any]:
        """Subclass payload for serialization."""

        raise NotImplementedError


@dataclass(kw_only=True)
class Host(BaseAsset):
    """A resolved host represented by canonical IP or hostname."""

    value: str
    kind: str = "domain"
    ip: str | None = None
    hostname: str | None = None
    aliases: list[str] = field(default_factory=list)

    ASSET_TYPE: ClassVar[str] = "host"

    def __post_init__(self) -> None:
        parsed: CanonicalHost = canonical_host(self.value)
        self.value = parsed.value
        self.kind = parsed.kind
        if parsed.ip:
            self.ip = parsed.ip
        if parsed.hostname:
            self.hostname = parsed.hostname
        self.aliases = sorted({normalize_hostname(alias) for alias in self.aliases if alias})
        super().__post_init__()

    def canonical_parts(self) -> tuple[str, ...]:
        return (self.kind, self.value)

    def merge_from(self, incoming: BaseAsset) -> bool:
        changed = super().merge_from(incoming)
        assert isinstance(incoming, Host)

        if incoming.ip and not self.ip:
            self.ip = incoming.ip
            changed = True
        if incoming.hostname and not self.hostname:
            self.hostname = incoming.hostname
            changed = True

        merged_aliases = set(self.aliases).union(incoming.aliases)
        if merged_aliases != set(self.aliases):
            self.aliases = sorted(merged_aliases)
            changed = True

        return changed

    def _type_payload(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "kind": self.kind,
            "ip": self.ip,
            "hostname": self.hostname,
            "aliases": self.aliases,
        }


@dataclass(kw_only=True)
class Port(BaseAsset):
    """A transport-level open/observed port on a host."""

    host_id: str
    number: int
    protocol: str = "tcp"
    state: str = "open"

    ASSET_TYPE: ClassVar[str] = "port"

    def __post_init__(self) -> None:
        self.protocol = normalize_protocol(self.protocol)
        self.state = self.state.strip().lower() if self.state else "unknown"
        super().__post_init__()

    def canonical_parts(self) -> tuple[str, ...]:
        return (self.host_id, self.protocol, str(self.number))

    def merge_from(self, incoming: BaseAsset) -> bool:
        changed = super().merge_from(incoming)
        assert isinstance(incoming, Port)

        state_priority = {"open": 3, "filtered": 2, "closed": 1, "unknown": 0}
        if state_priority.get(incoming.state, 0) > state_priority.get(self.state, 0):
            self.state = incoming.state
            changed = True
        return changed

    def _type_payload(self) -> dict[str, Any]:
        return {
            "host_id": self.host_id,
            "number": self.number,
            "protocol": self.protocol,
            "state": self.state,
        }


@dataclass(kw_only=True)
class Service(BaseAsset):
    """A service fingerprint running on a host/port."""

    host_id: str
    name: str
    protocol: str = "tcp"
    port_id: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    cpe: list[str] = field(default_factory=list)

    ASSET_TYPE: ClassVar[str] = "service"

    def __post_init__(self) -> None:
        self.name = normalize_service_name(self.name)
        self.protocol = normalize_protocol(self.protocol)
        self.product = self.product.strip() if self.product else None
        self.version = self.version.strip() if self.version else None
        self.banner = self.banner.strip() if self.banner else None
        self.cpe = sorted({item.strip().lower() for item in self.cpe if item})
        super().__post_init__()

    def canonical_parts(self) -> tuple[str, ...]:
        port_key = self.port_id or "no-port"
        return (self.host_id, port_key, self.protocol, self.name)

    def merge_from(self, incoming: BaseAsset) -> bool:
        changed = super().merge_from(incoming)
        assert isinstance(incoming, Service)

        if incoming.port_id and not self.port_id:
            self.port_id = incoming.port_id
            changed = True
        if incoming.product and not self.product:
            self.product = incoming.product
            changed = True
        if incoming.version and not self.version:
            self.version = incoming.version
            changed = True
        if incoming.banner and not self.banner:
            self.banner = incoming.banner
            changed = True

        merged_cpe = set(self.cpe).union(incoming.cpe)
        if merged_cpe != set(self.cpe):
            self.cpe = sorted(merged_cpe)
            changed = True

        return changed

    def _type_payload(self) -> dict[str, Any]:
        return {
            "host_id": self.host_id,
            "name": self.name,
            "protocol": self.protocol,
            "port_id": self.port_id,
            "product": self.product,
            "version": self.version,
            "banner": self.banner,
            "cpe": self.cpe,
        }


@dataclass(kw_only=True)
class Endpoint(BaseAsset):
    """HTTP/API endpoint discovered from probe results."""

    host_id: str
    url: str
    service_id: str | None = None
    scheme: str | None = None
    port: int | None = None
    path: str | None = None
    status_code: int | None = None
    title: str | None = None
    technologies: list[str] = field(default_factory=list)

    ASSET_TYPE: ClassVar[str] = "endpoint"

    def __post_init__(self) -> None:
        normalized_url = normalize_url(self.url)
        split = urlsplit(normalized_url)

        self.url = normalized_url
        self.scheme = self.scheme or extract_scheme_from_url(normalized_url)
        self.port = self.port if self.port is not None else extract_port_from_url(normalized_url)
        self.path = normalize_path(self.path if self.path is not None else split.path)
        self.title = self.title.strip() if self.title else None
        self.technologies = normalize_tech_list(self.technologies)
        super().__post_init__()

    def canonical_parts(self) -> tuple[str, ...]:
        service_key = self.service_id or "no-service"
        return (self.host_id, service_key, self.url)

    def merge_from(self, incoming: BaseAsset) -> bool:
        changed = super().merge_from(incoming)
        assert isinstance(incoming, Endpoint)

        if incoming.service_id and not self.service_id:
            self.service_id = incoming.service_id
            changed = True
        if incoming.scheme and not self.scheme:
            self.scheme = incoming.scheme
            changed = True
        if incoming.port and not self.port:
            self.port = incoming.port
            changed = True
        if incoming.path and (not self.path or len(incoming.path) > len(self.path)):
            self.path = incoming.path
            changed = True
        if incoming.status_code is not None and self.status_code is None:
            self.status_code = incoming.status_code
            changed = True
        if incoming.title and not self.title:
            self.title = incoming.title
            changed = True

        merged_tech = set(self.technologies).union(incoming.technologies)
        if merged_tech != set(self.technologies):
            self.technologies = sorted(merged_tech)
            changed = True

        return changed

    def _type_payload(self) -> dict[str, Any]:
        return {
            "host_id": self.host_id,
            "url": self.url,
            "service_id": self.service_id,
            "scheme": self.scheme,
            "port": self.port,
            "path": self.path,
            "status_code": self.status_code,
            "title": self.title,
            "technologies": self.technologies,
        }


@dataclass(kw_only=True)
class Finding(BaseAsset):
    """A normalized security or exposure finding."""

    target_asset_id: str
    title: str
    severity: str = "info"
    category: str = "general"
    description: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    external_id: str | None = None
    tier: str = "raw"
    reasoning: str | None = None

    ASSET_TYPE: ClassVar[str] = "finding"

    def __post_init__(self) -> None:
        self.title = self.title.strip()
        self.category = self.category.strip().lower() if self.category else "general"
        self.severity = normalize_severity(self.severity)
        self.description = self.description.strip() if self.description else None
        self.cve_ids = sorted({normalize_cve_id(item) for item in self.cve_ids if item})
        self.references = sorted({item.strip() for item in self.references if item and item.strip()})
        self.tier = normalize_tier(self.tier)
        self.reasoning = self.reasoning.strip() if self.reasoning else None
        super().__post_init__()

    def canonical_parts(self) -> tuple[str, ...]:
        external = self.external_id or "no-external"
        cve_key = ",".join(self.cve_ids)
        return (self.target_asset_id, self.category, self.title.lower(), external, cve_key)

    def merge_from(self, incoming: BaseAsset) -> bool:
        changed = super().merge_from(incoming)
        assert isinstance(incoming, Finding)

        stronger = choose_higher_severity(self.severity, incoming.severity)
        if stronger != self.severity:
            self.severity = stronger
            changed = True

        if incoming.description and not self.description:
            self.description = incoming.description
            changed = True
        if incoming.external_id and not self.external_id:
            self.external_id = incoming.external_id
            changed = True
        if incoming.reasoning and not self.reasoning:
            self.reasoning = incoming.reasoning
            changed = True

        merged_cves = set(self.cve_ids).union(incoming.cve_ids)
        if merged_cves != set(self.cve_ids):
            self.cve_ids = sorted(merged_cves)
            changed = True

        merged_refs = set(self.references).union(incoming.references)
        if merged_refs != set(self.references):
            self.references = sorted(merged_refs)
            changed = True

        next_tier = stronger_tier(self.tier, incoming.tier)
        if next_tier != self.tier:
            self.tier = next_tier
            changed = True

        return changed

    def _type_payload(self) -> dict[str, Any]:
        return {
            "target_asset_id": self.target_asset_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "cve_ids": self.cve_ids,
            "references": self.references,
            "external_id": self.external_id,
            "tier": self.tier,
            "reasoning": self.reasoning,
        }


Asset = Union[Host, Port, Service, Endpoint, Finding]


ASSET_REGISTRY: dict[str, Type[BaseAsset]] = {
    Host.ASSET_TYPE: Host,
    Port.ASSET_TYPE: Port,
    Service.ASSET_TYPE: Service,
    Endpoint.ASSET_TYPE: Endpoint,
    Finding.ASSET_TYPE: Finding,
}


def asset_from_dict(data: dict[str, Any]) -> BaseAsset:
    """Deserialize concrete asset from a dictionary payload."""

    asset_type = str(data.get("asset_type", "")).lower()
    cls = ASSET_REGISTRY.get(asset_type)
    if cls is None:
        raise ValueError(f"Unsupported asset_type '{asset_type}'")

    common = {
        "first_seen": str(data.get("first_seen", utc_now_iso())),
        "last_seen": str(data.get("last_seen", utc_now_iso())),
        "confidence": float(data.get("confidence", 0.5)),
        "evidence": EvidenceBag.load(list(data.get("evidence", []))),
        "tags": set(data.get("tags", [])),
        "metadata": dict(data.get("metadata", {})),
    }

    if cls is Host:
        asset = Host(
            value=str(data.get("value", "")),
            kind=str(data.get("kind", "domain")),
            ip=data.get("ip"),
            hostname=data.get("hostname"),
            aliases=list(data.get("aliases", [])),
            **common,
        )
    elif cls is Port:
        asset = Port(
            host_id=str(data.get("host_id", "")),
            number=int(data.get("number", 0)),
            protocol=str(data.get("protocol", "tcp")),
            state=str(data.get("state", "open")),
            **common,
        )
    elif cls is Service:
        asset = Service(
            host_id=str(data.get("host_id", "")),
            name=str(data.get("name", "unknown")),
            protocol=str(data.get("protocol", "tcp")),
            port_id=data.get("port_id"),
            product=data.get("product"),
            version=data.get("version"),
            banner=data.get("banner"),
            cpe=list(data.get("cpe", [])),
            **common,
        )
    elif cls is Endpoint:
        asset = Endpoint(
            host_id=str(data.get("host_id", "")),
            url=str(data.get("url", "")),
            service_id=data.get("service_id"),
            scheme=data.get("scheme"),
            port=data.get("port"),
            path=data.get("path"),
            status_code=data.get("status_code"),
            title=data.get("title"),
            technologies=list(data.get("technologies", [])),
            **common,
        )
    elif cls is Finding:
        asset = Finding(
            target_asset_id=str(data.get("target_asset_id", "")),
            title=str(data.get("title", "untitled finding")),
            severity=str(data.get("severity", "info")),
            category=str(data.get("category", "general")),
            description=data.get("description"),
            cve_ids=list(data.get("cve_ids", [])),
            references=list(data.get("references", [])),
            external_id=data.get("external_id"),
            tier=str(data.get("tier", "raw")),
            reasoning=data.get("reasoning"),
            **common,
        )
    else:
        raise ValueError(f"No deserializer implemented for asset type '{asset_type}'")

    # Preserve original IDs/keys when loading persisted state.
    incoming_id = data.get("id")
    if isinstance(incoming_id, str) and incoming_id:
        asset.id = incoming_id
    incoming_key = data.get("canonical_key")
    if isinstance(incoming_key, str) and incoming_key:
        asset.canonical_key = incoming_key

    return asset


def group_assets_by_type(assets: Iterable[BaseAsset]) -> dict[str, list[BaseAsset]]:
    """Group asset list by concrete asset type."""

    grouped: dict[str, list[BaseAsset]] = {}
    for asset in assets:
        grouped.setdefault(asset.asset_type, []).append(asset)
    return grouped
