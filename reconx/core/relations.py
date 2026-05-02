"""Typed relation edges between assets in the ReconX graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from reconx.core.evidence import EvidenceBag, utc_now_iso
from reconx.utils.hashing import deterministic_id
from reconx.utils.normalization import clamp_confidence


ALLOWED_RELATIONS: set[str] = {
    "resolves_to",   # domain host -> ip host
    "exposes",       # host -> port / endpoint
    "runs",          # port -> service
    "vulnerable_to", # asset -> finding
    "contains",      # endpoint -> endpoint or host -> endpoint
    "observed_on",   # finding -> asset
}


@dataclass(slots=True)
class Relation:
    """Directed relationship between two assets with evidence support."""

    source_id: str
    relation_type: str
    target_id: str
    confidence: float = 0.5
    first_seen: str = field(default_factory=utc_now_iso)
    last_seen: str = field(default_factory=utc_now_iso)
    evidence: EvidenceBag = field(default_factory=EvidenceBag)
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(init=False)

    def __post_init__(self) -> None:
        relation = self.relation_type.strip().lower()
        if relation not in ALLOWED_RELATIONS:
            raise ValueError(
                f"Unsupported relation type '{self.relation_type}'. "
                f"Expected one of {sorted(ALLOWED_RELATIONS)}"
            )
        self.relation_type = relation
        self.confidence = clamp_confidence(self.confidence)
        self.id = deterministic_id("rel", self.source_id, self.relation_type, self.target_id)

    def merge_from(self, incoming: "Relation") -> bool:
        """Merge another relation edge with identical identity."""

        if self.id != incoming.id:
            raise ValueError("Cannot merge relations with different IDs")

        changed = False
        if incoming.first_seen < self.first_seen:
            self.first_seen = incoming.first_seen
            changed = True
        if incoming.last_seen > self.last_seen:
            self.last_seen = incoming.last_seen
            changed = True
        if incoming.confidence > self.confidence:
            self.confidence = incoming.confidence
            changed = True

        inserted = self.evidence.extend(incoming.evidence.items)
        if inserted:
            changed = True
            source_bonus = min(0.15, 0.03 * max(0, self.evidence.source_count() - 1))
            self.confidence = clamp_confidence(max(self.confidence, self.confidence + source_bonus))

        if incoming.metadata:
            merged = dict(self.metadata)
            merged.update(incoming.metadata)
            if merged != self.metadata:
                self.metadata = merged
                changed = True

        return changed

    def to_dict(self) -> dict[str, Any]:
        """Serialize relation edge for storage/export."""

        return {
            "id": self.id,
            "source_id": self.source_id,
            "relation_type": self.relation_type,
            "target_id": self.target_id,
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "evidence": self.evidence.dump(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Relation":
        """Deserialize relation from plain dictionary."""

        instance = cls(
            source_id=str(data.get("source_id", "")),
            relation_type=str(data.get("relation_type", "contains")),
            target_id=str(data.get("target_id", "")),
            confidence=float(data.get("confidence", 0.5)),
            first_seen=str(data.get("first_seen", utc_now_iso())),
            last_seen=str(data.get("last_seen", utc_now_iso())),
            evidence=EvidenceBag.load(list(data.get("evidence", []))),
            metadata=dict(data.get("metadata", {})),
        )
        incoming_id = data.get("id")
        if isinstance(incoming_id, str) and incoming_id:
            instance.id = incoming_id
        return instance
