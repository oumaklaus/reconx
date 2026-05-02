"""Evidence primitives for ReconX asset confidence and provenance.

ReconX merges data from multiple scanner outputs. Every normalized asset and
relation carries one or more Evidence entries so analysts can inspect how a
fact was derived and score trust accordingly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from reconx.utils.hashing import hash_mapping, stable_json
from reconx.utils.normalization import clamp_confidence


def utc_now_iso() -> str:
    """Return an RFC3339-like UTC timestamp string."""

    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Evidence:
    """One piece of provenance information for an entity.

    Attributes:
        source: Tool or component that produced the evidence.
        raw: Raw scanner record (or a compact subset) for traceability.
        confidence: Confidence of this single evidence item in [0, 1].
        timestamp: Collection timestamp in UTC.
        note: Optional human-readable explanation.
        metadata: Additional structured context fields.
    """

    source: str
    raw: dict[str, Any] | str
    confidence: float = 0.5
    timestamp: str = field(default_factory=utc_now_iso)
    note: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        self.confidence = clamp_confidence(self.confidence)
        payload = {
            "source": self.source,
            "raw": self.raw,
            "note": self.note,
            "metadata": self.metadata,
        }
        self.fingerprint = hash_mapping("ev", payload)

    def to_dict(self) -> dict[str, Any]:
        """Serialize evidence to a plain dictionary for storage/export."""

        return {
            "source": self.source,
            "raw": self.raw,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "note": self.note,
            "metadata": self.metadata,
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Evidence":
        """Deserialize an Evidence object from plain data."""

        instance = cls(
            source=str(data.get("source", "unknown")),
            raw=data.get("raw", {}),
            confidence=float(data.get("confidence", 0.5)),
            timestamp=str(data.get("timestamp", utc_now_iso())),
            note=data.get("note"),
            metadata=dict(data.get("metadata", {})),
        )
        # Preserve original fingerprint when it is present in persisted data.
        fingerprint = data.get("fingerprint")
        if isinstance(fingerprint, str) and fingerprint:
            instance.fingerprint = fingerprint
        return instance


@dataclass(slots=True)
class EvidenceBag:
    """Container that enforces evidence uniqueness by fingerprint."""

    items: list[Evidence] = field(default_factory=list)
    _index: set[str] = field(default_factory=set, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.items:
            unique: list[Evidence] = []
            for item in self.items:
                if item.fingerprint in self._index:
                    continue
                self._index.add(item.fingerprint)
                unique.append(item)
            self.items = unique

    def add(self, evidence: Evidence) -> bool:
        """Add an evidence item if it is new; return True on insertion."""

        if evidence.fingerprint in self._index:
            return False
        self._index.add(evidence.fingerprint)
        self.items.append(evidence)
        return True

    def extend(self, values: list[Evidence]) -> int:
        """Add multiple evidence items and return number of new records."""

        inserted = 0
        for item in values:
            if self.add(item):
                inserted += 1
        return inserted

    def by_source(self) -> dict[str, list[Evidence]]:
        """Group evidence entries by source adapter/tool."""

        grouped: dict[str, list[Evidence]] = {}
        for item in self.items:
            grouped.setdefault(item.source, []).append(item)
        return grouped

    def dump(self) -> list[dict[str, Any]]:
        """Serialize all evidence items to dictionaries."""

        return [item.to_dict() for item in self.items]

    @classmethod
    def load(cls, values: list[dict[str, Any]]) -> "EvidenceBag":
        """Construct an EvidenceBag from serialized evidence entries."""

        return cls([Evidence.from_dict(value) for value in values])

    def source_count(self) -> int:
        """Return number of unique evidence sources represented."""

        return len({item.source for item in self.items})

    def stable_signature(self) -> str:
        """Return deterministic signature useful for caches/checksums."""

        serialized = [item.to_dict() for item in sorted(self.items, key=lambda v: v.fingerprint)]
        return stable_json(serialized)
