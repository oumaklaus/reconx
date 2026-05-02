"""Deterministic hashing helpers used across asset models.

ReconX depends heavily on stable IDs so that multiple ingest runs can merge
evidence from independent scanner outputs. These helpers intentionally avoid
runtime-randomized behavior and always sort keys for repeatable hashes.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


def stable_json(value: Any) -> str:
    """Return a deterministic JSON representation of ``value``.

    The output is used as hash input, so we force sorted keys and compact
    separators to ensure IDs remain stable across Python versions.
    """

    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def hash_text(text: str, *, length: int = 20) -> str:
    """Hash a text value and return a short hexadecimal digest."""

    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return digest[:length]


def deterministic_id(prefix: str, *parts: object, length: int = 20) -> str:
    """Generate a deterministic ID with a semantic prefix.

    Example:
        >>> deterministic_id("host", "ip", "192.168.1.10")
        'host_4f8b2c...'
    """

    serialized = stable_json([str(part) for part in parts])
    return f"{prefix}_{hash_text(serialized, length=length)}"


def hash_mapping(prefix: str, mapping: Mapping[str, Any], *, length: int = 20) -> str:
    """Hash an arbitrary mapping in a deterministic manner."""

    return f"{prefix}_{hash_text(stable_json(mapping), length=length)}"
