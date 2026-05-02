"""Shared adapter parsing helpers."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable


def read_text(path: Path) -> str:
    """Read UTF-8 text from path."""

    return path.read_text(encoding="utf-8")


def load_json_file(path: Path) -> Any:
    """Load complete JSON file from path."""

    return json.loads(read_text(path))


def iter_json_lines(path: Path) -> Iterable[dict[str, Any]]:
    """Yield JSON objects from newline-delimited file."""

    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_number}: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"Expected JSON object in {path}:{line_number}")
            yield value


def iter_csv_rows(path: Path) -> Iterable[dict[str, str]]:
    """Yield rows from CSV file as dictionaries."""

    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            yield dict(row)


def safe_int(value: Any, default: int | None = None) -> int | None:
    """Best-effort int conversion."""

    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def safe_float(value: Any, default: float | None = None) -> float | None:
    """Best-effort float conversion."""

    if value is None:
        return default
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def pick_first(mapping: dict[str, Any], candidates: list[str], default: Any = None) -> Any:
    """Return first present key value from mapping."""

    for key in candidates:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return default
