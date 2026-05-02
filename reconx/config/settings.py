"""Configuration model and loaders for ReconX.

Settings are loaded from defaults, then optional YAML/JSON config file, then
environment variables. Environment variables use a double-underscore path style:

    RECONX_RUNTIME__WORKER_COUNT=8
    RECONX_STORAGE__DB_PATH=./state/reconx.db
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping


DEFAULT_CONFIG_CANDIDATES = (
    Path("reconx.yaml"),
    Path("reconx.yml"),
    Path("reconx.json"),
)


@dataclass(slots=True)
class RuntimeSettings:
    """Execution runtime controls."""

    worker_count: int = 6
    rate_limit_per_sec: float = 20.0
    max_retries: int = 2
    backoff_base_seconds: float = 0.5
    task_timeout_seconds: float = 120.0
    cancel_on_error: bool = False


@dataclass(slots=True)
class StorageSettings:
    """Storage and export paths."""

    db_path: str = "./reconx.db"
    export_dir: str = "./out"
    persist_event_log: bool = True


@dataclass(slots=True)
class CorrelationSettings:
    """Correlation and enrichment tuning values."""

    cve_dataset_path: str = "./samples/cve_dataset.json"
    probable_confidence_threshold: float = 0.60
    validated_confidence_threshold: float = 0.85
    validated_min_sources: int = 2
    high_value_path_rules_enabled: bool = True
    cve_enrichment_enabled: bool = True


@dataclass(slots=True)
class LoggingSettings:
    """Logging behavior for CLI and libraries."""

    level: str = "INFO"
    json: bool = False


@dataclass(slots=True)
class AdapterSettings:
    """Adapter-specific behavior toggles."""

    nmap_enabled: bool = True
    http_enabled: bool = True
    nuclei_enabled: bool = True
    strict_parsing: bool = False


@dataclass(slots=True)
class UISettings:
    """Console/TUI output behavior."""

    enabled: bool = True
    debug: bool = False
    show_raw_findings: bool = False
    validated_only: bool = True


@dataclass(slots=True)
class Settings:
    """Root settings object."""

    runtime: RuntimeSettings = field(default_factory=RuntimeSettings)
    storage: StorageSettings = field(default_factory=StorageSettings)
    correlation: CorrelationSettings = field(default_factory=CorrelationSettings)
    logging: LoggingSettings = field(default_factory=LoggingSettings)
    adapters: AdapterSettings = field(default_factory=AdapterSettings)
    ui: UISettings = field(default_factory=UISettings)

    def to_dict(self) -> dict[str, Any]:
        """Serialize settings tree into plain dictionary."""

        return asdict(self)


def _deep_update(base: dict[str, Any], incoming: Mapping[str, Any]) -> dict[str, Any]:
    """Recursively merge incoming dict into base dict."""

    merged = dict(base)
    for key, value in incoming.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), dict):
            merged[key] = _deep_update(merged[key], value)
        else:
            merged[key] = value
    return merged


def _coerce_env_value(value: str) -> Any:
    """Coerce environment string values into bool/int/float when possible."""

    lowered = value.strip().lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _path_to_nested_dict(path_parts: list[str], value: Any) -> dict[str, Any]:
    """Build nested dict from key path pieces."""

    if not path_parts:
        return {}
    cursor: dict[str, Any] = {}
    root = cursor
    for part in path_parts[:-1]:
        cursor[part] = {}
        cursor = cursor[part]
    cursor[path_parts[-1]] = value
    return root


def _load_config_file(path: Path) -> dict[str, Any]:
    """Load configuration mapping from YAML or JSON file."""

    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise RuntimeError("PyYAML is required for YAML configuration files") from exc
        loaded = yaml.safe_load(text) or {}
    elif suffix == ".json":
        loaded = json.loads(text)
    else:
        raise ValueError(f"Unsupported config extension '{path.suffix}'")
    if not isinstance(loaded, dict):
        raise ValueError("Configuration root must be a mapping object")
    return loaded


def _settings_from_dict(raw: dict[str, Any]) -> Settings:
    """Convert merged dict into typed Settings object."""

    runtime = RuntimeSettings(**dict(raw.get("runtime", {})))
    storage = StorageSettings(**dict(raw.get("storage", {})))
    correlation = CorrelationSettings(**dict(raw.get("correlation", {})))
    logging = LoggingSettings(**dict(raw.get("logging", {})))
    adapters = AdapterSettings(**dict(raw.get("adapters", {})))
    ui = UISettings(**dict(raw.get("ui", {})))
    return Settings(
        runtime=runtime,
        storage=storage,
        correlation=correlation,
        logging=logging,
        adapters=adapters,
        ui=ui,
    )


def _resolve_config_path(explicit_path: str | Path | None) -> Path | None:
    """Resolve the config path from explicit argument or default candidates."""

    if explicit_path is not None:
        path = Path(explicit_path)
        return path if path.exists() else None
    for candidate in DEFAULT_CONFIG_CANDIDATES:
        if candidate.exists():
            return candidate
    return None


def load_settings(
    config_path: str | Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
    env_prefix: str = "RECONX_",
) -> Settings:
    """Load effective settings from defaults + config file + env vars."""

    defaults = Settings().to_dict()
    merged = dict(defaults)

    resolved = _resolve_config_path(config_path)
    if resolved is not None:
        file_data = _load_config_file(resolved)
        merged = _deep_update(merged, file_data)

    env_map = env or os.environ
    prefix = env_prefix.upper()
    for key, value in env_map.items():
        if not key.startswith(prefix):
            continue
        tail = key[len(prefix) :]
        if not tail:
            continue
        parts = [part.strip().lower() for part in tail.split("__") if part.strip()]
        if not parts:
            continue
        nested = _path_to_nested_dict(parts, _coerce_env_value(value))
        merged = _deep_update(merged, nested)

    return _settings_from_dict(merged)
