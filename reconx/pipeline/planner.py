"""Input planning for ingestion runs.

The planner classifies files by adapter compatibility and produces adapter input
units that can be scheduled independently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from reconx.adapters.base import AdapterInput, BaseAdapter
from reconx.pipeline.profiles import Profile


@dataclass(slots=True)
class Plan:
    """Execution plan produced from profile and input paths."""

    profile_name: str
    adapter_inputs: dict[str, list[AdapterInput]] = field(default_factory=dict)
    ignored_paths: list[Path] = field(default_factory=list)

    @property
    def total_inputs(self) -> int:
        """Total planned adapter input count."""

        return sum(len(items) for items in self.adapter_inputs.values())


class Planner:
    """Build execution plans from input files/directories."""

    def __init__(self, adapters: list[BaseAdapter]) -> None:
        self._adapters = {adapter.name: adapter for adapter in adapters}

    def build_plan(self, paths: list[str | Path], profile: Profile) -> Plan:
        """Create an adapter plan for selected profile."""

        enabled_adapters = {
            name: adapter
            for name, adapter in self._adapters.items()
            if name in profile.enabled_adapters
        }

        plan = Plan(profile_name=profile.name)
        for name in enabled_adapters:
            plan.adapter_inputs[name] = []

        for path in self._expand_paths(paths):
            matched_any = False
            for name, adapter in enabled_adapters.items():
                if adapter.accepts_path(path):
                    plan.adapter_inputs[name].append(
                        AdapterInput(kind="path", value=str(path), metadata={"planned_by": "planner"})
                    )
                    matched_any = True
            if not matched_any:
                plan.ignored_paths.append(path)

        return plan

    def _expand_paths(self, values: list[str | Path]) -> list[Path]:
        """Expand file and directory arguments into file paths."""

        files: list[Path] = []
        for value in values:
            path = Path(value)
            if path.is_dir():
                files.extend(sorted(item for item in path.rglob("*") if item.is_file()))
            elif path.is_file():
                files.append(path)
        return files
