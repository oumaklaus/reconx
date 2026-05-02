"""Base adapter interfaces for defensive scan-output ingestion."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from reconx.core.assets import BaseAsset
from reconx.core.event_bus import EventBus


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AdapterContext:
    """Execution context passed into adapters.

    Adapters can use this context to emit assets/events and inspect runtime
    options in a way that is decoupled from CLI-specific argument parsing.
    """

    event_bus: EventBus
    run_id: str
    profile: str
    debug: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    async def emit_asset(self, asset: BaseAsset, *, source: str) -> None:
        """Emit one asset event with source metadata."""

        await self.event_bus.emit_asset(
            asset,
            metadata={
                "run_id": self.run_id,
                "source": source,
                **self.metadata,
            },
        )


@dataclass(slots=True)
class AdapterInput:
    """One adapter unit of work.

    ``kind`` indicates how to interpret value:
    - ``path``: file path containing scanner output
    - ``asset``: previously discovered typed asset
    """

    kind: str
    value: Any
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AdapterRunResult:
    """Result summary from one adapter invocation."""

    adapter: str
    processed: int
    emitted: int
    errors: list[str] = field(default_factory=list)


class BaseAdapter(ABC):
    """Abstract base class for all scanner ingestion adapters."""

    name: str = "base"
    accepted_asset_types: set[str] = set()
    accepted_file_patterns: tuple[str, ...] = tuple()

    def accepts_asset(self, asset: BaseAsset) -> bool:
        """Return True when adapter can process this asset type."""

        return asset.asset_type in self.accepted_asset_types

    def accepts_path(self, path: Path) -> bool:
        """Return True when adapter can process this file path."""

        lowercase = path.name.lower()
        return any(lowercase.endswith(pattern) for pattern in self.accepted_file_patterns)

    def accepts_input(self, item: AdapterInput) -> bool:
        """Check if this adapter accepts an input item."""

        if item.kind == "asset" and isinstance(item.value, BaseAsset):
            return self.accepts_asset(item.value)
        if item.kind == "path":
            return self.accepts_path(Path(str(item.value)))
        return False

    async def run_many(self, items: Iterable[AdapterInput], context: AdapterContext) -> AdapterRunResult:
        """Process multiple adapter inputs sequentially.

        Parallelism is handled by the scheduler at a higher layer; this method
        intentionally keeps per-adapter logic simple and deterministic.
        """

        processed = 0
        emitted = 0
        errors: list[str] = []

        for item in items:
            if not self.accepts_input(item):
                continue
            processed += 1
            try:
                emitted += await self.run(item, context)
            except Exception as exc:  # noqa: BLE001
                message = f"{self.name} failed for {item.kind}:{item.value} -> {exc}"
                logger.exception(message)
                errors.append(message)

        return AdapterRunResult(adapter=self.name, processed=processed, emitted=emitted, errors=errors)

    async def emit(self, context: AdapterContext, asset: BaseAsset, *, source_suffix: str = "") -> None:
        """Emit normalized asset using context event bus."""

        source = self.name if not source_suffix else f"{self.name}.{source_suffix}"
        await context.emit_asset(asset, source=source)

    @abstractmethod
    async def run(self, item: AdapterInput, context: AdapterContext) -> int:
        """Process one input item and return emitted asset count."""


async def run_subprocess_json(command: list[str], *, timeout: float = 60.0) -> dict[str, Any]:
    """Run subprocess and parse stdout as JSON.

    While adapters in this defensive ingestion flow primarily read files, this
    helper enables optional parser-tool invocations where scanner output needs
    lightweight conversion before normalization.
    """

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise RuntimeError(f"Subprocess timed out: {' '.join(command)}")

    if process.returncode != 0:
        raise RuntimeError(
            f"Subprocess failed ({process.returncode}): {' '.join(command)}: {stderr.decode('utf-8', 'ignore')}"
        )

    import json

    text = stdout.decode("utf-8", "ignore").strip()
    if not text:
        return {}
    return json.loads(text)
