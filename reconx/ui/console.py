"""Rich-powered console/TUI renderer for ReconX.

Provides live progress tables, finding panels, and run summary output
using the Rich library. Falls back to plain text if Rich is unavailable.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from dataclasses import dataclass, field
from typing import Any

from reconx.core.assets import Finding
from reconx.core.event_bus import Event, EventBus
from reconx.core.scheduler import TaskStatusEvent

logger = logging.getLogger(__name__)

# Attempt Rich import; degrade gracefully
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.live import Live
    from rich.columns import Columns

    HAS_RICH = True
except ImportError:
    HAS_RICH = False

SEVERITY_COLORS: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim white",
}

TIER_SYMBOLS: dict[str, str] = {
    "validated": "✓",
    "probable": "◎",
    "raw": "○",
}

STATUS_COLORS: dict[str, str] = {
    "queued": "dim white",
    "running": "bold cyan",
    "completed": "green",
    "failed": "bold red",
    "cancelled": "yellow",
    "skipped": "dim yellow",
}


@dataclass(slots=True)
class ModuleStatus:
    """Progress counters for one module."""
    queued: int = 0
    running: int = 0
    completed: int = 0
    failed: int = 0
    cancelled: int = 0
    skipped: int = 0


@dataclass(slots=True)
class ConsoleState:
    """Mutable render state."""
    modules: dict[str, ModuleStatus] = field(default_factory=dict)
    findings_printed: set[str] = field(default_factory=set)
    findings_buffer: list[Finding] = field(default_factory=list)
    debug: bool = False
    validated_only: bool = True
    total_assets: int = 0
    total_relations: int = 0


class ConsoleRenderer:
    """Async console renderer subscribed to the event bus.

    When Rich is available, renders styled panels and tables.
    Otherwise falls back to plain stdout lines.
    """

    def __init__(self, *, debug: bool = False, validated_only: bool = True) -> None:
        self.state = ConsoleState(debug=debug, validated_only=validated_only)
        self._stop = asyncio.Event()
        self._console = Console(stderr=False) if HAS_RICH else None

    def stop(self) -> None:
        """Signal the renderer to stop."""
        self._stop.set()

    async def attach(self, event_bus: EventBus) -> None:
        """Consume event stream until stopped."""
        async for event in event_bus.stream():
            if self._stop.is_set():
                break
            await self._handle_event(event)

    async def _handle_event(self, event: Event[Any]) -> None:
        """Route events to appropriate render handlers."""

        if event.topic == "task.status" and isinstance(event.payload, TaskStatusEvent):
            self._update_module_status(event.payload)
            self._print_task_status(event.payload)
            return

        if event.topic == "asset.finding" and isinstance(event.payload, Finding):
            self._print_finding(event.payload)
            return

        if event.topic.startswith("asset."):
            self.state.total_assets += 1

        if event.topic == "relation.created":
            self.state.total_relations += 1

        if event.topic == "run.started":
            self._print_run_header(event.payload)

        if event.topic == "run.completed":
            self._print_run_footer(event.payload)

        if self.state.debug:
            self._write(f"[debug] {event.topic} {event.metadata}")

    def _update_module_status(self, payload: TaskStatusEvent) -> None:
        """Track module status transitions."""
        module = self.state.modules.setdefault(payload.module, ModuleStatus())
        status = payload.status
        if hasattr(module, status):
            setattr(module, status, getattr(module, status) + 1)

    def _print_run_header(self, payload: Any) -> None:
        """Print run start banner."""
        if self._console and HAS_RICH:
            header = Table.grid(padding=(0, 2))
            header.add_column(style="bold cyan")
            header.add_column()
            header.add_row("Run ID", str(payload.get("run_id", "?")))
            header.add_row("Profile", str(payload.get("profile", "?")))
            header.add_row("Inputs", str(payload.get("planned_inputs", "?")))
            panel = Panel(
                header,
                title="[bold green]⚡ ReconX Ingestion Started",
                border_style="green",
                padding=(1, 2),
            )
            self._console.print(panel)
        else:
            run_id = payload.get("run_id", "?") if isinstance(payload, dict) else "?"
            self._write(f"=== ReconX Run Started: {run_id} ===")

    def _print_run_footer(self, payload: Any) -> None:
        """Print run completion summary."""
        if self._console and HAS_RICH:
            scheduler = payload.get("scheduler", {}) if isinstance(payload, dict) else {}
            status = payload.get("status", "?") if isinstance(payload, dict) else "?"
            status_style = "green" if status == "completed" else "yellow"

            footer = Table.grid(padding=(0, 2))
            footer.add_column(style="bold")
            footer.add_column()
            footer.add_row("Status", f"[{status_style}]{status}[/]")
            footer.add_row("Completed", str(scheduler.get("completed", 0)))
            footer.add_row("Failed", str(scheduler.get("failed", 0)))
            footer.add_row("Assets", str(self.state.total_assets))
            footer.add_row("Relations", str(self.state.total_relations))
            footer.add_row("Findings", str(len(self.state.findings_printed)))

            panel = Panel(
                footer,
                title="[bold green]✔ Ingestion Complete",
                border_style="green",
                padding=(1, 2),
            )
            self._console.print(panel)
        else:
            self._write("=== Run Complete ===")

    def _print_task_status(self, payload: TaskStatusEvent) -> None:
        """Print task status transition."""
        if payload.status not in {"running", "completed", "failed", "cancelled", "skipped"}:
            return

        counters = self.state.modules.get(payload.module, ModuleStatus())

        if self._console and HAS_RICH:
            color = STATUS_COLORS.get(payload.status, "white")
            line = Text()
            line.append("  ● ", style="dim")
            line.append(f"[{payload.module}] ", style="bold dim")
            line.append(f"{payload.name} ", style="white")
            line.append(f"→ {payload.status} ", style=color)
            line.append(
                f"(✓{counters.completed} ✗{counters.failed} ⏳{counters.running})",
                style="dim",
            )
            if payload.error:
                line.append(f" err={payload.error}", style="red")
            self._console.print(line)
        else:
            msg = (
                f"  [{payload.module}] {payload.name} -> {payload.status} "
                f"(c:{counters.completed} f:{counters.failed} r:{counters.running})"
            )
            if payload.error:
                msg += f" error={payload.error}"
            self._write(msg)

    def _print_finding(self, finding: Finding) -> None:
        """Print a finding with severity-appropriate styling."""
        if finding.id in self.state.findings_printed:
            return
        if self.state.validated_only and finding.tier not in {"validated", "probable"}:
            if self.state.debug:
                self._write(f"  [debug] suppressed: {finding.id} tier={finding.tier}")
            return

        self.state.findings_printed.add(finding.id)
        self.state.findings_buffer.append(finding)

        if self._console and HAS_RICH:
            sev = finding.severity.upper()
            color = SEVERITY_COLORS.get(finding.severity, "white")
            tier_sym = TIER_SYMBOLS.get(finding.tier, "?")

            content = Table.grid(padding=(0, 1))
            content.add_column(style="bold", min_width=10)
            content.add_column()
            content.add_row("Title", finding.title)
            content.add_row("Target", finding.target_asset_id)
            content.add_row("Confidence", f"{finding.confidence:.2f}")
            content.add_row("Tier", f"{tier_sym} {finding.tier}")
            if finding.cve_ids:
                content.add_row("CVEs", ", ".join(finding.cve_ids))
            if finding.reasoning:
                content.add_row("Reason", finding.reasoning[:120])

            panel = Panel(
                content,
                title=f"[{color}]⚠ {sev}[/] Finding",
                border_style=color,
                padding=(0, 1),
            )
            self._console.print(panel)
        else:
            self._write(
                " | ".join([
                    f"FINDING {finding.severity.upper()}",
                    f"tier={finding.tier}",
                    finding.title,
                    f"target={finding.target_asset_id}",
                    f"conf={finding.confidence:.2f}",
                ])
            )

    def print_findings_summary(self, findings: list[Finding]) -> None:
        """Print a tabular findings summary (called after run completes)."""
        if not findings:
            return

        if self._console and HAS_RICH:
            table = Table(
                title="Findings Summary",
                show_lines=True,
                header_style="bold cyan",
                border_style="dim",
            )
            table.add_column("Severity", style="bold", width=10)
            table.add_column("Tier", width=10)
            table.add_column("Title", min_width=30)
            table.add_column("CVEs", width=20)
            table.add_column("Conf", width=6, justify="right")

            for f in findings:
                color = SEVERITY_COLORS.get(f.severity, "white")
                tier_sym = TIER_SYMBOLS.get(f.tier, "?")
                table.add_row(
                    f"[{color}]{f.severity.upper()}[/]",
                    f"{tier_sym} {f.tier}",
                    f.title[:60],
                    ", ".join(f.cve_ids[:2]) if f.cve_ids else "-",
                    f"{f.confidence:.2f}",
                )
            self._console.print(table)
        else:
            self._write("--- Findings Summary ---")
            for f in findings:
                self._write(f"  {f.severity.upper()} | {f.tier} | {f.title}")

    def _write(self, text: str) -> None:
        """Write a plain text line to stdout."""
        print(text, file=sys.stdout, flush=True)
