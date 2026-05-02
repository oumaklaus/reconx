"""CLI command implementations for ReconX."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reconx.config.settings import Settings
from reconx.core.orchestrator import Orchestrator, RunSummary


def run_ingest_command(args: Any, settings: Settings) -> RunSummary:
    """Execute ingest command and return orchestrator summary."""

    orchestrator = Orchestrator(settings=settings)
    try:
        summary = orchestrator.ingest_sync(
            inputs=[Path(path) for path in args.inputs],
            profile_name=args.profile,
            output_format=args.output,
            output_path=args.output_path,
            debug=args.debug,
            show_raw_findings=args.show_raw,
            enable_console=not args.no_console,
        )
    finally:
        orchestrator.close()
    return summary


def print_summary(summary: RunSummary, *, as_json: bool = True) -> None:
    """Print run summary to stdout."""

    if as_json:
        print(json.dumps(summary.to_dict(), indent=2))
        return

    print(f"Run: {summary.run_id}")
    print(f"Profile: {summary.profile}")
    print(f"Planned inputs: {summary.planned_inputs}")
    if summary.ignored_paths:
        print(f"Ignored paths: {len(summary.ignored_paths)}")
    print(
        "Scheduler: "
        f"completed={summary.scheduler.completed} "
        f"failed={summary.scheduler.failed} "
        f"cancelled={summary.scheduler.cancelled} "
        f"skipped={summary.scheduler.skipped}"
    )
    print(f"Assets: {summary.asset_counts}")
    print(f"Relations: {summary.relation_count}")
    print(f"Findings by tier: {summary.finding_counts_by_tier}")
    if summary.output_path:
        print(f"Export: {summary.output_path}")
