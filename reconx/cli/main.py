"""ReconX command line entrypoint.

Supports two modes:
  Active:  reconx <target>           — runs full recon pipeline
  Ingest:  reconx ingest <files>     — passive file ingestion (legacy)
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Sequence

from reconx.cli.commands import print_summary, run_ingest_command
from reconx.config.settings import load_settings
from reconx.utils.logging import configure_logging

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


BANNER = r"""
    ____                      _  __
   / __ \___  _________  ____| |/ /
  / /_/ / _ \/ ___/ __ \/ __ \   /
 / _, _/  __/ /__/ /_/ / / / /  |
/_/ |_|\___/\___/\____/_/ /_/_/|_|
"""


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""

    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX — Active Recon & Attack Surface Management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  reconx 10.10.11.194              Full recon on a target\n"
            "  reconx example.htb --web         Web-focused recon\n"
            "  reconx 10.10.11.194 --quick      Quick port scan only\n"
            "  reconx ingest scan.xml           Passive file ingestion\n"
        ),
    )
    parser.add_argument("--config", help="Path to YAML/JSON config file", default=None)
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--version", action="version", version="reconx 1.0.0")

    subparsers = parser.add_subparsers(dest="command")

    # ── Active scan mode ──────────────────────────────────────────────────
    scan = subparsers.add_parser("scan", help="Active recon scan (also the default)")
    scan.add_argument("target", help="Target IP, domain, or CIDR")
    scan.add_argument("--mode", default="full", choices=["quick", "web", "full"],
                       help="Scan mode (default: full)")
    scan.add_argument("--quick", action="store_const", const="quick", dest="mode",
                       help="Quick mode: nmap port scan only")
    scan.add_argument("--web", action="store_const", const="web", dest="mode",
                       help="Web mode: ports + HTTP + dirs + vulns")
    scan.add_argument("--output-dir", default=None, help="Custom output directory")
    scan.add_argument("--no-install", action="store_true",
                       help="Don't auto-install missing tools")
    scan.add_argument("--no-ffuf", action="store_true", help="Skip directory enumeration")
    scan.add_argument("--no-nuclei", action="store_true", help="Skip vulnerability scanning")
    scan.add_argument("--wordlist", default=None, help="Custom wordlist for ffuf")

    # ── Passive ingest mode (legacy) ──────────────────────────────────────
    ingest = subparsers.add_parser("ingest", help="Ingest existing scan output files")
    ingest.add_argument("inputs", nargs="+", help="Input files/directories")
    ingest.add_argument("--profile", default="default",
                         choices=["default", "web", "deep"], help="Execution profile")
    ingest.add_argument("--output", default="json",
                         choices=["json", "jsonl", "none"], help="Export format")
    ingest.add_argument("--output-path", default=None, help="Explicit export path")
    ingest.add_argument("--show-raw", action="store_true", help="Show raw findings")
    ingest.add_argument("--no-console", action="store_true", help="Disable TUI")
    ingest.add_argument("--text", action="store_true", help="Text summary output")

    return parser


def _run_active_scan(args: argparse.Namespace, settings) -> int:
    """Execute active recon pipeline."""
    from reconx.recon.target import parse_target
    from reconx.recon.pipeline import ReconPipeline
    from reconx.runners.deps import ensure_ready, check_all

    console = Console() if HAS_RICH else None

    # Print banner
    if console and HAS_RICH:
        console.print(f"[bold green]{BANNER}[/]")
    else:
        print(BANNER)

    # Parse target
    target = parse_target(args.target)

    # Dependency check
    if console:
        console.print("\n  [bold cyan]Checking dependencies...[/]")

    report = ensure_ready(auto_install=not args.no_install, console=console)

    if console and HAS_RICH:
        dep_table = Table(show_header=False, box=None, padding=(0, 1))
        dep_table.add_column(width=12)
        dep_table.add_column(width=8)
        dep_table.add_column()
        for name, status in report.tools.items():
            icon = "[green]✓[/]" if status.installed else "[red]✗[/]"
            path = status.path or "not found"
            dep_table.add_row(f"  {name}", icon, f"[dim]{path}[/]")
        sl_icon = "[green]✓[/]" if report.seclists_path else "[red]✗[/]"
        dep_table.add_row("  seclists", sl_icon,
                          f"[dim]{report.seclists_path or 'not found'}[/]")
        console.print(dep_table)

    # Check critical tools
    if not report.tools["nmap"].installed:
        if console:
            console.print("\n  [bold red]✗ nmap is required but not installed[/]")
        else:
            print("ERROR: nmap is required but not installed")
        return 1

    # Setup workspace
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.output_dir:
        workspace = Path(args.output_dir)
    else:
        workspace = Path.home() / ".reconx" / "scans" / f"{target.safe_name}_{timestamp}"
    workspace.mkdir(parents=True, exist_ok=True)

    # Run recon pipeline
    pipeline = ReconPipeline(
        target=target,
        workspace=workspace,
        mode=args.mode,
        console=console,
    )
    recon_result = pipeline.run()

    # Feed output files into analysis pipeline silently
    if recon_result.output_files:
        from reconx.core.orchestrator import Orchestrator

        settings.storage.db_path = str(workspace / "reconx.db")
        settings.storage.export_dir = str(workspace)
        settings.correlation.cve_dataset_path = str(
            Path(__file__).parent.parent / "samples" / "cve_dataset.json"
        )
        settings.ui.enabled = False

        orchestrator = Orchestrator(settings=settings)
        try:
            summary = orchestrator.ingest_sync(
                inputs=[str(p) for p in recon_result.output_files],
                profile_name="deep",
                output_format="json",
                output_path=str(workspace / "analysis.json"),
                debug=args.debug,
                show_raw_findings=True,
                enable_console=False,
            )

            # Show key findings on screen
            if console and HAS_RICH and summary.finding_counts_by_tier:
                console.print("\n  [bold white on blue] FINDINGS [/] [bold]Analysis Summary[/]")
                total = sum(summary.asset_counts.values())
                console.print(f"    [dim]Assets:[/] {total}  [dim]Relations:[/] {summary.relation_count}")
                for tier, count in summary.finding_counts_by_tier.items():
                    color = "green" if tier == "validated" else "yellow" if tier == "probable" else "dim"
                    console.print(f"    [{color}]{tier}: {count}[/]")
        finally:
            orchestrator.close()

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI program entrypoint."""

    parser = build_parser()

    # Handle bare target: `reconx 10.10.11.194` → treat as scan command
    raw_args = list(argv or sys.argv[1:])
    if raw_args and raw_args[0] not in ("scan", "ingest", "-h", "--help", "--version"):
        # Check if first arg looks like a target (not a flag)
        if not raw_args[0].startswith("-"):
            raw_args.insert(0, "scan")

    args = parser.parse_args(raw_args)

    if not args.command:
        parser.print_help()
        return 0

    settings = load_settings(args.config)
    configure_logging(
        level="DEBUG" if args.debug else settings.logging.level,
        json_logs=settings.logging.json,
    )

    if args.command == "scan":
        return _run_active_scan(args, settings)

    if args.command == "ingest":
        summary = run_ingest_command(args, settings)
        print_summary(summary, as_json=not args.text)
        return 0

    parser.error(f"Unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
