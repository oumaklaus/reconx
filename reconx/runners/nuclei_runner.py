"""Nuclei runner — vulnerability scanning."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reconx.runners.base import BaseRunner


class NucleiRunner(BaseRunner):
    """Execute nuclei for vulnerability assessment."""

    name = "nuclei"
    binary = "nuclei"

    def output_file(self, target: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", target)
        return self.workspace / f"nuclei_{safe}.jsonl"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        out = str(self.output_file(target))
        severity = kwargs.get("severity", "info,low,medium,high,critical")
        mode = kwargs.get("mode", "full")

        cmd = [
            self.binary,
            "-target", target,
            "-jsonl",
            "-o", out,
            "-severity", severity,
            "-silent",
            "-timeout", "10",
            "-retries", "2",
            "-rate-limit", "150",
            "-bulk-size", "25",
            "-concurrency", "25",
        ]

        if mode == "quick":
            # Only critical/high, faster
            cmd.extend(["-severity", "high,critical"])
        elif mode == "web":
            # Web-focused templates
            cmd.extend(["-tags", "cve,misconfig,exposure,tech"])

        return cmd

    def build_command_with_urls(
        self, urls: list[str], target: str, **kwargs: Any
    ) -> list[str]:
        """Build nuclei command targeting specific URLs."""
        out = str(self.output_file(target))
        url_file = self.workspace / "nuclei_targets.txt"
        url_file.write_text("\n".join(urls) + "\n")

        cmd = [
            self.binary,
            "-l", str(url_file),
            "-jsonl",
            "-o", out,
            "-severity", kwargs.get("severity", "info,low,medium,high,critical"),
            "-silent",
            "-timeout", "10",
            "-retries", "2",
            "-rate-limit", "150",
            "-bulk-size", "25",
            "-concurrency", "25",
        ]
        return cmd
