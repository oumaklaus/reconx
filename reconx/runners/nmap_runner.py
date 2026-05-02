"""Nmap runner — port scanning and service detection."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reconx.runners.base import BaseRunner


class NmapRunner(BaseRunner):
    """Execute nmap with service/OS detection and XML output."""

    name = "nmap"
    binary = "nmap"

    def output_file(self, target: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", target)
        return self.workspace / f"nmap_{safe}.xml"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        mode = kwargs.get("mode", "full")
        out = str(self.output_file(target))

        if mode == "quick":
            # Fast top-1000 port scan
            return [
                self.binary, "-sV", "--top-ports", "1000",
                "-T4", "--open", "-oX", out, target,
            ]
        elif mode == "stealth":
            # SYN scan, no DNS, slower but quieter
            return [
                self.binary, "-sS", "-sV", "-Pn", "-n",
                "-T2", "--open", "-oX", out, target,
            ]
        else:
            # Full scan: all common ports + service + OS + scripts
            return [
                self.binary, "-sV", "-sC", "-O", "-Pn",
                "-p-", "-T4", "--open",
                "--min-rate", "1000",
                "-oX", out, target,
            ]
