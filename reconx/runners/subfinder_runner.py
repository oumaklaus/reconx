"""Subfinder runner — passive subdomain enumeration."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reconx.runners.base import BaseRunner


class SubfinderRunner(BaseRunner):
    """Execute subfinder for passive subdomain discovery."""

    name = "subfinder"
    binary = "subfinder"

    def output_file(self, target: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", target)
        return self.workspace / f"subfinder_{safe}.txt"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        out = str(self.output_file(target))
        return [
            self.binary,
            "-d", target,
            "-o", out,
            "-silent",
            "-all",
            "-timeout", "30",
        ]
