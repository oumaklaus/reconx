"""Wafw00f runner — WAF detection."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reconx.runners.base import BaseRunner


class Wafw00fRunner(BaseRunner):
    """Execute wafw00f to detect web application firewalls."""

    name = "wafw00f"
    binary = "wafw00f"

    def output_file(self, target: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", target)
        return self.workspace / f"wafw00f_{safe}.json"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        out = str(self.output_file(target))
        return [
            self.binary,
            target,
            "-o", out,
            "-f", "json",
            "-a",  # Test all WAF signatures
        ]
