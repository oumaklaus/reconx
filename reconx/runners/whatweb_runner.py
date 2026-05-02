"""WhatWeb runner — technology fingerprinting."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reconx.runners.base import BaseRunner


class WhatwebRunner(BaseRunner):
    """Execute whatweb for web technology identification."""

    name = "whatweb"
    binary = "whatweb"

    def output_file(self, target: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", target)
        return self.workspace / f"whatweb_{safe}.json"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        out = str(self.output_file(target))
        aggression = kwargs.get("aggression", 3)  # 1=stealthy, 3=aggressive

        return [
            self.binary,
            "--log-json", out,
            f"--aggression={aggression}",
            "--color=never",
            "--no-errors",
            target,
        ]

    def build_command_for_urls(self, urls: list[str], target: str) -> list[str]:
        """Scan multiple URLs at once."""
        out = str(self.output_file(target))
        url_file = self.workspace / "whatweb_targets.txt"
        url_file.write_text("\n".join(urls) + "\n")

        return [
            self.binary,
            "--log-json", out,
            "--aggression=3",
            "--color=never",
            "--no-errors",
            "--input-file", str(url_file),
        ]
