"""WPScan runner — WordPress vulnerability scanner."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reconx.runners.base import BaseRunner


class WpscanRunner(BaseRunner):
    """Execute wpscan for WordPress vulnerability scanning."""

    name = "wpscan"
    binary = "wpscan"

    def output_file(self, target: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", target)
        return self.workspace / f"wpscan_{safe}.json"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        out = str(self.output_file(target))
        url = kwargs.get("url", target)
        if not url.startswith("http"):
            url = f"http://{url}"

        return [
            self.binary,
            "--url", url,
            "--format", "json",
            "--output", out,
            "--enumerate", "vp,vt,u1-20,m",  # Plugins, themes, users, media
            "--random-user-agent",
            "--no-banner",
            "--detection-mode", "aggressive",
        ]
