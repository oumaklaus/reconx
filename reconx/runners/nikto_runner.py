"""Nikto runner — web server vulnerability scanner."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reconx.runners.base import BaseRunner


class NiktoRunner(BaseRunner):
    """Execute nikto for web server vulnerability scanning."""

    name = "nikto"
    binary = "nikto"

    def output_file(self, target: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", target)
        return self.workspace / f"nikto_{safe}.txt"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        out = str(self.output_file(target))
        port = kwargs.get("port", 80)
        scheme = "https" if port in (443, 8443) else "http"
        host_url = f"{scheme}://{target}:{port}"

        return [
            self.binary,
            "-h", host_url,
            "-o", out,
            "-nointeractive",
            "-maxtime", "120s",
            "-Tuning", "123bde",  # Focused: info disclosure, file upload, remote source inclusion
        ]
