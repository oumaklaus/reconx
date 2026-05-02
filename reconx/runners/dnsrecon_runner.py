"""DNSRecon runner — DNS enumeration and zone transfers."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reconx.runners.base import BaseRunner


class DnsreconRunner(BaseRunner):
    """Execute dnsrecon for DNS enumeration."""

    name = "dnsrecon"
    binary = "dnsrecon"

    def output_file(self, target: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", target)
        return self.workspace / f"dnsrecon_{safe}.json"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        out = str(self.output_file(target))
        return [
            self.binary,
            "-d", target,
            "-j", out,
            "-t", "std,brt,axfr",
            "--lifetime", "3",
        ]
