"""SSLScan runner — SSL/TLS analysis."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reconx.runners.base import BaseRunner


class SslscanRunner(BaseRunner):
    """Execute sslscan for SSL/TLS certificate and cipher analysis."""

    name = "sslscan"
    binary = "sslscan"

    def output_file(self, target: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", target)
        return self.workspace / f"sslscan_{safe}.xml"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        out = str(self.output_file(target))
        port = kwargs.get("port", 443)
        host_port = f"{target}:{port}" if port != 443 else target

        return [
            self.binary,
            "--xml", out,
            "--no-colour",
            host_port,
        ]
