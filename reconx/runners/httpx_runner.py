"""httpx runner — HTTP probing and tech detection.

Requires the Go projectdiscovery httpx (httpx-toolkit on Kali).
The Python httpx CLI (/usr/bin/httpx from python3-httpx) is NOT compatible.

Install: sudo apt install httpx-toolkit
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from reconx.runners.base import BaseRunner

_SSL_PORTS = {443, 8443, 993, 995, 465}


def _find_httpx_binary() -> str | None:
    """Find the Go projectdiscovery httpx binary."""
    # httpx-toolkit is the Kali/Parrot package name
    if shutil.which("httpx-toolkit"):
        return "httpx-toolkit"
    # On other distros, Go httpx might be at httpx
    # but we need to verify it's the Go version, not Python
    httpx_path = shutil.which("httpx")
    if httpx_path:
        import subprocess
        try:
            r = subprocess.run([httpx_path, "-version"], capture_output=True, text=True, timeout=5)
            # Go httpx shows "Current Version: vX.X.X" or "projectdiscovery"
            out = r.stdout + r.stderr
            if "projectdiscovery" in out.lower() or "current version" in out.lower():
                return "httpx"
        except Exception:
            pass
    return None


class HttpxRunner(BaseRunner):
    name = "httpx"
    binary = _find_httpx_binary() or "httpx-toolkit"

    @property
    def available(self) -> bool:
        return _find_httpx_binary() is not None

    def output_file(self, target: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", target)
        return self.workspace / f"httpx_{safe}.jsonl"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        out = str(self.output_file(target))
        return [
            self.binary,
            "-json",
            "-o", out,
            "-title",
            "-tech-detect",
            "-status-code",
            "-content-length",
            "-follow-redirects",
            "-silent",
            "-timeout", "10",
            "-retries", "2",
        ]

    def get_stdin_urls(self, target: str, ports: list[int]) -> str:
        urls = []
        web_ports = ports if ports else [80, 443, 8080, 8443]
        for port in web_ports:
            scheme = "https" if port in _SSL_PORTS else "http"
            if port in (80, 443):
                urls.append(f"{scheme}://{target}")
            else:
                urls.append(f"{scheme}://{target}:{port}")
        return "\n".join(dict.fromkeys(urls)) + "\n"
