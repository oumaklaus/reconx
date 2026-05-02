"""Enum4linux runner — SMB/NetBIOS enumeration."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reconx.runners.base import BaseRunner


class Enum4linuxRunner(BaseRunner):
    """Execute enum4linux for SMB/NetBIOS enumeration."""

    name = "enum4linux"
    binary = "enum4linux"

    def output_file(self, target: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", target)
        return self.workspace / f"enum4linux_{safe}.txt"

    def run(self, target: str, *, timeout: int = 300, **kwargs: Any):
        """Override run to capture stdout since enum4linux doesn't support -o."""
        import subprocess
        import time

        cmd = self.build_command(target, **kwargs)
        out = self.output_file(target)
        start = time.monotonic()

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            duration = time.monotonic() - start
            # enum4linux outputs to stdout, not a file
            out.write_text(proc.stdout + proc.stderr)

            from reconx.runners.base import RunResult
            return RunResult(
                tool=self.name, success=proc.returncode == 0,
                output_path=out if out.stat().st_size > 0 else None,
                duration=duration, return_code=proc.returncode,
            )
        except Exception as e:
            from reconx.runners.base import RunResult
            return RunResult(
                tool=self.name, success=False, output_path=None,
                duration=time.monotonic() - start, return_code=-1, error=str(e),
            )

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        return [self.binary, "-a", target]
