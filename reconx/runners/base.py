"""Base runner framework for executing external tools.

Supports two modes:
  - run()      — capture output silently, return results
  - run_live() — stream tool output to terminal in real time
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    from rich.console import Console
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


@dataclass
class RunResult:
    """Result of executing an external tool."""
    tool: str
    success: bool
    output_path: Path | None
    duration: float
    return_code: int
    stdout_lines: int = 0
    stderr_preview: str = ""
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseRunner(ABC):
    """Abstract base for tool runners."""

    name: str = "base"
    binary: str = "echo"

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        ...

    @abstractmethod
    def output_file(self, target: str) -> Path:
        ...

    def run(self, target: str, *, timeout: int = 600, **kwargs: Any) -> RunResult:
        """Execute tool silently, capture all output."""
        cmd = self.build_command(target, **kwargs)
        out_path = self.output_file(target)
        start = time.monotonic()

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, cwd=str(self.workspace),
            )
            duration = time.monotonic() - start
            stdout_lines = len(proc.stdout.strip().split("\n")) if proc.stdout.strip() else 0
            stderr_preview = proc.stderr.strip()[:300] if proc.stderr else ""

            if proc.returncode != 0 and not out_path.exists():
                return RunResult(
                    tool=self.name, success=False, output_path=None,
                    duration=duration, return_code=proc.returncode,
                    stdout_lines=stdout_lines, stderr_preview=stderr_preview,
                    error=f"Exit code {proc.returncode}: {stderr_preview[:200]}",
                )

            if out_path.exists() and out_path.stat().st_size > 0:
                return RunResult(
                    tool=self.name, success=True, output_path=out_path,
                    duration=duration, return_code=proc.returncode,
                    stdout_lines=stdout_lines, stderr_preview=stderr_preview,
                )

            return RunResult(
                tool=self.name, success=True, output_path=None,
                duration=duration, return_code=proc.returncode,
                metadata={"note": "No results"},
            )

        except subprocess.TimeoutExpired:
            return RunResult(
                tool=self.name, success=False, output_path=None,
                duration=time.monotonic() - start, return_code=-1,
                error=f"Timeout after {timeout}s",
            )
        except FileNotFoundError:
            return RunResult(
                tool=self.name, success=False, output_path=None,
                duration=0, return_code=-1, error=f"Binary not found: {cmd[0]}",
            )

    def run_live(
        self,
        target: str,
        *,
        timeout: int = 600,
        console: Any = None,
        line_filter: Any = None,
        stdin_data: str | None = None,
        **kwargs: Any,
    ) -> RunResult:
        """Execute tool with live output streaming to terminal.

        Args:
            line_filter: Optional callable(line) -> str|None.
                         Return styled string to print, or None to skip.
            stdin_data:  Optional string to pipe to tool's stdin.
        """
        cmd = self.build_command(target, **kwargs)
        out_path = self.output_file(target)
        start = time.monotonic()

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE if stdin_data else None,
                text=True,
                cwd=str(self.workspace),
            )

            lines_count = 0
            if stdin_data and proc.stdin:
                proc.stdin.write(stdin_data)
                proc.stdin.close()

            if proc.stdout:
                for line in proc.stdout:
                    line = line.rstrip("\n")
                    lines_count += 1
                    if line_filter:
                        display = line_filter(line)
                        if display is not None:
                            if console and HAS_RICH:
                                console.print(display)
                            else:
                                print(display)
                    else:
                        if console and HAS_RICH:
                            console.print(f"    [dim]{line}[/]")
                        else:
                            print(f"    {line}")

            proc.wait(timeout=timeout)
            duration = time.monotonic() - start

            if out_path.exists() and out_path.stat().st_size > 0:
                return RunResult(
                    tool=self.name, success=True, output_path=out_path,
                    duration=duration, return_code=proc.returncode,
                    stdout_lines=lines_count,
                )

            return RunResult(
                tool=self.name, success=proc.returncode == 0,
                output_path=None, duration=duration,
                return_code=proc.returncode, stdout_lines=lines_count,
            )

        except subprocess.TimeoutExpired:
            proc.kill()
            return RunResult(
                tool=self.name, success=False, output_path=None,
                duration=time.monotonic() - start, return_code=-1,
                error=f"Timeout after {timeout}s",
            )
        except FileNotFoundError:
            return RunResult(
                tool=self.name, success=False, output_path=None,
                duration=0, return_code=-1, error=f"Binary not found: {cmd[0]}",
            )
