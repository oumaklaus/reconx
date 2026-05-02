"""ffuf runner — directory, file, and vhost discovery.

Supports:
  - Directory enumeration: ffuf -u http://target/FUZZ
  - VHost enumeration: ffuf -u http://target -H "Host: FUZZ.domain"
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reconx.runners.base import BaseRunner
from reconx.runners.deps import get_wordlist


class FfufRunner(BaseRunner):
    name = "ffuf"
    binary = "ffuf"

    def output_file(self, target: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", target)
        return self.workspace / f"ffuf_{safe}.json"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        url = kwargs.get("url", f"http://{target}/FUZZ")
        port = kwargs.get("port", 80)
        wordlist = kwargs.get("wordlist") or get_wordlist("common")
        threads = kwargs.get("threads", 50)

        # Build unique output file per port
        safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", f"{target}_{port}")
        out = str(self.workspace / f"ffuf_{safe}.json")

        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"

        cmd = [
            self.binary,
            "-u", url,
            "-w", wordlist or "/usr/share/wordlists/dirb/common.txt",
            "-o", out,
            "-of", "json",
            "-t", str(threads),
            "-mc", "200,201,204,301,302,307,308,401,403,405,500",
            "-fc", "404",
            "-ac",           # Auto-calibrate filtering
            "-timeout", "10",
        ]
        # NO -s flag — we want live output to stream to terminal
        return cmd

    def build_vhost_command(
        self, target_ip: str, domain: str, **kwargs: Any,
    ) -> list[str]:
        """Build ffuf command for vhost/subdomain enumeration."""
        wordlist = kwargs.get("wordlist") or get_wordlist("dns")
        safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", domain)
        out = str(self.workspace / f"ffuf_vhost_{safe}.json")

        return [
            self.binary,
            "-u", f"http://{target_ip}",
            "-H", f"Host: FUZZ.{domain}",
            "-w", wordlist or "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "-o", out,
            "-of", "json",
            "-t", "50",
            "-mc", "200,204,301,302,307,308,401,403,405",
            "-ac",            # Auto-calibrate to filter false positives
            "-timeout", "10",
        ]
