"""Dependency checker and auto-installer for external tools.

Checks if required tools and wordlists exist on the system.
Installs missing ones via apt, go install, or direct download.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)

SECLISTS_PATHS = [
    "/usr/share/seclists",
    "/usr/share/wordlists/seclists",
    "/opt/seclists",
    os.path.expanduser("~/.reconx/wordlists/seclists"),
]

WORDLIST_MAP = {
    "common": "Discovery/Web-Content/common.txt",
    "medium": "Discovery/Web-Content/directory-list-2.3-medium.txt",
    "big": "Discovery/Web-Content/big.txt",
    "dns": "Discovery/DNS/subdomains-top1million-5000.txt",
    "dns-large": "Discovery/DNS/subdomains-top1million-20000.txt",
    "raft-dirs": "Discovery/Web-Content/raft-medium-directories.txt",
    "raft-files": "Discovery/Web-Content/raft-medium-files.txt",
    "params": "Discovery/Web-Content/burp-parameter-names.txt",
    "vhosts": "Discovery/DNS/namelist.txt",
}


@dataclass
class ToolStatus:
    """Status of one external dependency."""
    name: str
    path: str | None
    installed: bool
    version: str | None = None
    required: bool = True  # False = optional enhancement


@dataclass
class DepsReport:
    """Full dependency check report."""
    tools: dict[str, ToolStatus]
    seclists_path: str | None
    all_ready: bool
    critical_ready: bool  # Only required tools


TOOLS: dict[str, dict] = {
    # ── Core (required) ───────────────────────────────────────────────────
    "nmap": {
        "check": "nmap", "install_apt": "nmap",
        "version_flag": "--version", "required": True,
    },
    "httpx": {
        "check": "httpx-toolkit", "alt_check": "httpx",
        "install_apt": "httpx-toolkit",
        "version_flag": "-version", "required": True,
    },
    "ffuf": {
        "check": "ffuf", "install_apt": "ffuf",
        "version_flag": "-V", "required": True,
    },
    "nuclei": {
        "check": "nuclei", "install_apt": "nuclei",
        "version_flag": "-version", "required": True,
    },
    # ── Web Enum ──────────────────────────────────────────────────────────
    "whatweb": {
        "check": "whatweb", "install_apt": "whatweb",
        "version_flag": "--version", "required": False,
    },
    "nikto": {
        "check": "nikto", "install_apt": "nikto",
        "version_flag": "-Version", "required": False,
    },
    "wafw00f": {
        "check": "wafw00f", "install_apt": "wafw00f",
        "version_flag": "--version", "required": False,
    },
    "wpscan": {
        "check": "wpscan", "install_apt": "wpscan",
        "version_flag": "--version", "required": False,
    },
    # ── DNS / Subdomain ───────────────────────────────────────────────────
    "dnsrecon": {
        "check": "dnsrecon", "install_apt": "dnsrecon",
        "version_flag": "--version", "required": False,
    },
    "subfinder": {
        "check": "subfinder", "install_apt": "subfinder",
        "version_flag": "-version", "required": False,
    },
    # ── SSL ────────────────────────────────────────────────────────────────
    "sslscan": {
        "check": "sslscan", "install_apt": "sslscan",
        "version_flag": "--version", "required": False,
    },
    # ── Network Enum ──────────────────────────────────────────────────────
    "enum4linux": {
        "check": "enum4linux", "alt_check": "enum4linux-ng",
        "install_apt": "enum4linux",
        "version_flag": "-h", "required": False,
    },
    # ── Screenshot ─────────────────────────────────────────────────────────
    "gowitness": {
        "check": "gowitness", "install_apt": "gowitness",
        "version_flag": "version", "required": False,
    },
}


def _which(name: str) -> str | None:
    return shutil.which(name)


def _get_version(binary: str, flag: str) -> str | None:
    try:
        result = subprocess.run(
            [binary, flag], capture_output=True, text=True, timeout=10,
        )
        output = (result.stdout + result.stderr).strip()
        for line in output.split("\n"):
            line = line.strip()
            if line:
                return line[:80]
    except Exception:
        pass
    return None


def _find_seclists() -> str | None:
    for path in SECLISTS_PATHS:
        expanded = os.path.expanduser(path)
        if os.path.isdir(expanded):
            common = os.path.join(expanded, WORDLIST_MAP["common"])
            if os.path.isfile(common):
                return expanded
    return None


def get_wordlist(name: str = "common") -> str | None:
    """Get path to a specific wordlist."""
    seclists = _find_seclists()
    if not seclists:
        # Fallback to common system wordlists
        fallbacks = {
            "common": "/usr/share/wordlists/dirb/common.txt",
            "medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "big": "/usr/share/wordlists/dirb/big.txt",
        }
        fallback = fallbacks.get(name)
        if fallback and os.path.isfile(fallback):
            return fallback
        return None

    relative = WORDLIST_MAP.get(name, name)
    full_path = os.path.join(seclists, relative)
    return full_path if os.path.isfile(full_path) else None


def check_tool(name: str) -> ToolStatus:
    """Check if a single tool is installed."""
    info = TOOLS.get(name, {"check": name, "required": False})

    path = _which(info["check"])
    if not path and "alt_check" in info:
        path = _which(info["alt_check"])

    if path:
        version = _get_version(path, info.get("version_flag", "--version"))
        return ToolStatus(
            name=name, path=path, installed=True,
            version=version, required=info.get("required", False),
        )

    return ToolStatus(
        name=name, path=None, installed=False,
        required=info.get("required", False),
    )


def check_all() -> DepsReport:
    """Check all dependencies."""
    tools = {name: check_tool(name) for name in TOOLS}
    seclists = _find_seclists()
    critical = [t for t in tools.values() if t.required]
    critical_ready = all(t.installed for t in critical) and seclists is not None
    all_ready = all(t.installed for t in tools.values()) and seclists is not None

    return DepsReport(
        tools=tools, seclists_path=seclists,
        all_ready=all_ready, critical_ready=critical_ready,
    )


def _run_install(cmd: list[str], desc: str) -> bool:
    logger.info("Installing %s: %s", desc, " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            logger.info("✓ Installed %s", desc)
            return True
        logger.error("✗ Failed: %s", result.stderr[:200])
        return False
    except (subprocess.TimeoutExpired, Exception) as e:
        logger.error("✗ Error installing %s: %s", desc, e)
        return False


def install_tool(name: str) -> bool:
    """Install a missing tool via apt."""
    info = TOOLS.get(name)
    if not info:
        return False
    apt_pkg = info.get("install_apt")
    if apt_pkg:
        return _run_install(["sudo", "apt-get", "install", "-y", apt_pkg], name)
    return False


def install_seclists() -> bool:
    if _run_install(["sudo", "apt-get", "install", "-y", "seclists"], "seclists"):
        return True
    dest = os.path.expanduser("~/.reconx/wordlists/seclists")
    if os.path.isdir(dest):
        return True
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    return _run_install(
        ["git", "clone", "--depth", "1",
         "https://github.com/danielmiessler/SecLists.git", dest],
        "seclists (git)",
    )


def ensure_ready(*, auto_install: bool = True, console=None) -> DepsReport:
    """Check deps and install missing ones if auto_install=True."""
    report = check_all()
    if report.critical_ready:
        return report
    if not auto_install:
        return report

    for name, status in report.tools.items():
        if not status.installed and status.required:
            if console:
                console.print(f"  [yellow]Installing {name}...[/]")
            install_tool(name)

    if not report.seclists_path:
        if console:
            console.print("  [yellow]Installing seclists...[/]")
        install_seclists()

    return check_all()
