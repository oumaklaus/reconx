"""Target parsing for ReconX.

Supports IP addresses, domains, and CIDR ranges.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field


@dataclass
class Target:
    """Parsed recon target."""

    raw: str
    kind: str  # "ip", "domain", "cidr"
    value: str
    ips: list[str] = field(default_factory=list)
    domain: str | None = None

    @property
    def display(self) -> str:
        return self.value

    @property
    def safe_name(self) -> str:
        """Filesystem-safe name for workspace directories."""
        return re.sub(r"[^a-zA-Z0-9._\-]", "_", self.value)


def parse_target(raw: str) -> Target:
    """Parse a raw target string into a Target object.

    Supports:
    - IPv4/IPv6 addresses: 10.10.11.194
    - CIDR ranges: 10.10.11.0/24
    - Domain names: example.htb
    """
    value = raw.strip()

    # CIDR range
    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
            ips = [str(ip) for ip in network.hosts()]
            return Target(
                raw=raw, kind="cidr", value=value,
                ips=ips[:256],  # Cap at /24 for safety
            )
        except ValueError:
            pass

    # Single IP
    try:
        ip = ipaddress.ip_address(value)
        return Target(raw=raw, kind="ip", value=str(ip), ips=[str(ip)])
    except ValueError:
        pass

    # Domain
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", value):
        return Target(raw=raw, kind="domain", value=value.lower(), domain=value.lower())

    # Fallback — treat as domain
    return Target(raw=raw, kind="domain", value=value.lower(), domain=value.lower())
