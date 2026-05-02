"""Ingestion profile definitions.

Profiles decide which adapters and correlation phases are active during one run.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Profile:
    """Execution profile for ingestion and correlation."""

    name: str
    description: str
    enabled_adapters: set[str] = field(default_factory=set)
    enable_endpoint_pattern_correlation: bool = True
    enable_cve_enrichment: bool = True
    finding_tiers_visible: tuple[str, ...] = ("validated", "probable")


DEFAULT_PROFILES: dict[str, Profile] = {
    "default": Profile(
        name="default",
        description="Balanced profile for mixed infrastructure and web inputs",
        enabled_adapters={"nmap", "http", "nuclei", "ffuf"},
        enable_endpoint_pattern_correlation=True,
        enable_cve_enrichment=True,
        finding_tiers_visible=("validated", "probable"),
    ),
    "web": Profile(
        name="web",
        description="Web-focused profile emphasizing endpoint and scanner findings",
        enabled_adapters={"http", "nuclei"},
        enable_endpoint_pattern_correlation=True,
        enable_cve_enrichment=True,
        finding_tiers_visible=("validated", "probable", "raw"),
    ),
    "deep": Profile(
        name="deep",
        description="Comprehensive profile with all adapters and broader visibility",
        enabled_adapters={"nmap", "http", "nuclei", "ffuf"},
        enable_endpoint_pattern_correlation=True,
        enable_cve_enrichment=True,
        finding_tiers_visible=("validated", "probable", "raw"),
    ),
}


def get_profile(name: str) -> Profile:
    """Return profile by name, raising ValueError for unknown values."""

    key = name.strip().lower()
    profile = DEFAULT_PROFILES.get(key)
    if profile is None:
        raise ValueError(f"Unknown profile '{name}'. Available: {', '.join(sorted(DEFAULT_PROFILES))}")
    return profile
