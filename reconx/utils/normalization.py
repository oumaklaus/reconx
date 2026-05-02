"""Canonicalization helpers for ingest pipelines.

The ingestion layer receives heterogeneous formats from multiple scanners and
normalization is where we enforce deterministic representations. Deterministic
 canonical values are foundational for stable IDs and deduplication.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


DEFAULT_PORTS: dict[str, int] = {
    "http": 80,
    "https": 443,
    "ssh": 22,
    "ftp": 21,
    "smtp": 25,
    "imap": 143,
    "imaps": 993,
    "mysql": 3306,
    "postgresql": 5432,
    "rdp": 3389,
}

SERVICE_ALIASES: dict[str, str] = {
    "www": "http",
    "www-http": "http",
    "ssl/http": "https",
    "https-alt": "https",
    "microsoft-ds": "smb",
    "ms-sql-s": "mssql",
    "domain": "dns",
}

SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(slots=True)
class CanonicalHost:
    """Normalized host information used for Host assets."""

    value: str
    kind: str
    ip: str | None = None
    hostname: str | None = None


def is_ip(value: str) -> bool:
    """Return True when ``value`` parses as IPv4 or IPv6."""

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def normalize_ip(value: str) -> str:
    """Normalize an IPv4/IPv6 string and raise ValueError on invalid input."""

    ip_obj = ipaddress.ip_address(value.strip())
    return ip_obj.compressed


def normalize_hostname(value: str) -> str:
    """Normalize hostname/domain values.

    - trims whitespace
    - strips trailing dot
    - lowercases
    - converts IDN into ASCII-compatible encoding for stable comparisons
    """

    cleaned = value.strip().rstrip(".").lower()
    if not cleaned:
        return ""
    labels = []
    for label in cleaned.split("."):
        if not label:
            continue
        labels.append(label.encode("idna").decode("ascii"))
    return ".".join(labels)


def canonical_host(value: str) -> CanonicalHost:
    """Convert user-provided host string into canonical host metadata."""

    raw = value.strip()
    raw = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    if is_ip(raw):
        normalized_ip = normalize_ip(raw)
        return CanonicalHost(
            value=normalized_ip,
            kind="ip",
            ip=normalized_ip,
            hostname=None,
        )
    normalized_host = normalize_hostname(raw)
    return CanonicalHost(
        value=normalized_host,
        kind="domain",
        ip=None,
        hostname=normalized_host,
    )


def normalize_protocol(value: str | None, default: str = "tcp") -> str:
    """Normalize transport protocol names."""

    if not value:
        return default
    return value.strip().lower()


def normalize_service_name(value: str | None) -> str:
    """Map known aliases to canonical service names."""

    if not value:
        return "unknown"
    key = value.strip().lower()
    return SERVICE_ALIASES.get(key, key)


def normalize_path(path: str | None) -> str:
    """Normalize URL path for deterministic IDs and dedup."""

    if not path:
        return "/"
    cleaned = re.sub(r"/{2,}", "/", path.strip())
    if not cleaned.startswith("/"):
        cleaned = f"/{cleaned}"
    return cleaned


def normalize_url(url: str, default_scheme: str = "http") -> str:
    """Normalize a URL into a deterministic canonical representation."""

    candidate = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = f"{default_scheme}://{candidate}"

    split = urlsplit(candidate)
    scheme = split.scheme.lower() or default_scheme

    netloc = split.netloc
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]

    if ":" in netloc and not netloc.startswith("["):
        host_part, port_part = netloc.rsplit(":", 1)
        host = canonical_host(host_part).value
        try:
            port = int(port_part)
        except ValueError:
            port = None
    else:
        host = canonical_host(netloc).value
        port = None

    default_port = DEFAULT_PORTS.get(scheme)
    include_port = port is not None and port != default_port
    canonical_netloc = f"{host}:{port}" if include_port else host

    path = normalize_path(split.path)
    query_pairs = sorted(parse_qsl(split.query, keep_blank_values=True))
    query = urlencode(query_pairs, doseq=True)

    return urlunsplit((scheme, canonical_netloc, path, query, ""))


def extract_host_from_url(url: str) -> Optional[str]:
    """Extract normalized hostname from URL; returns None for invalid values."""

    try:
        normalized = normalize_url(url)
    except Exception:
        return None
    split = urlsplit(normalized)
    netloc = split.netloc
    if ":" in netloc and not netloc.startswith("["):
        netloc = netloc.rsplit(":", 1)[0]
    return canonical_host(netloc).value if netloc else None


def extract_port_from_url(url: str) -> int | None:
    """Extract normalized port from URL where possible."""

    normalized = normalize_url(url)
    split = urlsplit(normalized)
    if split.port is not None:
        return split.port
    return DEFAULT_PORTS.get(split.scheme)


def extract_scheme_from_url(url: str) -> str:
    """Extract normalized scheme from URL."""

    normalized = normalize_url(url)
    return urlsplit(normalized).scheme


def normalize_tech_list(values: Iterable[str] | None) -> list[str]:
    """Normalize technology fingerprints for endpoint assets."""

    if not values:
        return []
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        cleaned = value.strip().lower()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        output.append(cleaned)
    return sorted(output)


def normalize_severity(value: str | None) -> str:
    """Normalize severity labels to a known finite set."""

    if not value:
        return "info"
    cleaned = value.strip().lower()
    if cleaned == "informational":
        return "info"
    if cleaned == "moderate":
        return "medium"
    return cleaned if cleaned in SEVERITY_ORDER else "info"


def severity_rank(value: str | None) -> int:
    """Return monotonic numeric rank for a normalized severity label."""

    return SEVERITY_ORDER.get(normalize_severity(value), 0)


def choose_higher_severity(first: str | None, second: str | None) -> str:
    """Return the stronger of two severity labels."""

    first_norm = normalize_severity(first)
    second_norm = normalize_severity(second)
    if severity_rank(first_norm) >= severity_rank(second_norm):
        return first_norm
    return second_norm


def normalize_cve_id(cve: str) -> str:
    """Canonicalize CVE identifiers."""

    cleaned = cve.strip().upper()
    if re.match(r"^CVE-\d{4}-\d{4,}$", cleaned):
        return cleaned
    return cleaned


def clamp_confidence(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    """Clamp confidence into a numeric probability range."""

    return max(minimum, min(maximum, value))
