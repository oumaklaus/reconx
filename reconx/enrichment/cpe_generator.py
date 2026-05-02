"""Heuristic CPE candidate generator for service fingerprints.

CPE strings follow ``cpe:2.3:a:VENDOR:PRODUCT:VERSION:*:*:*:*:*:*:*``.
This module uses curated vendor mappings + heuristic rules to produce
candidate CPEs from scanner fingerprints.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

KNOWN_VENDORS: dict[str, tuple[str, str]] = {
    "apache": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "openresty": ("openresty", "openresty"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "iis": ("microsoft", "internet_information_services"),
    "caddy": ("caddyserver", "caddy"),
    "tomcat": ("apache", "tomcat"),
    "apache tomcat": ("apache", "tomcat"),
    "openssh": ("openbsd", "openssh"),
    "dropbear": ("dropbear_ssh_project", "dropbear_ssh"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "postgres": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "bind": ("isc", "bind"),
    "isc bind": ("isc", "bind"),
    "haproxy": ("haproxy", "haproxy"),
    "varnish": ("varnish-cache", "varnish_cache"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "jenkins": ("jenkins", "jenkins"),
    "grafana": ("grafana", "grafana"),
    "gitlab": ("gitlab", "gitlab"),
    "openssl": ("openssl", "openssl"),
    "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"),
    "dovecot": ("dovecot", "dovecot"),
    "fortios": ("fortinet", "fortios"),
    "rabbitmq": ("vmware", "rabbitmq"),
}


@dataclass(slots=True)
class CPECandidate:
    """One CPE candidate with confidence and provenance."""
    cpe23: str
    vendor: str
    product: str
    version: str
    confidence: float
    reasoning: str
    source_product: str
    source_version: str | None


@dataclass(slots=True)
class CPEGeneratorResult:
    """Result of CPE generation for one service fingerprint."""
    candidates: list[CPECandidate] = field(default_factory=list)
    raw_product: str | None = None
    raw_version: str | None = None

    @property
    def best(self) -> CPECandidate | None:
        if not self.candidates:
            return None
        return max(self.candidates, key=lambda c: c.confidence)


def _sanitize_cpe(value: str) -> str:
    """Sanitize a string for CPE component use."""
    cleaned = re.sub(r"[\s/\\]+", "_", value.strip().lower())
    cleaned = re.sub(r"[^a-z0-9._\-]", "", cleaned)
    cleaned = re.sub(r"_{2,}", "_", cleaned)
    return cleaned.strip("_") or "unknown"


def _normalize_version(raw: str | None) -> str:
    """Normalize version string for CPE use."""
    if not raw or not raw.strip():
        return "*"
    v = raw.strip()
    if v.startswith(("v", "V")) and len(v) > 1 and v[1].isdigit():
        v = v[1:]
    v = re.sub(r"\s*\(.*?\)\s*", "", v)
    v = re.sub(r"[-+~](ubuntu|debian|deb|dfsg|el|fc|alpine).*$", "", v, flags=re.IGNORECASE)
    v = re.sub(r"[^0-9a-zA-Z._\-].*$", "", v)
    return v.strip() or "*"


def _build_cpe23(vendor: str, product: str, version: str) -> str:
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _extract_cpe_field(cpe_str: str, index: int) -> str:
    parts = cpe_str.split(":")
    return parts[index] if index < len(parts) else "*"


def generate_cpe_candidates(
    product: str | None,
    version: str | None = None,
    *,
    existing_cpes: list[str] | None = None,
    banner: str | None = None,
) -> CPEGeneratorResult:
    """Generate CPE candidates from service fingerprint.

    Strategy order:
    1. Scanner-provided CPEs (highest trust)
    2. Curated vendor lookup table
    3. Heuristic normalization (lowest confidence)
    4. Banner extraction for supplementary products
    """
    result = CPEGeneratorResult(raw_product=product, raw_version=version)

    # Strategy 1: Scanner-provided CPEs
    if existing_cpes:
        for cpe in existing_cpes:
            cleaned = cpe.strip().lower()
            if cleaned.startswith("cpe:"):
                result.candidates.append(CPECandidate(
                    cpe23=cleaned,
                    vendor=_extract_cpe_field(cleaned, 3),
                    product=_extract_cpe_field(cleaned, 4),
                    version=_extract_cpe_field(cleaned, 5),
                    confidence=0.90,
                    reasoning="Scanner-provided CPE",
                    source_product=product or "",
                    source_version=version,
                ))

    if not product:
        return result

    norm_product = product.strip().lower()
    norm_version = _normalize_version(version)

    # Strategy 2: Curated vendor lookup
    if norm_product in KNOWN_VENDORS:
        vendor, canonical = KNOWN_VENDORS[norm_product]
        cpe23 = _build_cpe23(vendor, canonical, norm_version)
        result.candidates.append(CPECandidate(
            cpe23=cpe23, vendor=vendor, product=canonical,
            version=norm_version, confidence=0.82,
            reasoning=f"Curated lookup: {norm_product} → {vendor}:{canonical}",
            source_product=product, source_version=version,
        ))
    else:
        # Strategy 3: Heuristic
        h_vendor = _sanitize_cpe(norm_product.split()[0])
        h_product = _sanitize_cpe(norm_product)
        cpe23 = _build_cpe23(h_vendor, h_product, norm_version)
        result.candidates.append(CPECandidate(
            cpe23=cpe23, vendor=h_vendor, product=h_product,
            version=norm_version, confidence=0.45,
            reasoning=f"Heuristic: {norm_product} → {h_vendor}:{h_product}",
            source_product=product, source_version=version,
        ))

    # Strategy 4: Banner extraction
    if banner:
        for match in re.finditer(r"([A-Za-z][\w.-]+)[/\s]+(\d[\w.]*)", banner):
            hint = match.group(1).strip().lower()
            ver = _normalize_version(match.group(2))
            if product and hint == product.strip().lower():
                continue
            if hint in KNOWN_VENDORS:
                v, c = KNOWN_VENDORS[hint]
                result.candidates.append(CPECandidate(
                    cpe23=_build_cpe23(v, c, ver), vendor=v, product=c,
                    version=ver, confidence=0.55,
                    reasoning=f"Banner: '{match.group(0)}' → {v}:{c}",
                    source_product=product or "", source_version=version,
                ))

    # Deduplicate keeping highest confidence
    seen: dict[str, CPECandidate] = {}
    for c in result.candidates:
        if c.cpe23 not in seen or c.confidence > seen[c.cpe23].confidence:
            seen[c.cpe23] = c
    result.candidates = sorted(seen.values(), key=lambda x: x.confidence, reverse=True)
    return result
