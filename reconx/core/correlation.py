"""Correlation and enrichment logic for defensive ASM findings.

The correlator turns independent scanner observations into prioritized findings
with consistent tiers (validated/probable/raw). It also performs lightweight
CVE enrichment by mapping service fingerprints to local CVE entries.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reconx.core.assets import Endpoint, Finding, Host, Service
from reconx.core.evidence import Evidence, EvidenceBag
from reconx.utils.normalization import clamp_confidence, normalize_severity


HIGH_VALUE_PATTERNS: list[tuple[str, str, str]] = [
    (r"/(admin|administrator|control-panel|cpanel)($|/)", "admin-panel", "high"),
    (r"/(login|signin|auth)($|/)", "login-page", "medium"),
    (r"/(\.env|config\.php|backup|dump\.sql|\.git)($|/)", "exposed-file", "critical"),
]


@dataclass(slots=True)
class CVERecord:
    """Minimal CVE dataset record used by the local matcher."""

    cve_id: str
    product: str
    version_pattern: str | None
    severity: str
    description: str
    references: list[str] = field(default_factory=list)
    cpe: list[str] = field(default_factory=list)


class CVEProvider:
    """Local CVE provider loaded from JSON dataset."""

    def __init__(self, dataset_path: Path | None = None) -> None:
        self._records: list[CVERecord] = []
        if dataset_path:
            self.load_dataset(dataset_path)

    def load_dataset(self, dataset_path: Path) -> None:
        """Load CVE records from JSON file.

        Expected schema is a list of objects with keys matching CVERecord.
        """

        data = json.loads(dataset_path.read_text(encoding="utf-8"))
        records: list[CVERecord] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            cve_id = str(item.get("cve_id", "")).upper()
            product = str(item.get("product", "")).strip().lower()
            if not cve_id or not product:
                continue
            records.append(
                CVERecord(
                    cve_id=cve_id,
                    product=product,
                    version_pattern=item.get("version_pattern"),
                    severity=normalize_severity(item.get("severity")),
                    description=str(item.get("description", "")),
                    references=list(item.get("references", [])),
                    cpe=list(item.get("cpe", [])),
                )
            )
        self._records = records

    def match(self, product: str, version: str | None = None) -> list[tuple[CVERecord, float, str]]:
        """Return matched CVEs with score and reasoning string."""

        normalized_product = product.strip().lower()
        normalized_version = version.strip().lower() if version else None
        matches: list[tuple[CVERecord, float, str]] = []
        for record in self._records:
            if record.product != normalized_product:
                continue

            if not record.version_pattern:
                matches.append((record, 0.60, "Product match"))
                continue

            if normalized_version and self._version_matches(normalized_version, record.version_pattern):
                matches.append((record, 0.85, f"Product+version match ({record.version_pattern})"))
            elif normalized_version:
                # Partial product match only when version does not fit pattern.
                matches.append((record, 0.35, f"Product matched; version {normalized_version} outside pattern"))

        # Highest confidence first
        matches.sort(key=lambda item: item[1], reverse=True)
        return matches

    @staticmethod
    def _version_matches(version: str, pattern: str) -> bool:
        """Heuristic version matcher supporting prefix, exact, and regex-like patterns."""

        cleaned_pattern = pattern.strip()
        if cleaned_pattern.endswith(".*"):
            return version.startswith(cleaned_pattern[:-2])
        if cleaned_pattern.startswith("^"):
            try:
                return re.search(cleaned_pattern, version) is not None
            except re.error:
                return False
        return version == cleaned_pattern


class CorrelationEngine:
    """Cross-asset correlation and enrichment routines."""

    def __init__(self, cve_provider: CVEProvider | None = None) -> None:
        self._cve_provider = cve_provider or CVEProvider()

    def classify_finding_tier(self, finding: Finding) -> str:
        """Classify output tier from confidence and evidence diversity."""

        source_count = finding.evidence.source_count()
        if finding.confidence >= 0.85 and source_count >= 2:
            return "validated"
        if finding.confidence >= 0.60:
            return "probable"
        return "raw"

    def analyze_endpoint(self, endpoint: Endpoint) -> list[Finding]:
        """Generate exposure findings based on endpoint URL patterns."""

        findings: list[Finding] = []
        for pattern, category, severity in HIGH_VALUE_PATTERNS:
            if re.search(pattern, endpoint.path or "/", flags=re.IGNORECASE):
                title = f"High-value endpoint pattern detected: {category}"
                evidence = Evidence(
                    source="correlation.endpoint-pattern",
                    raw={"url": endpoint.url, "pattern": pattern},
                    confidence=0.78,
                    note="Path pattern matched a high-value asset indicator",
                )
                finding = Finding(
                    target_asset_id=endpoint.id,
                    title=title,
                    severity=severity,
                    category="exposure",
                    description=(
                        "Endpoint path indicates potentially sensitive surface area. "
                        "Requires analyst validation before remediation decisions."
                    ),
                    tier="probable",
                    reasoning=f"Pattern '{pattern}' matched '{endpoint.path}'",
                    evidence=EvidenceBag([evidence]),
                    confidence=0.72,
                    metadata={"endpoint_url": endpoint.url},
                )
                findings.append(finding)
        return findings

    def enrich_service_with_cves(self, service: Service) -> list[Finding]:
        """Generate CVE findings from service product/version fingerprints."""

        if not service.product:
            return []

        matches = self._cve_provider.match(service.product, service.version)
        findings: list[Finding] = []
        for record, score, reason in matches:
            evidence = Evidence(
                source="correlation.cve-enrichment",
                raw={
                    "service": service.name,
                    "product": service.product,
                    "version": service.version,
                    "matched_cve": record.cve_id,
                },
                confidence=score,
                note=reason,
            )
            finding = Finding(
                target_asset_id=service.id,
                title=f"Potential vulnerable component: {record.cve_id}",
                severity=record.severity,
                category="cve",
                description=record.description,
                cve_ids=[record.cve_id],
                references=list(record.references),
                tier="probable" if score >= 0.65 else "raw",
                reasoning=reason,
                evidence=EvidenceBag([evidence]),
                confidence=clamp_confidence(score),
                metadata={
                    "product": service.product,
                    "version": service.version,
                    "matched_cpe": record.cpe,
                },
            )
            findings.append(finding)
        return findings

    def correlate_findings(
        self,
        findings: list[Finding],
        hosts: list[Host],
        endpoints: list[Endpoint],
        services: list[Service],
    ) -> list[Finding]:
        """Apply final confidence and tier adjustments on merged findings."""

        endpoint_ids = {endpoint.id for endpoint in endpoints}
        service_ids = {service.id for service in services}
        host_ids = {host.id for host in hosts}

        for finding in findings:
            if finding.target_asset_id in endpoint_ids:
                finding.tags.add("web-surface")
            if finding.target_asset_id in service_ids:
                finding.tags.add("service-surface")
            if finding.target_asset_id in host_ids:
                finding.tags.add("host-surface")

            if finding.category == "cve" and finding.cve_ids:
                finding.tags.add("vulnerability")
            if finding.severity in {"high", "critical"}:
                finding.tags.add("priority")

            # Encourage validated tier when multiple evidence sources corroborate.
            source_count = finding.evidence.source_count()
            if source_count >= 2:
                finding.confidence = clamp_confidence(finding.confidence + 0.10)
            finding.tier = self.classify_finding_tier(finding)

        findings.sort(
            key=lambda f: (
                {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(f.severity, 0),
                f.confidence,
            ),
            reverse=True,
        )
        return findings
