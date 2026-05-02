"""Standalone CVE enrichment pipeline.

Integrates the CPE generator with the CVE provider to produce enriched
findings from service fingerprints. This module bridges the gap between
raw service data and actionable vulnerability intelligence.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from reconx.core.assets import Finding, Service
from reconx.core.evidence import Evidence, EvidenceBag
from reconx.core.correlation import CVEProvider
from reconx.enrichment.cpe_generator import (
    CPECandidate,
    generate_cpe_candidates,
)
from reconx.utils.normalization import clamp_confidence

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class EnrichmentResult:
    """Result of enriching one service with CVE data."""
    service_id: str
    product: str | None
    version: str | None
    cpe_candidates: list[CPECandidate] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    enrichment_notes: list[str] = field(default_factory=list)


class CVEEnrichmentPipeline:
    """End-to-end CVE enrichment for service assets.

    Flow:
    1. Generate CPE candidates from service fingerprint
    2. Match CPE candidates against local CVE dataset
    3. Produce Finding assets with evidence and reasoning
    """

    def __init__(self, cve_provider: CVEProvider | None = None) -> None:
        self._provider = cve_provider or CVEProvider()

    def enrich_service(self, service: Service) -> EnrichmentResult:
        """Enrich a single service with CVE findings."""

        result = EnrichmentResult(
            service_id=service.id,
            product=service.product,
            version=service.version,
        )

        if not service.product:
            result.enrichment_notes.append("No product fingerprint available")
            return result

        # Step 1: Generate CPE candidates
        cpe_result = generate_cpe_candidates(
            product=service.product,
            version=service.version,
            existing_cpes=service.cpe,
            banner=service.banner,
        )
        result.cpe_candidates = cpe_result.candidates

        if not cpe_result.candidates:
            result.enrichment_notes.append("No CPE candidates generated")
            return result

        result.enrichment_notes.append(
            f"Generated {len(cpe_result.candidates)} CPE candidate(s)"
        )

        # Step 2: Match against CVE dataset
        matches = self._provider.match(service.product, service.version)

        if not matches:
            result.enrichment_notes.append("No CVE matches found")
            return result

        result.enrichment_notes.append(f"Found {len(matches)} CVE match(es)")

        # Step 3: Build findings
        best_cpe = cpe_result.best
        for record, score, reason in matches:
            # Boost confidence when CPE candidate quality is high
            cpe_boost = 0.0
            if best_cpe and best_cpe.confidence >= 0.80:
                cpe_boost = 0.08
            elif best_cpe and best_cpe.confidence >= 0.50:
                cpe_boost = 0.04

            adjusted_score = clamp_confidence(score + cpe_boost)

            evidence = Evidence(
                source="enrichment.cve-pipeline",
                raw={
                    "service_id": service.id,
                    "product": service.product,
                    "version": service.version,
                    "matched_cve": record.cve_id,
                    "cpe_candidates": [c.cpe23 for c in cpe_result.candidates[:3]],
                    "match_score": score,
                    "cpe_boost": cpe_boost,
                },
                confidence=adjusted_score,
                note=f"{reason} | CPE: {best_cpe.cpe23 if best_cpe else 'none'}",
            )

            tier = "probable" if adjusted_score >= 0.65 else "raw"

            finding = Finding(
                target_asset_id=service.id,
                title=f"CVE match: {record.cve_id}",
                severity=record.severity,
                category="cve",
                description=record.description,
                cve_ids=[record.cve_id],
                references=list(record.references),
                tier=tier,
                reasoning=(
                    f"{reason} | "
                    f"CPE confidence: {best_cpe.confidence:.2f} | "
                    f"Combined score: {adjusted_score:.2f}"
                ) if best_cpe else reason,
                evidence=EvidenceBag([evidence]),
                confidence=adjusted_score,
                metadata={
                    "product": service.product,
                    "version": service.version,
                    "cpe_candidates": [c.cpe23 for c in cpe_result.candidates[:3]],
                    "matched_cpe": record.cpe,
                    "enrichment_source": "cve-pipeline",
                },
            )
            result.findings.append(finding)

        return result

    def enrich_services(self, services: list[Service]) -> list[EnrichmentResult]:
        """Batch enrich multiple services."""

        results: list[EnrichmentResult] = []
        for service in services:
            try:
                results.append(self.enrich_service(service))
            except Exception:
                logger.exception("Failed to enrich service %s", service.id)
        return results
