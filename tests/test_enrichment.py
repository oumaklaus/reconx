"""Tests for CPE generator and CVE enrichment pipeline."""

from __future__ import annotations

import pytest

from reconx.enrichment.cpe_generator import (
    CPECandidate,
    generate_cpe_candidates,
    _normalize_version,
    _sanitize_cpe,
)
from reconx.enrichment.cve_enrichment import CVEEnrichmentPipeline
from reconx.core.assets import Service
from reconx.core.correlation import CVEProvider
from pathlib import Path

SAMPLES = Path(__file__).parent.parent / "samples"


class TestCPEGenerator:
    def test_known_product_lookup(self):
        result = generate_cpe_candidates("nginx", "1.24.0")
        assert len(result.candidates) >= 1
        best = result.best
        assert best is not None
        assert "nginx" in best.cpe23
        assert best.confidence >= 0.80

    def test_openssh_lookup(self):
        result = generate_cpe_candidates("OpenSSH", "8.9p1")
        assert result.best is not None
        assert "openssh" in result.best.cpe23

    def test_unknown_product_heuristic(self):
        result = generate_cpe_candidates("SomeCustomServer", "3.1")
        assert len(result.candidates) >= 1
        best = result.best
        assert best is not None
        assert best.confidence < 0.60  # Heuristic = lower confidence

    def test_existing_cpes_high_confidence(self):
        result = generate_cpe_candidates(
            "nginx", "1.24.0",
            existing_cpes=["cpe:/a:nginx:nginx:1.24.0"]
        )
        scanner_cpe = [c for c in result.candidates if c.confidence >= 0.85]
        assert len(scanner_cpe) >= 1

    def test_banner_extraction(self):
        result = generate_cpe_candidates(
            "nginx", "1.24.0",
            banner="OpenSSL/3.0.2 built on 2023-01-01"
        )
        openssl_cpes = [c for c in result.candidates if "openssl" in c.cpe23]
        assert len(openssl_cpes) >= 1

    def test_no_product(self):
        result = generate_cpe_candidates(None)
        assert len(result.candidates) == 0

    def test_version_normalization(self):
        assert _normalize_version("v1.2.3") == "1.2.3"
        assert _normalize_version("1.2.3-ubuntu4") == "1.2.3"
        assert _normalize_version("1.0 (stable)") == "1.0"
        assert _normalize_version(None) == "*"
        assert _normalize_version("") == "*"

    def test_sanitize_cpe_component(self):
        assert _sanitize_cpe("Apache HTTP Server") == "apache_http_server"
        assert _sanitize_cpe("nginx/openresty") == "nginx_openresty"


class TestCVEEnrichmentPipeline:
    def _make_provider(self) -> CVEProvider:
        path = SAMPLES / "cve_dataset.json"
        if not path.exists():
            pytest.skip("cve_dataset.json not found")
        provider = CVEProvider(path)
        return provider

    def test_enrich_nginx(self):
        provider = self._make_provider()
        pipeline = CVEEnrichmentPipeline(provider)
        svc = Service(host_id="h1", name="http", product="nginx", version="1.24.0")
        result = pipeline.enrich_service(svc)
        assert len(result.findings) >= 1
        assert any("CVE-2023-44487" in f.cve_ids for f in result.findings)

    def test_enrich_no_product(self):
        pipeline = CVEEnrichmentPipeline()
        svc = Service(host_id="h1", name="unknown")
        result = pipeline.enrich_service(svc)
        assert len(result.findings) == 0

    def test_enrich_openssh(self):
        provider = self._make_provider()
        pipeline = CVEEnrichmentPipeline(provider)
        svc = Service(host_id="h1", name="ssh", product="OpenSSH", version="7.6p1")
        result = pipeline.enrich_service(svc)
        # Should match Terrapin (CVE-2023-48795)
        assert len(result.findings) >= 1
