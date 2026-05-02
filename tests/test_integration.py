"""End-to-end integration test running the full pipeline."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from reconx.config.settings import Settings
from reconx.core.orchestrator import Orchestrator

SAMPLES = Path(__file__).parent.parent / "samples"


class TestEndToEnd:
    def test_full_ingest_pipeline(self, tmp_path):
        """Run the complete ingestion pipeline against sample data."""
        nmap_path = SAMPLES / "nmap_scan.xml"
        http_path = SAMPLES / "httpx_output.jsonl"
        nuclei_path = SAMPLES / "nuclei_output.jsonl"

        for p in [nmap_path, http_path, nuclei_path]:
            if not p.exists():
                pytest.skip(f"Sample file not found: {p}")

        output_path = tmp_path / "output.json"
        db_path = str(tmp_path / "test.db")

        settings = Settings()
        settings.storage.db_path = db_path
        settings.storage.export_dir = str(tmp_path)
        settings.correlation.cve_dataset_path = str(SAMPLES / "cve_dataset.json")
        settings.ui.enabled = False

        orchestrator = Orchestrator(settings=settings)
        try:
            summary = asyncio.run(orchestrator.ingest(
                inputs=[str(nmap_path), str(http_path), str(nuclei_path)],
                profile_name="default",
                output_format="json",
                output_path=str(output_path),
                debug=True,
                enable_console=False,
            ))

            # Verify summary structure
            assert summary.run_id
            assert summary.profile == "default"
            assert summary.planned_inputs >= 3
            assert summary.asset_counts.get("host", 0) > 0
            assert summary.asset_counts.get("finding", 0) > 0
            assert summary.relation_count > 0

            # Verify export file
            assert output_path.exists()
            with output_path.open() as f:
                export = json.load(f)
            assert len(export["assets"]) > 0
            assert len(export["relations"]) > 0

            # Verify findings tiers
            tiers = summary.finding_counts_by_tier
            assert tiers.get("probable", 0) + tiers.get("validated", 0) > 0

        finally:
            orchestrator.close()

    def test_jsonl_export(self, tmp_path):
        """Verify JSONL export produces correct files."""
        nmap_path = SAMPLES / "nmap_scan.xml"
        if not nmap_path.exists():
            pytest.skip("Sample not found")

        settings = Settings()
        settings.storage.db_path = str(tmp_path / "test.db")
        settings.storage.export_dir = str(tmp_path)
        settings.correlation.cve_dataset_path = str(SAMPLES / "cve_dataset.json")
        settings.ui.enabled = False

        orchestrator = Orchestrator(settings=settings)
        try:
            output_dir = tmp_path / "jsonl_out"
            summary = asyncio.run(orchestrator.ingest(
                inputs=[str(nmap_path)],
                profile_name="default",
                output_format="jsonl",
                output_path=str(output_dir),
                enable_console=False,
            ))

            assert (output_dir / "assets.jsonl").exists()
            assert (output_dir / "relations.jsonl").exists()

            with (output_dir / "assets.jsonl").open() as f:
                lines = f.readlines()
            assert len(lines) > 0
            for line in lines:
                parsed = json.loads(line)
                assert "asset_type" in parsed

        finally:
            orchestrator.close()


class TestStorage:
    def test_sqlite_persistence(self, tmp_path):
        """Verify assets survive storage round-trip."""
        from reconx.core.storage import Storage
        from reconx.core.assets import Host

        db_path = str(tmp_path / "roundtrip.db")
        storage = Storage(db_path)

        host = Host(value="10.0.0.1", hostname="test.local")
        storage.upsert_asset(host)

        loaded = storage.load_assets(asset_type="host")
        assert len(loaded) == 1
        assert loaded[0].value == "10.0.0.1"
        storage.close()
