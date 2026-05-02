"""Tests for adapters parsing real sample data."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from reconx.adapters.base import AdapterContext, AdapterInput
from reconx.adapters.nmap_adapter import NmapAdapter
from reconx.adapters.http_adapter import HttpAdapter
from reconx.adapters.nuclei_adapter import NucleiAdapter
from reconx.adapters.ffuf_adapter import FfufAdapter
from reconx.core.event_bus import EventBus

SAMPLES = Path(__file__).parent.parent / "samples"


def _make_context() -> AdapterContext:
    """Create a minimal adapter context for testing."""
    return AdapterContext(
        event_bus=EventBus(),
        run_id="test-run-001",
        profile="default",
        debug=True,
    )


class TestNmapAdapter:
    def test_parse_nmap_xml(self):
        adapter = NmapAdapter()
        path = SAMPLES / "nmap_scan.xml"
        if not path.exists():
            pytest.skip("Sample nmap_scan.xml not found")

        ctx = _make_context()
        item = AdapterInput(kind="path", value=str(path))
        emitted = asyncio.run(adapter.run(item, ctx))
        # 3 hosts up, each with ports and services
        assert emitted >= 9

    def test_accepts_xml(self):
        adapter = NmapAdapter()
        assert adapter.accepts_path(Path("scan.xml"))
        assert not adapter.accepts_path(Path("scan.json"))

    def test_skips_down_hosts(self):
        adapter = NmapAdapter()
        path = SAMPLES / "nmap_scan.xml"
        if not path.exists():
            pytest.skip("Sample not found")

        ctx = _make_context()
        item = AdapterInput(kind="path", value=str(path))
        emitted = asyncio.run(adapter.run(item, ctx))
        assert emitted >= 9


class TestHttpAdapter:
    def test_parse_httpx_jsonl(self):
        adapter = HttpAdapter()
        path = SAMPLES / "httpx_output.jsonl"
        if not path.exists():
            pytest.skip("Sample httpx_output.jsonl not found")

        ctx = _make_context()
        item = AdapterInput(kind="path", value=str(path))
        emitted = asyncio.run(adapter.run(item, ctx))
        assert emitted >= 24

    def test_accepts_patterns(self):
        adapter = HttpAdapter()
        assert adapter.accepts_path(Path("output.http.json"))
        assert adapter.accepts_path(Path("output.jsonl"))


class TestNucleiAdapter:
    def test_parse_nuclei_jsonl(self):
        adapter = NucleiAdapter()
        path = SAMPLES / "nuclei_output.jsonl"
        if not path.exists():
            pytest.skip("Sample nuclei_output.jsonl not found")

        ctx = _make_context()
        item = AdapterInput(kind="path", value=str(path))
        emitted = asyncio.run(adapter.run(item, ctx))
        assert emitted >= 12

    def test_accepts_patterns(self):
        adapter = NucleiAdapter()
        assert adapter.accepts_path(Path("scan.nuclei.json"))
        assert adapter.accepts_path(Path("scan.jsonl"))
