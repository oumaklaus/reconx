"""Tests for event bus, dedup, and correlation engine."""

from __future__ import annotations

import asyncio

import pytest

from reconx.core.event_bus import EventBus, Event
from reconx.core.dedup import DedupEngine
from reconx.core.assets import Host, Port, Service, Finding, Endpoint
from reconx.core.evidence import Evidence, EvidenceBag
from reconx.core.correlation import CorrelationEngine, CVEProvider
from reconx.core.relations import Relation


class TestEventBus:
    def test_emit_and_subscribe(self):
        async def _run():
            bus = EventBus()
            received: list[Event] = []

            async def handler(event: Event):
                received.append(event)

            bus.subscribe("test.topic", handler)
            await bus.emit("test.topic", {"data": 1})
            assert len(received) == 1
            assert received[0].topic == "test.topic"

        asyncio.run(_run())

    def test_wildcard_subscription(self):
        async def _run():
            bus = EventBus()
            received: list[Event] = []

            async def handler(event: Event):
                received.append(event)

            bus.subscribe("asset.*", handler)
            await bus.emit("asset.host", {"host": "10.0.0.1"})
            await bus.emit("asset.port", {"port": 80})
            assert len(received) == 2

        asyncio.run(_run())

    def test_global_wildcard(self):
        async def _run():
            bus = EventBus()
            received: list[Event] = []

            async def handler(event: Event):
                received.append(event)

            bus.subscribe("*", handler)
            await bus.emit("anything.here", {})
            assert len(received) == 1

        asyncio.run(_run())

    def test_emit_asset(self):
        async def _run():
            bus = EventBus()
            received: list[Event] = []

            async def handler(event: Event):
                received.append(event)

            bus.subscribe("asset.host", handler)
            host = Host(value="10.0.0.1")
            await bus.emit_asset(host)
            assert len(received) == 1
            assert received[0].payload is host

        asyncio.run(_run())

    def test_unsubscribe(self):
        async def _run():
            bus = EventBus()
            received: list[Event] = []

            async def handler(event: Event):
                received.append(event)

            token = bus.subscribe("test", handler)
            await bus.emit("test", {})
            assert len(received) == 1

            bus.unsubscribe(token)
            await bus.emit("test", {})
            assert len(received) == 1

        asyncio.run(_run())

    def test_once_subscription(self):
        async def _run():
            bus = EventBus()
            received: list[Event] = []

            async def handler(event: Event):
                received.append(event)

            bus.subscribe("test", handler, once=True)
            await bus.emit("test", {})
            await bus.emit("test", {})
            assert len(received) == 1

        asyncio.run(_run())


class TestDedupEngine:
    def test_new_asset(self):
        engine = DedupEngine()
        host = Host(value="10.0.0.1")
        merged, result = engine.ingest_asset(host)
        assert result.is_new
        assert result.changed

    def test_duplicate_merges(self):
        engine = DedupEngine()
        h1 = Host(value="10.0.0.1", confidence=0.5)
        h2 = Host(value="10.0.0.1", confidence=0.8, hostname="web.local")
        engine.ingest_asset(h1)
        merged, result = engine.ingest_asset(h2)
        assert not result.is_new
        assert result.changed
        assert merged.hostname == "web.local"

    def test_relation_dedup(self):
        engine = DedupEngine()
        r1 = Relation(source_id="h1", relation_type="exposes", target_id="p1", confidence=0.5)
        r2 = Relation(source_id="h1", relation_type="exposes", target_id="p1", confidence=0.9)
        engine.ingest_relation(r1)
        merged, result = engine.ingest_relation(r2)
        assert not result.is_new
        assert merged.confidence >= 0.9

    def test_summary(self):
        engine = DedupEngine()
        engine.ingest_asset(Host(value="10.0.0.1"))
        engine.ingest_asset(Port(host_id="h1", number=80))
        summary = engine.summary()
        assert summary["assets"] == 2


class TestCorrelationEngine:
    def test_endpoint_pattern_admin(self):
        engine = CorrelationEngine()
        ep = Endpoint(host_id="h1", url="https://example.com/admin/dashboard")
        findings = engine.analyze_endpoint(ep)
        assert len(findings) >= 1
        assert any("admin" in f.title.lower() for f in findings)

    def test_endpoint_pattern_env(self):
        engine = CorrelationEngine()
        ep = Endpoint(host_id="h1", url="https://example.com/.env")
        findings = engine.analyze_endpoint(ep)
        assert len(findings) >= 1
        assert any("exposed" in f.title.lower() for f in findings)

    def test_finding_tier_classification(self):
        engine = CorrelationEngine()
        f = Finding(
            target_asset_id="x", title="test", confidence=0.90,
            evidence=EvidenceBag([
                Evidence(source="a", raw={}, confidence=0.9),
                Evidence(source="b", raw={"x": 1}, confidence=0.85),
            ]),
        )
        tier = engine.classify_finding_tier(f)
        assert tier == "validated"

    def test_raw_tier_for_low_confidence(self):
        engine = CorrelationEngine()
        f = Finding(target_asset_id="x", title="test", confidence=0.3)
        tier = engine.classify_finding_tier(f)
        assert tier == "raw"
