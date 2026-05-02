"""Tests for core asset models, evidence, and relations."""

from __future__ import annotations

import pytest

from reconx.core.assets import (
    BaseAsset, Endpoint, Finding, Host, Port, Service,
    asset_from_dict, group_assets_by_type,
)
from reconx.core.evidence import Evidence, EvidenceBag
from reconx.core.relations import Relation
from reconx.utils.hashing import deterministic_id


class TestHost:
    def test_ip_host_creation(self):
        host = Host(value="192.168.1.1")
        assert host.kind == "ip"
        assert host.ip == "192.168.1.1"
        assert host.value == "192.168.1.1"
        assert host.asset_type == "host"
        assert host.id.startswith("host_")

    def test_domain_host_creation(self):
        host = Host(value="example.com")
        assert host.kind == "domain"
        assert host.hostname == "example.com"
        assert host.value == "example.com"

    def test_deterministic_id(self):
        h1 = Host(value="10.0.0.1")
        h2 = Host(value="10.0.0.1")
        assert h1.id == h2.id

    def test_merge_hosts(self):
        h1 = Host(value="10.0.0.1", confidence=0.5)
        h2 = Host(value="10.0.0.1", hostname="server.local", confidence=0.8)
        changed = h1.merge_from(h2)
        assert changed
        assert h1.hostname == "server.local"

    def test_host_aliases(self):
        host = Host(value="10.0.0.1", aliases=["web.local", "api.local"])
        assert len(host.aliases) == 2

    def test_host_serialization(self):
        host = Host(value="10.0.0.1", ip="10.0.0.1")
        data = host.to_dict()
        assert data["asset_type"] == "host"
        assert data["value"] == "10.0.0.1"
        restored = asset_from_dict(data)
        assert isinstance(restored, Host)
        assert restored.ip == "10.0.0.1"


class TestPort:
    def test_port_creation(self):
        port = Port(host_id="host_abc", number=443, protocol="tcp", state="open")
        assert port.number == 443
        assert port.protocol == "tcp"
        assert port.state == "open"

    def test_port_deterministic_id(self):
        p1 = Port(host_id="host_abc", number=80)
        p2 = Port(host_id="host_abc", number=80)
        assert p1.id == p2.id

    def test_port_merge_state_priority(self):
        p1 = Port(host_id="host_abc", number=80, state="filtered")
        p2 = Port(host_id="host_abc", number=80, state="open")
        p1.merge_from(p2)
        assert p1.state == "open"


class TestService:
    def test_service_creation(self):
        svc = Service(host_id="h1", name="http", product="nginx", version="1.24.0")
        assert svc.name == "http"
        assert svc.product == "nginx"

    def test_service_alias_normalization(self):
        svc = Service(host_id="h1", name="www-http")
        assert svc.name == "http"

    def test_service_merge_fills_blanks(self):
        s1 = Service(host_id="h1", name="ssh")
        s2 = Service(host_id="h1", name="ssh", product="OpenSSH", version="8.9p1")
        s1.merge_from(s2)
        assert s1.product == "OpenSSH"
        assert s1.version == "8.9p1"


class TestEndpoint:
    def test_endpoint_url_normalization(self):
        ep = Endpoint(host_id="h1", url="HTTP://Example.COM:80/path//")
        assert ep.url.startswith("http://example.com/path/")

    def test_endpoint_tech_normalization(self):
        ep = Endpoint(host_id="h1", url="http://x.com", technologies=["Nginx", "nginx", "PHP"])
        assert ep.technologies == sorted({"nginx", "php"})


class TestFinding:
    def test_finding_creation(self):
        f = Finding(
            target_asset_id="svc_123",
            title="Test CVE",
            severity="HIGH",
            cve_ids=["CVE-2024-1234"],
        )
        assert f.severity == "high"
        assert f.cve_ids == ["CVE-2024-1234"]
        assert f.tier == "raw"

    def test_finding_merge_severity_upgrade(self):
        f1 = Finding(target_asset_id="x", title="vuln", severity="medium")
        f2 = Finding(target_asset_id="x", title="vuln", severity="critical")
        f1.merge_from(f2)
        assert f1.severity == "critical"

    def test_finding_tier_upgrade(self):
        f1 = Finding(target_asset_id="x", title="vuln", tier="raw")
        f2 = Finding(target_asset_id="x", title="vuln", tier="validated")
        f1.merge_from(f2)
        assert f1.tier == "validated"


class TestEvidence:
    def test_evidence_fingerprint(self):
        e1 = Evidence(source="nmap", raw={"port": 80}, confidence=0.9)
        e2 = Evidence(source="nmap", raw={"port": 80}, confidence=0.9)
        assert e1.fingerprint == e2.fingerprint

    def test_evidence_bag_dedup(self):
        e1 = Evidence(source="nmap", raw={"port": 80})
        e2 = Evidence(source="nmap", raw={"port": 80})
        bag = EvidenceBag([e1, e2])
        assert len(bag.items) == 1

    def test_evidence_bag_source_count(self):
        bag = EvidenceBag([
            Evidence(source="nmap", raw={"a": 1}),
            Evidence(source="nuclei", raw={"b": 2}),
        ])
        assert bag.source_count() == 2

    def test_evidence_serialization(self):
        e = Evidence(source="test", raw={"x": 1}, note="test note")
        data = e.to_dict()
        restored = Evidence.from_dict(data)
        assert restored.source == "test"
        assert restored.note == "test note"


class TestRelation:
    def test_relation_creation(self):
        r = Relation(source_id="h1", relation_type="exposes", target_id="p1")
        assert r.relation_type == "exposes"
        assert r.id.startswith("rel_")

    def test_relation_invalid_type(self):
        with pytest.raises(ValueError):
            Relation(source_id="h1", relation_type="invalid_type", target_id="p1")

    def test_relation_merge(self):
        r1 = Relation(source_id="h1", relation_type="exposes", target_id="p1", confidence=0.5)
        r2 = Relation(source_id="h1", relation_type="exposes", target_id="p1", confidence=0.8)
        r1.merge_from(r2)
        assert r1.confidence >= 0.8


class TestGrouping:
    def test_group_by_type(self):
        assets = [
            Host(value="10.0.0.1"),
            Host(value="10.0.0.2"),
            Port(host_id="h1", number=80),
        ]
        grouped = group_assets_by_type(assets)
        assert len(grouped["host"]) == 2
        assert len(grouped["port"]) == 1
