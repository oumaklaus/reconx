"""Nmap XML ingestion adapter.

This adapter parses Nmap XML output from authorized scans and emits normalized
Host, Port, and Service assets with provenance evidence.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from pathlib import Path

from reconx.adapters.base import AdapterContext, AdapterInput, BaseAdapter
from reconx.core.assets import Host, Port, Service
from reconx.core.evidence import Evidence, EvidenceBag
from reconx.core.relations import Relation


logger = logging.getLogger(__name__)


class NmapAdapter(BaseAdapter):
    """Adapter for nmap XML outputs."""

    name = "nmap"
    accepted_file_patterns = (".xml", ".nmap.xml")

    async def run(self, item: AdapterInput, context: AdapterContext) -> int:
        if item.kind != "path":
            return 0

        path = Path(str(item.value))
        tree = ET.parse(path)
        root = tree.getroot()
        emitted = 0

        for host_node in root.findall("host"):
            status_node = host_node.find("status")
            if status_node is not None and status_node.attrib.get("state", "").lower() == "down":
                continue

            host_asset = self._parse_host(host_node, path)
            if host_asset is None:
                continue
            await self.emit(context, host_asset)
            emitted += 1

            relation_candidates: list[Relation] = []

            for port_node in host_node.findall("./ports/port"):
                state_node = port_node.find("state")
                state = state_node.attrib.get("state", "unknown") if state_node is not None else "unknown"
                if state not in {"open", "filtered", "closed"}:
                    continue

                protocol = port_node.attrib.get("protocol", "tcp")
                port_id = int(port_node.attrib.get("portid", "0"))
                port_evidence = Evidence(
                    source="nmap",
                    raw={
                        "path": str(path),
                        "port": port_id,
                        "protocol": protocol,
                        "state": state,
                    },
                    confidence=0.90,
                    note="Parsed from nmap XML port entry",
                )
                port_asset = Port(
                    host_id=host_asset.id,
                    number=port_id,
                    protocol=protocol,
                    state=state,
                    confidence=0.80,
                    evidence=EvidenceBag([port_evidence]),
                    metadata={"source_file": str(path)},
                )
                await self.emit(context, port_asset)
                emitted += 1

                relation_candidates.append(
                    Relation(
                        source_id=host_asset.id,
                        relation_type="exposes",
                        target_id=port_asset.id,
                        confidence=0.85,
                        evidence=port_asset.evidence,
                    )
                )

                service_node = port_node.find("service")
                if service_node is None:
                    continue

                service_name = service_node.attrib.get("name", "unknown")
                service_product = service_node.attrib.get("product")
                service_version = service_node.attrib.get("version")
                service_banner_parts = [
                    service_node.attrib.get("extrainfo"),
                    service_node.attrib.get("ostype"),
                    service_node.attrib.get("method"),
                ]
                service_banner = " | ".join(part for part in service_banner_parts if part)
                cpe_values = [cpe_node.text for cpe_node in service_node.findall("cpe") if cpe_node.text]

                service_evidence = Evidence(
                    source="nmap",
                    raw={
                        "path": str(path),
                        "port": port_id,
                        "service": service_name,
                        "product": service_product,
                        "version": service_version,
                    },
                    confidence=0.83,
                    note="Parsed from nmap XML service entry",
                )
                service_asset = Service(
                    host_id=host_asset.id,
                    port_id=port_asset.id,
                    name=service_name,
                    protocol=protocol,
                    product=service_product,
                    version=service_version,
                    banner=service_banner or None,
                    cpe=[value.strip() for value in cpe_values],
                    confidence=0.72,
                    evidence=EvidenceBag([service_evidence]),
                    metadata={"source_file": str(path)},
                )
                await self.emit(context, service_asset)
                emitted += 1

                relation_candidates.append(
                    Relation(
                        source_id=port_asset.id,
                        relation_type="runs",
                        target_id=service_asset.id,
                        confidence=0.82,
                        evidence=service_asset.evidence,
                    )
                )

            for relation in relation_candidates:
                await context.event_bus.emit(
                    "relation.created",
                    relation,
                    metadata={"run_id": context.run_id, "source": self.name},
                )

        logger.debug("NmapAdapter emitted %s assets from %s", emitted, path)
        return emitted

    def _parse_host(self, host_node: ET.Element, path: Path) -> Host | None:
        """Parse one nmap <host> node into a Host asset."""

        addresses = host_node.findall("address")
        ip_value: str | None = None
        mac_value: str | None = None
        for address in addresses:
            addr_type = address.attrib.get("addrtype", "").lower()
            addr = address.attrib.get("addr")
            if not addr:
                continue
            if addr_type in {"ipv4", "ipv6"} and ip_value is None:
                ip_value = addr
            elif addr_type == "mac":
                mac_value = addr

        hostnames = [
            node.attrib.get("name")
            for node in host_node.findall("./hostnames/hostname")
            if node.attrib.get("name")
        ]
        primary_hostname = hostnames[0] if hostnames else None
        identity = ip_value or primary_hostname
        if not identity:
            return None

        host_evidence = Evidence(
            source="nmap",
            raw={
                "path": str(path),
                "identity": identity,
                "ip": ip_value,
                "hostname": primary_hostname,
                "mac": mac_value,
            },
            confidence=0.92,
            note="Parsed host identity from nmap XML",
        )
        return Host(
            value=identity,
            ip=ip_value,
            hostname=primary_hostname,
            aliases=hostnames,
            confidence=0.76,
            evidence=EvidenceBag([host_evidence]),
            metadata={"mac": mac_value, "source_file": str(path)},
        )
