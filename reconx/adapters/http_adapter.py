"""HTTP probe output ingestion adapter.

Supports JSON and JSONL records similar to httpx output and emits Endpoint
assets plus related host/service records when needed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reconx.adapters.base import AdapterContext, AdapterInput, BaseAdapter
from reconx.adapters.utils import iter_json_lines, load_json_file, pick_first, safe_int
from reconx.core.assets import Endpoint, Host, Service
from reconx.core.evidence import Evidence, EvidenceBag
from reconx.core.relations import Relation
from reconx.utils.normalization import canonical_host, normalize_url


class HttpAdapter(BaseAdapter):
    """Adapter ingesting authorized HTTP probe scanner output files."""

    name = "http"
    accepted_file_patterns = (".http.json", ".http.jsonl", ".json", ".jsonl")
    accepted_asset_types = {"service", "endpoint"}

    async def run(self, item: AdapterInput, context: AdapterContext) -> int:
        if item.kind == "path":
            return await self._run_from_path(Path(str(item.value)), context)
        if item.kind == "asset":
            return await self._run_from_asset(item.value, context)
        return 0

    async def _run_from_path(self, path: Path, context: AdapterContext) -> int:
        emitted = 0
        records = list(self._iter_records(path))
        for record in records:
            emitted += await self._emit_from_record(record, context, source_path=path)
        return emitted

    async def _run_from_asset(self, asset: Any, context: AdapterContext) -> int:
        # Defensive ingestion flow does not actively probe. This path supports
        # downstream workflows where another component passes already normalized
        # endpoint-like dictionaries as metadata attached to Service assets.
        metadata_records = asset.metadata.get("http_observations", []) if hasattr(asset, "metadata") else []
        emitted = 0
        for record in metadata_records:
            if not isinstance(record, dict):
                continue
            emitted += await self._emit_from_record(record, context, source_path=None)
        return emitted

    def _iter_records(self, path: Path) -> list[dict[str, Any]]:
        suffix = path.suffix.lower()
        if suffix == ".jsonl" or path.name.lower().endswith(".http.jsonl"):
            return list(iter_json_lines(path))

        data = load_json_file(path)
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            return [data]
        return []

    async def _emit_from_record(
        self,
        record: dict[str, Any],
        context: AdapterContext,
        *,
        source_path: Path | None,
    ) -> int:
        url = pick_first(record, ["url", "input", "host"])
        if not isinstance(url, str) or not url.strip():
            return 0

        normalized_url = normalize_url(url)
        parsed_host = canonical_host(normalized_url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0])

        host_evidence = Evidence(
            source="http",
            raw={"url": normalized_url, "source_file": str(source_path) if source_path else None},
            confidence=0.75,
            note="Host inferred from HTTP probe URL",
        )
        host_asset = Host(
            value=parsed_host.value,
            ip=parsed_host.ip,
            hostname=parsed_host.hostname,
            confidence=0.62,
            evidence=EvidenceBag([host_evidence]),
            metadata={"source_file": str(source_path) if source_path else None},
        )
        await self.emit(context, host_asset)

        port = safe_int(pick_first(record, ["port", "url_port", "host_port"]))
        scheme = pick_first(record, ["scheme", "protocol"]) or normalized_url.split(":", 1)[0]
        service_evidence = Evidence(
            source="http",
            raw={
                "url": normalized_url,
                "scheme": scheme,
                "port": port,
            },
            confidence=0.70,
            note="Service inferred from HTTP probe metadata",
        )
        service_asset = Service(
            host_id=host_asset.id,
            name="https" if str(scheme).lower() == "https" else "http",
            protocol="tcp",
            port_id=None,
            product=pick_first(record, ["webserver", "server"]),
            version=None,
            cpe=[],
            confidence=0.58,
            evidence=EvidenceBag([service_evidence]),
            metadata={"source_file": str(source_path) if source_path else None},
        )
        await self.emit(context, service_asset)

        technologies = record.get("tech") or record.get("technologies") or []
        if isinstance(technologies, str):
            technologies = [part.strip() for part in technologies.split(",") if part.strip()]

        endpoint_evidence = Evidence(
            source="http",
            raw=record,
            confidence=0.80,
            note="Endpoint parsed from HTTP probe output",
        )
        endpoint_asset = Endpoint(
            host_id=host_asset.id,
            service_id=service_asset.id,
            url=normalized_url,
            scheme=str(scheme),
            port=port,
            status_code=safe_int(pick_first(record, ["status_code", "status"])),
            title=pick_first(record, ["title"]),
            technologies=technologies if isinstance(technologies, list) else [],
            confidence=0.68,
            evidence=EvidenceBag([endpoint_evidence]),
            metadata={
                "source_file": str(source_path) if source_path else None,
                "content_length": safe_int(pick_first(record, ["content_length", "length"])),
            },
        )
        await self.emit(context, endpoint_asset)

        # Publish relation events for graph linking.
        relations = [
            Relation(
                source_id=host_asset.id,
                relation_type="exposes",
                target_id=endpoint_asset.id,
                confidence=0.72,
                evidence=endpoint_asset.evidence,
            ),
            Relation(
                source_id=service_asset.id,
                relation_type="contains",
                target_id=endpoint_asset.id,
                confidence=0.70,
                evidence=endpoint_asset.evidence,
            ),
        ]
        for relation in relations:
            await context.event_bus.emit(
                "relation.created",
                relation,
                metadata={"run_id": context.run_id, "source": self.name},
            )

        return 3
