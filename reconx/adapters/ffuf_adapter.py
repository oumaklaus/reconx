"""FFUF result ingestion adapter.

Defensive mode only: this adapter parses existing ffuf output files (JSON/CSV)
from authorized scans and converts them into Endpoint and Finding assets.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reconx.adapters.base import AdapterContext, AdapterInput, BaseAdapter
from reconx.adapters.utils import iter_csv_rows, load_json_file, pick_first, safe_int
from reconx.core.assets import Endpoint, Finding, Host
from reconx.core.evidence import Evidence, EvidenceBag
from reconx.core.relations import Relation
from reconx.utils.normalization import canonical_host, normalize_url


class FfufAdapter(BaseAdapter):
    """Adapter ingesting ffuf results for endpoint discovery."""

    name = "ffuf"
    accepted_file_patterns = (".ffuf.json", ".ffuf.csv", ".json", ".csv")
    accepted_asset_types = {"endpoint"}

    async def run(self, item: AdapterInput, context: AdapterContext) -> int:
        if item.kind == "path":
            return await self._run_from_path(Path(str(item.value)), context)
        if item.kind == "asset":
            return await self._run_from_asset(item.value, context)
        return 0

    async def _run_from_asset(self, asset: Any, context: AdapterContext) -> int:
        records = asset.metadata.get("ffuf_results", []) if hasattr(asset, "metadata") else []
        emitted = 0
        for record in records:
            if not isinstance(record, dict):
                continue
            emitted += await self._emit_record(record, context, source_path=None)
        return emitted

    async def _run_from_path(self, path: Path, context: AdapterContext) -> int:
        emitted = 0
        if path.suffix.lower() == ".csv" or path.name.lower().endswith(".ffuf.csv"):
            records = list(iter_csv_rows(path))
        else:
            records = self._load_ffuf_json_records(path)

        for record in records:
            if not self._looks_like_ffuf_record(record):
                continue
            emitted += await self._emit_record(record, context, source_path=path)
        return emitted

    def _load_ffuf_json_records(self, path: Path) -> list[dict[str, Any]]:
        data = load_json_file(path)
        if isinstance(data, dict):
            # ffuf JSON commonly stores discovered entries under ``results``.
            if isinstance(data.get("results"), list):
                return [item for item in data["results"] if isinstance(item, dict)]
            return [data]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    def _looks_like_ffuf_record(self, record: dict[str, Any]) -> bool:
        keys = set(record.keys())
        return bool(
            {"url", "input", "position", "status", "status_code", "length", "words", "lines"}.intersection(keys)
        )

    async def _emit_record(
        self,
        record: dict[str, Any],
        context: AdapterContext,
        *,
        source_path: Path | None,
    ) -> int:
        url_value = pick_first(record, ["url", "input"])
        if not isinstance(url_value, str) or not url_value.strip():
            return 0

        url = normalize_url(url_value)
        host_text = url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        host_info = canonical_host(host_text)

        host_asset = Host(
            value=host_info.value,
            ip=host_info.ip,
            hostname=host_info.hostname,
            confidence=0.55,
            evidence=EvidenceBag(
                [
                    Evidence(
                        source="ffuf",
                        raw={"url": url, "source_file": str(source_path) if source_path else None},
                        confidence=0.65,
                        note="Host inferred from ffuf discovered URL",
                    )
                ]
            ),
            metadata={"source_file": str(source_path) if source_path else None},
        )
        await self.emit(context, host_asset)

        endpoint_asset = Endpoint(
            host_id=host_asset.id,
            url=url,
            status_code=safe_int(pick_first(record, ["status", "status_code"])),
            title=None,
            technologies=[],
            confidence=0.66,
            evidence=EvidenceBag(
                [
                    Evidence(
                        source="ffuf",
                        raw=record,
                        confidence=0.75,
                        note="Endpoint discovered via ffuf output ingestion",
                    )
                ]
            ),
            metadata={
                "source_file": str(source_path) if source_path else None,
                "length": safe_int(pick_first(record, ["length"])),
                "words": safe_int(pick_first(record, ["words"])),
                "lines": safe_int(pick_first(record, ["lines"])),
            },
        )
        await self.emit(context, endpoint_asset)

        relation = Relation(
            source_id=host_asset.id,
            relation_type="exposes",
            target_id=endpoint_asset.id,
            confidence=0.70,
            evidence=endpoint_asset.evidence,
        )
        await context.event_bus.emit(
            "relation.created",
            relation,
            metadata={"run_id": context.run_id, "source": self.name},
        )

        status = endpoint_asset.status_code or 0
        finding_emitted = 0
        if 200 <= status < 400:
            finding = Finding(
                target_asset_id=endpoint_asset.id,
                title="Discovered reachable endpoint from ffuf dataset",
                severity="info",
                category="exposure",
                description="Endpoint responded successfully in ffuf output.",
                tier="raw",
                reasoning=f"HTTP status {status} indicates reachable path",
                confidence=0.58,
                evidence=endpoint_asset.evidence,
                metadata={"status_code": status},
            )
            await self.emit(context, finding)
            finding_emitted = 1

            vuln_relation = Relation(
                source_id=endpoint_asset.id,
                relation_type="vulnerable_to",
                target_id=finding.id,
                confidence=0.55,
                evidence=finding.evidence,
            )
            await context.event_bus.emit(
                "relation.created",
                vuln_relation,
                metadata={"run_id": context.run_id, "source": self.name},
            )

        return 2 + finding_emitted
