"""Nuclei-like JSON/JSONL ingestion adapter.

In defensive mode ReconX ingests scanner findings and maps them into normalized
Finding assets tied to Endpoint/Host/Service targets.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reconx.adapters.base import AdapterContext, AdapterInput, BaseAdapter
from reconx.adapters.utils import iter_json_lines, load_json_file, pick_first
from reconx.core.assets import Finding, Host
from reconx.core.evidence import Evidence, EvidenceBag
from reconx.core.relations import Relation
from reconx.utils.normalization import normalize_cve_id, normalize_severity


class NucleiAdapter(BaseAdapter):
    """Adapter for nuclei-like JSON outputs."""

    name = "nuclei"
    accepted_file_patterns = (".nuclei.json", ".nuclei.jsonl", ".json", ".jsonl")

    async def run(self, item: AdapterInput, context: AdapterContext) -> int:
        if item.kind != "path":
            return 0

        path = Path(str(item.value))
        records = list(self._iter_records(path))
        emitted = 0

        for record in records:
            target = pick_first(record, ["matched-at", "host", "url", "target"])
            if not isinstance(target, str) or not target.strip():
                continue

            # Build host context to ensure finding has graph anchor.
            host_asset = Host(
                value=target.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0],
                confidence=0.50,
                evidence=EvidenceBag(
                    [
                        Evidence(
                            source="nuclei",
                            raw={"target": target, "source_file": str(path)},
                            confidence=0.65,
                            note="Host inferred from nuclei target",
                        )
                    ]
                ),
                metadata={"source_file": str(path)},
            )
            await self.emit(context, host_asset)
            emitted += 1

            info = record.get("info") if isinstance(record.get("info"), dict) else {}
            title = str(pick_first(info, ["name", "description"], default="Scanner finding"))
            severity = normalize_severity(str(pick_first(info, ["severity"], default="info")))
            references = info.get("reference") if isinstance(info.get("reference"), list) else []
            classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}

            cve_candidates: list[str] = []
            cve_list = classification.get("cve-id")
            if isinstance(cve_list, list):
                cve_candidates.extend([normalize_cve_id(item) for item in cve_list if isinstance(item, str)])

            template_id = str(record.get("template-id", "")) or None
            matched = str(target)

            confidence = 0.72
            if severity in {"high", "critical"}:
                confidence += 0.10
            if cve_candidates:
                confidence += 0.10

            finding = Finding(
                target_asset_id=host_asset.id,
                title=title,
                severity=severity,
                category="vulnerability",
                description=str(record.get("matcher-name") or info.get("description") or ""),
                cve_ids=sorted(set(cve_candidates)),
                references=[str(value) for value in references if isinstance(value, str)],
                external_id=template_id,
                tier="probable",
                reasoning=f"Ingested from nuclei result for target {matched}",
                confidence=min(confidence, 0.95),
                evidence=EvidenceBag(
                    [
                        Evidence(
                            source="nuclei",
                            raw=record,
                            confidence=min(confidence, 0.95),
                            note="Normalized from nuclei JSON result",
                        )
                    ]
                ),
                metadata={
                    "source_file": str(path),
                    "template": template_id,
                    "matched_at": matched,
                    "tags": info.get("tags", []),
                },
            )
            await self.emit(context, finding)
            emitted += 1

            relation = Relation(
                source_id=host_asset.id,
                relation_type="vulnerable_to",
                target_id=finding.id,
                confidence=0.77,
                evidence=finding.evidence,
            )
            await context.event_bus.emit(
                "relation.created",
                relation,
                metadata={"run_id": context.run_id, "source": self.name},
            )

        return emitted

    def _iter_records(self, path: Path) -> list[dict[str, Any]]:
        suffix = path.suffix.lower()
        if suffix == ".jsonl" or path.name.lower().endswith(".nuclei.jsonl"):
            return list(iter_json_lines(path))

        data = load_json_file(path)
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            return [data]
        return []
