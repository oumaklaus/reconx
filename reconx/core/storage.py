"""SQLite persistence layer for ReconX assets, relations, and run metadata."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from reconx.core.assets import BaseAsset, Finding, asset_from_dict
from reconx.core.relations import Relation
from reconx.core.evidence import utc_now_iso
from reconx.utils.hashing import deterministic_id


@dataclass(slots=True)
class RunRecord:
    """Metadata record for one ingestion run."""

    run_id: str
    profile: str
    status: str
    started_at: str
    ended_at: str | None = None
    input_count: int = 0
    metadata: dict[str, Any] | None = None


class Storage:
    """SQLite-backed storage abstraction.

    The schema keeps each asset row as a serialized JSON payload in addition to
    searchable top-level columns. This balances flexibility with queryability.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def close(self) -> None:
        """Close sqlite connection."""

        self._conn.close()

    def _init_schema(self) -> None:
        """Create required tables and indexes."""

        cursor = self._conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                profile TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                input_count INTEGER NOT NULL DEFAULT 0,
                metadata_json TEXT
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                asset_type TEXT NOT NULL,
                canonical_key TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                confidence REAL NOT NULL,
                payload_json TEXT NOT NULL,
                run_id TEXT,
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            )
            """
        )
        cursor.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_identity
            ON assets(asset_type, canonical_key)
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS relations (
                id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                relation_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                confidence REAL NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                run_id TEXT,
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                topic TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                metadata_json TEXT,
                run_id TEXT,
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            )
            """
        )
        self._conn.commit()

    def create_run(self, profile: str, input_count: int, metadata: dict[str, Any] | None = None) -> RunRecord:
        """Insert and return a new run record."""

        run_id = deterministic_id("run", profile, utc_now_iso(), input_count)
        started = utc_now_iso()
        self._conn.execute(
            """
            INSERT INTO runs (run_id, profile, status, started_at, input_count, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (run_id, profile, "running", started, input_count, json.dumps(metadata or {})),
        )
        self._conn.commit()
        return RunRecord(
            run_id=run_id,
            profile=profile,
            status="running",
            started_at=started,
            input_count=input_count,
            metadata=metadata or {},
        )

    def update_run_status(self, run_id: str, status: str, *, ended: bool = False) -> None:
        """Update run status and optional completion timestamp."""

        ended_at = utc_now_iso() if ended else None
        self._conn.execute(
            """
            UPDATE runs
            SET status = ?, ended_at = COALESCE(?, ended_at)
            WHERE run_id = ?
            """,
            (status, ended_at, run_id),
        )
        self._conn.commit()

    def upsert_asset(self, asset: BaseAsset, *, run_id: str | None = None) -> None:
        """Insert or update an asset row by deterministic ID."""

        payload = asset.to_dict()
        self._conn.execute(
            """
            INSERT INTO assets (id, asset_type, canonical_key, first_seen, last_seen, confidence, payload_json, run_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                first_seen=excluded.first_seen,
                last_seen=excluded.last_seen,
                confidence=excluded.confidence,
                payload_json=excluded.payload_json,
                run_id=COALESCE(excluded.run_id, assets.run_id)
            """,
            (
                asset.id,
                asset.asset_type,
                asset.canonical_key,
                asset.first_seen,
                asset.last_seen,
                asset.confidence,
                json.dumps(payload),
                run_id,
            ),
        )
        self._conn.commit()

    def upsert_assets(self, assets: Iterable[BaseAsset], *, run_id: str | None = None) -> None:
        """Batch upsert assets with one transaction."""

        cursor = self._conn.cursor()
        rows = []
        for asset in assets:
            rows.append(
                (
                    asset.id,
                    asset.asset_type,
                    asset.canonical_key,
                    asset.first_seen,
                    asset.last_seen,
                    asset.confidence,
                    json.dumps(asset.to_dict()),
                    run_id,
                )
            )
        cursor.executemany(
            """
            INSERT INTO assets (id, asset_type, canonical_key, first_seen, last_seen, confidence, payload_json, run_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                first_seen=excluded.first_seen,
                last_seen=excluded.last_seen,
                confidence=excluded.confidence,
                payload_json=excluded.payload_json,
                run_id=COALESCE(excluded.run_id, assets.run_id)
            """,
            rows,
        )
        self._conn.commit()

    def upsert_relation(self, relation: Relation, *, run_id: str | None = None) -> None:
        """Insert or update relation row."""

        payload = relation.to_dict()
        self._conn.execute(
            """
            INSERT INTO relations (id, source_id, relation_type, target_id, confidence, first_seen, last_seen, payload_json, run_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                confidence=excluded.confidence,
                first_seen=excluded.first_seen,
                last_seen=excluded.last_seen,
                payload_json=excluded.payload_json,
                run_id=COALESCE(excluded.run_id, relations.run_id)
            """,
            (
                relation.id,
                relation.source_id,
                relation.relation_type,
                relation.target_id,
                relation.confidence,
                relation.first_seen,
                relation.last_seen,
                json.dumps(payload),
                run_id,
            ),
        )
        self._conn.commit()

    def upsert_relations(self, relations: Iterable[Relation], *, run_id: str | None = None) -> None:
        """Batch upsert relations in one transaction."""

        cursor = self._conn.cursor()
        rows = []
        for relation in relations:
            rows.append(
                (
                    relation.id,
                    relation.source_id,
                    relation.relation_type,
                    relation.target_id,
                    relation.confidence,
                    relation.first_seen,
                    relation.last_seen,
                    json.dumps(relation.to_dict()),
                    run_id,
                )
            )
        cursor.executemany(
            """
            INSERT INTO relations (id, source_id, relation_type, target_id, confidence, first_seen, last_seen, payload_json, run_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                confidence=excluded.confidence,
                first_seen=excluded.first_seen,
                last_seen=excluded.last_seen,
                payload_json=excluded.payload_json,
                run_id=COALESCE(excluded.run_id, relations.run_id)
            """,
            rows,
        )
        self._conn.commit()

    def persist_event(
        self,
        event_id: str,
        topic: str,
        payload: dict[str, Any],
        metadata: dict[str, Any] | None = None,
        *,
        run_id: str | None = None,
        timestamp: str | None = None,
    ) -> None:
        """Persist one event record."""

        self._conn.execute(
            """
            INSERT OR REPLACE INTO events (id, topic, timestamp, payload_json, metadata_json, run_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                topic,
                timestamp or utc_now_iso(),
                json.dumps(payload),
                json.dumps(metadata or {}),
                run_id,
            ),
        )
        self._conn.commit()

    def load_assets(self, *, asset_type: str | None = None) -> list[BaseAsset]:
        """Load all assets, optionally filtered by asset type."""

        cursor = self._conn.cursor()
        if asset_type:
            rows = cursor.execute(
                "SELECT payload_json FROM assets WHERE asset_type = ?",
                (asset_type,),
            ).fetchall()
        else:
            rows = cursor.execute("SELECT payload_json FROM assets").fetchall()
        assets: list[BaseAsset] = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            assets.append(asset_from_dict(payload))
        return assets

    def load_relations(self) -> list[Relation]:
        """Load all relation rows."""

        rows = self._conn.execute("SELECT payload_json FROM relations").fetchall()
        return [Relation.from_dict(json.loads(row["payload_json"])) for row in rows]

    def list_findings(
        self,
        *,
        tiers: tuple[str, ...] | None = None,
        min_confidence: float = 0.0,
        limit: int = 200,
    ) -> list[Finding]:
        """Return finding assets sorted by severity and confidence.

        Filtering is performed in-memory because finding fields are stored inside
        payload_json. For larger deployments this can be migrated to dedicated
        columns or a document index.
        """

        findings = [asset for asset in self.load_assets(asset_type="finding") if isinstance(asset, Finding)]
        filtered = []
        for finding in findings:
            if tiers is not None and finding.tier not in tiers:
                continue
            if finding.confidence < min_confidence:
                continue
            filtered.append(finding)
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        filtered.sort(key=lambda f: (severity_order.get(f.severity, 0), f.confidence), reverse=True)
        return filtered[:limit]

    def export_json(self, output_path: str | Path) -> Path:
        """Export full graph state to one JSON file."""

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "runs": [dict(row) for row in self._conn.execute("SELECT * FROM runs").fetchall()],
            "assets": [asset.to_dict() for asset in self.load_assets()],
            "relations": [relation.to_dict() for relation in self.load_relations()],
        }
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return output

    def export_jsonl(self, output_dir: str | Path) -> Path:
        """Export assets and relations in JSONL files."""

        directory = Path(output_dir)
        directory.mkdir(parents=True, exist_ok=True)
        assets_path = directory / "assets.jsonl"
        relations_path = directory / "relations.jsonl"
        findings_path = directory / "findings.jsonl"

        with assets_path.open("w", encoding="utf-8") as handle:
            for asset in self.load_assets():
                handle.write(json.dumps(asset.to_dict()) + "\n")

        with relations_path.open("w", encoding="utf-8") as handle:
            for relation in self.load_relations():
                handle.write(json.dumps(relation.to_dict()) + "\n")

        with findings_path.open("w", encoding="utf-8") as handle:
            for finding in self.list_findings(limit=10_000):
                handle.write(json.dumps(finding.to_dict()) + "\n")

        return directory
