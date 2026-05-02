"""Main orchestration engine for defensive ReconX ingestion workflows."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reconx.adapters.base import AdapterContext, AdapterInput, BaseAdapter
from reconx.adapters.ffuf_adapter import FfufAdapter
from reconx.adapters.http_adapter import HttpAdapter
from reconx.adapters.nmap_adapter import NmapAdapter
from reconx.adapters.nuclei_adapter import NucleiAdapter
from reconx.enrichment.cve_enrichment import CVEEnrichmentPipeline
from reconx.config.settings import Settings
from reconx.core.assets import BaseAsset, Endpoint, Finding, Host, Service
from reconx.core.correlation import CVEProvider, CorrelationEngine
from reconx.core.dedup import DedupEngine
from reconx.core.event_bus import Event, EventBus
from reconx.core.relations import Relation
from reconx.core.scheduler import ScheduledTask, Scheduler, SchedulerResult, TaskStatusEvent
from reconx.core.storage import RunRecord, Storage
from reconx.pipeline.planner import Plan, Planner
from reconx.pipeline.profiles import Profile, get_profile
from reconx.ui.console import ConsoleRenderer
from reconx.utils.hashing import stable_json


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class RunSummary:
    """High-level result returned by one orchestrator run."""

    run_id: str
    profile: str
    planned_inputs: int
    ignored_paths: list[str]
    scheduler: SchedulerResult
    asset_counts: dict[str, int]
    relation_count: int
    finding_counts_by_tier: dict[str, int]
    output_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize summary into JSON-friendly shape."""

        return {
            "run_id": self.run_id,
            "profile": self.profile,
            "planned_inputs": self.planned_inputs,
            "ignored_paths": self.ignored_paths,
            "scheduler": self.scheduler.to_dict(),
            "asset_counts": self.asset_counts,
            "relation_count": self.relation_count,
            "finding_counts_by_tier": self.finding_counts_by_tier,
            "output_path": self.output_path,
        }


class Orchestrator:
    """Coordinates planning, adapter execution, dedup, and correlation.

    The orchestrator follows an asset-driven flow:
    1) Adapters ingest authorized scanner outputs and emit typed assets.
    2) Event handlers deduplicate/persist those assets.
    3) Asset-triggered adapters and correlation logic derive additional context.
    4) Final pass computes validated/probable/raw tiers for clean reporting.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        adapters: list[BaseAdapter] | None = None,
        event_bus: EventBus | None = None,
        dedup: DedupEngine | None = None,
        storage: Storage | None = None,
        correlation_engine: CorrelationEngine | None = None,
    ) -> None:
        self.settings = settings
        self.event_bus = event_bus or EventBus()
        self.dedup = dedup or DedupEngine()
        self.storage = storage or Storage(settings.storage.db_path)

        dataset = Path(settings.correlation.cve_dataset_path)
        provider = CVEProvider(dataset if dataset.exists() else None)
        if correlation_engine is None:
            correlation_engine = CorrelationEngine(provider)
        self.correlation_engine = correlation_engine

        default_adapters: list[BaseAdapter] = [
            NmapAdapter(), HttpAdapter(), NucleiAdapter(), FfufAdapter(),
        ]
        self.adapters = {adapter.name: adapter for adapter in (adapters or default_adapters)}

        # Standalone CVE enrichment pipeline for deeper analysis
        self.enrichment_pipeline = CVEEnrichmentPipeline(provider)
        self.planner = Planner(list(self.adapters.values()))

        self.scheduler = Scheduler(
            worker_count=settings.runtime.worker_count,
            rate_limit_per_sec=settings.runtime.rate_limit_per_sec,
            max_retries=settings.runtime.max_retries,
            backoff_base_seconds=settings.runtime.backoff_base_seconds,
            task_timeout_seconds=settings.runtime.task_timeout_seconds,
            cancel_on_error=settings.runtime.cancel_on_error,
            event_bus=self.event_bus,
        )

        self._active_profile: Profile | None = None
        self._active_run_id: str | None = None
        self._active_context: AdapterContext | None = None
        self._subscription_tokens: list[str] = []
        self._asset_trigger_seen: set[tuple[str, str]] = set()
        self._derived_signature_seen: set[str] = set()

    async def ingest(
        self,
        inputs: list[str | Path],
        *,
        profile_name: str = "default",
        output_format: str = "json",
        output_path: str | Path | None = None,
        debug: bool = False,
        show_raw_findings: bool = False,
        enable_console: bool = True,
    ) -> RunSummary:
        """Execute one complete ingestion run."""

        profile = get_profile(profile_name)
        self._active_profile = profile

        plan = self.planner.build_plan([Path(item) for item in inputs], profile)
        run = self.storage.create_run(
            profile=profile.name,
            input_count=plan.total_inputs,
            metadata={
                "inputs": [str(item) for item in inputs],
                "ignored": [str(path) for path in plan.ignored_paths],
            },
        )
        self._active_run_id = run.run_id
        self._active_context = AdapterContext(
            event_bus=self.event_bus,
            run_id=run.run_id,
            profile=profile.name,
            debug=debug,
            metadata={"profile": profile.name},
        )
        self._asset_trigger_seen = set()
        self._derived_signature_seen = set()

        self._register_event_handlers(run)

        console_renderer: ConsoleRenderer | None = None
        console_task: asyncio.Task[Any] | None = None
        if enable_console and self.settings.ui.enabled:
            console_renderer = ConsoleRenderer(
                debug=debug or self.settings.ui.debug,
                validated_only=(self.settings.ui.validated_only and not show_raw_findings),
            )
            console_task = asyncio.create_task(console_renderer.attach(self.event_bus))

        scheduler_result: SchedulerResult
        try:
            await self.event_bus.emit(
                "run.started",
                {"run_id": run.run_id, "profile": profile.name, "planned_inputs": plan.total_inputs},
                metadata={"run_id": run.run_id},
            )

            scheduled_tasks = self._build_tasks(plan)
            scheduler_result = await self.scheduler.run(scheduled_tasks)

            # One deterministic final pass across all findings.
            await self._finalize_correlation()

            run_status = "completed" if scheduler_result.failed == 0 else "completed_with_errors"
            self.storage.update_run_status(run.run_id, run_status, ended=True)
            await self.event_bus.emit(
                "run.completed",
                {
                    "run_id": run.run_id,
                    "status": run_status,
                    "scheduler": scheduler_result.to_dict(),
                },
                metadata={"run_id": run.run_id},
            )
        except Exception as exc:  # noqa: BLE001
            self.storage.update_run_status(run.run_id, "failed", ended=True)
            await self.event_bus.emit(
                "run.failed",
                {"run_id": run.run_id, "error": str(exc)},
                metadata={"run_id": run.run_id},
            )
            raise
        finally:
            if console_renderer is not None:
                console_renderer.stop()
            if console_task is not None:
                await asyncio.sleep(0)
                console_task.cancel()
                try:
                    await console_task
                except asyncio.CancelledError:
                    pass
            self._unregister_event_handlers()

        output_target: str | None = None
        if output_format.lower() == "json":
            target = Path(output_path) if output_path else Path(self.settings.storage.export_dir) / f"{run.run_id}.json"
            output_target = str(self.storage.export_json(target))
        elif output_format.lower() == "jsonl":
            target = Path(output_path) if output_path else Path(self.settings.storage.export_dir) / run.run_id
            output_target = str(self.storage.export_jsonl(target))

        return self._build_summary(
            run_id=run.run_id,
            profile=profile,
            plan=plan,
            scheduler_result=scheduler_result,
            output_path=output_target,
        )

    def ingest_sync(
        self,
        inputs: list[str | Path],
        *,
        profile_name: str = "default",
        output_format: str = "json",
        output_path: str | Path | None = None,
        debug: bool = False,
        show_raw_findings: bool = False,
        enable_console: bool = True,
    ) -> RunSummary:
        """Synchronous wrapper around :meth:`ingest` for CLI invocation."""

        return asyncio.run(
            self.ingest(
                inputs,
                profile_name=profile_name,
                output_format=output_format,
                output_path=output_path,
                debug=debug,
                show_raw_findings=show_raw_findings,
                enable_console=enable_console,
            )
        )

    def close(self) -> None:
        """Close persistent resources."""

        self.storage.close()

    def _register_event_handlers(self, run: RunRecord) -> None:
        """Attach event handlers for this active run."""

        self._subscription_tokens = []
        self._subscription_tokens.append(
            self.event_bus.subscribe("asset.*", self._handle_asset_event, name="orchestrator-assets")
        )
        self._subscription_tokens.append(
            self.event_bus.subscribe("relation.created", self._handle_relation_event, name="orchestrator-relations")
        )
        self._subscription_tokens.append(
            self.event_bus.subscribe("task.status", self._handle_task_status_event, name="orchestrator-task-status")
        )
        logger.debug("Registered %d subscriptions for run %s", len(self._subscription_tokens), run.run_id)

    def _unregister_event_handlers(self) -> None:
        """Detach run-scoped event handlers."""

        for token in self._subscription_tokens:
            self.event_bus.unsubscribe(token)
        self._subscription_tokens = []

    def _build_tasks(self, plan: Plan) -> list[ScheduledTask]:
        """Build scheduler tasks from file-based adapter plan."""

        if self._active_context is None:
            raise RuntimeError("No active adapter context")

        tasks: list[ScheduledTask] = []
        adapter_task_ids: list[str] = []

        for adapter_name, items in plan.adapter_inputs.items():
            adapter = self.adapters.get(adapter_name)
            if adapter is None:
                continue

            for index, item in enumerate(items):
                task_name = f"{adapter_name}:{index + 1}"

                async def run_item(
                    adapter: BaseAdapter = adapter,
                    item: AdapterInput = item,
                    context: AdapterContext = self._active_context,
                ) -> None:
                    await adapter.run(item, context)

                task = ScheduledTask(
                    name=task_name,
                    module=f"adapter.{adapter_name}",
                    run=run_item,
                    metadata={"input": str(item.value)},
                )
                tasks.append(task)
                adapter_task_ids.append(task.id)

        async def finalize() -> None:
            await self._finalize_correlation()

        tasks.append(
            ScheduledTask(
                name="finalize-correlation",
                module="pipeline.correlation",
                run=finalize,
                dependencies=set(adapter_task_ids),
                metadata={"phase": "post-adapter"},
            )
        )

        return tasks

    async def _handle_asset_event(self, event: Event[Any]) -> None:
        """Persist, deduplicate, and enrich asset events."""

        payload = event.payload
        if not isinstance(payload, BaseAsset):
            return
        if self._active_run_id is None:
            return

        merged_asset, merge = self.dedup.ingest_asset(payload)
        if merge.is_new or merge.changed:
            self.storage.upsert_asset(merged_asset, run_id=self._active_run_id)

        if self.settings.storage.persist_event_log:
            self.storage.persist_event(
                event_id=event.id,
                topic=event.topic,
                payload=merged_asset.to_dict(),
                metadata=event.metadata,
                run_id=self._active_run_id,
                timestamp=event.timestamp,
            )

        await self._trigger_asset_adapters(merged_asset)
        await self._emit_derived_findings(merged_asset)

    async def _handle_relation_event(self, event: Event[Any]) -> None:
        """Persist relation edges and event records."""

        payload = event.payload
        if not isinstance(payload, Relation):
            return
        if self._active_run_id is None:
            return

        relation, merge = self.dedup.ingest_relation(payload)
        if merge.is_new or merge.changed:
            self.storage.upsert_relation(relation, run_id=self._active_run_id)

        if self.settings.storage.persist_event_log:
            self.storage.persist_event(
                event_id=event.id,
                topic=event.topic,
                payload=relation.to_dict(),
                metadata=event.metadata,
                run_id=self._active_run_id,
                timestamp=event.timestamp,
            )

    async def _handle_task_status_event(self, event: Event[Any]) -> None:
        """Persist task state transition events."""

        if self._active_run_id is None:
            return
        payload = event.payload
        if not isinstance(payload, TaskStatusEvent):
            return
        if self.settings.storage.persist_event_log:
            self.storage.persist_event(
                event_id=event.id,
                topic=event.topic,
                payload=payload.to_dict(),
                metadata=event.metadata,
                run_id=self._active_run_id,
                timestamp=event.timestamp,
            )

    async def _trigger_asset_adapters(self, asset: BaseAsset) -> None:
        """Run adapters that accept this asset type.

        This keeps orchestration asset-driven while preserving defensive scope:
        adapters only transform/ingest existing data and never launch intrusive
        scans against live targets.
        """

        if self._active_profile is None or self._active_context is None:
            return

        for adapter_name in self._active_profile.enabled_adapters:
            adapter = self.adapters.get(adapter_name)
            if adapter is None:
                continue
            if not adapter.accepts_asset(asset):
                continue

            marker = (adapter.name, asset.id)
            if marker in self._asset_trigger_seen:
                continue
            self._asset_trigger_seen.add(marker)

            item = AdapterInput(
                kind="asset",
                value=asset,
                metadata={"trigger": "asset-event", "asset_type": asset.asset_type},
            )
            try:
                await adapter.run(item, self._active_context)
            except Exception:  # noqa: BLE001
                logger.exception("Asset-triggered adapter %s failed for asset %s", adapter.name, asset.id)

    async def _emit_derived_findings(self, asset: BaseAsset) -> None:
        """Emit correlation findings derived from service/endpoint assets."""

        if self._active_profile is None:
            return

        findings: list[Finding] = []

        if isinstance(asset, Service) and self._active_profile.enable_cve_enrichment:
            signature = stable_json(["cve", asset.id, asset.product, asset.version, asset.cpe])
            if signature not in self._derived_signature_seen:
                self._derived_signature_seen.add(signature)
                # Use both the inline correlation and the standalone enrichment pipeline
                findings.extend(self.correlation_engine.enrich_service_with_cves(asset))
                enrichment = self.enrichment_pipeline.enrich_service(asset)
                for ef in enrichment.findings:
                    # Avoid duplicating CVEs already found by the inline correlator
                    existing_cves = {cve for f in findings for cve in f.cve_ids}
                    if not any(c in existing_cves for c in ef.cve_ids):
                        findings.append(ef)

        if isinstance(asset, Endpoint) and self._active_profile.enable_endpoint_pattern_correlation:
            signature = stable_json(["endpoint-pattern", asset.id, asset.path])
            if signature not in self._derived_signature_seen:
                self._derived_signature_seen.add(signature)
                findings.extend(self.correlation_engine.analyze_endpoint(asset))

        if isinstance(asset, Finding):
            desired = self.correlation_engine.classify_finding_tier(asset)
            if desired != asset.tier:
                asset.tier = desired
                if self._active_run_id:
                    self.storage.upsert_asset(asset, run_id=self._active_run_id)

        for finding in findings:
            await self.event_bus.emit_asset(
                finding,
                metadata={
                    "run_id": self._active_run_id,
                    "source": "correlation",
                    "derived_from": asset.id,
                },
            )

            relation = Relation(
                source_id=asset.id,
                relation_type="vulnerable_to",
                target_id=finding.id,
                confidence=finding.confidence,
                evidence=finding.evidence,
            )
            await self.event_bus.emit(
                "relation.created",
                relation,
                metadata={"run_id": self._active_run_id, "source": "correlation"},
            )

    async def _finalize_correlation(self) -> None:
        """Run final confidence/tier adjustments and persist updated findings."""

        if self._active_run_id is None:
            return

        assets = self.dedup.all_assets()
        hosts = [asset for asset in assets if isinstance(asset, Host)]
        services = [asset for asset in assets if isinstance(asset, Service)]
        endpoints = [asset for asset in assets if isinstance(asset, Endpoint)]
        findings = [asset for asset in assets if isinstance(asset, Finding)]

        correlated = self.correlation_engine.correlate_findings(findings, hosts, endpoints, services)
        for finding in correlated:
            merged, merge = self.dedup.ingest_asset(finding)
            if merge.is_new or merge.changed:
                self.storage.upsert_asset(merged, run_id=self._active_run_id)

            relation = Relation(
                source_id=finding.id,
                relation_type="observed_on",
                target_id=finding.target_asset_id,
                confidence=finding.confidence,
                evidence=finding.evidence,
            )
            merged_relation, rel_merge = self.dedup.ingest_relation(relation)
            if rel_merge.is_new or rel_merge.changed:
                self.storage.upsert_relation(merged_relation, run_id=self._active_run_id)

    def _build_summary(
        self,
        *,
        run_id: str,
        profile: Profile,
        plan: Plan,
        scheduler_result: SchedulerResult,
        output_path: str | None,
    ) -> RunSummary:
        """Assemble final run summary from in-memory graph state."""

        assets = self.dedup.all_assets()
        asset_counts: dict[str, int] = {}
        for asset in assets:
            asset_counts[asset.asset_type] = asset_counts.get(asset.asset_type, 0) + 1

        findings = [asset for asset in assets if isinstance(asset, Finding)]
        finding_counts = {"validated": 0, "probable": 0, "raw": 0}
        for finding in findings:
            finding_counts[finding.tier] = finding_counts.get(finding.tier, 0) + 1

        return RunSummary(
            run_id=run_id,
            profile=profile.name,
            planned_inputs=plan.total_inputs,
            ignored_paths=[str(path) for path in plan.ignored_paths],
            scheduler=scheduler_result,
            asset_counts=asset_counts,
            relation_count=len(self.dedup.all_relations()),
            finding_counts_by_tier=finding_counts,
            output_path=output_path,
        )
