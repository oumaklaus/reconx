"""Asynchronous execution engine with retries, rate limiting, and status events."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from typing import Any, Awaitable, Callable

from reconx.core.evidence import utc_now_iso
from reconx.core.event_bus import EventBus
from reconx.utils.hashing import deterministic_id


TaskCoroutine = Callable[[], Awaitable[Any]]


@dataclass(slots=True)
class ScheduledTask:
    """One runnable task managed by :class:`Scheduler`."""

    name: str
    module: str
    run: TaskCoroutine
    dependencies: set[str] = field(default_factory=set)
    max_retries: int = 2
    timeout_seconds: float = 120.0
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(init=False)

    def __post_init__(self) -> None:
        self.id = deterministic_id("task", self.module, self.name, sorted(self.dependencies))


@dataclass(slots=True)
class TaskState:
    """Runtime state for one scheduled task."""

    task_id: str
    name: str
    module: str
    status: str = "queued"
    attempts: int = 0
    error: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class TaskStatusEvent:
    """Payload emitted on ``task.status`` events."""

    task_id: str
    name: str
    module: str
    status: str
    attempts: int
    started_at: str | None
    ended_at: str | None
    error: str | None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize status event payload."""

        return asdict(self)


@dataclass(slots=True)
class SchedulerResult:
    """Summary of scheduler execution."""

    total: int
    completed: int
    failed: int
    cancelled: int
    skipped: int
    states: dict[str, TaskState]

    def to_dict(self) -> dict[str, Any]:
        """Serialize scheduler result into JSON-safe data."""

        return {
            "total": self.total,
            "completed": self.completed,
            "failed": self.failed,
            "cancelled": self.cancelled,
            "skipped": self.skipped,
            "states": {task_id: asdict(state) for task_id, state in self.states.items()},
        }


class AsyncRateLimiter:
    """Simple token spacing limiter for global scheduler throughput."""

    def __init__(self, rate_per_sec: float) -> None:
        self._rate = max(rate_per_sec, 0.0)
        self._interval = 1.0 / self._rate if self._rate > 0 else 0.0
        self._next_allowed = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until next action slot is available."""

        if self._interval == 0.0:
            return
        async with self._lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            wait = self._next_allowed - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = loop.time()
            self._next_allowed = max(self._next_allowed, now) + self._interval


class Scheduler:
    """Dependency-aware async task scheduler.

    Features:
    - worker pool
    - dependency unlocking
    - retries + backoff
    - cancellation support
    - task status event publication
    """

    def __init__(
        self,
        *,
        worker_count: int = 4,
        rate_limit_per_sec: float = 20.0,
        max_retries: int = 2,
        backoff_base_seconds: float = 0.5,
        task_timeout_seconds: float = 120.0,
        cancel_on_error: bool = False,
        event_bus: EventBus | None = None,
    ) -> None:
        self.worker_count = max(1, worker_count)
        self.rate_limit_per_sec = rate_limit_per_sec
        self.default_max_retries = max_retries
        self.backoff_base_seconds = max(backoff_base_seconds, 0.0)
        self.default_task_timeout_seconds = max(task_timeout_seconds, 1.0)
        self.cancel_on_error = cancel_on_error
        self.event_bus = event_bus

        self._cancel_event = asyncio.Event()
        self._state_lock = asyncio.Lock()
        self._states: dict[str, TaskState] = {}
        self._module_counters: dict[str, dict[str, int]] = {}

    def cancel(self) -> None:
        """Request cancellation of pending and future tasks."""

        self._cancel_event.set()

    def module_status(self) -> dict[str, dict[str, int]]:
        """Return current module counters."""

        return {module: dict(values) for module, values in self._module_counters.items()}

    async def run(self, tasks: list[ScheduledTask]) -> SchedulerResult:
        """Run scheduled tasks and return execution summary."""

        self._cancel_event = asyncio.Event()
        self._states = {}
        self._module_counters = {}

        if not tasks:
            return SchedulerResult(total=0, completed=0, failed=0, cancelled=0, skipped=0, states={})

        task_by_id = {task.id: task for task in tasks}
        if len(task_by_id) != len(tasks):
            raise ValueError("Duplicate task IDs detected")

        for task in tasks:
            for dependency in task.dependencies:
                if dependency not in task_by_id:
                    raise ValueError(f"Task {task.id} depends on unknown task {dependency}")

        remaining_dependencies = {task.id: len(task.dependencies) for task in tasks}
        dependency_failed = {task.id: False for task in tasks}
        dependents: dict[str, set[str]] = {task.id: set() for task in tasks}
        for task in tasks:
            for dependency in task.dependencies:
                dependents[dependency].add(task.id)

        queue: asyncio.Queue[str | None] = asyncio.Queue()

        for task in tasks:
            self._states[task.id] = TaskState(
                task_id=task.id,
                name=task.name,
                module=task.module,
                status="queued",
                metadata=dict(task.metadata),
            )
            self._increment_counter(task.module, "queued")

        for task in tasks:
            if remaining_dependencies[task.id] == 0:
                queue.put_nowait(task.id)

        limiter = AsyncRateLimiter(self.rate_limit_per_sec)
        workers = [
            asyncio.create_task(
                self._worker(
                    worker_id=idx,
                    queue=queue,
                    task_by_id=task_by_id,
                    remaining_dependencies=remaining_dependencies,
                    dependency_failed=dependency_failed,
                    dependents=dependents,
                    limiter=limiter,
                )
            )
            for idx in range(self.worker_count)
        ]

        await queue.join()

        for task in tasks:
            state = self._states[task.id]
            if state.status == "queued" and dependency_failed[task.id]:
                await self._set_status(task.id, "skipped", error="Blocked by failed dependency", ended_at=utc_now_iso())
            elif state.status == "queued" and self._cancel_event.is_set():
                await self._set_status(task.id, "cancelled", ended_at=utc_now_iso())

        for _ in workers:
            queue.put_nowait(None)
        await asyncio.gather(*workers, return_exceptions=False)

        states = dict(self._states)
        completed = sum(1 for state in states.values() if state.status == "completed")
        failed = sum(1 for state in states.values() if state.status == "failed")
        cancelled = sum(1 for state in states.values() if state.status == "cancelled")
        skipped = sum(1 for state in states.values() if state.status == "skipped")
        return SchedulerResult(
            total=len(tasks),
            completed=completed,
            failed=failed,
            cancelled=cancelled,
            skipped=skipped,
            states=states,
        )

    async def _worker(
        self,
        *,
        worker_id: int,
        queue: asyncio.Queue[str | None],
        task_by_id: dict[str, ScheduledTask],
        remaining_dependencies: dict[str, int],
        dependency_failed: dict[str, bool],
        dependents: dict[str, set[str]],
        limiter: AsyncRateLimiter,
    ) -> None:
        """Worker loop consuming runnable task IDs."""

        _ = worker_id
        while True:
            task_id = await queue.get()
            if task_id is None:
                queue.task_done()
                break

            task = task_by_id[task_id]

            if self._cancel_event.is_set():
                await self._set_status(task.id, "cancelled", ended_at=utc_now_iso())
                queue.task_done()
                continue

            if dependency_failed[task.id]:
                await self._set_status(task.id, "skipped", error="Blocked by failed dependency", ended_at=utc_now_iso())
                queue.task_done()
                continue

            await self._set_status(task.id, "running", started_at=utc_now_iso())

            max_retries = max(task.max_retries, self.default_max_retries)
            timeout = max(task.timeout_seconds, self.default_task_timeout_seconds)
            succeeded = False
            last_error: str | None = None

            for attempt in range(max_retries + 1):
                if self._cancel_event.is_set():
                    last_error = "Cancelled"
                    break
                self._states[task.id].attempts = attempt + 1
                try:
                    await limiter.acquire()
                    await asyncio.wait_for(task.run(), timeout=timeout)
                except asyncio.TimeoutError:
                    last_error = f"Timeout after {timeout:.1f}s"
                except asyncio.CancelledError:
                    last_error = "Cancelled"
                    self._cancel_event.set()
                    break
                except Exception as exc:  # noqa: BLE001
                    last_error = str(exc)
                else:
                    succeeded = True
                    break

                if attempt < max_retries and not self._cancel_event.is_set():
                    backoff = self.backoff_base_seconds * (2**attempt)
                    if backoff > 0:
                        await asyncio.sleep(backoff)

            if succeeded:
                await self._set_status(task.id, "completed", ended_at=utc_now_iso())
            elif self._cancel_event.is_set() and last_error == "Cancelled":
                await self._set_status(task.id, "cancelled", error=last_error, ended_at=utc_now_iso())
            else:
                await self._set_status(task.id, "failed", error=last_error, ended_at=utc_now_iso())
                if self.cancel_on_error:
                    self._cancel_event.set()

            for dependent_id in dependents[task.id]:
                remaining_dependencies[dependent_id] -= 1
                if self._states[task.id].status in {"failed", "cancelled", "skipped"}:
                    dependency_failed[dependent_id] = True
                if remaining_dependencies[dependent_id] == 0:
                    if dependency_failed[dependent_id]:
                        await self._set_status(
                            dependent_id,
                            "skipped",
                            error="Blocked by failed dependency",
                            ended_at=utc_now_iso(),
                        )
                    else:
                        queue.put_nowait(dependent_id)

            queue.task_done()

    async def _set_status(
        self,
        task_id: str,
        status: str,
        *,
        started_at: str | None = None,
        ended_at: str | None = None,
        error: str | None = None,
    ) -> None:
        """Transition task status and emit event."""

        async with self._state_lock:
            state = self._states[task_id]
            previous_status = state.status
            if previous_status == status and error is None:
                return

            self._decrement_counter(state.module, previous_status)
            state.status = status
            if started_at is not None:
                state.started_at = started_at
            if ended_at is not None:
                state.ended_at = ended_at
            if error is not None:
                state.error = error
            self._increment_counter(state.module, status)

            payload = TaskStatusEvent(
                task_id=state.task_id,
                name=state.name,
                module=state.module,
                status=state.status,
                attempts=state.attempts,
                started_at=state.started_at,
                ended_at=state.ended_at,
                error=state.error,
                metadata=state.metadata,
            )

        if self.event_bus is not None:
            await self.event_bus.emit("task.status", payload)

    def _increment_counter(self, module: str, status: str) -> None:
        counters = self._module_counters.setdefault(
            module,
            {"queued": 0, "running": 0, "completed": 0, "failed": 0, "cancelled": 0, "skipped": 0},
        )
        counters[status] = counters.get(status, 0) + 1

    def _decrement_counter(self, module: str, status: str) -> None:
        counters = self._module_counters.setdefault(
            module,
            {"queued": 0, "running": 0, "completed": 0, "failed": 0, "cancelled": 0, "skipped": 0},
        )
        counters[status] = max(0, counters.get(status, 0) - 1)
