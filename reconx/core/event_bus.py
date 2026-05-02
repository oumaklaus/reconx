"""Thread-safe, async-friendly in-process pub/sub event bus.

ReconX uses broadcast semantics rather than destructive queue consumption.
When one component emits an asset event, every matching subscriber receives it.
This lets adapters, persistence hooks, and UI listeners react independently.
"""

from __future__ import annotations

import asyncio
import inspect
import threading
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable, Generic, TypeVar

from reconx.core.evidence import utc_now_iso
from reconx.utils.hashing import deterministic_id


PayloadT = TypeVar("PayloadT")
EventCallback = Callable[["Event[Any]"], Any]


@dataclass(slots=True)
class Event(Generic[PayloadT]):
    """A published event flowing through the in-process event bus."""

    topic: str
    payload: PayloadT
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now_iso)
    id: str = field(init=False)

    def __post_init__(self) -> None:
        self.id = deterministic_id("evt", self.topic, self.timestamp, id(self.payload))


@dataclass(slots=True)
class Subscription:
    """Internal subscription record."""

    token: str
    topic_pattern: str
    callback: EventCallback
    name: str
    once: bool = False


class EventBus:
    """Broadcast event bus with wildcard topic support.

    Topic matching rules:
    - Exact topic: ``asset.host``
    - Prefix wildcard: ``asset.*`` (matches ``asset.host`` and ``asset.finding``)
    - Global wildcard: ``*``
    """

    def __init__(self) -> None:
        self._subscriptions: dict[str, list[Subscription]] = {}
        self._lock = threading.RLock()
        self._stream_listeners: dict[str, asyncio.Queue[Event[Any]]] = {}

    def subscribe(
        self,
        topic_pattern: str,
        callback: EventCallback,
        *,
        name: str | None = None,
        once: bool = False,
    ) -> str:
        """Register a callback for topic events and return a token."""

        cleaned_pattern = topic_pattern.strip()
        if not cleaned_pattern:
            raise ValueError("topic_pattern cannot be empty")

        token = deterministic_id("sub", cleaned_pattern, name or repr(callback), id(callback))
        record = Subscription(
            token=token,
            topic_pattern=cleaned_pattern,
            callback=callback,
            name=name or getattr(callback, "__name__", "anonymous"),
            once=once,
        )
        with self._lock:
            self._subscriptions.setdefault(cleaned_pattern, []).append(record)
        return token

    def unsubscribe(self, token: str) -> bool:
        """Remove a subscription token. Returns True if removed."""

        removed = False
        with self._lock:
            for pattern, records in list(self._subscriptions.items()):
                kept = [record for record in records if record.token != token]
                if len(kept) != len(records):
                    removed = True
                    if kept:
                        self._subscriptions[pattern] = kept
                    else:
                        del self._subscriptions[pattern]
        return removed

    async def emit(
        self,
        topic: str,
        payload: PayloadT,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> Event[PayloadT]:
        """Publish an event to all matching subscribers."""

        event = Event(topic=topic.strip(), payload=payload, metadata=dict(metadata or {}))
        subscriptions = self._matching_subscriptions(event.topic)
        if subscriptions:
            await self._dispatch(event, subscriptions)
        await self._broadcast_to_streams(event)
        return event

    async def emit_asset(self, asset: Any, *, metadata: dict[str, Any] | None = None) -> Event[Any]:
        """Emit an asset event using its ``asset_type`` field.

        This helper standardizes the event topic naming convention.
        """

        asset_type = getattr(asset, "asset_type", None)
        if not isinstance(asset_type, str) or not asset_type:
            raise ValueError("emit_asset expected payload with non-empty 'asset_type'")
        return await self.emit(f"asset.{asset_type}", asset, metadata=metadata)

    def emit_sync(
        self,
        topic: str,
        payload: PayloadT,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> Event[PayloadT]:
        """Synchronous wrapper for contexts without direct async access."""

        coroutine = self.emit(topic, payload, metadata=metadata)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coroutine)

        if loop.is_running():
            raise RuntimeError("emit_sync cannot be called from a running event loop")

        future = asyncio.run_coroutine_threadsafe(coroutine, loop)
        return future.result()

    async def _dispatch(self, event: Event[Any], subscriptions: list[Subscription]) -> None:
        """Execute all subscription callbacks for one event."""

        tasks: list[Awaitable[Any]] = []
        remove_tokens: list[str] = []
        for subscription in subscriptions:
            result = subscription.callback(event)
            if inspect.isawaitable(result):
                tasks.append(result)
            if subscription.once:
                remove_tokens.append(subscription.token)

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=False)
        for token in remove_tokens:
            self.unsubscribe(token)

    async def _broadcast_to_streams(self, event: Event[Any]) -> None:
        """Fan out event to stream listeners used by the UI."""

        with self._lock:
            listeners = list(self._stream_listeners.values())
        for queue in listeners:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Backpressure: dropping stale events for stream consumers is
                # acceptable because durable state lives in storage.
                continue

    def _matching_subscriptions(self, topic: str) -> list[Subscription]:
        """Resolve all subscribers matching a topic pattern."""

        matched: list[Subscription] = []
        with self._lock:
            matched.extend(self._subscriptions.get("*", []))
            exact = self._subscriptions.get(topic, [])
            matched.extend(exact)

            # Prefix wildcard matching (e.g., asset.*)
            for pattern, records in self._subscriptions.items():
                if pattern == "*" or pattern == topic:
                    continue
                if pattern.endswith("*"):
                    prefix = pattern[:-1]
                    if topic.startswith(prefix):
                        matched.extend(records)
                elif pattern == topic:
                    matched.extend(records)
        return matched

    async def stream(self, *, max_queue: int = 1000) -> AsyncIterator[Event[Any]]:
        """Yield all events emitted after subscription registration.

        This is useful for TUI/console rendering and metrics exporters.
        """

        token = deterministic_id("stream", str(id(asyncio.current_task())), utc_now_iso())
        queue: asyncio.Queue[Event[Any]] = asyncio.Queue(maxsize=max_queue)
        with self._lock:
            self._stream_listeners[token] = queue

        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            with self._lock:
                self._stream_listeners.pop(token, None)
