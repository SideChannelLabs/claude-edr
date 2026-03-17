"""Event pipeline - routes events from sensors through enrichment, detection, to storage."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from claude_edr.backend.models.events import EDREvent
from claude_edr.backend.pipeline.enrichment import enrich_event
from claude_edr.backend.registry.agent_registry import AgentRegistry
from claude_edr.backend.storage.sqlite_store import EventStore

logger = logging.getLogger(__name__)


class EventPipeline:
    """Async event processing pipeline.

    Consumes events from sensor queue → enriches → detects → stores.
    Also notifies WebSocket subscribers for real-time dashboard updates.
    """

    def __init__(
        self,
        event_queue: asyncio.Queue[EDREvent],
        store: EventStore,
        registry: AgentRegistry,
    ):
        self.event_queue = event_queue
        self.store = store
        self.registry = registry
        self._running = False
        self._task: asyncio.Task | None = None
        self._subscribers: list[Callable[[EDREvent], None]] = []
        self._detection_engine = None  # Set after initialization
        self.events_processed = 0

    def set_detection_engine(self, engine) -> None:
        """Set the detection engine (called after both are initialized)."""
        self._detection_engine = engine

    def subscribe(self, callback: Callable[[EDREvent], None]) -> None:
        """Subscribe to real-time event stream (for WebSocket)."""
        self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[EDREvent], None]) -> None:
        """Unsubscribe from event stream."""
        self._subscribers = [s for s in self._subscribers if s is not callback]

    async def start(self) -> None:
        """Start processing events from the queue."""
        self._running = True
        self._task = asyncio.create_task(self._run())
        logger.info("Event pipeline started")

    async def stop(self) -> None:
        """Stop the pipeline."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Event pipeline stopped (%d events processed)", self.events_processed)

    async def _run(self) -> None:
        """Main pipeline loop.

        Drains up to 100 events per iteration to keep up with
        high-throughput eBPF sensors. SQLite batches commits for
        better write performance.
        """
        while self._running:
            try:
                # Wait for at least one event
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                raise

            # Process this event + drain up to 99 more
            batch = [event]
            for _ in range(99):
                try:
                    batch.append(self.event_queue.get_nowait())
                except asyncio.QueueEmpty:
                    break

            for evt in batch:
                try:
                    await self._process_event(evt)
                except Exception:
                    logger.exception("Error processing event")

    async def _process_event(self, event: EDREvent) -> None:
        """Process a single event through the pipeline."""
        # 1. Enrich
        event = enrich_event(event)

        # 2. Update agent registry
        self.registry.update_from_event(event)

        # 3. Run detection rules
        if self._detection_engine:
            await self._detection_engine.evaluate(event)

        # 4. Store
        try:
            await self.store.store_event(event)
        except Exception:
            logger.exception("Failed to store event %s", event.id)

        # 5. Notify subscribers (dashboard WebSocket)
        event_dict = event.to_dict()
        for subscriber in self._subscribers:
            try:
                subscriber(event_dict)
            except Exception:
                logger.exception("Error in event subscriber")

        self.events_processed += 1

    async def process_event_dict(self, event_dict: dict) -> None:
        """Process a pre-serialized event dict from the sensor transport.

        Skips EDREvent object creation - stores directly and runs detection
        on the dict representation.
        """
        # Store directly
        try:
            await self.store.store_event_dict(event_dict)
        except Exception:
            logger.exception("Failed to store sensor event")

        # Run detection if we have an engine
        if self._detection_engine:
            try:
                await self._detection_engine.evaluate_dict(event_dict)
            except Exception:
                logger.exception("Detection failed on sensor event")

        # Notify WebSocket subscribers
        for subscriber in self._subscribers:
            try:
                subscriber(event_dict)
            except Exception:
                pass

        self.events_processed += 1
