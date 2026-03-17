"""Base sensor interface for all EDR data collection sensors."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from claude_edr.sensor.models.events import EDREvent

logger = logging.getLogger(__name__)


class BaseSensor(ABC):
    """Abstract base class for all sensors.

    Each sensor collects events from a different source and emits them
    as EDREvents into a shared async queue for the pipeline to process.
    """

    def __init__(self, event_queue: asyncio.Queue[EDREvent]):
        self.event_queue = event_queue
        self._running = False
        self._task: asyncio.Task | None = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable sensor name."""
        ...

    @property
    @abstractmethod
    def sensor_type(self) -> str:
        """Sensor type identifier (hook, procmon, ebpf, logwatch)."""
        ...

    async def emit(self, event: EDREvent) -> None:
        """Emit an event to the pipeline.

        Non-blocking: drops event if queue is full rather than
        blocking the sensor's event loop (which would cause BPF
        perf buffer overflows).
        """
        event.sensor_source = self.sensor_type
        try:
            self.event_queue.put_nowait(event)
        except asyncio.QueueFull:
            pass  # Drop event rather than block sensor

    @abstractmethod
    async def _run(self) -> None:
        """Main sensor loop. Override this in subclasses."""
        ...

    async def start(self) -> None:
        """Start the sensor."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_wrapper())
        logger.info("Sensor started: %s", self.name)

    async def stop(self) -> None:
        """Stop the sensor."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Sensor stopped: %s", self.name)

    async def _run_wrapper(self) -> None:
        """Wrapper that handles errors in the sensor loop."""
        try:
            await self._run()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Sensor %s crashed", self.name)
            self._running = False
