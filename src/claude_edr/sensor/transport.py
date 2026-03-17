"""Transport layer for sending sensor data to the backend.

Sends inventory snapshots and real-time events to the backend API
over HTTP. Handles connection failures with retry and buffering.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Default backend URL (local deployment)
DEFAULT_BACKEND_URL = "http://localhost:7400"


@dataclass
class TransportConfig:
    backend_url: str = DEFAULT_BACKEND_URL
    retry_interval_s: float = 5.0
    batch_size: int = 50
    flush_interval_s: float = 1.0
    max_buffer_size: int = 10000


class BackendTransport:
    """Sends sensor data to the backend API over HTTP."""

    def __init__(self, config: TransportConfig | None = None):
        self.config = config or TransportConfig()
        self._event_buffer: list[dict[str, Any]] = []
        self._connected = False
        self._running = False
        self._flush_task: asyncio.Task | None = None
        self._session = None

    async def start(self) -> None:
        """Start the transport layer."""
        try:
            import aiohttp
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10),
            )
        except ImportError:
            raise RuntimeError("aiohttp required for transport: pip install aiohttp")

        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.info("Transport started, backend: %s", self.config.backend_url)

    async def stop(self) -> None:
        """Stop transport and flush remaining events."""
        self._running = False
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        # Final flush
        await self._flush()
        if self._session:
            await self._session.close()

    async def send_inventory(self, inventory: list[dict]) -> bool:
        """Send agent inventory snapshot to backend."""
        url = f"{self.config.backend_url}/api/sensor/inventory"
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agents": inventory,
        }
        return await self._post(url, payload)

    async def send_endpoint_info(self, endpoint: dict) -> bool:
        """Send endpoint info to backend for registration."""
        url = f"{self.config.backend_url}/api/sensor/endpoint"
        return await self._post(url, endpoint)

    async def send_event(self, event: dict) -> None:
        """Buffer an event for batched delivery to backend."""
        if len(self._event_buffer) >= self.config.max_buffer_size:
            # Drop oldest events when buffer full
            self._event_buffer.pop(0)
        self._event_buffer.append(event)

    async def _flush_loop(self) -> None:
        """Periodically flush buffered events to backend."""
        while self._running:
            await asyncio.sleep(self.config.flush_interval_s)
            if self._event_buffer:
                await self._flush()

    async def _flush(self) -> None:
        """Send buffered events to backend in batches."""
        if not self._event_buffer:
            return

        # Drain buffer into batches
        events = self._event_buffer[:self.config.batch_size]
        self._event_buffer = self._event_buffer[self.config.batch_size:]

        url = f"{self.config.backend_url}/api/sensor/events"
        payload = {"events": events, "count": len(events)}
        ok = await self._post(url, payload)

        if not ok:
            # Put events back at front of buffer for retry
            self._event_buffer = events + self._event_buffer

    async def _post(self, url: str, payload: dict) -> bool:
        """POST JSON to backend. Returns True on success."""
        if not self._session:
            return False
        try:
            async with self._session.post(url, json=payload) as resp:
                if resp.status == 200:
                    self._connected = True
                    return True
                else:
                    logger.warning("Backend returned %d for %s", resp.status, url)
                    return False
        except Exception as e:
            if self._connected:
                logger.warning("Lost connection to backend: %s", e)
                self._connected = False
            return False

    @property
    def is_connected(self) -> bool:
        return self._connected
