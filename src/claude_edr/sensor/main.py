"""Claude EDR Sensor - main entry point.

Runs on the endpoint (developer workstation), discovers AI coding agents,
monitors their activity via eBPF and hooks, and sends data to the backend.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from datetime import datetime, timezone

from claude_edr.sensor.inventory.agent_inventory import discover_all_agents
from claude_edr.sensor.inventory.endpoint import collect_endpoint_info
from claude_edr.sensor.models.events import EDREvent
from claude_edr.sensor.transport import BackendTransport, TransportConfig

logger = logging.getLogger(__name__)

# How often to re-scan inventory (seconds)
INVENTORY_SCAN_INTERVAL = 60


class SensorDaemon:
    """Main sensor process that discovers agents and monitors activity."""

    def __init__(self, backend_url: str = "http://localhost:7400"):
        self._shutdown = asyncio.Event()
        self._event_queue: asyncio.Queue[EDREvent] = asyncio.Queue(maxsize=10000)
        self._transport = BackendTransport(TransportConfig(backend_url=backend_url))
        self._ebpf_sensor = None
        self._process_sensor = None
        self._hook_sensor = None

    async def start(self) -> None:
        """Start the sensor daemon."""
        logger.info("Claude EDR Sensor starting...")

        # Start transport
        await self._transport.start()

        # Register this endpoint with the backend
        endpoint = collect_endpoint_info()
        agents = discover_all_agents()
        endpoint_dict = endpoint.to_dict()
        endpoint_dict["agent_count"] = len([a for a in agents if a.installed])
        await self._transport.send_endpoint_info(endpoint_dict)

        # Send initial inventory
        inventory = [a.to_dict() for a in agents]
        await self._transport.send_inventory(inventory)
        logger.info(
            "Registered endpoint %s with %d agents, %d total MCPs",
            endpoint.hostname,
            len(agents),
            sum(len(a.mcp_servers) for a in agents),
        )

        # Start sensors
        await self._start_sensors()

        # Start event forwarding and inventory refresh
        asyncio.create_task(self._forward_events())
        asyncio.create_task(self._inventory_loop())

        logger.info("Sensor running. Ctrl+C to stop.")
        await self._shutdown.wait()

    async def _start_sensors(self) -> None:
        """Start all available sensors."""
        # Try eBPF first (requires root)
        if os.geteuid() == 0:
            try:
                from claude_edr.sensor.sensors.ebpf_sensor import EbpfSensor
                self._ebpf_sensor = EbpfSensor(self._event_queue)
                await self._ebpf_sensor.start()
                logger.info("eBPF sensor started (full kernel visibility)")

                # Seed eBPF with discovered agent PIDs
                await self._seed_ebpf_pids()
            except Exception as e:
                logger.warning("eBPF sensor failed, falling back to process monitor: %s", e)
                self._ebpf_sensor = None

        if not self._ebpf_sensor:
            # Fallback: psutil-based process monitor (no root needed)
            from claude_edr.sensor.sensors.process_sensor import ProcessSensor
            self._process_sensor = ProcessSensor(self._event_queue)
            await self._process_sensor.start()
            logger.info("Process sensor started (psutil polling, no root)")

        # Hook sensor always runs (listens on Unix socket for Claude Code hooks)
        from claude_edr.sensor.sensors.hook_sensor import HookSensor
        from pathlib import Path
        socket_path = Path(os.environ.get("EDR_SOCKET", "/run/claude-edr/edr.sock"))
        try:
            self._hook_sensor = HookSensor(self._event_queue, socket_path)
            await self._hook_sensor.start()
            logger.info("Hook sensor started on %s", socket_path)
        except Exception as e:
            logger.warning("Hook sensor failed (may need socket dir): %s", e)

        # MCP Server Scanner (agent-agnostic tool call capture)
        try:
            from claude_edr.sensor.sensors.mcp_scanner import MCPScanner
            self._mcp_scanner = MCPScanner(
                self._event_queue,
                ebpf_sensor=self._ebpf_sensor,
                scan_interval=5.0,
            )
            await self._mcp_scanner.start()
            logger.info(
                "MCP scanner started%s",
                " (with eBPF pipe capture)" if self._ebpf_sensor else "",
            )
        except Exception as e:
            logger.warning("MCP scanner failed to start: %s", e)

    async def _seed_ebpf_pids(self) -> None:
        """Feed discovered agent PIDs to the eBPF sensor for tracking."""
        if not self._ebpf_sensor:
            return

        import psutil
        from claude_edr.sensor.models.events import AgentType
        from claude_edr.sensor.sensors.process_sensor import AGENT_SIGNATURES

        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                name = (proc.info["name"] or "").lower()
                cmdline = " ".join(proc.info["cmdline"] or []).lower()

                for agent_type, sig in AGENT_SIGNATURES.items():
                    matched = False
                    if sig["match_name"] and name in {n.lower() for n in sig["match_name"]}:
                        matched = True
                    if sig["match_cmdline"] and any(m.lower() in cmdline for m in sig["match_cmdline"]):
                        matched = True
                    if matched:
                        exclude = sig.get("exclude_args", set())
                        if any(exc.lower() in cmdline for exc in exclude):
                            continue
                        self._ebpf_sensor.track_agent(proc.info["pid"], agent_type)
                        logger.info("Seeded eBPF with %s PID %d", agent_type.value, proc.info["pid"])
            except Exception:
                continue

    async def _forward_events(self) -> None:
        """Read events from sensor queue and send to backend."""
        while not self._shutdown.is_set():
            try:
                event = await asyncio.wait_for(
                    self._event_queue.get(), timeout=1.0
                )
                await self._transport.send_event(event.to_dict())
            except asyncio.TimeoutError:
                continue
            except Exception:
                logger.exception("Error forwarding event")

    async def _inventory_loop(self) -> None:
        """Periodically re-scan and send inventory updates."""
        while not self._shutdown.is_set():
            await asyncio.sleep(INVENTORY_SCAN_INTERVAL)
            try:
                agents = discover_all_agents()
                inventory = [a.to_dict() for a in agents]
                await self._transport.send_inventory(inventory)
                logger.debug("Inventory refresh: %d agents", len(agents))

                # If eBPF is running, seed any newly discovered agent PIDs
                if self._ebpf_sensor:
                    await self._seed_ebpf_pids()
            except Exception:
                logger.exception("Error in inventory scan")

    async def stop(self) -> None:
        """Stop all sensors and transport."""
        logger.info("Sensor shutting down...")
        if self._ebpf_sensor:
            await self._ebpf_sensor.stop()
        if self._process_sensor:
            await self._process_sensor.stop()
        if self._hook_sensor:
            await self._hook_sensor.stop()
        await self._transport.stop()
        logger.info("Sensor stopped.")

    def request_shutdown(self) -> None:
        self._shutdown.set()


def main() -> None:
    """CLI entry point for the sensor."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    backend_url = os.environ.get("EDR_BACKEND_URL", "http://localhost:7400")
    daemon = SensorDaemon(backend_url=backend_url)

    loop = asyncio.new_event_loop()

    def handle_signal(signum, frame):
        daemon.request_shutdown()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        loop.run_until_complete(daemon.start())
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(daemon.stop())
        loop.close()


if __name__ == "__main__":
    main()
