"""Main EDR daemon - orchestrates all components.

Local mode: runs sensors + pipeline + dashboard in a single process.
Enterprise mode (future): backend only, receives events from remote sensors.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from pathlib import Path

import psutil
import uvicorn

from claude_edr.backend.config import Config
from claude_edr.backend.detection.engine import DetectionEngine
from claude_edr.backend.pipeline.router import EventPipeline
from claude_edr.backend.registry.agent_registry import AgentRegistry
from claude_edr.backend.storage.sqlite_store import EventStore

logger = logging.getLogger(__name__)


class EDRDaemon:
    """Main daemon that wires together all EDR components.

    In local mode, runs sensors in-process alongside the backend.
    """

    def __init__(self, config: Config):
        self.config = config
        self._shutdown_event = asyncio.Event()

        # Core components
        self.event_queue: asyncio.Queue = asyncio.Queue(maxsize=50000)
        self.store = EventStore(config.storage.db_path)
        self.registry = AgentRegistry()
        self.pipeline = EventPipeline(self.event_queue, self.store, self.registry)
        self.detection = DetectionEngine(self.store, self.registry)

        # Sensors (populated in _start_sensors)
        self.sensors = []
        self._ebpf_sensor = None

    async def start(self) -> None:
        """Start all components."""
        logger.info("Starting Claude EDR daemon (local mode)...")

        # Initialize storage
        await self.store.initialize()

        # Register this endpoint
        await self._register_local_endpoint()

        # Load detection rules
        for rules_dir in self.config.detection.rules_dirs:
            rules_path = Path(rules_dir)
            if not rules_path.is_absolute():
                rules_path = Path.cwd() / rules_path
            self.detection.load_rules_from_dir(rules_path)

        # Wire detection engine to pipeline
        self.pipeline.set_detection_engine(self.detection)

        # Start pipeline
        await self.pipeline.start()

        # Start sensors
        await self._start_sensors()

        # Start dashboard
        if self.config.dashboard.enabled:
            from claude_edr.backend.api.server import app, configure
            # Pass first rules_dir for custom rule persistence
            first_rules_dir = None
            if self.config.detection.rules_dirs:
                first_rules_dir = Path(self.config.detection.rules_dirs[0])
                if not first_rules_dir.is_absolute():
                    first_rules_dir = Path.cwd() / first_rules_dir
            configure(self.store, self.registry, self.pipeline, self.detection, rules_dir=first_rules_dir)

            uvicorn_config = uvicorn.Config(
                app,
                host=self.config.dashboard.host,
                port=self.config.dashboard.port,
                log_level="warning",
            )
            server = uvicorn.Server(uvicorn_config)
            asyncio.create_task(server.serve())
            logger.info(
                "Dashboard running at http://%s:%d",
                self.config.dashboard.host,
                self.config.dashboard.port,
            )

        # Summary
        sensor_names = [s.name for s in self.sensors]
        ebpf_status = "active" if self._ebpf_sensor else "unavailable"
        logger.info(
            "Claude EDR running | Sensors: %s | eBPF: %s | Rules: %d | Dashboard: %s",
            ", ".join(sensor_names) or "none",
            ebpf_status,
            len(self.detection.rules),
            f"http://{self.config.dashboard.host}:{self.config.dashboard.port}"
            if self.config.dashboard.enabled
            else "disabled",
        )

        # Wait for shutdown
        await self._shutdown_event.wait()

    async def _start_sensors(self) -> None:
        """Start all configured sensors."""
        # Hook sensor (Claude Code hooks via Unix socket)
        if self.config.sensors.hooks_enabled:
            try:
                from claude_edr.sensor.sensors.hook_sensor import HookSensor
                hook_sensor = HookSensor(self.event_queue, self.config.socket_path)
                self.sensors.append(hook_sensor)
                await hook_sensor.start()
            except ImportError:
                logger.warning("claude-edr-sensor not installed, hook sensor unavailable")
            except Exception as e:
                logger.warning("Hook sensor failed to start: %s", e)

        # eBPF sensor (requires root, provides kernel-level visibility)
        if self.config.sensors.ebpf_enabled and os.geteuid() == 0:
            try:
                from claude_edr.sensor.sensors.ebpf_sensor import EbpfSensor
                self._ebpf_sensor = EbpfSensor(
                    self.event_queue,
                    enable_ssl=self.config.ssl_capture.enabled,
                    enable_pipe_capture=True,
                )
                await self._ebpf_sensor.start()
                self.sensors.append(self._ebpf_sensor)
                logger.info("eBPF sensor active - kernel-level monitoring enabled")

                # Wait for BPF to compile before seeding PIDs
                try:
                    await asyncio.wait_for(self._ebpf_sensor.ready.wait(), timeout=30)
                except asyncio.TimeoutError:
                    logger.warning("eBPF BPF compilation timed out")

                # Seed with discovered agent PIDs
                await self._seed_ebpf_pids()
            except ImportError:
                logger.warning("BCC not available, eBPF sensor unavailable")
                self._ebpf_sensor = None
            except Exception as e:
                logger.warning("eBPF sensor failed: %s", e)
                self._ebpf_sensor = None

        # Process sensor (psutil fallback when eBPF unavailable)
        if self.config.sensors.process_monitor_enabled and not self._ebpf_sensor:
            try:
                from claude_edr.sensor.sensors.process_sensor import ProcessSensor
                proc_sensor = ProcessSensor(
                    self.event_queue,
                    self.config.sensors.poll_interval_ms,
                )
                self.sensors.append(proc_sensor)
                await proc_sensor.start()
                logger.info("Process sensor active (psutil polling, eBPF unavailable)")
            except ImportError:
                logger.warning("claude-edr-sensor not installed, process sensor unavailable")
            except Exception as e:
                logger.warning("Process sensor failed: %s", e)

        # MCP Server Scanner (agent-agnostic MCP tool call capture)
        # Works with or without eBPF: discovers MCP servers and wires pipe tracking
        try:
            from claude_edr.sensor.sensors.mcp_scanner import MCPScanner
            mcp_scanner = MCPScanner(
                self.event_queue,
                ebpf_sensor=self._ebpf_sensor,
                scan_interval=5.0,
            )
            self.sensors.append(mcp_scanner)
            await mcp_scanner.start()
            logger.info(
                "MCP scanner active - detecting MCP servers across all agents%s",
                " (with eBPF pipe capture)" if self._ebpf_sensor else "",
            )
        except ImportError:
            logger.warning("claude-edr-sensor not installed, MCP scanner unavailable")
        except Exception as e:
            logger.warning("MCP scanner failed to start: %s", e)

        # Start periodic inventory refresh
        asyncio.create_task(self._inventory_refresh_loop())

    async def _seed_ebpf_pids(self) -> None:
        """Feed discovered agent PIDs to the eBPF sensor for tracking."""
        if not self._ebpf_sensor:
            return

        try:
            from claude_edr.sensor.sensors.process_sensor import AGENT_SIGNATURES
            from claude_edr.sensor.models.events import AgentType
        except ImportError:
            return

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
                        logger.info(
                            "eBPF tracking %s (PID %d)", agent_type.value, proc.info["pid"]
                        )
            except Exception:
                continue

    async def _inventory_refresh_loop(self) -> None:
        """Periodically re-scan agent inventory and update dashboard cache."""
        while not self._shutdown_event.is_set():
            await asyncio.sleep(60)
            try:
                from claude_edr.sensor.inventory.agent_inventory import discover_all_agents
                from claude_edr.backend.api.server import get_inventory_cache

                agents = discover_all_agents()
                # Update the in-memory cache used by dashboard pages
                inventory = [a.to_dict() for a in agents]
                # Direct update since we're in-process
                from claude_edr.backend.api import server
                server._inventory_cache = inventory

                logger.debug("Inventory refresh: %d agents", len(agents))

                # Re-seed eBPF with any new agent PIDs
                if self._ebpf_sensor:
                    await self._seed_ebpf_pids()
            except ImportError:
                pass
            except Exception:
                logger.exception("Error in inventory refresh")

    async def _register_local_endpoint(self) -> None:
        """Register this machine as an endpoint in the database."""
        try:
            from claude_edr.sensor.inventory.agent_inventory import discover_all_agents
            from claude_edr.sensor.inventory.endpoint import collect_endpoint_info
        except ImportError:
            logger.warning("claude-edr-sensor not installed, skipping endpoint registration")
            return

        info = collect_endpoint_info()
        agents = discover_all_agents()

        # Cache initial inventory
        from claude_edr.backend.api import server
        server._inventory_cache = [a.to_dict() for a in agents]

        await self.store.register_endpoint(
            endpoint_id=info.endpoint_id,
            hostname=info.hostname,
            os_name=info.os_name,
            os_version=info.os_version,
            kernel=info.kernel,
            arch=info.arch,
            ip_addresses=info.ip_addresses,
            username=info.username,
            cpu_count=info.cpu_count,
            memory_total_gb=info.memory_total_gb,
            agent_count=len([a for a in agents if a.installed]),
        )
        logger.info("Registered endpoint: %s (%s)", info.hostname, info.endpoint_id)

    async def stop(self) -> None:
        """Stop all components gracefully."""
        logger.info("Shutting down Claude EDR...")

        for sensor in self.sensors:
            await sensor.stop()

        await self.pipeline.stop()
        await self.store.close()

        logger.info("Claude EDR stopped.")

    def request_shutdown(self) -> None:
        """Signal the daemon to shut down."""
        self._shutdown_event.set()


def run_daemon(config: Config) -> None:
    """Entry point for running the daemon."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    daemon = EDRDaemon(config)

    loop = asyncio.new_event_loop()

    def handle_signal(signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
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
