"""Process tree monitoring sensor.

Discovers AI coding agent processes and monitors their process trees
using psutil and /proc. Works for ALL agents without agent-specific
integration. No root required.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone

import psutil

from claude_edr.sensor.models.events import (
    AgentContext,
    AgentType,
    EDREvent,
    EventAction,
    EventCategory,
    NetworkContext,
    ProcessContext,
    Severity,
)
from claude_edr.sensor.sensors.base import BaseSensor

logger = logging.getLogger(__name__)

# Short-lived child processes from hooks/scripts - no security value
_NOISY_PROCESS_NAMES = frozenset({
    "grep", "cat", "head", "tail", "sed", "awk", "cut", "sort", "uniq",
    "wc", "tr", "tee", "xargs", "find", "basename", "dirname", "realpath",
    "jq", "paplay", "aplay", "notify-send",
    "true", "false", "test", "[",
})

# Agent process signatures
AGENT_SIGNATURES: dict[AgentType, dict] = {
    AgentType.CLAUDE_CODE: {
        "match_name": {"claude"},
        "match_cmdline": set(),
        "api_hosts": {"api.anthropic.com"},
    },
    AgentType.CURSOR: {
        "match_name": {"cursor", "Cursor"},
        "match_cmdline": set(),
        "exclude_args": {"--type="},  # Exclude Electron helper processes
        "api_hosts": {"api.cursor.com", "api.openai.com"},
    },
    AgentType.CODEX: {
        "match_name": {"codex"},
        "match_cmdline": {"codex"},
        "api_hosts": {"api.openai.com"},
    },
    AgentType.COPILOT: {
        "match_name": set(),
        "match_cmdline": {"copilot"},
        "api_hosts": {"copilot-proxy.githubusercontent.com"},
    },
    AgentType.WINDSURF: {
        "match_name": {"windsurf", "Windsurf"},
        "match_cmdline": set(),
        "exclude_args": {"--type="},
        "api_hosts": {"api.codeium.com"},
    },
    AgentType.AIDER: {
        "match_name": set(),
        "match_cmdline": {"aider"},
        "api_hosts": {"api.openai.com", "api.anthropic.com"},
    },
}


class ProcessSensor(BaseSensor):
    """Monitors process trees of AI coding agents."""

    def __init__(self, event_queue: asyncio.Queue[EDREvent], poll_interval_ms: int = 500):
        super().__init__(event_queue)
        self.poll_interval = poll_interval_ms / 1000.0
        self._tracked_agents: dict[int, AgentType] = {}  # pid -> agent_type
        self._known_children: dict[int, set[int]] = {}  # root_pid -> {child_pids}
        self._known_connections: dict[int, set[tuple]] = {}  # pid -> {(remote_addr, port)}

    @property
    def name(self) -> str:
        return "Process Monitor"

    @property
    def sensor_type(self) -> str:
        return "procmon"

    async def _run(self) -> None:
        """Main polling loop."""
        logger.info("Process sensor starting (poll interval: %dms)", int(self.poll_interval * 1000))
        while self._running:
            try:
                await self._scan()
            except Exception:
                logger.exception("Error in process scan")
            await asyncio.sleep(self.poll_interval)

    async def _scan(self) -> None:
        """Single scan cycle: discover agents, track children, monitor network."""
        # Discover new agent processes
        await self._discover_agents()

        # Track children of known agents
        for root_pid, agent_type in list(self._tracked_agents.items()):
            try:
                proc = psutil.Process(root_pid)
                await self._scan_children(proc, agent_type)
                await self._scan_connections(proc, agent_type)
            except psutil.NoSuchProcess:
                # Agent process exited
                logger.info("Agent process exited: %s (PID %d)", agent_type.value, root_pid)
                await self.emit(EDREvent(
                    category=EventCategory.SESSION,
                    action=EventAction.SESSION_END,
                    agent=AgentContext(agent_type=agent_type, agent_pid=root_pid),
                    process=ProcessContext(pid=root_pid, name=agent_type.value),
                ))
                self._tracked_agents.pop(root_pid, None)
                self._known_children.pop(root_pid, None)
                self._known_connections.pop(root_pid, None)

    async def _discover_agents(self) -> None:
        """Scan for new AI agent processes."""
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                pid = proc.info["pid"]
                if pid in self._tracked_agents:
                    continue

                agent_type = self._identify_agent(proc)
                if agent_type:
                    self._tracked_agents[pid] = agent_type
                    self._known_children[pid] = set()
                    self._known_connections[pid] = set()

                    cwd = ""
                    try:
                        cwd = proc.cwd()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                    logger.info("Discovered agent: %s (PID %d) in %s", agent_type.value, pid, cwd)
                    await self.emit(EDREvent(
                        category=EventCategory.SESSION,
                        action=EventAction.SESSION_START,
                        agent=AgentContext(
                            agent_type=agent_type,
                            agent_pid=pid,
                            working_directory=cwd,
                        ),
                        process=ProcessContext(
                            pid=pid,
                            name=proc.info["name"] or "",
                            cmdline=" ".join(proc.info["cmdline"] or []),
                        ),
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _identify_agent(self, proc: psutil.Process) -> AgentType | None:
        """Check if a process matches any known AI agent signature."""
        try:
            name = (proc.info["name"] or "").lower()
            cmdline_parts = proc.info["cmdline"] or []
            cmdline = " ".join(cmdline_parts).lower()

            for agent_type, sig in AGENT_SIGNATURES.items():
                # Check excluded args (e.g., Electron helper processes)
                exclude_args = sig.get("exclude_args", set())
                if any(exc.lower() in cmdline for exc in exclude_args):
                    continue

                # Check name match
                if sig["match_name"] and name in {n.lower() for n in sig["match_name"]}:
                    return agent_type

                # Check cmdline match
                if sig["match_cmdline"] and any(m.lower() in cmdline for m in sig["match_cmdline"]):
                    return agent_type

            return None
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    async def _scan_children(self, proc: psutil.Process, agent_type: AgentType) -> None:
        """Track child process spawning/exit for an agent."""
        root_pid = proc.pid
        try:
            current_children = set()
            for child in proc.children(recursive=True):
                current_children.add(child.pid)

            known = self._known_children.get(root_pid, set())

            # New children
            for child_pid in current_children - known:
                try:
                    child = psutil.Process(child_pid)
                    child_cmdline = " ".join(child.cmdline())
                    child_name = child.name()

                    # Skip noisy short-lived processes
                    if child_name in _NOISY_PROCESS_NAMES:
                        continue

                    await self.emit(EDREvent(
                        category=EventCategory.PROCESS_ACTIVITY,
                        action=EventAction.PROCESS_SPAWN,
                        agent=AgentContext(agent_type=agent_type, agent_pid=root_pid),
                        process=ProcessContext(
                            pid=child_pid,
                            ppid=child.ppid(),
                            name=child_name,
                            cmdline=child_cmdline,
                            uid=child.uids().real if hasattr(child, "uids") else 0,
                        ),
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Exited children (don't emit exit events for noisy processes)
            for child_pid in known - current_children:
                await self.emit(EDREvent(
                    category=EventCategory.PROCESS_ACTIVITY,
                    action=EventAction.PROCESS_EXIT,
                    agent=AgentContext(agent_type=agent_type, agent_pid=root_pid),
                    process=ProcessContext(pid=child_pid),
                ))

            self._known_children[root_pid] = current_children

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    async def _scan_connections(self, proc: psutil.Process, agent_type: AgentType) -> None:
        """Monitor network connections for an agent process tree."""
        root_pid = proc.pid
        try:
            current_conns: set[tuple] = set()

            # Get connections from root and all children
            pids = {root_pid} | self._known_children.get(root_pid, set())
            for pid in pids:
                try:
                    p = psutil.Process(pid)
                    for conn in p.net_connections(kind="inet"):
                        if conn.status == "ESTABLISHED" and conn.raddr:
                            key = (conn.raddr.ip, conn.raddr.port, pid)
                            current_conns.add(key)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            known = self._known_connections.get(root_pid, set())

            # New connections
            for remote_ip, remote_port, pid in current_conns - known:
                await self.emit(EDREvent(
                    category=EventCategory.NETWORK_ACTIVITY,
                    action=EventAction.NET_CONNECT,
                    agent=AgentContext(agent_type=agent_type, agent_pid=root_pid),
                    process=ProcessContext(pid=pid),
                    network=NetworkContext(
                        direction="outbound",
                        protocol="tcp",
                        remote_addr=remote_ip,
                        remote_port=remote_port,
                    ),
                ))

            self._known_connections[root_pid] = current_conns

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def get_tracked_agents(self) -> dict[int, AgentType]:
        """Return currently tracked agents (for API)."""
        return dict(self._tracked_agents)
