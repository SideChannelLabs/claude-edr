"""Claude Code hook sensor.

Receives events from Claude Code's PreToolUse/PostToolUse hooks
via a Unix domain socket. This is the highest-fidelity sensor for
Claude Code - it knows the tool name, inputs, and can block operations.

Hook scripts (in hooks/) send JSON events to /run/claude-edr/edr.sock.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from claude_edr.sensor.models.events import (
    AgentContext,
    AgentType,
    EDREvent,
    EventAction,
    EventCategory,
    FileContext,
    NetworkContext,
    ProcessContext,
    Severity,
)
from claude_edr.sensor.sensors.base import BaseSensor

logger = logging.getLogger(__name__)

# Map Claude Code tool names to event categories and actions
TOOL_EVENT_MAP: dict[str, tuple[EventCategory, EventAction]] = {
    "Bash": (EventCategory.PROCESS_ACTIVITY, EventAction.TOOL_INVOKE),
    "Read": (EventCategory.FILE_ACTIVITY, EventAction.FILE_READ),
    "Write": (EventCategory.FILE_ACTIVITY, EventAction.FILE_WRITE),
    "Edit": (EventCategory.FILE_ACTIVITY, EventAction.FILE_WRITE),
    "Glob": (EventCategory.FILE_ACTIVITY, EventAction.FILE_READ),
    "Grep": (EventCategory.FILE_ACTIVITY, EventAction.FILE_READ),
    "WebFetch": (EventCategory.NETWORK_ACTIVITY, EventAction.NET_CONNECT),
    "WebSearch": (EventCategory.NETWORK_ACTIVITY, EventAction.NET_CONNECT),
    "Task": (EventCategory.PROCESS_ACTIVITY, EventAction.PROCESS_SPAWN),
}


class HookSensor(BaseSensor):
    """Receives events from Claude Code hook scripts via Unix domain socket."""

    def __init__(self, event_queue: asyncio.Queue[EDREvent], socket_path: Path):
        super().__init__(event_queue)
        self.socket_path = socket_path
        self._server: asyncio.AbstractServer | None = None

    @property
    def name(self) -> str:
        return "Claude Code Hooks"

    @property
    def sensor_type(self) -> str:
        return "hook"

    async def _run(self) -> None:
        """Start Unix domain socket server to receive hook events."""
        # Ensure socket directory exists
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)

        # Remove stale socket file
        if self.socket_path.exists():
            self.socket_path.unlink()

        self._server = await asyncio.start_unix_server(
            self._handle_connection, path=str(self.socket_path)
        )
        # Make socket world-writable so hook scripts (running as user) can connect
        os.chmod(str(self.socket_path), 0o777)

        logger.info("Hook sensor listening on %s", self.socket_path)

        async with self._server:
            await self._server.serve_forever()

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming connection from a hook script."""
        try:
            data = await reader.read(1024 * 1024)  # 1MB max
            if not data:
                return

            payload = json.loads(data.decode("utf-8"))
            event = self._parse_hook_event(payload)
            if event:
                await self.emit(event)
                logger.debug("Hook event: %s %s", event.action.value, event.agent.tool_name if event.agent else "")
        except json.JSONDecodeError:
            logger.warning("Invalid JSON from hook script")
        except Exception:
            logger.exception("Error handling hook connection")
        finally:
            writer.close()
            await writer.wait_closed()

    def _parse_hook_event(self, payload: dict) -> EDREvent | None:
        """Parse a hook script payload into an EDREvent."""
        hook_type = payload.get("hook_event_name", "")
        tool_name = payload.get("tool_name", "")
        tool_input = payload.get("tool_input", {})
        tool_response = payload.get("tool_response")
        session_id = payload.get("session_id", "")
        cwd = payload.get("cwd", "")

        # Determine action based on hook type and tool
        if hook_type == "PreToolUse":
            action = EventAction.TOOL_INVOKE
        elif hook_type == "PostToolUse":
            action = EventAction.TOOL_COMPLETE
        elif hook_type == "SessionStart":
            return self._session_event(payload, EventAction.SESSION_START)
        elif hook_type == "SessionEnd":
            return self._session_event(payload, EventAction.SESSION_END)
        elif hook_type == "ConfigChange":
            return self._config_event(payload)
        else:
            return None

        # Get category from tool name
        category, _ = TOOL_EVENT_MAP.get(tool_name, (EventCategory.TOOL_CALL, EventAction.TOOL_INVOKE))

        event = EDREvent(
            category=category,
            action=action,
            agent=AgentContext(
                agent_type=AgentType.CLAUDE_CODE,
                session_id=session_id,
                working_directory=cwd,
                tool_name=tool_name,
                tool_input=tool_input,
                tool_response=tool_response,
            ),
            raw_data=payload,
        )

        # Extract file context for file operations
        file_path = tool_input.get("file_path", "")
        if file_path:
            event.file = FileContext(
                path=file_path,
                operation=tool_name.lower(),
            )

        # Extract process context for Bash commands
        if tool_name == "Bash":
            command = tool_input.get("command", "")
            event.process = ProcessContext(
                pid=0,  # Will be enriched later by process sensor
                name="bash",
                cmdline=command,
            )

        # Extract network context for web operations
        if tool_name == "WebFetch":
            url = tool_input.get("url", "")
            event.network = NetworkContext(
                direction="outbound",
                protocol="https",
                domain=self._extract_domain(url),
            )
        elif tool_name == "WebSearch":
            event.network = NetworkContext(
                direction="outbound",
                protocol="https",
                domain="search",
            )

        return event

    def _session_event(self, payload: dict, action: EventAction) -> EDREvent:
        """Create a session start/end event."""
        return EDREvent(
            category=EventCategory.SESSION,
            action=action,
            agent=AgentContext(
                agent_type=AgentType.CLAUDE_CODE,
                session_id=payload.get("session_id", ""),
                working_directory=payload.get("cwd", ""),
            ),
            raw_data=payload,
        )

    def _config_event(self, payload: dict) -> EDREvent:
        """Create a config change event."""
        return EDREvent(
            category=EventCategory.CONFIG_CHANGE,
            action=EventAction.CONFIG_CHANGED,
            severity=Severity.MEDIUM,
            agent=AgentContext(
                agent_type=AgentType.CLAUDE_CODE,
                session_id=payload.get("session_id", ""),
                working_directory=payload.get("cwd", ""),
            ),
            raw_data=payload,
        )

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            return urlparse(url).hostname or ""
        except Exception:
            return ""

    async def stop(self) -> None:
        if self._server:
            self._server.close()
        await super().stop()
