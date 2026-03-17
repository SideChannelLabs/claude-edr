"""Agent registry - tracks all active AI coding agent sessions."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from claude_edr.backend.models.events import AgentType, EDREvent, EventAction

logger = logging.getLogger(__name__)


@dataclass
class AgentSession:
    """An active AI agent session."""

    session_id: str
    agent_type: AgentType
    root_pid: int
    start_time: datetime
    working_directory: str = ""
    event_count: int = 0
    alert_count: int = 0
    child_pids: set[int] = field(default_factory=set)
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "agent_type": self.agent_type.value,
            "root_pid": self.root_pid,
            "start_time": self.start_time.isoformat(),
            "working_directory": self.working_directory,
            "event_count": self.event_count,
            "alert_count": self.alert_count,
            "child_pids": list(self.child_pids),
            "last_activity": self.last_activity.isoformat(),
        }


class AgentRegistry:
    """Central registry of all active AI agent sessions.

    Updated by the pipeline as events flow through.
    Queried by the API/dashboard for agent status.
    """

    def __init__(self):
        self._sessions: dict[str, AgentSession] = {}  # session_id -> session
        self._pid_to_session: dict[int, str] = {}  # root_pid -> session_id

    def update_from_event(self, event: EDREvent) -> None:
        """Update registry based on an incoming event."""
        if not event.agent:
            return

        session_id = event.agent.session_id or f"pid-{event.agent.agent_pid}"

        if event.action == EventAction.SESSION_START:
            session = AgentSession(
                session_id=session_id,
                agent_type=event.agent.agent_type,
                root_pid=event.agent.agent_pid,
                start_time=event.timestamp,
                working_directory=event.agent.working_directory,
            )
            self._sessions[session_id] = session
            if event.agent.agent_pid:
                self._pid_to_session[event.agent.agent_pid] = session_id
            logger.info(
                "Registered agent session: %s (%s PID %d)",
                session_id, event.agent.agent_type.value, event.agent.agent_pid,
            )
            return

        if event.action == EventAction.SESSION_END:
            session = self._sessions.get(session_id)
            if session:
                logger.info("Agent session ended: %s", session_id)
            return

        # Update existing session
        session = self._sessions.get(session_id)
        if not session and event.agent.agent_pid:
            # Try lookup by PID
            sid = self._pid_to_session.get(event.agent.agent_pid)
            if sid:
                session = self._sessions.get(sid)

        if not session:
            # Auto-register from first event (agent discovered by process sensor)
            session = AgentSession(
                session_id=session_id,
                agent_type=event.agent.agent_type,
                root_pid=event.agent.agent_pid,
                start_time=event.timestamp,
                working_directory=event.agent.working_directory,
            )
            self._sessions[session_id] = session
            if event.agent.agent_pid:
                self._pid_to_session[event.agent.agent_pid] = session_id

        session.event_count += 1
        session.last_activity = event.timestamp

        # Track child PIDs
        if event.process and event.action == EventAction.PROCESS_SPAWN:
            session.child_pids.add(event.process.pid)

    def increment_alerts(self, session_id: str) -> None:
        """Increment alert count for a session."""
        session = self._sessions.get(session_id)
        if session:
            session.alert_count += 1

    def get_session(self, session_id: str) -> AgentSession | None:
        return self._sessions.get(session_id)

    def get_session_by_pid(self, pid: int) -> AgentSession | None:
        sid = self._pid_to_session.get(pid)
        return self._sessions.get(sid) if sid else None

    def get_all_sessions(self) -> list[AgentSession]:
        return list(self._sessions.values())

    def get_active_sessions(self) -> list[AgentSession]:
        """Sessions with activity in the last 5 minutes."""
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        return [s for s in self._sessions.values() if s.last_activity >= cutoff]
