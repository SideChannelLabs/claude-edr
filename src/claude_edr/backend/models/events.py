"""Core event data model for Claude EDR.

Every event flowing through the system is represented as an EDREvent.
Follows OCSF-inspired schema simplified for AI agent monitoring.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EventCategory(str, Enum):
    FILE_ACTIVITY = "file_activity"
    PROCESS_ACTIVITY = "process_activity"
    NETWORK_ACTIVITY = "network_activity"
    TOOL_CALL = "tool_call"
    LLM_REQUEST = "llm_request"
    MCP_ACTIVITY = "mcp_activity"
    SESSION = "session"
    CONFIG_CHANGE = "config_change"


class EventAction(str, Enum):
    # File
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    FILE_CREATE = "file_create"
    FILE_RENAME = "file_rename"

    # Process
    PROCESS_SPAWN = "process_spawn"
    PROCESS_EXIT = "process_exit"
    PROCESS_EXEC = "process_exec"

    # Network
    NET_CONNECT = "net_connect"
    NET_LISTEN = "net_listen"
    NET_DNS = "net_dns"

    # Tool calls (from hooks)
    TOOL_INVOKE = "tool_invoke"
    TOOL_COMPLETE = "tool_complete"
    TOOL_BLOCKED = "tool_blocked"

    # LLM API
    LLM_REQUEST_SENT = "llm_request_sent"
    LLM_RESPONSE_RECEIVED = "llm_response_received"

    # Session
    SESSION_START = "session_start"
    SESSION_END = "session_end"

    # Config
    CONFIG_CHANGED = "config_changed"


class Severity(int, Enum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AgentType(str, Enum):
    CLAUDE_CODE = "claude_code"
    CURSOR = "cursor"
    CODEX = "codex"
    COPILOT = "copilot"
    WINDSURF = "windsurf"
    AIDER = "aider"
    UNKNOWN = "unknown"


@dataclass
class AgentContext:
    """Identifies which AI agent generated this event."""

    agent_type: AgentType
    session_id: str = ""
    agent_pid: int = 0
    working_directory: str = ""
    tool_name: str = ""
    tool_input: dict[str, Any] | None = None
    tool_response: dict[str, Any] | None = None


@dataclass
class ProcessContext:
    """Process information for process-related events."""

    pid: int
    ppid: int = 0
    name: str = ""
    cmdline: str = ""
    uid: int = 0
    exe_path: str = ""


@dataclass
class FileContext:
    """File information for file-related events."""

    path: str
    operation: str = ""
    size: int | None = None
    permissions: str | None = None
    content_snippet: str | None = None


@dataclass
class NetworkContext:
    """Network information for network-related events."""

    direction: str = ""  # "outbound", "inbound"
    protocol: str = ""  # "tcp", "udp", "tls"
    remote_addr: str = ""
    remote_port: int = 0
    local_addr: str = ""
    local_port: int = 0
    domain: str = ""


@dataclass
class LLMContext:
    """LLM API call information captured from SSL interception."""

    provider: str = ""  # "anthropic", "openai", "codeium"
    model: str = ""
    tokens_in: int = 0
    tokens_out: int = 0
    has_tools: bool = False
    tool_names: list[str] = field(default_factory=list)
    contains_credentials: bool = False
    contains_pii: bool = False
    endpoint: str = ""


@dataclass
class EDREvent:
    """Core event type flowing through the entire system.

    Every sensor emits EDREvents, the pipeline enriches them,
    the detection engine evaluates them, and storage persists them.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    category: EventCategory = EventCategory.TOOL_CALL
    action: EventAction = EventAction.TOOL_INVOKE
    severity: Severity = Severity.INFO

    # Context objects (populated based on event type)
    agent: AgentContext | None = None
    process: ProcessContext | None = None
    file: FileContext | None = None
    network: NetworkContext | None = None
    llm: LLMContext | None = None

    # Detection
    rule_matches: list[str] = field(default_factory=list)
    risk_score: float = 0.0

    # Metadata
    sensor_source: str = ""  # "hook", "procmon", "ebpf", "logwatch"
    raw_data: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for storage and API responses."""
        d: dict[str, Any] = {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "category": self.category.value,
            "action": self.action.value,
            "severity": self.severity.value,
            "severity_name": self.severity.name,
            "risk_score": self.risk_score,
            "rule_matches": self.rule_matches,
            "sensor_source": self.sensor_source,
        }
        if self.agent:
            d["agent"] = {
                "agent_type": self.agent.agent_type.value,
                "session_id": self.agent.session_id,
                "agent_pid": self.agent.agent_pid,
                "working_directory": self.agent.working_directory,
                "tool_name": self.agent.tool_name,
                "tool_input": self.agent.tool_input,
            }
        if self.process:
            d["process"] = {
                "pid": self.process.pid,
                "ppid": self.process.ppid,
                "name": self.process.name,
                "cmdline": self.process.cmdline,
                "uid": self.process.uid,
                "exe_path": self.process.exe_path,
            }
        if self.file:
            d["file"] = {
                "path": self.file.path,
                "operation": self.file.operation,
                "size": self.file.size,
            }
        if self.network:
            d["network"] = {
                "direction": self.network.direction,
                "protocol": self.network.protocol,
                "remote_addr": self.network.remote_addr,
                "remote_port": self.network.remote_port,
                "domain": self.network.domain,
            }
        if self.llm:
            d["llm"] = {
                "provider": self.llm.provider,
                "model": self.llm.model,
                "tokens_in": self.llm.tokens_in,
                "tokens_out": self.llm.tokens_out,
                "has_tools": self.llm.has_tools,
                "tool_names": self.llm.tool_names,
                "contains_credentials": self.llm.contains_credentials,
                "endpoint": self.llm.endpoint,
            }
        return d
