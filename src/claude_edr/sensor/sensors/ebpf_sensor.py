"""eBPF-based sensor for monitoring AI coding agent process trees.

Provides kernel-level visibility into:
  - Process execution: what commands MCP servers run
  - File access: what files MCP servers open
  - Network connections: where MCP servers connect
  - Pipe I/O: MCP JSON-RPC traffic (tool calls + results)
  - SSL traffic: LLM API calls (prompts, responses, API keys)

Requires root or CAP_BPF + CAP_PERFMON capabilities.
Falls back gracefully if BCC is not available.
"""

from __future__ import annotations

import asyncio
import ctypes
import json
import logging
import os
import re
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path

from claude_edr.sensor.models.events import (
    AgentContext,
    AgentType,
    EDREvent,
    EventAction,
    EventCategory,
    FileContext,
    LLMContext,
    NetworkContext,
    ProcessContext,
    Severity,
)
from claude_edr.sensor.sensors.base import BaseSensor

logger = logging.getLogger(__name__)

# Debug log file for troubleshooting BPF map writes from non-root terminals
_DEBUG_LOG = "/tmp/edr-bpf-debug.log"


def _debug_log(msg: str) -> None:
    """Write debug message to /tmp for access from non-root terminals."""
    try:
        from datetime import datetime, timezone
        with open(_DEBUG_LOG, "a") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat()} {msg}\n")
    except Exception:
        pass


# Event type constants (must match agent_monitor.bpf.c)
EVENT_EXEC = 1
EVENT_OPENAT = 2
EVENT_CONNECT = 3
EVENT_PIPE_WRITE = 4
EVENT_EXIT = 5
EVENT_SSL_WRITE = 6
EVENT_SSL_READ = 7

# BPF C source path
BPF_SOURCE = Path(__file__).parent / "ebpf" / "agent_monitor.bpf.c"

# Sensitive paths that trigger alerts
SENSITIVE_PATHS = {
    ".ssh", ".gnupg", ".aws", ".config/gcloud", ".env",
    "credentials", "secrets", "id_rsa", "id_ed25519",
    "/etc/shadow", "/etc/passwd",
}

# ── Noise filters ─────────────────────────────────────────────────────
# File paths that generate massive event volume with no security value
_NOISY_PATH_PREFIXES = (
    "/proc/", "/dev/", "/sys/", "/tmp/",
    "/run/", "/var/run/",
)
_NOISY_PATH_SUBSTRINGS = (
    ".claude/projects/",   # Session JSONL writes
    "/.claude/settings",
    "/node_modules/",
    "/.git/objects/",
    "/.git/refs/",
)

# Short-lived child processes from hooks/scripts - no security value
_NOISY_PROCESS_NAMES = frozenset({
    "grep", "cat", "head", "tail", "sed", "awk", "cut", "sort", "uniq",
    "wc", "tr", "tee", "xargs", "find", "basename", "dirname", "realpath",
    "jq", "paplay", "aplay", "notify-send",
    "true", "false", "test", "[",
})


# ── LLM provider detection ───────────────────────────────────────────
# Map Host header → provider name
_HOST_TO_PROVIDER = {
    "api.anthropic.com": "anthropic",
    "api.openai.com": "openai",
    "generativelanguage.googleapis.com": "google",
    "api.cohere.com": "cohere",
    "api.mistral.ai": "mistral",
    "api.groq.com": "groq",
    "api.together.xyz": "together",
    "api.fireworks.ai": "fireworks",
    "api.deepseek.com": "deepseek",
}

# Headers that contain secrets and must be redacted
_REDACT_HEADERS = frozenset({
    "authorization", "x-api-key", "api-key",
    "cookie", "set-cookie", "proxy-authorization",
})

# Regex to find model in JSON body (lightweight, no full parse)
_MODEL_RE = re.compile(rb'"model"\s*:\s*"([^"]{3,80})"')


def _parse_http_request(raw: bytes) -> dict:
    """Parse HTTP request from SSL_write plaintext.

    Returns dict with: method, path, host, headers (redacted),
    provider, model, endpoint, body_preview, has_tools,
    contains_credentials.
    """
    result = {
        "method": "",
        "path": "",
        "host": "",
        "headers_redacted": "",
        "provider": "",
        "model": "",
        "endpoint": "",
        "body_preview": "",
        "has_tools": False,
        "contains_credentials": False,
    }

    # Split headers from body
    header_end = raw.find(b"\r\n\r\n")
    if header_end < 0:
        # Not HTTP - might be a continuation chunk or TLS data
        return result

    header_block = raw[:header_end]
    body = raw[header_end + 4:]

    lines = header_block.split(b"\r\n")
    if not lines:
        return result

    # Parse request line: "POST /v1/messages HTTP/1.1"
    req_line = lines[0].decode("utf-8", errors="replace")
    parts = req_line.split(" ", 2)
    if len(parts) >= 2:
        result["method"] = parts[0]
        result["path"] = parts[1]
        result["endpoint"] = parts[1]

    # Parse and redact headers
    redacted_lines = [req_line]
    for line in lines[1:]:
        decoded = line.decode("utf-8", errors="replace")
        colon = decoded.find(":")
        if colon < 0:
            continue
        name = decoded[:colon].strip()
        value = decoded[colon + 1:].strip()

        if name.lower() in _REDACT_HEADERS:
            # Keep type hint but redact value
            if value.lower().startswith("bearer "):
                redacted_lines.append(f"{name}: Bearer [REDACTED]")
            else:
                redacted_lines.append(f"{name}: [REDACTED]")
            result["contains_credentials"] = True
        else:
            redacted_lines.append(decoded)

        if name.lower() == "host":
            result["host"] = value
            result["provider"] = _HOST_TO_PROVIDER.get(value.lower(), "")

    result["headers_redacted"] = "\r\n".join(redacted_lines)

    # Extract model from body (lightweight regex, avoid full JSON parse)
    m = _MODEL_RE.search(body)
    if m:
        result["model"] = m.group(1).decode("utf-8", errors="replace")

    # Check for tool use indicators
    if b'"tools"' in body or b'"tool_choice"' in body or b'"functions"' in body:
        result["has_tools"] = True

    # Body preview - include after headers, truncate total to 1000 bytes
    if body:
        result["body_preview"] = body[:10000].decode("utf-8", errors="replace")

    # Combined output: headers + body, truncated to 1000
    combined = result["headers_redacted"] + "\r\n\r\n" + result["body_preview"]
    result["combined"] = combined[:10000]

    return result


def _parse_http_response(raw: bytes) -> dict:
    """Parse HTTP response from SSL_read plaintext.

    Returns dict with: status, headers_redacted, body_preview,
    model, tokens_in, tokens_out.
    """
    result = {
        "status": 0,
        "headers_redacted": "",
        "body_preview": "",
        "model": "",
        "tokens_in": 0,
        "tokens_out": 0,
    }

    header_end = raw.find(b"\r\n\r\n")
    if header_end < 0:
        # Continuation data or chunked body
        result["body_preview"] = raw[:500].decode("utf-8", errors="replace")
        return result

    header_block = raw[:header_end]
    body = raw[header_end + 4:]

    lines = header_block.split(b"\r\n")
    if not lines:
        return result

    # Parse status line: "HTTP/1.1 200 OK"
    status_line = lines[0].decode("utf-8", errors="replace")
    parts = status_line.split(" ", 2)
    if len(parts) >= 2:
        try:
            result["status"] = int(parts[1])
        except ValueError:
            pass

    # Redact headers
    redacted_lines = [status_line]
    for line in lines[1:]:
        decoded = line.decode("utf-8", errors="replace")
        colon = decoded.find(":")
        if colon < 0:
            continue
        name = decoded[:colon].strip()
        if name.lower() in _REDACT_HEADERS:
            redacted_lines.append(f"{name}: [REDACTED]")
        else:
            redacted_lines.append(decoded)

    result["headers_redacted"] = "\r\n".join(redacted_lines)

    # Extract model and token usage from response body
    m = _MODEL_RE.search(body)
    if m:
        result["model"] = m.group(1).decode("utf-8", errors="replace")

    # Token usage (Anthropic: input_tokens/output_tokens, OpenAI: prompt_tokens/completion_tokens)
    for pattern, key in [
        (rb'"input_tokens"\s*:\s*(\d+)', "tokens_in"),
        (rb'"prompt_tokens"\s*:\s*(\d+)', "tokens_in"),
        (rb'"output_tokens"\s*:\s*(\d+)', "tokens_out"),
        (rb'"completion_tokens"\s*:\s*(\d+)', "tokens_out"),
    ]:
        tok_m = re.search(pattern, body)
        if tok_m:
            result[key] = int(tok_m.group(1))

    if body:
        result["body_preview"] = body[:10000].decode("utf-8", errors="replace")

    # Combined output: headers + body, truncated to 1000
    combined = result["headers_redacted"] + "\r\n\r\n" + result["body_preview"]
    result["combined"] = combined[:10000]

    return result


def _ip4_to_str(addr: int) -> str:
    """Convert a 32-bit IPv4 address (network byte order) to string."""
    return socket.inet_ntoa(struct.pack("!I", socket.ntohl(addr)))


def _ip6_to_str(addr_bytes: bytes) -> str:
    """Convert 16 bytes to IPv6 string."""
    return socket.inet_ntop(socket.AF_INET6, addr_bytes)


class EbpfSensor(BaseSensor):
    """eBPF-based sensor for AI agent process tree monitoring."""

    def __init__(
        self,
        event_queue: asyncio.Queue[EDREvent],
        enable_ssl: bool = True,
        enable_pipe_capture: bool = True,
    ):
        super().__init__(event_queue)
        self._bpf = None
        self._enable_ssl = enable_ssl
        self._enable_pipe_capture = enable_pipe_capture
        self._tracked_roots: dict[int, AgentType] = {}  # root_pid -> agent_type
        self._ssl_attached: set[int] = set()  # PIDs with SSL probes attached
        self._loop: asyncio.AbstractEventLoop | None = None
        self.ready = asyncio.Event()  # Set when BPF is compiled and loaded

        # MCP server tracking (populated by MCPScanner)
        self._mcp_server_names: dict[int, str] = {}  # pid -> server_name
        # Map (pid, fd) -> server_name for agent-side pipe FDs
        self._mcp_pipe_map: dict[tuple[int, int], str] = {}
        # Correlate JSON-RPC request IDs to tool names for response matching
        # Key: (server_name, msg_id) -> tool_name
        self._pending_calls: dict[tuple[str, int | str], str] = {}

    @property
    def name(self) -> str:
        return "eBPF Agent Monitor"

    @property
    def sensor_type(self) -> str:
        return "ebpf"

    def _load_bpf(self) -> None:
        """Compile and load the BPF program."""
        try:
            from bcc import BPF
        except ImportError:
            raise RuntimeError(
                "BCC not available. Install python3-bpfcc or run as root. "
                "Falling back to process sensor."
            )

        if os.geteuid() != 0:
            raise RuntimeError(
                "eBPF sensor requires root. Run with sudo or set "
                "CAP_BPF + CAP_PERFMON capabilities."
            )

        source = BPF_SOURCE.read_text()
        logger.info("Compiling BPF program from %s", BPF_SOURCE)
        self._bpf = BPF(text=source)
        logger.info("BPF program loaded successfully")

    def track_agent(self, pid: int, agent_type: AgentType) -> None:
        """Add an agent root PID to the tracked set.

        Called by the process sensor when it discovers a new agent.
        The eBPF program will automatically track all child processes.
        """
        if self._bpf is None:
            logger.warning("BPF not loaded, cannot track PID %d", pid)
            return

        # Value 0 means "this IS the root agent"
        key = ctypes.c_uint32(pid)
        val = ctypes.c_uint32(0)
        self._bpf["tracked_pids"][key] = val
        self._tracked_roots[pid] = agent_type
        logger.info("eBPF now tracking agent %s (PID %d)", agent_type.value, pid)

        # Attempt SSL probe attachment for this agent's binary
        if self._enable_ssl and pid not in self._ssl_attached:
            self._attach_ssl_probes(pid)

    def untrack_agent(self, pid: int) -> None:
        """Remove an agent root PID from tracking."""
        if self._bpf is None:
            return

        key = ctypes.c_uint32(pid)
        try:
            del self._bpf["tracked_pids"][key]
        except KeyError:
            pass
        self._tracked_roots.pop(pid, None)
        self._ssl_attached.discard(pid)
        logger.info("eBPF stopped tracking PID %d", pid)

    def track_pipe_fd(self, pid: int, fd: int) -> None:
        """Register a pipe fd for MCP JSON-RPC capture.

        Called when we identify that a specific fd on a tracked PID
        is a pipe to/from an MCP server.
        """
        if self._bpf is None or not self._enable_pipe_capture:
            logger.warning(
                "track_pipe_fd(%d, %d): BPF=%s pipe_capture=%s",
                pid, fd, self._bpf is not None, self._enable_pipe_capture,
            )
            return

        raw_key = (pid << 32) | fd
        key = ctypes.c_uint64(raw_key)
        val = ctypes.c_uint8(1)
        self._bpf["tracked_pipe_fds"][key] = val

        # Verify the write succeeded
        try:
            readback = self._bpf["tracked_pipe_fds"][key].value
            msg = f"tracked_pipe_fds[PID {pid}, fd {fd}] = 1 (verified: {readback}, raw_key: 0x{raw_key:x})"
            logger.info(msg)
            _debug_log(msg)
        except KeyError:
            msg = f"FAILED to write tracked_pipe_fds[PID {pid}, fd {fd}]!"
            logger.error(msg)
            _debug_log(msg)

        # Also verify the PID is in tracked_pids (required by BPF filter)
        pid_key = ctypes.c_uint32(pid)
        try:
            root = self._bpf["tracked_pids"][pid_key].value
            msg = f"  (PID {pid} is tracked, root_agent={root})"
            logger.info(msg)
            _debug_log(msg)
        except KeyError:
            msg = f"  WARNING: PID {pid} NOT in tracked_pids! write() will be ignored by BPF!"
            logger.warning(msg)
            _debug_log(msg)

    def prime_blocked_read(self, pid: int, fd: int) -> None:
        """Pre-seed pipe_read_args_map for a read() that's already blocking.

        When the daemon starts AFTER MCP servers are already running, the
        server may be blocked in read(fd=0, buf, size). Since sys_enter_read
        fired before the BPF program was loaded, pipe_read_args_map has no
        entry and sys_exit_read can't capture the data.

        Fix: read /proc/PID/syscall to get the buf pointer from the blocked
        read() call, then write it directly into the BPF map.
        """
        if self._bpf is None:
            return

        try:
            # /proc/PID/syscall format: nr arg1 arg2 arg3 arg4 arg5 arg6 sp pc
            # For read(fd, buf, count): arg1=fd, arg2=buf_ptr, arg3=count
            # read = syscall 0 on x86_64, recvmsg = 47
            data = Path(f"/proc/{pid}/syscall").read_text().strip()
            parts = data.split()
            if len(parts) < 4 or parts[0] == "running":
                return

            syscall_nr = int(parts[0])
            arg1 = int(parts[1], 16)  # fd
            arg2 = int(parts[2], 16)  # buf ptr

            # Check if blocked in read() on the target fd
            if syscall_nr == 0 and arg1 == fd:  # read = 0 on x86_64
                # Pre-populate pipe_read_args_map
                key = ctypes.c_uint32(pid)
                val_type = self._bpf["pipe_read_args_map"].Leaf
                val = val_type()
                val.buf_ptr = arg2
                val.fd = fd
                self._bpf["pipe_read_args_map"][key] = val
                msg = f"Primed blocked read: PID {pid} fd {fd} buf_ptr=0x{arg2:x}"
                logger.info(msg)
                _debug_log(msg)

            # Check if blocked in recvfrom() on the target fd
            elif syscall_nr == 45 and arg1 == fd:  # recvfrom = 45 on x86_64
                # Pre-populate recvfrom_args_map
                key = ctypes.c_uint32(pid)
                val_type = self._bpf["recvfrom_args_map"].Leaf
                val = val_type()
                val.buf_ptr = arg2
                val.fd = fd
                self._bpf["recvfrom_args_map"][key] = val
                msg = f"Primed blocked recvfrom: PID {pid} fd {fd} buf_ptr=0x{arg2:x}"
                logger.info(msg)
                _debug_log(msg)

            # Check if blocked in recvmsg() on the target fd
            elif syscall_nr == 47 and arg1 == fd:  # recvmsg = 47 on x86_64
                # For recvmsg, arg2 is msghdr ptr - need to read iov from it
                # This is complex from userspace; skip for now - the deferred
                # fd check in BPF handles most cases
                msg = f"PID {pid} blocked in recvmsg on fd {fd} (not priming - deferred check handles it)"
                logger.info(msg)
                _debug_log(msg)

            else:
                msg = f"PID {pid} fd {fd}: syscall_nr={syscall_nr} arg1=0x{arg1:x} (not read/recvfrom/recvmsg)"
                logger.info(msg)
                _debug_log(msg)

        except (OSError, ValueError, IndexError, KeyError) as e:
            _debug_log(f"prime_blocked_read({pid}, {fd}): {e}")
        except Exception:
            logger.debug("prime_blocked_read(%d, %d) failed", pid, fd, exc_info=True)

    def track_child(self, child_pid: int, root_agent_pid: int) -> None:
        """Track a child process under an existing agent root.

        Unlike track_agent() which marks the PID as a root, this sets
        the root_agent_pid so the child is attributed correctly.
        """
        if self._bpf is None:
            logger.warning("track_child(%d): BPF not loaded!", child_pid)
            return

        key = ctypes.c_uint32(child_pid)
        val = ctypes.c_uint32(root_agent_pid)
        self._bpf["tracked_pids"][key] = val

        # Verify the write succeeded
        try:
            readback = self._bpf["tracked_pids"][key].value
            msg = f"eBPF tracked_pids[{child_pid}] = {root_agent_pid} (verified: {readback})"
            logger.info(msg)
            _debug_log(msg)
        except KeyError:
            msg = f"FAILED to write tracked_pids[{child_pid}]!"
            logger.error(msg)
            _debug_log(msg)

    def register_mcp_server(self, pid: int, server_name: str) -> None:
        """Register an MCP server so pipe events get the right tool_name prefix."""
        self._mcp_server_names[pid] = server_name

    def unregister_mcp_server(self, pid: int) -> None:
        """Remove MCP server registration."""
        server_name = self._mcp_server_names.pop(pid, None)
        if server_name:
            # Clean up pipe mappings for this server
            to_remove = [k for k, v in self._mcp_pipe_map.items() if v == server_name]
            for k in to_remove:
                self._mcp_pipe_map.pop(k, None)

    def register_mcp_pipe(self, pid: int, fd: int, server_name: str) -> None:
        """Map an (agent_pid, fd) to an MCP server name.

        Used for agent-side write FDs so that request events get
        attributed to the correct MCP server.
        """
        self._mcp_pipe_map[(pid, fd)] = server_name

    def dump_bpf_maps(self, label: str = "") -> None:
        """Debug: dump BPF map contents for troubleshooting.

        Also writes to /tmp/edr-bpf-debug.log for access from non-root terminals.
        """
        if self._bpf is None:
            logger.warning("dump_bpf_maps: BPF not loaded")
            return

        lines = [f"\n=== BPF MAP DUMP {label} ==="]

        # Dump tracked_pids
        tracked = self._bpf["tracked_pids"]
        pid_count = 0
        for key in tracked.keys():
            pid_val = key.value
            root_val = tracked[key].value
            line = f"  tracked_pids[{pid_val}] = {root_val}"
            logger.info(line)
            lines.append(line)
            pid_count += 1
        summary = f"tracked_pids: {pid_count} entries total"
        logger.info(summary)
        lines.append(summary)

        # Dump tracked_pipe_fds
        pipes = self._bpf["tracked_pipe_fds"]
        fd_count = 0
        for key in pipes.keys():
            raw = key.value
            pid_part = raw >> 32
            fd_part = raw & 0xFFFFFFFF
            line = f"  tracked_pipe_fds[PID {pid_part}, fd {fd_part}] = {pipes[key].value}"
            logger.info(line)
            lines.append(line)
            fd_count += 1
        summary = f"tracked_pipe_fds: {fd_count} entries total"
        logger.info(summary)
        lines.append(summary)

        # Write to file for easy access
        try:
            with open("/tmp/edr-bpf-debug.log", "a") as f:
                from datetime import datetime, timezone
                f.write(f"\n--- {datetime.now(timezone.utc).isoformat()} ---\n")
                f.write("\n".join(lines) + "\n")
        except Exception:
            pass

    def _get_mcp_server_name(self, pid: int, fd: int = -1) -> str:
        """Look up the MCP server name for a pipe event.

        Checks:
        1. Direct PID match (MCP server writing responses on stdout)
        2. (PID, fd) match (agent writing requests to server stdin)
        """
        name = self._mcp_server_names.get(pid)
        if name:
            return name
        if fd >= 0:
            name = self._mcp_pipe_map.get((pid, fd))
            if name:
                return name
        return ""

    def _attach_ssl_probes(self, pid: int) -> None:
        """Attach SSL_write/SSL_read uprobes for an agent process.

        Two-tier approach:
          1. If process links libssl.so dynamically → attach by symbol name (reliable)
          2. If not → scan binary for embedded BoringSSL signatures (fallback)
        """
        from claude_edr.sensor.sensors.ebpf.ssl_scanner import discover_ssl_for_pid

        info = discover_ssl_for_pid(pid)

        if info["method"] == "none":
            logger.info(
                "PID %d: no SSL interception available (Go/Rust/no-TLS)",
                pid,
            )
            return

        # ── Attach SSL_write ──
        try:
            if info["method"] == "libssl":
                # Tier 1: attach by symbol name on the shared library
                self._bpf.attach_uprobe(
                    name=info["library"],
                    sym="SSL_write",
                    fn_name="ssl_write_entry",
                    pid=pid,
                )
                logger.info(
                    "SSL_write uprobe attached for PID %d via %s (symbol)",
                    pid, info["library"],
                )
            else:
                # Tier 2: attach by address on the main binary
                self._bpf.attach_uprobe(
                    name=info["binary"],
                    sym="",
                    addr=info["ssl_write"],
                    fn_name="ssl_write_entry",
                    pid=pid,
                )
                logger.info(
                    "SSL_write uprobe attached for PID %d at 0x%x (signature)",
                    pid, info["ssl_write"],
                )
            self._ssl_attached.add(pid)
            _debug_log(f"SSL_write uprobe attached PID {pid} method={info['method']}")
        except Exception as e:
            logger.exception("Failed to attach SSL_write uprobe for PID %d", pid)
            _debug_log(f"SSL_write FAILED PID {pid}: {e}")
            return  # no point trying SSL_read if SSL_write failed

        # ── Attach SSL_read ──
        if info["ssl_read"] is None:
            logger.info("PID %d: SSL_write attached but SSL_read not found", pid)
            _debug_log(f"SSL_read not found for PID {pid}")
            return

        try:
            if info["method"] == "libssl":
                self._bpf.attach_uprobe(
                    name=info["library"],
                    sym="SSL_read",
                    fn_name="ssl_read_entry",
                    pid=pid,
                )
                _debug_log(f"SSL_read uprobe attached PID {pid} via {info['library']}")
                self._bpf.attach_uretprobe(
                    name=info["library"],
                    sym="SSL_read",
                    fn_name="ssl_read_return",
                    pid=pid,
                )
                _debug_log(f"SSL_read uretprobe attached PID {pid} via {info['library']}")
                logger.info(
                    "SSL_read uprobe+uretprobe attached for PID %d via %s",
                    pid, info["library"],
                )
            else:
                self._bpf.attach_uprobe(
                    name=info["binary"],
                    sym="",
                    addr=info["ssl_read"],
                    fn_name="ssl_read_entry",
                    pid=pid,
                )
                _debug_log(f"SSL_read uprobe attached PID {pid} at 0x{info['ssl_read']:x}")
                self._bpf.attach_uretprobe(
                    name=info["binary"],
                    sym="",
                    addr=info["ssl_read"],
                    fn_name="ssl_read_return",
                    pid=pid,
                )
                _debug_log(f"SSL_read uretprobe attached PID {pid} at 0x{info['ssl_read']:x}")
                logger.info(
                    "SSL_read uprobe+uretprobe attached for PID %d at 0x%x",
                    pid, info["ssl_read"],
                )
        except Exception as e:
            logger.exception("Failed to attach SSL_read uprobe for PID %d", pid)
            _debug_log(f"SSL_read FAILED PID {pid}: {e}")

    def _get_agent_type_for_pid(self, pid: int) -> AgentType:
        """Look up which agent a tracked PID belongs to."""
        # Check if it's a root agent
        if pid in self._tracked_roots:
            return self._tracked_roots[pid]

        # Check BPF map for root_pid mapping
        if self._bpf:
            key = ctypes.c_uint32(pid)
            try:
                root_pid = self._bpf["tracked_pids"][key].value
                if root_pid in self._tracked_roots:
                    return self._tracked_roots[root_pid]
            except KeyError:
                pass

        return AgentType.UNKNOWN

    def _handle_lost_events(self, lost_cnt: int) -> None:
        """Callback when perf buffer drops events."""
        _debug_log(f"PERF BUFFER LOST {lost_cnt} events!")
        logger.warning("BPF perf buffer lost %d events", lost_cnt)

    def _handle_event(self, cpu: int, data, size: int) -> None:
        """Callback for BPF perf events. Runs in the polling thread."""
        if size < 8:
            return

        # BCC passes data as a ctypes void pointer - convert to bytes
        raw = ctypes.string_at(data, size)
        event_type = struct.unpack_from("<I", raw, 0)[0]

        try:
            if event_type == EVENT_EXEC:
                self._handle_exec(raw)
            elif event_type == EVENT_OPENAT:
                self._handle_openat(raw)
            elif event_type == EVENT_CONNECT:
                self._handle_connect(raw)
            elif event_type == EVENT_PIPE_WRITE:
                self._handle_pipe_write(raw)
            elif event_type == EVENT_EXIT:
                self._handle_exit(raw)
            elif event_type == EVENT_SSL_WRITE:
                self._handle_ssl_write(raw)
            elif event_type == EVENT_SSL_READ:
                self._handle_ssl_read(raw)
        except Exception:
            logger.exception("Error handling eBPF event type %d", event_type)

    def _handle_exec(self, data: bytes) -> None:
        """Handle sched_process_exec event."""
        # Parse exec_event struct
        event_type, pid, ppid, uid = struct.unpack_from("<IIII", data, 0)
        timestamp_ns = struct.unpack_from("<Q", data, 16)[0]
        comm = data[24:40].split(b'\x00')[0].decode('utf-8', errors='replace')
        filename = data[40:40 + 256].split(b'\x00')[0].decode('utf-8', errors='replace')

        # Skip noisy short-lived child processes (grep, cat, jq, etc.)
        if comm in _NOISY_PROCESS_NAMES:
            return

        agent_type = self._get_agent_type_for_pid(pid)

        event = EDREvent(
            category=EventCategory.PROCESS_ACTIVITY,
            action=EventAction.PROCESS_SPAWN,
            agent=AgentContext(agent_type=agent_type, agent_pid=pid),
            process=ProcessContext(
                pid=pid,
                ppid=ppid,
                name=comm,
                cmdline=filename,
                uid=uid,
            ),
            severity=Severity.INFO,
        )

        if self._loop:
            self._loop.call_soon_threadsafe(
                self._loop.create_task, self.emit(event)
            )

    def _handle_openat(self, data: bytes) -> None:
        """Handle sys_enter_openat event."""
        event_type, pid, ppid = struct.unpack_from("<III", data, 0)
        timestamp_ns = struct.unpack_from("<Q", data, 12)[0]
        flags = struct.unpack_from("<i", data, 20)[0]
        comm = data[24:40].split(b'\x00')[0].decode('utf-8', errors='replace')
        filename = data[40:40 + 256].split(b'\x00')[0].decode('utf-8', errors='replace')

        # Determine severity based on path
        severity = Severity.INFO
        for sensitive in SENSITIVE_PATHS:
            if sensitive in filename:
                severity = Severity.HIGH
                break

        # Skip noisy low-value file events (unless they hit sensitive paths)
        if severity == Severity.INFO:
            if any(filename.startswith(p) for p in _NOISY_PATH_PREFIXES):
                return
            if any(s in filename for s in _NOISY_PATH_SUBSTRINGS):
                return

        agent_type = self._get_agent_type_for_pid(pid)

        event = EDREvent(
            category=EventCategory.FILE_ACTIVITY,
            action=EventAction.FILE_READ if (flags & 0x3) == 0 else EventAction.FILE_WRITE,
            agent=AgentContext(agent_type=agent_type, agent_pid=pid),
            process=ProcessContext(pid=pid, ppid=ppid, name=comm),
            file=FileContext(path=filename),
            severity=severity,
        )

        if self._loop:
            self._loop.call_soon_threadsafe(
                self._loop.create_task, self.emit(event)
            )

    def _handle_connect(self, data: bytes) -> None:
        """Handle sys_enter_connect event."""
        event_type, pid = struct.unpack_from("<II", data, 0)
        timestamp_ns = struct.unpack_from("<Q", data, 8)[0]
        family, port = struct.unpack_from("<HH", data, 16)
        addr_v4 = struct.unpack_from("<I", data, 20)[0]
        addr_v6 = data[24:40]
        comm = data[40:56].split(b'\x00')[0].decode('utf-8', errors='replace')

        if family == socket.AF_INET:
            remote_addr = _ip4_to_str(addr_v4)
        elif family == socket.AF_INET6:
            remote_addr = _ip6_to_str(addr_v6)
        else:
            return

        agent_type = self._get_agent_type_for_pid(pid)

        event = EDREvent(
            category=EventCategory.NETWORK_ACTIVITY,
            action=EventAction.NET_CONNECT,
            agent=AgentContext(agent_type=agent_type, agent_pid=pid),
            process=ProcessContext(pid=pid, name=comm),
            network=NetworkContext(
                direction="outbound",
                protocol="tcp",
                remote_addr=remote_addr,
                remote_port=port,
            ),
            severity=Severity.INFO,
        )

        if self._loop:
            self._loop.call_soon_threadsafe(
                self._loop.create_task, self.emit(event)
            )

    @staticmethod
    def _try_parse_truncated_json(text: str, original_size: int) -> dict | None:
        """Extract JSON-RPC fields from truncated JSON using regex.

        When the BPF buffer cap truncates a large JSON-RPC message,
        we can still extract key fields (method, id, tool name) for
        event attribution even though json.loads() fails.
        """
        if '"jsonrpc"' not in text[:200]:
            return None

        msg: dict = {}

        # Extract "id": <number>
        m = re.search(r'"id"\s*:\s*(\d+)', text)
        if m:
            msg["id"] = int(m.group(1))

        # Extract "method": "..."
        m = re.search(r'"method"\s*:\s*"([^"]*)"', text)
        if m:
            msg["method"] = m.group(1)

        # Detect response type
        if '"result"' in text[:500]:
            # Try to extract a preview of the content text
            m = re.search(r'"text"\s*:\s*"([^"]{0,200})', text)
            preview = m.group(1) if m else ""
            msg["result"] = {
                "content": [{"type": "text", "text": f"[truncated {original_size}B] {preview}..."}]
            }

        if '"error"' in text[:500] and "result" not in msg:
            m = re.search(r'"message"\s*:\s*"([^"]*)"', text)
            error_msg = m.group(1) if m else "unknown error"
            msg["error"] = {"code": -1, "message": f"[truncated] {error_msg}"}

        # For tool call requests, extract tool name from params
        if msg.get("method") == "tools/call":
            m = re.search(r'"name"\s*:\s*"([^"]*)"', text)
            if m:
                msg.setdefault("params", {})["name"] = m.group(1)
                # Arguments will be partial but still note them
                args_match = re.search(r'"arguments"\s*:\s*\{(.{0,500})', text)
                if args_match:
                    msg["params"]["arguments"] = {
                        "_truncated": True,
                        "_original_size": original_size,
                        "_preview": args_match.group(1)[:200],
                    }
                else:
                    msg["params"]["arguments"] = {"_truncated": True}

        return msg if ("method" in msg or "result" in msg or "error" in msg) else None

    def _handle_pipe_write(self, data: bytes) -> None:
        """Handle MCP JSON-RPC pipe write event.

        Parses JSON-RPC messages from captured pipe buffers and creates
        appropriate events:
          - tools/call request  → TOOL_INVOKE  with tool_name + tool_input
          - JSON-RPC response   → TOOL_COMPLETE with tool_response
          - Other methods       → MCP_ACTIVITY
          - Non-JSON            → raw PIPE_WRITE

        If the BPF buffer cap (4000 bytes) truncated the message,
        falls back to regex extraction of key JSON-RPC fields.
        """
        event_type, pid = struct.unpack_from("<II", data, 0)
        timestamp_ns = struct.unpack_from("<Q", data, 8)[0]
        fd, count, buf_len = struct.unpack_from("<III", data, 16)
        comm = data[28:44].split(b'\x00')[0].decode('utf-8', errors='replace')
        buf = data[44:44 + buf_len]

        _debug_log(f"PIPE_WRITE event: pid={pid} fd={fd} count={count} buf_len={buf_len} comm={comm}")

        agent_type = self._get_agent_type_for_pid(pid)
        server_name = self._get_mcp_server_name(pid, fd)
        _debug_log(f"  agent_type={agent_type} server_name={server_name}")

        # Try to parse as JSON-RPC (newline-delimited)
        try:
            text = buf.decode('utf-8', errors='replace').strip()
        except UnicodeDecodeError:
            text = ""

        truncated = buf_len < count  # BPF cap truncated the buffer

        if text and text[0] == '{':
            _debug_log(f"  JSON detected, first 200 chars: {text[:200]}")
            # May contain multiple newline-delimited JSON messages
            parsed_count = 0
            for line in text.split('\n'):
                line = line.strip()
                if not line or line[0] != '{':
                    continue
                try:
                    msg = json.loads(line)
                    parsed_count += 1
                except json.JSONDecodeError as e:
                    _debug_log(f"  JSON parse error: {e}")
                    # If the buffer was truncated, try regex extraction
                    if truncated:
                        msg = self._try_parse_truncated_json(line, count)
                        if msg:
                            _debug_log(
                                f"  Recovered truncated JSON: method={msg.get('method')} "
                                f"id={msg.get('id')} has_result={'result' in msg}"
                            )
                            parsed_count += 1
                        else:
                            continue
                    else:
                        continue

                self._process_jsonrpc_message(
                    msg, pid, fd, comm, agent_type, server_name
                )
            _debug_log(f"  Parsed {parsed_count} JSON-RPC messages")
            return

        # Non-JSON pipe write
        event = EDREvent(
            category=EventCategory.PROCESS_ACTIVITY,
            action=EventAction.PIPE_WRITE,
            agent=AgentContext(agent_type=agent_type, agent_pid=pid),
            process=ProcessContext(pid=pid, name=comm),
            severity=Severity.INFO,
        )
        if self._loop:
            self._loop.call_soon_threadsafe(
                self._loop.create_task, self.emit(event)
            )

    def _process_jsonrpc_message(
        self,
        msg: dict,
        pid: int,
        fd: int,
        comm: str,
        agent_type: AgentType,
        server_name: str,
    ) -> None:
        """Process a single parsed JSON-RPC message into an EDREvent."""
        method = msg.get("method", "")
        has_result = "result" in msg
        has_error = "error" in msg
        msg_id = msg.get("id")

        # Format tool_name with MCP server prefix for dashboard matching
        # Dashboard expects: mcp__server_name__tool_name
        # Scanner derives names like "mcp-memory-service" but inventory uses
        # "memory-service", so strip redundant "mcp-" prefix before adding "mcp__"
        def _fmt_tool_name(name: str) -> str:
            if server_name:
                clean = server_name
                if clean.startswith("mcp-"):
                    clean = clean[4:]  # "mcp-memory-service" -> "memory-service"
                prefix = clean.replace("-", "_")
                tool = name or method
                if tool:
                    return f"mcp__{prefix}__{tool}"
                return f"mcp__{prefix}"  # uncorrelated response - omit unknown suffix
            return name or method or server_name

        event: EDREvent | None = None
        _debug_log(f"  JSONRPC: method={method} has_result={has_result} has_error={has_error} msg_id={msg_id} server={server_name}")

        if method == "tools/call":
            # ── Tool invocation request ──
            params = msg.get("params", {})
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})

            # Track request ID → tool name for response correlation
            if msg_id is not None and server_name:
                self._pending_calls[(server_name, msg_id)] = tool_name
                # Prevent unbounded growth: cap at 500 entries
                if len(self._pending_calls) > 500:
                    oldest = next(iter(self._pending_calls))
                    del self._pending_calls[oldest]

            event = EDREvent(
                category=EventCategory.MCP_ACTIVITY,
                action=EventAction.TOOL_INVOKE,
                agent=AgentContext(agent_type=agent_type, agent_pid=pid),
                process=ProcessContext(pid=pid, name=comm),
                tool_name=_fmt_tool_name(tool_name),
                tool_input_json=json.dumps(arguments, default=str)[:4096],
                severity=Severity.INFO,
            )

        elif has_result and msg_id is not None:
            # ── Tool response (success) ──
            # Look up the original tool name from the request
            correlated_tool = self._pending_calls.pop(
                (server_name, msg_id), ""
            )
            result = msg.get("result", {})
            # Try to extract tool output text from MCP content array
            response_text = ""
            if isinstance(result, dict):
                content = result.get("content", [])
                if isinstance(content, list):
                    texts = []
                    for item in content:
                        if isinstance(item, dict) and item.get("type") == "text":
                            texts.append(item.get("text", ""))
                    response_text = "\n".join(texts)

            if not response_text:
                response_text = json.dumps(result, default=str)

            event = EDREvent(
                category=EventCategory.MCP_ACTIVITY,
                action=EventAction.TOOL_COMPLETE,
                agent=AgentContext(agent_type=agent_type, agent_pid=pid),
                process=ProcessContext(pid=pid, name=comm),
                tool_name=_fmt_tool_name(correlated_tool),
                tool_response_json=response_text[:4096],
                severity=Severity.INFO,
            )

        elif has_error and msg_id is not None:
            # ── Tool response (error) ──
            correlated_tool = self._pending_calls.pop(
                (server_name, msg_id), ""
            )
            error = msg.get("error", {})
            event = EDREvent(
                category=EventCategory.MCP_ACTIVITY,
                action=EventAction.TOOL_BLOCKED,
                agent=AgentContext(agent_type=agent_type, agent_pid=pid),
                process=ProcessContext(pid=pid, name=comm),
                tool_name=_fmt_tool_name(correlated_tool),
                tool_response_json=json.dumps(error, default=str)[:4096],
                severity=Severity.MEDIUM,
            )

        elif method:
            # ── Other JSON-RPC methods (initialize, tools/list, notifications, etc.) ──
            params = msg.get("params", {})
            event = EDREvent(
                category=EventCategory.MCP_ACTIVITY,
                action=EventAction.TOOL_INVOKE,
                agent=AgentContext(agent_type=agent_type, agent_pid=pid),
                process=ProcessContext(pid=pid, name=comm),
                tool_name=_fmt_tool_name(method),
                tool_input_json=json.dumps(params, default=str)[:4096] if params else "",
                severity=Severity.INFO,
            )

        if event and self._loop:
            _debug_log(f"  EMIT: {event.category.value}/{event.action.value} tool={event.tool_name}")
            self._loop.call_soon_threadsafe(
                self._loop.create_task, self.emit(event)
            )
        elif not event:
            _debug_log(f"  NO EVENT created for method={method} result={has_result} error={has_error}")

    def _handle_exit(self, data: bytes) -> None:
        """Handle sched_process_exit event."""
        event_type, pid = struct.unpack_from("<II", data, 0)
        timestamp_ns = struct.unpack_from("<Q", data, 8)[0]
        comm = data[20:36].split(b'\x00')[0].decode('utf-8', errors='replace')

        # If this was a root agent, clean up (always, even if noisy)
        if pid in self._tracked_roots:
            self.untrack_agent(pid)

        # Skip noisy short-lived child processes
        if comm in _NOISY_PROCESS_NAMES:
            return

        agent_type = self._get_agent_type_for_pid(pid)

        event = EDREvent(
            category=EventCategory.PROCESS_ACTIVITY,
            action=EventAction.PROCESS_EXIT,
            agent=AgentContext(agent_type=agent_type, agent_pid=pid),
            process=ProcessContext(pid=pid, name=comm),
            severity=Severity.INFO,
        )

        if self._loop:
            self._loop.call_soon_threadsafe(
                self._loop.create_task, self.emit(event)
            )

    def _handle_ssl_write(self, data: bytes) -> None:
        """Handle SSL_write uprobe event - outbound LLM API data."""
        event_type, pid = struct.unpack_from("<II", data, 0)
        timestamp_ns = struct.unpack_from("<Q", data, 8)[0]
        length, buf_len = struct.unpack_from("<II", data, 16)
        comm = data[24:40].split(b'\x00')[0].decode('utf-8', errors='replace')
        buf = data[40:40 + buf_len]

        agent_type = self._get_agent_type_for_pid(pid)
        parsed = _parse_http_request(buf)

        # Skip non-HTTP data (TLS continuation, binary chunks)
        if not parsed["method"]:
            return

        llm_ctx = LLMContext(
            provider=parsed["provider"],
            model=parsed["model"],
            has_tools=parsed["has_tools"],
            contains_credentials=parsed["contains_credentials"],
            endpoint=parsed["endpoint"],
        )

        event = EDREvent(
            category=EventCategory.LLM_REQUEST,
            action=EventAction.LLM_CALL,
            agent=AgentContext(agent_type=agent_type, agent_pid=pid),
            process=ProcessContext(pid=pid, name=comm),
            llm=llm_ctx,
            network=NetworkContext(
                direction="outbound",
                protocol="tls",
                domain=parsed["host"],
            ),
            tool_input_json=parsed["combined"],
            severity=Severity.MEDIUM if parsed["contains_credentials"] else Severity.INFO,
            sensor_source="ebpf",
        )

        if self._loop:
            self._loop.call_soon_threadsafe(
                self._loop.create_task, self.emit(event)
            )

    def _handle_ssl_read(self, data: bytes) -> None:
        """Handle SSL_read uretprobe event - inbound LLM API response."""
        event_type, pid = struct.unpack_from("<II", data, 0)
        timestamp_ns = struct.unpack_from("<Q", data, 8)[0]
        length, buf_len = struct.unpack_from("<II", data, 16)
        comm = data[24:40].split(b'\x00')[0].decode('utf-8', errors='replace')
        buf = data[40:40 + buf_len]

        agent_type = self._get_agent_type_for_pid(pid)
        parsed = _parse_http_response(buf)

        llm_ctx = LLMContext(
            provider="",  # Populated from correlated request if needed
            model=parsed["model"],
            tokens_in=parsed["tokens_in"],
            tokens_out=parsed["tokens_out"],
        )

        event = EDREvent(
            category=EventCategory.LLM_REQUEST,
            action=EventAction.LLM_RESPONSE,
            agent=AgentContext(agent_type=agent_type, agent_pid=pid),
            process=ProcessContext(pid=pid, name=comm),
            llm=llm_ctx,
            tool_response_json=parsed.get("combined", parsed["body_preview"][:1000]),
            severity=Severity.INFO,
            sensor_source="ebpf",
        )

        if self._loop:
            self._loop.call_soon_threadsafe(
                self._loop.create_task, self.emit(event)
            )

    async def _run(self) -> None:
        """Main sensor loop: load BPF program and poll for events."""
        self._loop = asyncio.get_event_loop()

        try:
            self._load_bpf()
        except RuntimeError as e:
            logger.error("eBPF sensor failed to start: %s", e)
            return

        # Register perf event callback
        self._bpf["events"].open_perf_buffer(
            self._handle_event,
            page_cnt=1024,  # 4MB ring buffer (was 256KB - too small, caused drops)
            lost_cb=self._handle_lost_events,
        )

        logger.info("eBPF sensor running - polling for events")
        self.ready.set()

        while self._running:
            # Poll BPF perf buffer with short timeout to avoid
            # starving the asyncio event loop. The event loop needs
            # time to run the pipeline (store events, run detection).
            self._bpf.perf_buffer_poll(timeout=10)
            # Yield to asyncio event loop - give pipeline time to drain
            await asyncio.sleep(0.01)

    async def stop(self) -> None:
        """Stop the sensor and cleanup BPF resources."""
        await super().stop()
        if self._bpf:
            self._bpf.cleanup()
            self._bpf = None
            logger.info("BPF program unloaded")
