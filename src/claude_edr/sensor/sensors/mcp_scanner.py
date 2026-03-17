"""MCP Server Scanner - Agent-agnostic discovery of MCP server processes.

Detects running MCP servers by their OS-level characteristics:
  - stdin (fd 0) and stdout (fd 1) connected to pipes
  - Command line matches known MCP server patterns
  - Parent process is a known AI coding agent

When an MCP server is found, registers its pipe FDs with the eBPF sensor
so that JSON-RPC traffic (tool calls + responses) is captured transparently.

Works for ALL AI agents: Claude Code, Cursor, Codex, Copilot, Windsurf, Aider.
No config changes required on any agent.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

from claude_edr.sensor.models.events import (
    AgentContext,
    AgentType,
    EDREvent,
    EventAction,
    EventCategory,
    ProcessContext,
    Severity,
)
from claude_edr.sensor.sensors.base import BaseSensor

logger = logging.getLogger(__name__)


# ── Config-based MCP detection ───────────────────────────────────────────────
# Read MCP server configs from all known AI agent config files so we can
# identify MCP processes even when their command line doesn't contain "mcp".

@dataclass
class _ConfiguredMCP:
    """An MCP server entry from an agent config file."""
    name: str
    command: str       # basename of the command
    args: list[str]    # basenames of args
    full_command: str   # original full command path
    full_args: list[str]  # original full args


def _load_all_configured_mcps() -> list[_ConfiguredMCP]:
    """Load MCP server configs from all known AI agent config files."""
    configs: list[_ConfiguredMCP] = []
    home = Path.home()

    # ── Claude Code ──
    # Global + project-level: ~/.claude.json
    claude_json = home / ".claude.json"
    if claude_json.exists():
        try:
            data = json.loads(claude_json.read_text())
            # Global mcpServers
            for name, cfg in data.get("mcpServers", {}).items():
                if cfg.get("type", "stdio") == "stdio":
                    configs.append(_make_config_entry(name, cfg))
            # Project-level mcpServers
            for _proj_path, proj_cfg in data.get("projects", {}).items():
                for name, cfg in proj_cfg.get("mcpServers", {}).items():
                    if cfg.get("type", "stdio") == "stdio":
                        configs.append(_make_config_entry(name, cfg))
        except Exception:
            pass

    # Local project configs: ~/.claude/settings.local.json (no MCP there)
    # and .mcp.json files under ~/.claude/projects/*/
    claude_dir = home / ".claude"
    if claude_dir.exists():
        for mcp_json in claude_dir.glob("projects/*/.mcp.json"):
            try:
                mcp_data = json.loads(mcp_json.read_text())
                for name, cfg in mcp_data.get("mcpServers", {}).items():
                    if cfg.get("type", "stdio") == "stdio":
                        configs.append(_make_config_entry(name, cfg))
            except Exception:
                pass

    # ── Cursor ──
    cursor_mcp = home / ".cursor" / "mcp.json"
    if cursor_mcp.exists():
        try:
            data = json.loads(cursor_mcp.read_text())
            for name, cfg in data.get("mcpServers", {}).items():
                if cfg.get("type", "stdio") == "stdio":
                    configs.append(_make_config_entry(name, cfg))
        except Exception:
            pass

    # ── Windsurf / Codeium ──
    for wpath in [
        home / ".windsurf" / "mcp.json",
        home / ".codeium" / "windsurf" / "mcp_config.json",
        home / ".codeium" / "mcp.json",
    ]:
        if wpath.exists():
            try:
                data = json.loads(wpath.read_text())
                for name, cfg in data.get("mcpServers", {}).items():
                    if cfg.get("type", "stdio") == "stdio":
                        configs.append(_make_config_entry(name, cfg))
            except Exception:
                pass

    # ── VS Code (Copilot, Cline, Roo, Continue) ──
    vscode_mcp = home / ".vscode" / "mcp.json"
    if vscode_mcp.exists():
        try:
            data = json.loads(vscode_mcp.read_text())
            for name, cfg in data.get("mcpServers", {}).items():
                if cfg.get("type", "stdio") == "stdio":
                    configs.append(_make_config_entry(name, cfg))
        except Exception:
            pass

    # ── Continue.dev ──
    continue_cfg = home / ".continue" / "config.json"
    if continue_cfg.exists():
        try:
            data = json.loads(continue_cfg.read_text())
            for mcp_entry in data.get("mcpServers", []):
                if isinstance(mcp_entry, dict):
                    name = mcp_entry.get("name", "")
                    if name and mcp_entry.get("type", "stdio") == "stdio":
                        configs.append(_make_config_entry(name, mcp_entry))
        except Exception:
            pass

    # ── Claude Desktop (Linux) ──
    # ~/.config/Claude/claude_desktop_config.json (standard mcpServers key)
    claude_desktop = home / ".config" / "Claude" / "claude_desktop_config.json"
    if claude_desktop.exists():
        try:
            data = json.loads(claude_desktop.read_text())
            for name, cfg in data.get("mcpServers", {}).items():
                if cfg.get("type", "stdio") == "stdio":
                    configs.append(_make_config_entry(name, cfg))
        except Exception:
            pass

    # ── Amazon Q Developer ──
    # Global: ~/.aws/amazonq/mcp.json
    # Workspace: .amazonq/mcp.json (relative, skip for now)
    amazon_q_mcp = home / ".aws" / "amazonq" / "mcp.json"
    if amazon_q_mcp.exists():
        try:
            data = json.loads(amazon_q_mcp.read_text())
            for name, cfg in data.get("mcpServers", {}).items():
                if cfg.get("type", "stdio") == "stdio":
                    configs.append(_make_config_entry(name, cfg))
        except Exception:
            pass

    # ── Gemini CLI ──
    # Global: ~/.gemini/settings.json (mcpServers key)
    gemini_settings = home / ".gemini" / "settings.json"
    if gemini_settings.exists():
        try:
            data = json.loads(gemini_settings.read_text())
            for name, cfg in data.get("mcpServers", {}).items():
                if cfg.get("type", "stdio") == "stdio":
                    configs.append(_make_config_entry(name, cfg))
        except Exception:
            pass

    # ── Zed ──
    # ~/.config/zed/settings.json uses "context_servers" key (NOT mcpServers)
    # Format: { "context_servers": { "name": { "command": { "path": "...", "args": [...] } } } }
    zed_settings = home / ".config" / "zed" / "settings.json"
    if zed_settings.exists():
        try:
            data = json.loads(zed_settings.read_text())
            for name, cfg in data.get("context_servers", {}).items():
                cmd_cfg = cfg.get("command", {})
                if isinstance(cmd_cfg, dict) and cmd_cfg.get("path"):
                    configs.append(_ConfiguredMCP(
                        name=name,
                        command=os.path.basename(cmd_cfg["path"]),
                        args=[os.path.basename(a) for a in cmd_cfg.get("args", [])],
                        full_command=cmd_cfg["path"],
                        full_args=cmd_cfg.get("args", []),
                    ))
        except Exception:
            pass

    # ── Goose (Block/Square) ──
    # ~/.config/goose/config.yaml - YAML format with "extensions" key
    # Format: extensions: { name: { command: "...", args: [...] } }
    goose_cfg = home / ".config" / "goose" / "config.yaml"
    if goose_cfg.exists():
        try:
            import yaml
            data = yaml.safe_load(goose_cfg.read_text())
            if isinstance(data, dict):
                for name, cfg in data.get("extensions", {}).items():
                    if isinstance(cfg, dict) and cfg.get("command"):
                        cmd = cfg["command"]
                        args = cfg.get("args", [])
                        if isinstance(args, list):
                            configs.append(_ConfiguredMCP(
                                name=name,
                                command=os.path.basename(cmd),
                                args=[os.path.basename(str(a)) for a in args],
                                full_command=cmd,
                                full_args=[str(a) for a in args],
                            ))
        except ImportError:
            pass  # pyyaml not installed
        except Exception:
            pass

    # ── OpenAI Codex CLI ──
    # ~/.codex/config.toml - TOML format with [mcp_servers.name] sections
    codex_cfg = home / ".codex" / "config.toml"
    if codex_cfg.exists():
        _tomllib = None
        try:
            import tomllib as _tomllib
        except ImportError:
            try:
                import tomli as _tomllib  # type: ignore[no-redef]
            except ImportError:
                pass
        if _tomllib is not None:
            try:
                with open(codex_cfg, "rb") as f:
                    data = _tomllib.load(f)
                for name, cfg in data.get("mcp_servers", {}).items():
                    if isinstance(cfg, dict) and cfg.get("command"):
                        cmd = cfg["command"]
                        args = cfg.get("args", [])
                        if isinstance(args, list):
                            configs.append(_ConfiguredMCP(
                                name=name,
                                command=os.path.basename(cmd),
                                args=[os.path.basename(str(a)) for a in args],
                                full_command=cmd,
                                full_args=[str(a) for a in args],
                            ))
            except Exception:
                pass

    # ── Cline (VS Code extension) ──
    # ~/Library/... on mac, ~/.config/Code/... on Linux
    # cline stores settings in VS Code globalStorage:
    # ~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json
    for code_variant in ["Code", "Code - Insiders"]:
        cline_settings = (
            home / ".config" / code_variant / "User" / "globalStorage"
            / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json"
        )
        if cline_settings.exists():
            try:
                data = json.loads(cline_settings.read_text())
                for name, cfg in data.get("mcpServers", {}).items():
                    if isinstance(cfg, dict) and cfg.get("type", "stdio") == "stdio":
                        configs.append(_make_config_entry(name, cfg))
            except Exception:
                pass

    # ── Roo Code (VS Code extension, fork of Cline) ──
    for code_variant in ["Code", "Code - Insiders"]:
        roo_settings = (
            home / ".config" / code_variant / "User" / "globalStorage"
            / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json"
        )
        if roo_settings.exists():
            try:
                data = json.loads(roo_settings.read_text())
                for name, cfg in data.get("mcpServers", {}).items():
                    if isinstance(cfg, dict) and cfg.get("type", "stdio") == "stdio":
                        configs.append(_make_config_entry(name, cfg))
            except Exception:
                pass

    # ── Kilo Code (VS Code extension) ──
    kilo_mcp = home / ".kilocode" / "mcp.json"
    if kilo_mcp.exists():
        try:
            data = json.loads(kilo_mcp.read_text())
            for name, cfg in data.get("mcpServers", {}).items():
                if isinstance(cfg, dict) and cfg.get("type", "stdio") == "stdio":
                    configs.append(_make_config_entry(name, cfg))
        except Exception:
            pass

    # ── Tabnine ──
    # ~/.tabnine/mcp_servers.json
    tabnine_mcp = home / ".tabnine" / "mcp_servers.json"
    if tabnine_mcp.exists():
        try:
            data = json.loads(tabnine_mcp.read_text())
            for name, cfg in data.get("mcpServers", {}).items():
                if isinstance(cfg, dict) and cfg.get("type", "stdio") == "stdio":
                    configs.append(_make_config_entry(name, cfg))
        except Exception:
            pass

    # ── Kiro (AWS IDE) ──
    kiro_mcp = home / ".kiro" / "mcp.json"
    if kiro_mcp.exists():
        try:
            data = json.loads(kiro_mcp.read_text())
            for name, cfg in data.get("mcpServers", {}).items():
                if isinstance(cfg, dict) and cfg.get("type", "stdio") == "stdio":
                    configs.append(_make_config_entry(name, cfg))
        except Exception:
            pass

    # ── Amp (Sourcegraph) ──
    # ~/.amp/mcp.json or similar
    amp_mcp = home / ".amp" / "mcp.json"
    if amp_mcp.exists():
        try:
            data = json.loads(amp_mcp.read_text())
            for name, cfg in data.get("mcpServers", {}).items():
                if isinstance(cfg, dict) and cfg.get("type", "stdio") == "stdio":
                    configs.append(_make_config_entry(name, cfg))
        except Exception:
            pass

    # ── GitHub Copilot CLI ──
    # ~/.config/github-copilot/copilot.json or similar
    copilot_cfg = home / ".config" / "github-copilot" / "copilot.json"
    if copilot_cfg.exists():
        try:
            data = json.loads(copilot_cfg.read_text())
            for name, cfg in data.get("mcpServers", {}).items():
                if isinstance(cfg, dict) and cfg.get("type", "stdio") == "stdio":
                    configs.append(_make_config_entry(name, cfg))
        except Exception:
            pass

    # Deduplicate by (name, command, args_tuple)
    seen: set[tuple] = set()
    unique: list[_ConfiguredMCP] = []
    for c in configs:
        key = (c.name, c.command, tuple(c.args))
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


def _make_config_entry(name: str, cfg: dict) -> _ConfiguredMCP:
    """Build a _ConfiguredMCP from a config dict."""
    command = cfg.get("command", "")
    args = cfg.get("args", [])
    return _ConfiguredMCP(
        name=name,
        command=os.path.basename(command),
        args=[os.path.basename(a) for a in args],
        full_command=command,
        full_args=args,
    )

# ── Agent detection ──────────────────────────────────────────────────────────

# Process comm names that identify AI coding agents
# These are the actual /proc/PID/comm values (max 15 chars) on Linux
AGENT_COMM_NAMES: dict[str, AgentType] = {
    # CLI agents (native binaries)
    "claude": AgentType.CLAUDE_CODE,
    "claude-code": AgentType.CLAUDE_CODE,
    "codex": AgentType.CODEX,
    "copilot": AgentType.COPILOT,
    "gemini": AgentType.GEMINI,
    "q": AgentType.AMAZON_Q,              # Amazon Q Developer CLI
    "goose": AgentType.GOOSE,
    "amp": AgentType.AMP,                 # Sourcegraph Amp
    # Electron IDE/editors (spawn MCP as child processes)
    "cursor": AgentType.CURSOR,
    "windsurf": AgentType.WINDSURF,
    "windsurf-next": AgentType.WINDSURF,  # beta channel
    "code": AgentType.VSCODE,             # VS Code (Copilot, Cline, Roo, Continue)
    "code-insiders": AgentType.VSCODE,
    "zed-editor": AgentType.ZED,          # Zed (Rust native, not Electron)
    "kiro": AgentType.KIRO,               # AWS Kiro IDE
    "pearai": AgentType.PEARAI,
    "claude-desktop": AgentType.CLAUDE_DESKTOP,
    "lm-studio": AgentType.LM_STUDIO,
    "llmster": AgentType.LM_STUDIO,       # LM Studio headless daemon
    "Goose": AgentType.GOOSE,             # Goose desktop GUI (capital G)
    # aider: shows as "python3" in comm, detected via cmdline patterns below
    # JetBrains: shows as "java" in comm, detected via cmdline patterns below
}

# Cmdline patterns to identify agent processes (checked against parent tree)
# Used for agents whose comm name is generic (python3, java, node, electron)
AGENT_CMDLINE_PATTERNS: list[tuple[re.Pattern, AgentType]] = [
    (re.compile(r"\bclaude\b", re.I), AgentType.CLAUDE_CODE),
    (re.compile(r"\bcursor\b", re.I), AgentType.CURSOR),
    (re.compile(r"\bcodex\b", re.I), AgentType.CODEX),
    (re.compile(r"\bcopilot\b", re.I), AgentType.COPILOT),
    (re.compile(r"\b(?:windsurf|codeium)\b", re.I), AgentType.WINDSURF),
    (re.compile(r"\bgemini\b", re.I), AgentType.GEMINI),
    (re.compile(r"\bamazon-?q\b", re.I), AgentType.AMAZON_Q),
    (re.compile(r"\bgoose\b", re.I), AgentType.GOOSE),
    (re.compile(r"\bamp\b", re.I), AgentType.AMP),
    (re.compile(r"\bkiro\b", re.I), AgentType.KIRO),
    (re.compile(r"\bzed\b", re.I), AgentType.ZED),
    (re.compile(r"\bpearai\b", re.I), AgentType.PEARAI),
    (re.compile(r"\blm-?studio\b", re.I), AgentType.LM_STUDIO),
    (re.compile(r"\b(?:idea|pycharm|webstorm|phpstorm|goland|rubymine|clion|rider|intellij)\b", re.I), AgentType.JETBRAINS),
    (re.compile(r"\baider\b", re.I), AgentType.AIDER),
]

# ── MCP server detection ────────────────────────────────────────────────────

# Strong indicators: command line contains MCP-specific strings
MCP_STRONG_PATTERNS: list[re.Pattern] = [
    re.compile(r"mcp[-_]server", re.I),
    re.compile(r"modelcontextprotocol", re.I),
    re.compile(r"@anthropic/mcp-", re.I),
    re.compile(r"-m\s+mcp[-_.]", re.I),
    re.compile(r"\buvx\s+mcp-", re.I),
    re.compile(r"\bnpx\s+.*mcp", re.I),
    re.compile(r"mcp[-_]memory", re.I),
    re.compile(r"mcp[-_]filesystem", re.I),
    re.compile(r"mcp[-_]github", re.I),
    re.compile(r"mcp[-_]postgres", re.I),
    re.compile(r"mcp[-_]sqlite", re.I),
    re.compile(r"mcp[-_]slack", re.I),
    re.compile(r"mcp[-_]brave", re.I),
    re.compile(r"mcp[-_]puppeteer", re.I),
]

# Weak indicators: process is a runtime that COULD host an MCP server
# Requires additional evidence (known agent parent) to classify as MCP
MCP_HOST_BINARIES = frozenset({
    "node", "python", "python3", "python3.11", "python3.12", "python3.13",
    "uvx", "npx", "bun", "deno", "tsx",
    "java",       # JetBrains IDEs (AI Assistant, Junie)
    "electron",   # Claude Desktop (Linux community builds)
})

# Processes to always skip (too common, never MCP servers)
SKIP_COMMS = frozenset({
    "bash", "sh", "zsh", "fish", "dash",
    "systemd", "init", "sshd", "login",
    "sudo", "su", "env",
    "grep", "sed", "awk", "cat", "ls", "find",
    "git", "ssh", "scp",
})


@dataclass
class MCPServerInfo:
    """Discovered MCP server process."""

    pid: int
    ppid: int
    comm: str           # /proc/PID/comm
    cmdline: str        # full command line
    stdin_inode: str    # pipe:[NNNNN]
    stdout_inode: str   # pipe:[NNNNN]
    agent_pid: int = 0
    agent_type: AgentType = AgentType.UNKNOWN
    server_name: str = ""
    agent_write_fd: int | None = None   # agent's fd that writes to server stdin
    agent_read_fd: int | None = None    # agent's fd that reads server stdout


class MCPScanner(BaseSensor):
    """Scans /proc for MCP server processes and wires pipe capture.

    Agent-agnostic: looks at OS-level process characteristics rather
    than reading any agent's configuration files.

    Discovery algorithm:
      1. Find processes with pipe-connected stdin AND stdout
      2. Check if command matches MCP patterns (strong match)
         OR command is a runtime binary (node/python) with an agent parent (weak match)
      3. Walk process tree to identify the parent AI agent
      4. Register pipe FDs with eBPF sensor for JSON-RPC capture
    """

    def __init__(
        self,
        event_queue: asyncio.Queue[EDREvent],
        ebpf_sensor=None,
        scan_interval: float = 5.0,
    ):
        super().__init__(event_queue)
        self._ebpf = ebpf_sensor
        self._scan_interval = scan_interval
        self._known_servers: dict[int, MCPServerInfo] = {}
        # Config-based MCP detection
        self._configured_mcps: list[_ConfiguredMCP] = []
        self._config_loaded_at: float = 0.0
        self._config_refresh_interval: float = 60.0  # reload every 60s

    @property
    def name(self) -> str:
        return "MCP Server Scanner"

    @property
    def sensor_type(self) -> str:
        return "mcp_scanner"

    def set_ebpf_sensor(self, ebpf_sensor) -> None:
        """Set or update the eBPF sensor reference."""
        self._ebpf = ebpf_sensor

    # ── Sensor loop ──────────────────────────────────────────────────────

    async def _run(self) -> None:
        logger.info(
            "MCP scanner starting (interval: %.1fs, ebpf: %s)",
            self._scan_interval,
            "attached" if self._ebpf else "none",
        )

        while self._running:
            try:
                await self._scan_cycle()
            except Exception:
                logger.exception("MCP scan cycle failed")

            await asyncio.sleep(self._scan_interval)

    def _refresh_config(self) -> None:
        """Reload MCP configs from agent config files if stale."""
        now = time.monotonic()
        if now - self._config_loaded_at < self._config_refresh_interval:
            return
        self._configured_mcps = _load_all_configured_mcps()
        self._config_loaded_at = now
        if self._configured_mcps:
            logger.info(
                "Loaded %d configured MCP servers from agent configs: %s",
                len(self._configured_mcps),
                [c.name for c in self._configured_mcps],
            )

    def _match_config(self, cmdline: str) -> str:
        """Check if a process cmdline matches a configured MCP server.

        Compares command basename and arg basenames against all configured
        MCP entries. Returns the config name if matched, empty string otherwise.
        """
        parts = cmdline.split()
        if not parts:
            return ""
        proc_cmd = os.path.basename(parts[0])
        proc_args = [os.path.basename(p) for p in parts[1:]]

        for cfg in self._configured_mcps:
            if not cfg.command:
                continue
            # Command basename must match
            if proc_cmd != cfg.command:
                continue
            # All config args must appear in process args (by basename)
            if cfg.args and not all(a in proc_args for a in cfg.args):
                continue
            return cfg.name
        return ""

    async def _scan_cycle(self) -> None:
        """One full scan: discover new servers, detect exited ones."""
        self._refresh_config()
        live_pids: set[int] = set()

        try:
            proc_entries = os.listdir("/proc")
        except OSError:
            return

        for entry in proc_entries:
            if not entry.isdigit():
                continue

            pid = int(entry)
            live_pids.add(pid)

            if pid in self._known_servers:
                continue

            info = self._probe_process(pid)
            if info is not None:
                self._known_servers[pid] = info
                await self._on_discovered(info)

        # Detect exited servers
        gone = [p for p in self._known_servers if p not in live_pids]
        for pid in gone:
            info = self._known_servers.pop(pid)
            await self._on_exited(info)

    # ── Process probing ──────────────────────────────────────────────────

    def _probe_process(self, pid: int) -> MCPServerInfo | None:
        """Check whether *pid* is an MCP server.

        Returns MCPServerInfo if it looks like one, else None.
        """
        comm = self._read_comm(pid)
        if not comm or comm in SKIP_COMMS:
            return None

        # Step 1: stdin and stdout must both be pipes or sockets
        # Node.js child_process.spawn uses socketpair() on Linux,
        # so MCP servers show socket:[NNNNN] instead of pipe:[NNNNN]
        stdin_link = self._read_fd_link(pid, 0)
        stdout_link = self._read_fd_link(pid, 1)
        if not stdin_link or not stdout_link:
            return None
        if not self._is_ipc_fd(stdin_link) or not self._is_ipc_fd(stdout_link):
            return None

        # Step 2: command line
        cmdline = self._read_cmdline(pid)
        if not cmdline:
            return None

        # Step 3: classify
        strong_match = self._is_strong_mcp_match(cmdline, comm)
        config_name = ""

        if not strong_match:
            # Config path: check if this process matches a configured MCP server
            config_name = self._match_config(cmdline)
            if config_name:
                strong_match = True  # treat config match as definitive

        if not strong_match:
            # Weak path: must be a known runtime AND have an agent parent
            base = os.path.basename(comm)
            if base not in MCP_HOST_BINARIES:
                return None
            # Also check if cmdline args hint at MCP (e.g. "mcp" anywhere)
            if "mcp" not in cmdline.lower():
                return None

        # Step 4: find parent agent
        ppid = self._read_ppid(pid)
        agent_pid, agent_type = self._walk_to_agent(pid)

        # For weak matches, require a known agent parent
        if not strong_match and agent_type == AgentType.UNKNOWN:
            return None

        # Build info — use config name if available, else derive from cmdline
        server_name = config_name or self._derive_name(cmdline)

        info = MCPServerInfo(
            pid=pid,
            ppid=ppid,
            comm=comm,
            cmdline=cmdline,
            stdin_inode=stdin_link,
            stdout_inode=stdout_link,
            agent_pid=agent_pid,
            agent_type=agent_type,
            server_name=server_name,
        )

        # Find agent-side FDs for pipe capture
        if agent_pid > 0:
            info.agent_write_fd = self._find_agent_peer_fd(agent_pid, stdin_link)
            info.agent_read_fd = self._find_agent_peer_fd(agent_pid, stdout_link)

        return info

    # ── /proc readers ────────────────────────────────────────────────────

    @staticmethod
    def _read_comm(pid: int) -> str:
        try:
            return Path(f"/proc/{pid}/comm").read_text().strip()
        except (OSError, FileNotFoundError):
            return ""

    @staticmethod
    def _read_cmdline(pid: int) -> str:
        try:
            raw = Path(f"/proc/{pid}/cmdline").read_bytes()
            return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except (OSError, FileNotFoundError):
            return ""

    @staticmethod
    def _read_ppid(pid: int) -> int:
        try:
            for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                if line.startswith("PPid:"):
                    return int(line.split()[1])
        except (OSError, FileNotFoundError, ValueError, IndexError):
            pass
        return 0

    @staticmethod
    def _read_fd_link(pid: int, fd: int) -> str | None:
        try:
            return os.readlink(f"/proc/{pid}/fd/{fd}")
        except (OSError, FileNotFoundError):
            return None

    @staticmethod
    def _find_fd_by_inode(pid: int, target_inode: str) -> int | None:
        """Find the fd on *pid* that points to *target_inode* (e.g. pipe:[12345])."""
        try:
            fd_dir = f"/proc/{pid}/fd"
            for name in os.listdir(fd_dir):
                try:
                    link = os.readlink(f"{fd_dir}/{name}")
                    if link == target_inode:
                        return int(name)
                except (OSError, ValueError):
                    continue
        except OSError:
            pass
        return None

    @staticmethod
    def _find_agent_peer_fd(agent_pid: int, server_fd_link: str) -> int | None:
        """Find the agent's fd that connects to a server's pipe or socket.

        For pipes: both ends share the same inode → exact match.
        For sockets: socketpair() creates two ends with different inodes.
        On Linux, socketpair typically allocates consecutive inodes, so
        the peer is at inode+1 (or inode-1).
        """
        if server_fd_link.startswith("pipe:"):
            return MCPScanner._find_fd_by_inode(agent_pid, server_fd_link)

        if server_fd_link.startswith("socket:"):
            m = re.match(r"socket:\[(\d+)\]", server_fd_link)
            if not m:
                return None
            ino = int(m.group(1))

            # socketpair allocates consecutive inodes on Linux
            for offset in (1, -1, 2, -2):
                candidate = f"socket:[{ino + offset}]"
                fd = MCPScanner._find_fd_by_inode(agent_pid, candidate)
                if fd is not None:
                    return fd

        return None

    # ── Classification helpers ───────────────────────────────────────────

    @staticmethod
    def _is_ipc_fd(link: str) -> bool:
        """Check if an fd link is a pipe or socket (IPC channel).

        Node.js child_process.spawn uses socketpair() on Linux,
        so MCP servers show 'socket:[NNNNN]' not 'pipe:[NNNNN]'.
        Both are valid IPC channels for MCP JSON-RPC traffic.
        """
        return link.startswith("pipe:") or link.startswith("socket:")

    @staticmethod
    def _is_strong_mcp_match(cmdline: str, comm: str = "") -> bool:
        """Check for strong MCP server indicators.

        Strong signals: specific MCP patterns in cmdline, or "mcp" in the
        process name (comm) itself (e.g. analytics-mcp, mcp-server-github).
        """
        # Process name contains "mcp" → strong signal
        if comm and "mcp" in comm.lower():
            return True

        for pat in MCP_STRONG_PATTERNS:
            if pat.search(cmdline):
                return True
        return False

    def _walk_to_agent(self, pid: int) -> tuple[int, AgentType]:
        """Walk the process tree upward looking for a known AI agent parent."""
        cur = pid
        visited: set[int] = set()

        for _ in range(25):
            ppid = self._read_ppid(cur)
            if ppid <= 1 or ppid in visited:
                break
            visited.add(ppid)

            comm = self._read_comm(ppid).lower()
            for name, atype in AGENT_COMM_NAMES.items():
                if name in comm:
                    return ppid, atype

            cmdline = self._read_cmdline(ppid)
            for pat, atype in AGENT_CMDLINE_PATTERNS:
                if pat.search(cmdline):
                    return ppid, atype

            cur = ppid

        return 0, AgentType.UNKNOWN

    @staticmethod
    def _derive_name(cmdline: str) -> str:
        """Extract a human-readable MCP server name from cmdline."""
        # mcp-server-NAME or mcp_server_NAME
        m = re.search(r"mcp[-_]server[-_]([\w]+)", cmdline, re.I)
        if m:
            return f"mcp-server-{m.group(1)}"

        # @scope/mcp-NAME
        m = re.search(r"@[\w-]+/(mcp-[\w-]+)", cmdline, re.I)
        if m:
            return m.group(1)

        # -m mcp_something.server
        m = re.search(r"-m\s+([\w.]+)", cmdline)
        if m:
            mod = m.group(1)
            # e.g. mcp_memory_service.server -> mcp-memory-service
            return mod.split(".")[0].replace("_", "-")

        # Generic mcp-NAME anywhere
        m = re.search(r"(mcp[-_][\w-]+)", cmdline, re.I)
        if m:
            return m.group(1).replace("_", "-")

        # Fallback: second arg (the script/module after the interpreter)
        parts = cmdline.split()
        if len(parts) >= 2:
            return os.path.basename(parts[1]).replace("_", "-")
        return os.path.basename(parts[0]) if parts else "unknown-mcp"

    # ── Event handlers ───────────────────────────────────────────────────

    async def _on_discovered(self, info: MCPServerInfo) -> None:
        logger.info(
            "MCP server discovered: %s (PID %d) | parent: %s (PID %d) | cmd: %s",
            info.server_name,
            info.pid,
            info.agent_type.value,
            info.agent_pid,
            info.cmdline[:120],
        )

        # Wire eBPF pipe capture
        if self._ebpf is not None:
            logger.info(
                "  Wiring eBPF for %s (PID %d): stdin=%s stdout=%s agent_pid=%d agent_write_fd=%s",
                info.server_name, info.pid, info.stdin_inode, info.stdout_inode,
                info.agent_pid, info.agent_write_fd,
            )

            # Ensure MCP server PID is tracked
            self._ebpf.track_child(info.pid, info.agent_pid or info.pid)

            # Register MCP server name for tool_name formatting
            self._ebpf.register_mcp_server(info.pid, info.server_name)

            # Track MCP server stdout (fd 1) → captures JSON-RPC responses
            self._ebpf.track_pipe_fd(info.pid, 1)
            logger.info(
                "  eBPF tracking server stdout: PID %d fd 1 → responses",
                info.pid,
            )

            # Track MCP server stdin (fd 0) → captures JSON-RPC requests
            # via sys_exit_read hook (agent may use sendmsg instead of write)
            self._ebpf.track_pipe_fd(info.pid, 0)
            logger.info(
                "  eBPF tracking server stdin: PID %d fd 0 → requests (read-side)",
                info.pid,
            )

            # Track agent's write fd → captures JSON-RPC requests
            if info.agent_write_fd is not None and info.agent_pid > 0:
                self._ebpf.track_pipe_fd(info.agent_pid, info.agent_write_fd)
                # Also register the agent PID as belonging to this MCP server
                # so requests get the right server name
                self._ebpf.register_mcp_pipe(
                    info.agent_pid, info.agent_write_fd, info.server_name
                )
                logger.info(
                    "  eBPF tracking agent requests: PID %d fd %d → requests",
                    info.agent_pid,
                    info.agent_write_fd,
                )

            # Prime any blocked reads: if the server is already blocking in
            # read(fd=0), the BPF entry hook missed it (loaded after the read
            # started). Pre-seed the BPF map so the exit hook can capture data.
            self._ebpf.prime_blocked_read(info.pid, 0)

            # Dump BPF maps after wiring (debug)
            self._ebpf.dump_bpf_maps()

        # Emit discovery event
        await self.emit(
            EDREvent(
                category=EventCategory.MCP_ACTIVITY,
                action=EventAction.SESSION_START,
                agent=AgentContext(
                    agent_type=info.agent_type,
                    agent_pid=info.agent_pid,
                ),
                process=ProcessContext(
                    pid=info.pid,
                    ppid=info.ppid,
                    name=info.comm,
                    cmdline=info.cmdline,
                ),
                tool_name=info.server_name,
                severity=Severity.INFO,
            )
        )

    async def _on_exited(self, info: MCPServerInfo) -> None:
        logger.info(
            "MCP server exited: %s (PID %d)", info.server_name, info.pid
        )

        # Clean up eBPF state
        if self._ebpf is not None:
            self._ebpf.unregister_mcp_server(info.pid)

        await self.emit(
            EDREvent(
                category=EventCategory.MCP_ACTIVITY,
                action=EventAction.SESSION_END,
                agent=AgentContext(
                    agent_type=info.agent_type,
                    agent_pid=info.agent_pid,
                ),
                process=ProcessContext(
                    pid=info.pid,
                    ppid=info.ppid,
                    name=info.comm,
                    cmdline=info.cmdline,
                ),
                tool_name=info.server_name,
                severity=Severity.INFO,
            )
        )

    # ── Public API ───────────────────────────────────────────────────────

    def get_known_servers(self) -> list[MCPServerInfo]:
        """Return currently known MCP servers."""
        return list(self._known_servers.values())
