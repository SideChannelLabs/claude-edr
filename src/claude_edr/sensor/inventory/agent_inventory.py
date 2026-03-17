"""Agent inventory - discovers installed AI agents and their configurations.

For each agent, discovers:
- MCP servers connected
- Skills/extensions installed
- Hooks configured
- Permission mode
- API endpoints configured
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class MCPServer:
    """An MCP server connected to an agent."""

    name: str
    command: str = ""
    args: list[str] = field(default_factory=list)
    server_type: str = "stdio"  # stdio, sse, http
    env_vars: list[str] = field(default_factory=list)  # Names only, not values
    tools: list[str] = field(default_factory=list)
    # Package metadata (auto-detected or from registry)
    description: str = ""
    version: str = ""
    author: str = ""
    homepage: str = ""
    repository: str = ""
    license: str = ""
    package_name: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "command": self.command,
            "args": self.args,
            "server_type": self.server_type,
            "env_vars": self.env_vars,
            "tools": self.tools,
            "description": self.description,
            "version": self.version,
            "author": self.author,
            "homepage": self.homepage,
            "repository": self.repository,
            "license": self.license,
            "package_name": self.package_name,
        }


@dataclass
class HookConfig:
    """A hook configured for an agent."""

    event_type: str  # PreToolUse, PostToolUse, etc.
    matcher: str = ""
    command: str = ""
    is_async: bool = False

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "matcher": self.matcher,
            "command": self.command,
            "is_async": self.is_async,
        }


@dataclass
class AgentInventory:
    """Full inventory of an installed AI agent."""

    agent_type: str
    installed: bool = False
    version: str = ""
    config_path: str = ""
    permission_mode: str = ""
    mcp_servers: list[MCPServer] = field(default_factory=list)
    hooks: list[HookConfig] = field(default_factory=list)
    extensions: list[str] = field(default_factory=list)
    model: str = ""
    api_endpoint: str = ""

    def to_dict(self) -> dict:
        return {
            "agent_type": self.agent_type,
            "installed": self.installed,
            "version": self.version,
            "config_path": self.config_path,
            "permission_mode": self.permission_mode,
            "mcp_servers": [m.to_dict() for m in self.mcp_servers],
            "hooks": [h.to_dict() for h in self.hooks],
            "extensions": self.extensions,
            "model": self.model,
            "api_endpoint": self.api_endpoint,
            "mcp_count": len(self.mcp_servers),
            "hook_count": len(self.hooks),
        }


def discover_claude_code() -> AgentInventory:
    """Discover Claude Code installation and configuration."""
    inv = AgentInventory(agent_type="claude_code")
    home = Path.home()

    # Check if Claude Code is installed
    claude_dir = home / ".claude"
    if not claude_dir.exists():
        return inv

    inv.installed = True
    inv.config_path = str(claude_dir)

    # Read settings.json for hooks and permissions
    settings_path = claude_dir / "settings.json"
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
            inv.permission_mode = settings.get("permissions", {}).get("mode", "default")

            # Parse hooks
            hooks_data = settings.get("hooks", {})
            for event_type, hook_groups in hooks_data.items():
                if isinstance(hook_groups, list):
                    for group in hook_groups:
                        for hook in group.get("hooks", []):
                            inv.hooks.append(HookConfig(
                                event_type=event_type,
                                matcher=group.get("matcher", ""),
                                command=hook.get("command", ""),
                                is_async=hook.get("async", False),
                            ))
        except Exception as e:
            logger.warning("Failed to parse Claude Code settings: %s", e)

    # Read settings.local.json for local overrides
    local_settings = claude_dir / "settings.local.json"
    if local_settings.exists():
        try:
            local = json.loads(local_settings.read_text())
            # Local hooks
            hooks_data = local.get("hooks", {})
            for event_type, hook_groups in hooks_data.items():
                if isinstance(hook_groups, list):
                    for group in hook_groups:
                        for hook in group.get("hooks", []):
                            inv.hooks.append(HookConfig(
                                event_type=event_type,
                                matcher=group.get("matcher", ""),
                                command=hook.get("command", ""),
                                is_async=hook.get("async", False),
                            ))
        except Exception as e:
            logger.warning("Failed to parse Claude Code local settings: %s", e)

    # Read .claude.json for MCP servers (global config)
    claude_json = home / ".claude.json"
    if claude_json.exists():
        try:
            data = json.loads(claude_json.read_text())

            # Global MCP servers
            global_mcps = data.get("mcpServers", {})
            for name, config in global_mcps.items():
                inv.mcp_servers.append(_parse_mcp_server(name, config))

            # Project-level MCP servers
            projects = data.get("projects", {})
            for project_path, project_config in projects.items():
                project_mcps = project_config.get("mcpServers", {})
                for name, config in project_mcps.items():
                    mcp = _parse_mcp_server(name, config)
                    mcp.name = f"{name} ({Path(project_path).name})"
                    inv.mcp_servers.append(mcp)
        except Exception as e:
            logger.warning("Failed to parse .claude.json: %s", e)

    # Check for project-level CLAUDE.md files with MCP configs
    # Look in current project directories
    for project_dir in claude_dir.glob("projects/*"):
        mcp_json = project_dir / ".mcp.json"
        if mcp_json.exists():
            try:
                mcp_data = json.loads(mcp_json.read_text())
                for name, config in mcp_data.get("mcpServers", {}).items():
                    inv.mcp_servers.append(_parse_mcp_server(name, config))
            except Exception:
                pass

    # Deduplicate MCP servers — same (base_name, command, type) across projects = one entry
    seen: dict[tuple, MCPServer] = {}
    for mcp in inv.mcp_servers:
        # Strip project suffix like "memory-service (my-project)" -> "memory-service"
        base_name = mcp.name.split(" (")[0]
        key = (base_name, mcp.command, mcp.server_type)
        if key not in seen:
            mcp.name = base_name  # Use clean name
            seen[key] = mcp
    inv.mcp_servers = list(seen.values())

    return inv


def discover_cursor() -> AgentInventory:
    """Discover Cursor installation and configuration."""
    inv = AgentInventory(agent_type="cursor")
    home = Path.home()

    cursor_dir = home / ".cursor"
    if not cursor_dir.exists():
        return inv

    inv.installed = True
    inv.config_path = str(cursor_dir)

    # Read Cursor settings
    settings_path = cursor_dir / "User" / "settings.json"
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
            inv.model = settings.get("cursor.model", "")
            inv.api_endpoint = settings.get("cursor.apiEndpoint", "")
        except Exception:
            pass

    # Read extensions
    extensions_dir = cursor_dir / "extensions"
    if extensions_dir.exists():
        for ext_dir in extensions_dir.iterdir():
            if ext_dir.is_dir():
                inv.extensions.append(ext_dir.name)

    # Cursor MCP config
    mcp_json = cursor_dir / "mcp.json"
    if mcp_json.exists():
        try:
            mcp_data = json.loads(mcp_json.read_text())
            for name, config in mcp_data.get("mcpServers", {}).items():
                inv.mcp_servers.append(_parse_mcp_server(name, config))
        except Exception:
            pass

    return inv


def discover_windsurf() -> AgentInventory:
    """Discover Windsurf installation and configuration."""
    inv = AgentInventory(agent_type="windsurf")
    home = Path.home()

    windsurf_dir = home / ".windsurf"
    if not windsurf_dir.exists():
        # Also check .codeium
        windsurf_dir = home / ".codeium"
        if not windsurf_dir.exists():
            return inv

    inv.installed = True
    inv.config_path = str(windsurf_dir)

    # Extensions
    extensions_dir = windsurf_dir / "extensions"
    if extensions_dir.exists():
        for ext_dir in extensions_dir.iterdir():
            if ext_dir.is_dir():
                inv.extensions.append(ext_dir.name)

    # MCP config
    mcp_json = windsurf_dir / "mcp.json"
    if mcp_json.exists():
        try:
            mcp_data = json.loads(mcp_json.read_text())
            for name, config in mcp_data.get("mcpServers", {}).items():
                inv.mcp_servers.append(_parse_mcp_server(name, config))
        except Exception:
            pass

    return inv


def discover_codex() -> AgentInventory:
    """Discover OpenAI Codex CLI installation."""
    inv = AgentInventory(agent_type="codex")
    home = Path.home()

    codex_dir = home / ".codex"
    if not codex_dir.exists():
        return inv

    inv.installed = True
    inv.config_path = str(codex_dir)

    # Read codex config
    config_path = codex_dir / "config.json"
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text())
            inv.model = config.get("model", "")
        except Exception:
            pass

    return inv


def discover_all_agents() -> list[AgentInventory]:
    """Discover all installed AI coding agents."""
    agents = []
    for discover_fn in [discover_claude_code, discover_cursor, discover_windsurf, discover_codex]:
        try:
            agent = discover_fn()
            if agent.installed:
                agents.append(agent)
        except Exception as e:
            logger.warning("Failed to discover agent: %s", e)
    return agents


def _parse_mcp_server(name: str, config: dict) -> MCPServer:
    """Parse an MCP server configuration."""
    env_names = list(config.get("env", {}).keys()) if isinstance(config.get("env"), dict) else []
    server = MCPServer(
        name=name,
        command=config.get("command", ""),
        args=config.get("args", []),
        server_type=config.get("type", "stdio"),
        env_vars=env_names,
    )
    _enrich_mcp_metadata(server, config)
    return server


# ── Known MCP server registry ────────────────────────────────────────────────
# Maps identifying patterns (module names, commands, URLs) to curated metadata.
# Checked first before falling back to pip/npm introspection.

_KNOWN_MCP_SERVERS: dict[str, dict] = {
    "mcp_memory_service": {
        "description": "Persistent memory storage for AI assistants using ChromaDB vector search",
        "repository": "https://github.com/doobidoo/mcp-memory-service",
        "homepage": "https://pypi.org/project/mcp-memory-service/",
        "license": "MIT",
        "package_name": "mcp-memory-service",
    },
    "analytics-mcp": {
        "description": "Google Analytics Data API access - run reports, realtime data, account management",
        "repository": "https://github.com/nicholasgriffintn/analytics-mcp",
        "homepage": "https://pypi.org/project/analytics-mcp/",
        "license": "Apache-2.0",
        "package_name": "analytics-mcp",
    },
    "mcp-atlassian": {
        "description": "Atlassian Confluence & Jira integration - search, create, update pages and issues",
        "repository": "https://github.com/sooperset/mcp-atlassian",
        "homepage": "https://pypi.org/project/mcp-atlassian/",
        "license": "MIT",
        "package_name": "mcp-atlassian",
    },
    "mcp.stripe.com": {
        "description": "Stripe API access - payments, customers, subscriptions, invoices",
        "repository": "https://github.com/stripe/agent-toolkit",
        "homepage": "https://docs.stripe.com/agents",
        "author": "Stripe",
        "license": "MIT",
        "package_name": "stripe-agent-toolkit",
    },
    "ahrefs-mcp": {
        "description": "Ahrefs SEO API - backlink analysis, keyword research, site audit",
        "homepage": "https://ahrefs.com/api",
        "author": "Ahrefs",
        "package_name": "ahrefs-mcp",
    },
    "mcp-server-fetch": {
        "description": "Web content fetching and conversion for AI consumption",
        "repository": "https://github.com/modelcontextprotocol/servers",
        "license": "MIT",
        "package_name": "@modelcontextprotocol/server-fetch",
    },
    "mcp-server-filesystem": {
        "description": "Local filesystem access - read, write, search files and directories",
        "repository": "https://github.com/modelcontextprotocol/servers",
        "license": "MIT",
        "package_name": "@modelcontextprotocol/server-filesystem",
    },
    "mcp-server-github": {
        "description": "GitHub API - repos, issues, PRs, code search, actions",
        "repository": "https://github.com/modelcontextprotocol/servers",
        "license": "MIT",
        "package_name": "@modelcontextprotocol/server-github",
    },
    "mcp-server-slack": {
        "description": "Slack workspace access - read/send messages, manage channels",
        "repository": "https://github.com/modelcontextprotocol/servers",
        "license": "MIT",
        "package_name": "@modelcontextprotocol/server-slack",
    },
    "mcp-server-postgres": {
        "description": "PostgreSQL database access - query, schema inspection",
        "repository": "https://github.com/modelcontextprotocol/servers",
        "license": "MIT",
        "package_name": "@modelcontextprotocol/server-postgres",
    },
    "mcp-server-sqlite": {
        "description": "SQLite database access - query, schema inspection, data analysis",
        "repository": "https://github.com/modelcontextprotocol/servers",
        "license": "MIT",
        "package_name": "@modelcontextprotocol/server-sqlite",
    },
    "mcp-server-puppeteer": {
        "description": "Browser automation - screenshots, navigation, form filling",
        "repository": "https://github.com/modelcontextprotocol/servers",
        "license": "MIT",
        "package_name": "@modelcontextprotocol/server-puppeteer",
    },
    "mcp-server-brave-search": {
        "description": "Brave Search API - web search, news, local results",
        "repository": "https://github.com/modelcontextprotocol/servers",
        "license": "MIT",
        "package_name": "@modelcontextprotocol/server-brave-search",
    },
    "mcp-server-google-maps": {
        "description": "Google Maps API - geocoding, directions, places search",
        "repository": "https://github.com/modelcontextprotocol/servers",
        "license": "MIT",
        "package_name": "@modelcontextprotocol/server-google-maps",
    },
}


def _enrich_mcp_metadata(server: MCPServer, config: dict) -> None:
    """Auto-detect package metadata for an MCP server.

    Checks the built-in registry first, then falls back to pip/npm
    package introspection for unknown servers.
    """
    # Build identifiers to match against the registry
    identifiers = [server.name]
    cmd = server.command
    args_str = " ".join(server.args)

    # Extract Python module name from -m flag (e.g., "-m mcp_memory_service.server")
    if "-m" in server.args:
        idx = server.args.index("-m")
        if idx + 1 < len(server.args):
            module = server.args[idx + 1].split(".")[0]  # mcp_memory_service
            identifiers.append(module)

    # Extract package name from uvx/npx/pipx args
    for runner in ("uvx", "npx", "pipx"):
        if cmd.endswith(runner) or f"/{runner}" in cmd:
            # Last non-flag arg is typically the package
            for arg in server.args:
                if not arg.startswith("-"):
                    identifiers.append(arg)
                    break

    # Check command basename
    if cmd:
        identifiers.append(cmd.rsplit("/", 1)[-1])

    # For HTTP servers, check the URL domain
    url = config.get("url", "")
    if url:
        # e.g., "https://mcp.stripe.com/" → "mcp.stripe.com"
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.hostname:
            identifiers.append(parsed.hostname)

    # Match against known registry
    for ident in identifiers:
        if ident in _KNOWN_MCP_SERVERS:
            meta = _KNOWN_MCP_SERVERS[ident]
            server.description = meta.get("description", "")
            server.repository = meta.get("repository", "")
            server.homepage = meta.get("homepage", "")
            server.author = meta.get("author", "")
            server.license = meta.get("license", "")
            server.package_name = meta.get("package_name", "")
            break

    # Try to get version from installed Python packages
    if not server.version:
        _detect_python_version(server, identifiers)


def _detect_python_version(server: MCPServer, identifiers: list[str]) -> None:
    """Try to detect the installed version of a Python MCP server package."""
    try:
        from importlib.metadata import metadata as pkg_metadata, PackageNotFoundError
    except ImportError:
        return

    # Try each identifier as a package name
    candidates = list(identifiers)
    if server.package_name:
        candidates.insert(0, server.package_name)

    for name in candidates:
        # Try both raw name and with hyphens/underscores swapped
        for variant in [name, name.replace("_", "-"), name.replace("-", "_")]:
            try:
                meta = pkg_metadata(variant)
                server.version = meta.get("Version", "")
                if not server.author:
                    server.author = meta.get("Author", "") or meta.get("Author-email", "")
                if not server.description:
                    server.description = meta.get("Summary", "")
                if not server.homepage:
                    server.homepage = meta.get("Home-page", "")
                if not server.license:
                    server.license = meta.get("License", "")
                if not server.package_name:
                    server.package_name = meta.get("Name", variant)
                return
            except PackageNotFoundError:
                continue
