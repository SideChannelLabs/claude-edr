"""CLI interface for Claude EDR."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from claude_edr.backend import __version__
from claude_edr.backend.config import Config

console = Console()


@click.group()
@click.version_option(__version__)
def main():
    """Claude EDR - Endpoint Detection and Response for AI coding agents."""
    pass


@main.command()
@click.option("--config", "-c", type=click.Path(exists=False), default=None, help="Config file path")
def start(config):
    """Start the EDR daemon and dashboard."""
    cfg = Config.load(Path(config) if config else None)

    console.print("[bold blue]Claude EDR[/bold blue] v" + __version__)
    console.print(f"  Dashboard: http://{cfg.dashboard.host}:{cfg.dashboard.port}")
    console.print(f"  Socket: {cfg.socket_path}")
    console.print(f"  Database: {cfg.storage.db_path}")
    console.print(f"  Sensors: hooks={'on' if cfg.sensors.hooks_enabled else 'off'} "
                  f"procmon={'on' if cfg.sensors.process_monitor_enabled else 'off'} "
                  f"ebpf={'on' if cfg.sensors.ebpf_enabled else 'off'}")
    console.print()

    from claude_edr.backend.daemon import run_daemon
    run_daemon(cfg)


@main.command()
def stop():
    """Stop the running EDR daemon."""
    # Send signal to running daemon via PID file
    pid_file = Path("/run/claude-edr/daemon.pid")
    if pid_file.exists():
        import os
        import signal

        pid = int(pid_file.read_text().strip())
        try:
            os.kill(pid, signal.SIGTERM)
            console.print(f"[green]Sent stop signal to daemon (PID {pid})[/green]")
        except ProcessLookupError:
            console.print("[yellow]Daemon not running (stale PID file)[/yellow]")
            pid_file.unlink()
    else:
        console.print("[yellow]No daemon PID file found. Is the daemon running?[/yellow]")


@main.command()
def status():
    """Check EDR daemon status."""
    import urllib.request

    cfg = Config.load()
    url = f"http://{cfg.dashboard.host}:{cfg.dashboard.port}/api/stats"

    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            data = json.loads(resp.read())

        console.print("[bold green]Claude EDR is running[/bold green]")
        console.print(f"  Events processed: {data.get('events_processed', 0)}")
        console.print(f"  Total events (1h): {data.get('total_events', 0)}")
        console.print(f"  Open alerts: {data.get('open_alerts', 0)}")
    except Exception:
        console.print("[bold red]Claude EDR is not running[/bold red]")
        console.print("  Start with: claude-edr start")


@main.command()
@click.option("--hours", "-h", default=1, help="Hours to look back")
@click.option("--severity", "-s", default=0, help="Minimum severity (0-4)")
@click.option("--agent", "-a", default=None, help="Agent type filter")
@click.option("--category", "-c", default=None, help="Event category filter")
@click.option("--limit", "-l", default=50, help="Max results")
def query(hours, severity, agent, category, limit):
    """Query events from the event store."""
    import urllib.request
    import urllib.parse

    cfg = Config.load()
    params = {"hours": hours, "min_severity": severity, "limit": limit}
    if agent:
        params["agent_type"] = agent
    if category:
        params["category"] = category

    url = f"http://{cfg.dashboard.host}:{cfg.dashboard.port}/api/events?" + urllib.parse.urlencode(params)

    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
    except Exception:
        console.print("[red]Cannot connect to EDR daemon. Is it running?[/red]")
        return

    events = data.get("events", [])
    if not events:
        console.print("[yellow]No events found.[/yellow]")
        return

    table = Table(title=f"Events ({len(events)} results)")
    table.add_column("Time", style="dim")
    table.add_column("Sev", justify="center")
    table.add_column("Agent")
    table.add_column("Action")
    table.add_column("Tool")
    table.add_column("Details", max_width=60)

    sev_colors = {0: "white", 1: "green", 2: "yellow", 3: "red", 4: "bold red"}
    sev_names = {0: "INFO", 1: "LOW", 2: "MED", 3: "HIGH", 4: "CRIT"}

    for e in events:
        sev = e.get("severity", 0)
        details = e.get("file_path") or e.get("process_cmdline") or e.get("net_remote_addr") or ""
        if len(details) > 60:
            details = details[:60] + "..."

        table.add_row(
            e.get("timestamp", "")[:19],
            f"[{sev_colors.get(sev, 'white')}]{sev_names.get(sev, '?')}[/]",
            e.get("agent_type", "-"),
            e.get("action", ""),
            e.get("tool_name", "-"),
            details,
        )

    console.print(table)


@main.command(name="setup")
@click.argument("agent", type=click.Choice(["claude-code"]))
def setup_agent(agent):
    """Configure EDR hooks for an AI agent."""
    if agent == "claude-code":
        _setup_claude_code()


def _setup_claude_code():
    """Install Claude Code hooks for EDR monitoring."""
    settings_path = Path.home() / ".claude" / "settings.json"

    # Read existing settings
    if settings_path.exists():
        with open(settings_path) as f:
            settings = json.load(f)
    else:
        settings = {}

    # Hook script path
    hook_script = Path(__file__).parent.parent.parent / "hooks" / "claude_code_hook.py"
    if not hook_script.exists():
        # Try installed location
        hook_script = Path(sys.prefix) / "hooks" / "claude_code_hook.py"

    hook_cmd = f"python3 {hook_script}"

    # Add hooks
    hooks = settings.get("hooks", {})

    for event_type in ["PreToolUse", "PostToolUse", "SessionStart", "SessionEnd"]:
        matcher = ".*" if event_type.startswith("Pre") or event_type.startswith("Post") else ""
        is_async = event_type == "PostToolUse"

        existing = hooks.get(event_type, [])
        # Check if our hook is already installed
        already_installed = any(
            any("claude_code_hook" in h.get("command", "") for h in group.get("hooks", []))
            for group in existing
        )

        if not already_installed:
            existing.append({
                "matcher": matcher,
                "hooks": [{"type": "command", "command": hook_cmd, "async": is_async}],
            })
            hooks[event_type] = existing

    settings["hooks"] = hooks

    # Write settings
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)

    console.print("[bold green]Claude Code hooks installed![/bold green]")
    console.print(f"  Settings: {settings_path}")
    console.print(f"  Hook script: {hook_script}")
    console.print()
    console.print("Events from PreToolUse, PostToolUse, SessionStart, SessionEnd")
    console.print("will now be sent to the EDR daemon.")
    console.print()
    console.print("[yellow]Restart Claude Code for hooks to take effect.[/yellow]")


@main.command()
def dashboard():
    """Open the dashboard in a browser."""
    import webbrowser
    cfg = Config.load()
    url = f"http://{cfg.dashboard.host}:{cfg.dashboard.port}"
    webbrowser.open(url)
    console.print(f"Opening {url}")


if __name__ == "__main__":
    main()
