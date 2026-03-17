"""Response actions for the EDR.

When detection rules fire, the response engine can take action:
kill processes, block operations (via hooks), quarantine files, or alert.
"""

from __future__ import annotations

import logging
import os
import signal
import shutil
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

QUARANTINE_DIR = Path.home() / ".local" / "share" / "claude-edr" / "quarantine"


class ResponseAction(str, Enum):
    ALERT_ONLY = "alert_only"
    KILL_PROCESS = "kill_process"
    BLOCK_OPERATION = "block_operation"
    QUARANTINE_FILE = "quarantine_file"
    PAUSE_AGENT = "pause_agent"


async def execute_response(action: ResponseAction, context: dict) -> dict:
    """Execute a response action. Returns result dict."""
    match action:
        case ResponseAction.ALERT_ONLY:
            return {"status": "ok", "action": "alert_only"}

        case ResponseAction.KILL_PROCESS:
            pid = context.get("pid")
            if not pid:
                return {"status": "error", "message": "No PID provided"}
            try:
                os.kill(pid, signal.SIGTERM)
                logger.warning("Killed process PID %d", pid)
                return {"status": "ok", "action": "kill_process", "pid": pid}
            except ProcessLookupError:
                return {"status": "error", "message": f"Process {pid} not found"}
            except PermissionError:
                return {"status": "error", "message": f"Permission denied to kill {pid}"}

        case ResponseAction.PAUSE_AGENT:
            pid = context.get("pid")
            if not pid:
                return {"status": "error", "message": "No PID provided"}
            try:
                os.kill(pid, signal.SIGSTOP)
                logger.warning("Paused process PID %d (SIGSTOP)", pid)
                return {"status": "ok", "action": "pause_agent", "pid": pid}
            except ProcessLookupError:
                return {"status": "error", "message": f"Process {pid} not found"}
            except PermissionError:
                return {"status": "error", "message": f"Permission denied to pause {pid}"}

        case ResponseAction.QUARANTINE_FILE:
            file_path = context.get("file_path")
            if not file_path:
                return {"status": "error", "message": "No file path provided"}
            return _quarantine_file(Path(file_path))

        case ResponseAction.BLOCK_OPERATION:
            # For Claude Code hooks: the hook script checks our decision
            # and returns exit code 2 to block. This is handled in the hook script.
            return {"status": "ok", "action": "block_operation", "message": "Block signal set"}

    return {"status": "error", "message": f"Unknown action: {action}"}


def _quarantine_file(file_path: Path) -> dict:
    """Move a file to quarantine directory."""
    if not file_path.exists():
        return {"status": "error", "message": f"File not found: {file_path}"}

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    dest = QUARANTINE_DIR / f"{file_path.name}.quarantined"

    try:
        shutil.move(str(file_path), str(dest))
        logger.warning("Quarantined file: %s -> %s", file_path, dest)
        return {"status": "ok", "action": "quarantine", "original": str(file_path), "quarantine": str(dest)}
    except Exception as e:
        return {"status": "error", "message": str(e)}
