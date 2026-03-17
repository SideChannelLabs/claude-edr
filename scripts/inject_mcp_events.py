#!/usr/bin/env python3
"""Inject MCP tool call events and trigger some alerts."""

import json
import socket
import time
import uuid

SOCKET_PATH = "/run/claude-edr/edr.sock"
SESSION_ID = str(uuid.uuid4())


def send_event(payload: dict) -> dict | None:
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect(SOCKET_PATH)
        sock.sendall(json.dumps(payload).encode("utf-8"))
        sock.shutdown(socket.SHUT_WR)
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        if data:
            return json.loads(data.decode("utf-8"))
    except Exception as e:
        print(f"  Error: {e}")
    return None


def evt(hook_type, tool_name="", tool_input=None, tool_response=None):
    return {
        "hook_event_name": hook_type,
        "tool_name": tool_name,
        "tool_input": tool_input or {},
        "tool_response": tool_response,
        "session_id": SESSION_ID,
        "cwd": "/home/user/projects/example",
    }


EVENTS = [
    ("SessionStart", "", {}, None),

    # MCP memory-service calls
    ("PreToolUse", "mcp__memory_service__store_memory", {"content": "EDR project architecture notes", "metadata": {"tags": ["edr", "architecture"]}}, None),
    ("PostToolUse", "mcp__memory_service__store_memory", {}, "Memory stored successfully"),

    ("PreToolUse", "mcp__memory_service__retrieve_memory", {"query": "claude-edr dashboard design"}, None),
    ("PostToolUse", "mcp__memory_service__retrieve_memory", {}, "Found 3 relevant memories"),

    ("PreToolUse", "mcp__memory_service__search_by_tag", {"tags": ["edr"]}, None),
    ("PostToolUse", "mcp__memory_service__search_by_tag", {}, "2 results"),

    # MCP analytics calls
    ("PreToolUse", "mcp__analytics__run_report", {"property_id": "properties/123456", "dimensions": ["date"], "metrics": ["sessions"]}, None),
    ("PostToolUse", "mcp__analytics__run_report", {}, "Report: 1,234 sessions"),

    ("PreToolUse", "mcp__analytics__get_account_summaries", {}, None),
    ("PostToolUse", "mcp__analytics__get_account_summaries", {}, "3 accounts found"),

    # MCP atlassian calls
    ("PreToolUse", "mcp__atlassian__search_issues", {"query": "project = EDR AND status = Open"}, None),
    ("PostToolUse", "mcp__atlassian__search_issues", {}, "Found 7 issues"),

    ("PreToolUse", "mcp__atlassian__get_issue", {"issue_key": "EDR-42"}, None),
    ("PostToolUse", "mcp__atlassian__get_issue", {}, "EDR-42: Add eBPF sensor support"),

    # Suspicious: MCP memory deleting memories (should look concerning)
    ("PreToolUse", "mcp__memory_service__delete_by_tag", {"tags": ["credentials", "secrets"]}, None),
    ("PostToolUse", "mcp__memory_service__delete_by_tag", {}, "Deleted 5 memories"),

    # More normal MCP calls
    ("PreToolUse", "mcp__memory_service__recall_memory", {"query": "AWS account IDs"}, None),
    ("PostToolUse", "mcp__memory_service__recall_memory", {}, "Found: example-account 123456789012"),

    ("PreToolUse", "mcp__analytics__run_realtime_report", {"property_id": "properties/123456"}, None),
    ("PostToolUse", "mcp__analytics__run_realtime_report", {}, "12 active users"),

    # Bash that reads sensitive data THEN stores in MCP (exfil pattern)
    ("PreToolUse", "Bash", {"command": "cat /etc/shadow"}, None),
    ("PostToolUse", "Bash", {"command": "cat /etc/shadow"}, "[redacted]"),

    ("PreToolUse", "mcp__memory_service__store_memory", {"content": "system password hashes from shadow file", "metadata": {"tags": ["credentials"]}}, None),
    ("PostToolUse", "mcp__memory_service__store_memory", {}, "Memory stored"),

    # Normal wrap-up
    ("PreToolUse", "mcp__memory_service__retrieve_memory", {"query": "project status update"}, None),
    ("PostToolUse", "mcp__memory_service__retrieve_memory", {}, "Found 1 memory"),

    ("SessionEnd", "", {}, None),
]


def main():
    print(f"Injecting MCP events into {SOCKET_PATH}")
    print(f"Session ID: {SESSION_ID[:12]}...")
    print()

    for i, (hook_type, tool_name, tool_input, tool_response) in enumerate(EVENTS, 1):
        payload = evt(hook_type, tool_name, tool_input, tool_response)
        label = tool_name or hook_type
        resp = send_event(payload)
        status = "OK"
        if resp and resp.get("decision") == "block":
            status = f"BLOCKED"
        print(f"  [{i:02d}/{len(EVENTS)}] {label} ... {status}")
        time.sleep(0.1)

    print(f"\nDone! View at http://localhost:7400")


if __name__ == "__main__":
    main()
