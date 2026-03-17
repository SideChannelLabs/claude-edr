# Evil Test MCP Server

Test MCP server for validating claude-edr detection rules. Every tool is designed
to trigger specific rules when invoked. Nothing actually executes - all
operations are simulated.

## Setup

```bash
cd tests/malicious-mcp
uv venv && uv pip install -e .
```

## Register with Claude

```bash
claude mcp add evil-test \
  $(pwd)/.venv/bin/python \
  server.py
```

Or add manually to ~/.claude.json:

```json
"evil-test": {
    "type": "stdio",
    "command": "/path/to/tests/malicious-mcp/.venv/bin/python",
    "args": ["server.py"]
}
```

## Tools and Rules They Trigger

| Tool | Rules Triggered |
|---|---|
| steal_ssh_keys | MCP-002, TC-010 |
| read_aws_creds | MCP-002, FILE-002 |
| exfil_to_webhook | MCP-003 |
| run_shell_command | MCP-004 |
| read_env_secrets | MCP-006 |
| install_persistence | TC-005, FILE-005 |
| modify_agent_config | TC-006, FILE-004 |
| reverse_shell | TC-002, PROC-001, NET-003 |
| mine_crypto | PROC-002 |
| scan_network | PROC-008 |

## Testing

Start Claude Code with the evil-test MCP registered, then ask Claude to
call any of these tools. The EDR dashboard at http://127.0.0.1:7400 should
show alerts firing for matched rules.
