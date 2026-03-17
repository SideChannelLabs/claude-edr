"""FastAPI dashboard server for Claude EDR."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from claude_edr.backend.models.events import EDREvent
from claude_edr.backend.pipeline.router import EventPipeline
from claude_edr.backend.registry.agent_registry import AgentRegistry
from claude_edr.backend.storage.sqlite_store import EventStore

logger = logging.getLogger(__name__)

def _resolve_webapp_dirs() -> tuple[Path, Path]:
    """Find templates/static dirs from the monolith dashboard package."""
    # Monolith layout: dashboard is a sibling package under claude_edr
    dashboard_root = Path(__file__).resolve().parent.parent.parent / "dashboard"
    dashboard_templates = dashboard_root / "templates"
    dashboard_static = dashboard_root / "static"
    if dashboard_templates.is_dir() and dashboard_static.is_dir():
        return dashboard_templates, dashboard_static

    # Local fallback (if templates exist alongside api/)
    local_templates = Path(__file__).parent / "templates"
    local_static = Path(__file__).parent / "static"
    if local_templates.is_dir() and local_static.is_dir():
        return local_templates, local_static

    # Fallback: check CLAUDE_EDR_WEBAPP_DIR env var
    import os
    env_dir = os.environ.get("CLAUDE_EDR_WEBAPP_DIR")
    if env_dir:
        env_path = Path(env_dir)
        if (env_path / "templates").is_dir():
            return env_path / "templates", env_path / "static"

    # Last resort: return local paths (will fail at runtime with clear error)
    return local_templates, local_static


TEMPLATES_DIR, STATIC_DIR = _resolve_webapp_dirs()

app = FastAPI(title="Claude EDR", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# These get set by the daemon at startup
_store: EventStore | None = None
_registry: AgentRegistry | None = None
_pipeline: EventPipeline | None = None
_detection_engine = None
_rules_dir: Path | None = None

# In-memory inventory cache (updated by daemon or sensor pushes)
_inventory_cache: list[dict] = []


def get_inventory_cache() -> list[dict]:
    """Get cached inventory for dashboard pages."""
    return _inventory_cache


def discover_all_agents():
    """Get agent inventory - from sensor package (local) or cache (enterprise)."""
    try:
        from claude_edr.sensor.inventory.agent_inventory import discover_all_agents as _discover
        return _discover()
    except ImportError:
        # Enterprise mode: sensor not installed locally, use cache
        return _inventory_cache


def collect_endpoint_info():
    """Get endpoint info - from sensor package (local) or empty dict (enterprise)."""
    try:
        from claude_edr.sensor.inventory.endpoint import collect_endpoint_info as _collect
        return _collect()
    except ImportError:

        class _FakeEndpoint:
            def to_dict(self):
                return {"hostname": "unknown", "endpoint_id": "unknown"}

        return _FakeEndpoint()


def configure(store: EventStore, registry: AgentRegistry, pipeline: EventPipeline, detection_engine, rules_dir: Path | None = None) -> None:
    """Wire up shared state from the daemon."""
    global _store, _registry, _pipeline, _detection_engine, _rules_dir
    _store = store
    _registry = registry
    _pipeline = pipeline
    _detection_engine = detection_engine
    _rules_dir = rules_dir


# =========================================================================
# LEVEL 1: Fleet View - All Endpoints
# =========================================================================

@app.get("/", response_class=HTMLResponse)
async def fleet_page(request: Request):
    """Top-level fleet view: all endpoints with the sensor installed."""
    assert _store and _registry
    endpoints = await _store.get_all_endpoints()
    fleet_stats = await _store.get_endpoint_stats()

    # Enrich each endpoint with live session/alert counts
    for ep in endpoints:
        ep_sessions = [s for s in _registry.get_active_sessions()]
        ep["active_sessions"] = len(ep_sessions)
        ep["total_alerts"] = fleet_stats["open_alerts"]

    return templates.TemplateResponse("fleet.html", {
        "request": request,
        "endpoints": endpoints,
        "stats": fleet_stats,
        "page": "endpoints",
    })


# =========================================================================
# LEVEL 2: Endpoint Detail (agents, sessions on this machine)
# =========================================================================

@app.get("/endpoint/{endpoint_id}", response_class=HTMLResponse)
async def endpoint_detail_page(request: Request, endpoint_id: str):
    """Drill into a specific endpoint: see agents, sessions, events."""
    assert _store and _registry
    endpoint = await _store.get_endpoint(endpoint_id)
    if not endpoint:
        endpoint = collect_endpoint_info().to_dict()

    agents_inventory = discover_all_agents()
    active_sessions = _registry.get_active_sessions()
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    counts = await _store.get_event_counts(since=since)

    # Get events for MCP correlation (query mcp_activity separately to avoid
    # MCP events being pushed out by the flood of LLM/file/process events)
    since_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    all_mcp_events = await _store.query_events(
        category="mcp_activity", since=since_24h, limit=500,
    )
    all_events = await _store.query_events(since=since_24h, limit=1000)
    event_by_id = {e.get("id", ""): e for e in all_events}

    # Pre-compute alert counts per MCP and per hook for each agent
    agents_dicts = []
    for a in agents_inventory:
        ad = a.to_dict()

        # Attach event_count and alert_count to each MCP using SQL JOIN
        agent_mcp_events = [e for e in all_mcp_events if e.get("agent_type") == ad["agent_type"]
                            or e.get("category") == "mcp_activity"]
        for mcp in ad.get("mcp_servers", []):
            base_name = mcp["name"].split(" (")[0]
            prefix = f"mcp__{base_name.replace('-', '_')}__"
            def _matches_mcp(tool: str, cat: str = "") -> bool:
                if not tool:
                    return False
                return (tool.startswith(prefix)
                        or tool == base_name
                        or tool == f"mcp-{base_name}"
                        or (cat == "mcp_activity" and base_name.replace("-", "_") in tool.replace("-", "_")))
            mcp["event_count"] = sum(
                1 for e in agent_mcp_events
                if _matches_mcp(e.get("tool_name") or "", e.get("category") or "")
            )
            mcp_alerts = await _store.query_alerts_by_tool_prefix(
                tool_prefix=prefix, agent_type=ad["agent_type"], limit=200
            )
            mcp["alert_count"] = len(mcp_alerts)

        # Get alerts for hook correlation and total agent alert count
        alerts = await _store.query_alerts(limit=200)
        agent_alerts = [al for al in alerts if al.get("agent_type") == ad["agent_type"]]

        # Attach alert_count to each hook
        for i, hook in enumerate(ad.get("hooks", [])):
            matcher = hook.get("matcher", "")
            event_type = hook.get("event_type", "")
            count = 0
            for al in agent_alerts:
                try:
                    eids = json.loads(al.get("event_ids_json") or "[]")
                except (json.JSONDecodeError, TypeError):
                    eids = []
                for eid in eids:
                    ev = event_by_id.get(eid, {})
                    action = ev.get("action", "")
                    tool = ev.get("tool_name", "") or ""
                    if event_type == "PreToolUse" and action == "tool_invoke":
                        if not matcher or matcher == "*" or tool in matcher.split("|"):
                            count += 1
                    elif event_type == "PostToolUse" and action == "tool_complete":
                        if not matcher or matcher == "*" or tool in matcher.split("|"):
                            count += 1
            hook["alert_count"] = count

        # Total alerts for this agent
        ad["alert_count"] = len(agent_alerts)
        agents_dicts.append(ad)

    return templates.TemplateResponse("endpoint_detail.html", {
        "request": request,
        "endpoint": endpoint,
        "agents_inventory": agents_dicts,
        "active_sessions": [s.to_dict() for s in active_sessions],
        "counts": counts,
        "page": "endpoints",
    })


# =========================================================================
# LEVEL 3: Agent Detail (MCPs, Hooks, Extensions, Config)
# =========================================================================

@app.get("/agent/{agent_type}", response_class=HTMLResponse)
async def agent_detail_page(request: Request, agent_type: str):
    """Drill-down: specific agent's config, MCPs, hooks — all expandable inline."""
    assert _store and _registry
    agents_inventory = discover_all_agents()
    agent_inv = next((a for a in agents_inventory if a.agent_type == agent_type), None)

    sessions = [s for s in _registry.get_all_sessions() if s.agent_type.value == agent_type]

    since = datetime.now(timezone.utc) - timedelta(hours=24)
    # Fetch MCP events separately so they don't get pushed out by the
    # flood of file/process/network events in the 500-event window
    all_mcp_events = await _store.query_events(
        agent_type=agent_type, category="mcp_activity", since=since, limit=500,
    )
    all_events = all_mcp_events
    agent_dict = agent_inv.to_dict() if agent_inv else {"agent_type": agent_type, "installed": False, "mcp_servers": [], "hooks": [], "extensions": []}

    # Pre-compute activity + alerts per MCP using SQL JOIN for accurate counts
    # (the old approach with query_alerts(limit=20) missed alerts buried in the window)
    for mcp in agent_dict.get("mcp_servers", []):
        base_name = mcp["name"].split(" (")[0]
        prefix = f"mcp__{base_name.replace('-', '_')}__"
        def _match(tool: str, cat: str = "") -> bool:
            if not tool:
                return False
            return (tool.startswith(prefix)
                    or tool == base_name
                    or tool == f"mcp-{base_name}"
                    or (cat == "mcp_activity" and base_name.replace("-", "_") in tool.replace("-", "_")))
        mcp["events"] = [e for e in all_events if _match(e.get("tool_name") or "", e.get("category") or "")]
        mcp["event_count"] = len(mcp["events"])
        mcp_alerts = await _store.query_alerts_by_tool_prefix(
            tool_prefix=prefix, agent_type=agent_type, limit=200
        )
        mcp["alert_count"] = len(mcp_alerts)

    # Fetch alerts for hook correlation and template display
    all_alerts = await _store.query_alerts(min_severity=0, limit=200)
    agent_alerts = [a for a in all_alerts if a.get("agent_type") == agent_type]
    event_by_id = {e.get("id", ""): e for e in all_events}

    # Pre-compute matched events + alerts per hook
    for i, hook in enumerate(agent_dict.get("hooks", [])):
        matcher = hook.get("matcher", "")
        event_type = hook.get("event_type", "")
        matched = []
        for e in all_events:
            action = e.get("action", "")
            tool = e.get("tool_name", "") or ""
            if event_type == "PreToolUse" and action == "tool_invoke":
                if not matcher or matcher == "*" or tool in matcher.split("|"):
                    matched.append(e)
            elif event_type == "PostToolUse" and action == "tool_complete":
                if not matcher or matcher == "*" or tool in matcher.split("|"):
                    matched.append(e)
            elif event_type == "UserPromptSubmit" and action in ("session_start", "tool_invoke"):
                matched.append(e)
            elif event_type == "Stop" and action in ("session_end", "tool_complete"):
                matched.append(e)
        hook["events"] = matched[:20]
        hook["event_count"] = len(matched)
        hook["alert_count"] = 0
        for al in agent_alerts:
            try:
                eids = json.loads(al.get("event_ids_json") or "[]")
            except (json.JSONDecodeError, TypeError):
                eids = []
            for eid in eids:
                ev = event_by_id.get(eid, {})
                a = ev.get("action", "")
                t = ev.get("tool_name", "") or ""
                if event_type == "PreToolUse" and a == "tool_invoke" and (not matcher or matcher == "*" or t in matcher.split("|")):
                    hook["alert_count"] += 1; break
                elif event_type == "PostToolUse" and a == "tool_complete" and (not matcher or matcher == "*" or t in matcher.split("|")):
                    hook["alert_count"] += 1; break

    # Get endpoint for breadcrumb navigation
    endpoints = await _store.get_all_endpoints()
    endpoint = endpoints[0] if endpoints else collect_endpoint_info().to_dict()

    return templates.TemplateResponse("agent_detail.html", {
        "request": request,
        "agent": agent_dict,
        "sessions": [s.to_dict() for s in sessions],
        "events": all_events[:50],
        "alerts": agent_alerts,
        "endpoint": endpoint,
        "page": "agents",
    })


# =========================================================================
# LEVEL 4: MCP Detail (config + activity)
# =========================================================================

@app.get("/agent/{agent_type}/mcp/{mcp_name:path}", response_class=HTMLResponse)
async def mcp_detail_page(request: Request, agent_type: str, mcp_name: str):
    """Drill into a specific MCP server: config + related tool activity."""
    assert _store and _registry
    agents_inventory = discover_all_agents()
    agent_inv = next((a for a in agents_inventory if a.agent_type == agent_type), None)

    mcp = None
    if agent_inv:
        mcp_dict = agent_inv.to_dict()
        mcp = next((m for m in mcp_dict.get("mcp_servers", []) if m["name"] == mcp_name), None)

    # Find events related to this MCP
    # MCP tools follow the pattern mcp__{server_name}__{tool_name}
    # Also match bare server names (from eBPF sensor)
    base_mcp_name = mcp_name.split(" (")[0]
    mcp_tool_prefix = f"mcp__{base_mcp_name.replace('-', '_')}__"

    def _mcp_match(tool: str, cat: str = "") -> bool:
        if not tool:
            return False
        return (tool.startswith(mcp_tool_prefix)
                or tool == base_mcp_name
                or tool == f"mcp-{base_mcp_name}"
                or (cat == "mcp_activity" and base_mcp_name.replace("-", "_") in tool.replace("-", "_")))

    since = datetime.now(timezone.utc) - timedelta(hours=24)
    # Query MCP events directly instead of fetching all categories.
    # The old limit=500 across all categories meant MCP events got pushed
    # out by the flood of file/process/network events.
    all_mcp_events = await _store.query_events(
        agent_type=agent_type, category="mcp_activity", since=since, limit=500,
    )
    mcp_events = [e for e in all_mcp_events if _mcp_match(e.get("tool_name") or "", e.get("category") or "")]

    # Find alerts related to this MCP's tools using SQL JOIN
    # (the old approach with query_alerts(limit=200) + event_by_id missed alerts
    # when MCP alerts were buried beyond the 200-alert window by LLM/NET alerts)
    mcp_alerts = await _store.query_alerts_by_tool_prefix(
        tool_prefix=mcp_tool_prefix, agent_type=agent_type, limit=200
    )

    # Get endpoint for breadcrumb navigation
    endpoints = await _store.get_all_endpoints()
    endpoint = endpoints[0] if endpoints else collect_endpoint_info().to_dict()

    return templates.TemplateResponse("mcp_detail.html", {
        "request": request,
        "agent_type": agent_type,
        "mcp": mcp or {"name": mcp_name},
        "events": mcp_events,
        "alerts": mcp_alerts,
        "endpoint": endpoint,
        "page": "agents",
    })


# =========================================================================
# LEVEL 4: Hook Detail (config + triggered events)
# =========================================================================

@app.get("/agent/{agent_type}/hook/{hook_index}", response_class=HTMLResponse)
async def hook_detail_page(request: Request, agent_type: str, hook_index: int):
    """Drill into a specific hook: config + events it would have triggered."""
    assert _store and _registry
    agents_inventory = discover_all_agents()
    agent_inv = next((a for a in agents_inventory if a.agent_type == agent_type), None)

    hook = None
    if agent_inv:
        hooks_list = agent_inv.to_dict().get("hooks", [])
        if 0 <= hook_index < len(hooks_list):
            hook = hooks_list[hook_index]

    # Find events matching this hook's event_type and matcher
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    all_events = await _store.query_events(agent_type=agent_type, since=since, limit=500)

    hook_events = []
    if hook:
        matcher = hook.get("matcher", "")
        event_type = hook.get("event_type", "")
        for e in all_events:
            action = e.get("action", "")
            tool = e.get("tool_name", "") or ""
            # PreToolUse hooks fire on tool_invoke, PostToolUse on tool_complete
            if event_type == "PreToolUse" and action == "tool_invoke":
                if not matcher or matcher == "*" or tool in matcher.split("|"):
                    hook_events.append(e)
            elif event_type == "PostToolUse" and action == "tool_complete":
                if not matcher or matcher == "*" or tool in matcher.split("|"):
                    hook_events.append(e)
            elif event_type == "UserPromptSubmit" and action == "session_start":
                hook_events.append(e)
            elif event_type == "Stop" and action == "session_end":
                hook_events.append(e)

    # Find alerts matching this hook's criteria
    all_alerts = await _store.query_alerts(limit=200)
    event_by_id = {e.get("id", ""): e for e in all_events}
    hook_alerts = []
    if hook:
        matcher = hook.get("matcher", "")
        event_type = hook.get("event_type", "")
        for al in all_alerts:
            if al.get("agent_type") != agent_type:
                continue
            try:
                eids = json.loads(al.get("event_ids_json") or "[]")
            except (json.JSONDecodeError, TypeError):
                eids = []
            for eid in eids:
                ev = event_by_id.get(eid, {})
                action = ev.get("action", "")
                tool = ev.get("tool_name", "") or ""
                matched = False
                if event_type == "PreToolUse" and action == "tool_invoke":
                    if not matcher or matcher == "*" or tool in matcher.split("|"):
                        matched = True
                elif event_type == "PostToolUse" and action == "tool_complete":
                    if not matcher or matcher == "*" or tool in matcher.split("|"):
                        matched = True
                elif event_type == "UserPromptSubmit" and action == "session_start":
                    matched = True
                elif event_type == "Stop" and action == "session_end":
                    matched = True
                if matched:
                    hook_alerts.append(al)
                    break

    # Get endpoint for breadcrumb navigation
    endpoints = await _store.get_all_endpoints()
    endpoint = endpoints[0] if endpoints else collect_endpoint_info().to_dict()

    return templates.TemplateResponse("hook_detail.html", {
        "request": request,
        "agent_type": agent_type,
        "hook": hook or {"event_type": "unknown", "matcher": "", "command": ""},
        "hook_index": hook_index,
        "events": hook_events,
        "alerts": hook_alerts,
        "endpoint": endpoint,
        "page": "agents",
    })


# =========================================================================
# LEVEL 3/4: Session Activity (LLM calls, tool calls, files, network)
# =========================================================================

@app.get("/session/{session_id}", response_class=HTMLResponse)
async def session_detail_page(request: Request, session_id: str):
    """Deepest drill-down: full activity for a specific agent session."""
    assert _store and _registry
    session = _registry.get_session(session_id)

    # Get all events for this session
    events = await _store.query_events(session_id=session_id, limit=500)

    # Categorize events
    tool_calls = [e for e in events if e.get("category") == "tool_call" or e.get("tool_name")]
    file_events = [e for e in events if e.get("category") == "file_activity"]
    network_events = [e for e in events if e.get("category") == "network_activity"]
    process_events = [e for e in events if e.get("category") == "process_activity"]
    llm_events = [e for e in events if e.get("category") == "llm_request"]

    alerts = await _store.query_alerts(limit=50)
    session_alerts = [a for a in alerts if a.get("agent_session_id") == session_id]

    return templates.TemplateResponse("session_detail.html", {
        "request": request,
        "session": session.to_dict() if session else {"session_id": session_id},
        "events": events,
        "tool_calls": tool_calls,
        "file_events": file_events,
        "network_events": network_events,
        "process_events": process_events,
        "llm_events": llm_events,
        "alerts": session_alerts,
        "page": "session",
    })


# =========================================================================
# Legacy pages (kept for navigation)
# =========================================================================

@app.get("/timeline", response_class=HTMLResponse)
async def timeline_page(request: Request):
    """Live event timeline."""
    assert _store and _registry
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    counts = await _store.get_event_counts(since=since)
    agents = _registry.get_active_sessions()
    return templates.TemplateResponse("timeline.html", {
        "request": request,
        "counts": counts,
        "agents": [a.to_dict() for a in agents],
        "page": "timeline",
    })


@app.get("/llm-traffic", response_class=HTMLResponse)
async def llm_traffic_page(request: Request, hours: int = 6):
    """LLM API traffic page - shows SSL-intercepted LLM requests/responses."""
    assert _store
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    events = await _store.query_events(category="llm_request", since=since, limit=500)

    # Compute stats
    providers = set()
    models = set()
    total_calls = 0
    total_responses = 0
    credential_exposures = 0
    for e in events:
        if e.get("llm_provider"):
            providers.add(e["llm_provider"])
        if e.get("llm_model"):
            models.add(e["llm_model"])
        if e.get("action") == "llm_call":
            total_calls += 1
        elif e.get("action") == "llm_response":
            total_responses += 1
        if e.get("llm_contains_credentials"):
            credential_exposures += 1

    stats = {
        "total_calls": total_calls,
        "total_responses": total_responses,
        "providers": sorted(providers),
        "models": sorted(models),
        "credential_exposures": credential_exposures,
    }

    return templates.TemplateResponse("llm_traffic.html", {
        "request": request,
        "events": events,
        "stats": stats,
        "page": "llm_traffic",
    })


@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    """Alerts page."""
    assert _store
    alerts = await _store.query_alerts(limit=100)
    return templates.TemplateResponse("alerts.html", {
        "request": request,
        "alerts": alerts,
        "page": "alerts",
    })


# =========================================================================
# Rules Management Pages
# =========================================================================

@app.get("/rules", response_class=HTMLResponse)
async def rules_list_page(request: Request):
    """List all detection rules."""
    rules = _detection_engine.get_rules() if _detection_engine else []
    return templates.TemplateResponse("rules_list.html", {
        "request": request,
        "rules": rules,
        "page": "rules",
    })


@app.get("/rules/{rule_id}", response_class=HTMLResponse)
async def rule_detail_page(request: Request, rule_id: str):
    """View/edit a detection rule."""
    assert _store and _detection_engine
    rules = _detection_engine.get_rules()
    rule = next((r for r in rules if r["id"] == rule_id), None)

    # Get alerts fired by this rule
    all_alerts = await _store.query_alerts(limit=200)
    rule_alerts = [a for a in all_alerts if a.get("rule_id") == rule_id]

    return templates.TemplateResponse("rule_detail.html", {
        "request": request,
        "rule": rule or {"id": rule_id, "name": "Unknown", "conditions": [], "tags": [], "severity": "INFO", "enabled": False},
        "alerts": rule_alerts,
        "page": "rules",
    })


# =========================================================================
# Rules CRUD API
# =========================================================================

@app.get("/api/rules")
async def api_rules_list():
    """Get detection rules."""
    if _detection_engine:
        return {"rules": _detection_engine.get_rules()}
    return {"rules": []}


@app.post("/api/rules")
async def api_create_rule(request: Request):
    """Create a new custom detection rule."""
    assert _detection_engine
    body = await request.json()

    if _detection_engine.get_rule(body.get("id", "")):
        return {"ok": False, "error": f"Rule '{body['id']}' already exists"}

    try:
        _detection_engine.add_rule(body)
        if _rules_dir:
            _detection_engine.save_custom_rules(_rules_dir)
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.put("/api/rules/{rule_id}")
async def api_update_rule(rule_id: str, request: Request):
    """Update an existing detection rule."""
    assert _detection_engine
    body = await request.json()

    rule = _detection_engine.update_rule(rule_id, body)
    if not rule:
        return {"ok": False, "error": "Rule not found"}

    if _rules_dir:
        _detection_engine.save_custom_rules(_rules_dir)
    return {"ok": True}


@app.delete("/api/rules/{rule_id}")
async def api_delete_rule(rule_id: str):
    """Delete a custom detection rule."""
    assert _detection_engine
    if _detection_engine.delete_rule(rule_id):
        if _rules_dir:
            _detection_engine.save_custom_rules(_rules_dir)
        return {"ok": True}
    return {"ok": False, "error": "Rule not found or is a default rule (cannot delete)"}


@app.post("/api/rules/{rule_id}/toggle")
async def api_toggle_rule(rule_id: str, request: Request):
    """Enable or disable a detection rule."""
    assert _detection_engine
    body = await request.json()
    if _detection_engine.toggle_rule(rule_id, body.get("enabled", True)):
        return {"ok": True}
    return {"ok": False, "error": "Rule not found"}


@app.post("/api/rules/{rule_id}/test")
async def api_test_rule(rule_id: str, request: Request):
    """Test a rule against recent events to see what it would match."""
    assert _store and _detection_engine
    body = await request.json()

    from claude_edr.backend.detection.engine import DetectionRule
    from claude_edr.backend.models.events import Severity as _Sev

    severity_val = body.get("severity", "MEDIUM")
    severity = _Sev[severity_val.upper()] if isinstance(severity_val, str) else _Sev(severity_val)

    temp_rule = DetectionRule(
        id="test",
        name="test",
        severity=severity,
        conditions=body.get("conditions", []),
    )

    since = datetime.now(timezone.utc) - timedelta(hours=24)
    events = await _store.query_events(since=since, limit=500)

    matches = []
    for e in events:
        class _EventProxy:
            pass

        proxy = _EventProxy()
        proxy.action = e.get("action", "")
        proxy.category = e.get("category", "")

        if e.get("file_path"):
            proxy.file = _EventProxy()
            proxy.file.path = e["file_path"]
        else:
            proxy.file = None

        if e.get("process_cmdline"):
            proxy.process = _EventProxy()
            proxy.process.cmdline = e["process_cmdline"]
        else:
            proxy.process = None

        proxy.agent = _EventProxy()
        proxy.agent.tool_name = e.get("tool_name", "")
        proxy.agent.agent_type = e.get("agent_type", "")

        proxy.network = _EventProxy()
        proxy.network.remote_addr = e.get("remote_addr", "")
        proxy.network.domain = e.get("domain", "")

        if temp_rule.evaluate(proxy):
            matches.append(e)

    return {"matches": matches[:50], "total": len(matches)}


# =========================================================================
# API Endpoints
# =========================================================================

@app.get("/api/endpoint")
async def api_endpoint():
    """Get local endpoint info."""
    return collect_endpoint_info().to_dict()


@app.get("/api/endpoints")
async def api_endpoints():
    """Get all registered endpoints."""
    assert _store
    endpoints = await _store.get_all_endpoints()
    return {"endpoints": endpoints, "count": len(endpoints)}


@app.get("/api/inventory")
async def api_inventory():
    """Get full agent inventory."""
    agents = discover_all_agents()
    return {"agents": [a.to_dict() for a in agents]}


@app.get("/api/events")
async def api_events(
    category: str | None = None,
    action: str | None = None,
    agent_type: str | None = None,
    session_id: str | None = None,
    min_severity: int = 0,
    tool_name: str | None = None,
    hours: int = 1,
    limit: int = 100,
):
    """Query events."""
    assert _store
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    events = await _store.query_events(
        category=category, action=action, agent_type=agent_type,
        session_id=session_id, min_severity=min_severity,
        tool_name=tool_name, since=since, limit=limit,
    )
    return {"events": events, "count": len(events)}


@app.get("/api/agents")
async def api_agents():
    """Get all tracked agent sessions."""
    assert _registry
    return {"agents": [a.to_dict() for a in _registry.get_all_sessions()]}


@app.get("/api/alerts")
async def api_alerts(status: str | None = None, min_severity: int = 0):
    """Query alerts."""
    assert _store
    alerts = await _store.query_alerts(status=status, min_severity=min_severity)
    return {"alerts": alerts, "count": len(alerts)}


@app.post("/api/alerts/{alert_id}/status")
async def update_alert(alert_id: str, request: Request):
    """Update alert status."""
    assert _store
    body = await request.json()
    await _store.update_alert_status(alert_id, body["status"])
    return {"ok": True}


@app.get("/api/stats")
async def api_stats(hours: int = 1):
    """Dashboard stats."""
    assert _store and _pipeline
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    counts = await _store.get_event_counts(since=since)
    counts["events_processed"] = _pipeline.events_processed
    return counts



# =========================================================================
# Sensor Receiver Endpoints (sensor pushes data to backend)
# =========================================================================

@app.post("/api/sensor/endpoint")
async def sensor_register_endpoint(request: Request):
    """Receive endpoint info from sensor and register it."""
    assert _store
    body = await request.json()
    await _store.register_endpoint(
        endpoint_id=body.get("endpoint_id", ""),
        hostname=body.get("hostname", ""),
        os_name=body.get("os_name", ""),
        os_version=body.get("os_version", ""),
        kernel=body.get("kernel", ""),
        arch=body.get("arch", ""),
        ip_addresses=body.get("ip_addresses", []),
        username=body.get("username", ""),
        cpu_count=body.get("cpu_count", 0),
        memory_total_gb=body.get("memory_total_gb", 0.0),
        agent_count=body.get("agent_count", 0),
    )
    logger.info("Sensor registered endpoint: %s", body.get("hostname", "unknown"))
    return {"ok": True}


@app.post("/api/sensor/inventory")
async def sensor_inventory(request: Request):
    """Receive agent inventory snapshot from sensor."""
    global _inventory_cache
    body = await request.json()
    _inventory_cache = body.get("agents", [])
    logger.info(
        "Sensor inventory update: %d agents",
        len(_inventory_cache),
    )
    return {"ok": True, "agents_received": len(_inventory_cache)}


@app.post("/api/sensor/events")
async def sensor_events(request: Request):
    """Receive batched events from sensor and feed into pipeline."""
    assert _pipeline
    body = await request.json()
    events = body.get("events", [])
    count = 0
    for event_dict in events:
        try:
            event = EDREvent(
                category=event_dict.get("category", "tool_call"),
                action=event_dict.get("action", "tool_invoke"),
                severity=event_dict.get("severity", 0),
            )
            # Feed into pipeline as dict (pipeline handles dict events too)
            await _pipeline.process_event_dict(event_dict)
            count += 1
        except Exception:
            logger.warning("Failed to process sensor event: %s", event_dict.get("action"))
    return {"ok": True, "events_processed": count}


# --- HTMX Partials ---

@app.get("/htmx/events")
async def htmx_events(request: Request, hours: int = 1, limit: int = 50):
    assert _store
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    events = await _store.query_events(since=since, limit=limit)
    return templates.TemplateResponse("partials/event_rows.html", {"request": request, "events": events})


@app.get("/htmx/stats")
async def htmx_stats(request: Request):
    assert _store and _registry and _pipeline
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    counts = await _store.get_event_counts(since=since)
    agents = _registry.get_active_sessions()
    return templates.TemplateResponse("partials/stats_cards.html", {
        "request": request, "counts": counts,
        "active_agents": len(agents), "events_processed": _pipeline.events_processed,
    })


# --- WebSocket ---

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    assert _pipeline
    await websocket.accept()
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)

    def on_event(event_dict: dict):
        try:
            queue.put_nowait(event_dict)
        except asyncio.QueueFull:
            pass

    _pipeline.subscribe(on_event)
    try:
        while True:
            event_dict = await queue.get()
            await websocket.send_json(event_dict)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _pipeline.unsubscribe(on_event)
