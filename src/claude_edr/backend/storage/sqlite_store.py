"""SQLite event storage with WAL mode for concurrent reads during writes."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from claude_edr.backend.models.events import EDREvent, Severity

logger = logging.getLogger(__name__)

SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class EventStore:
    """Async SQLite event store.

    Uses WAL mode for non-blocking concurrent reads while the pipeline writes.
    """

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        """Create database and apply schema."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self.db_path), isolation_level=None)
        self._db.row_factory = aiosqlite.Row

        # PRAGMAs must run outside transactions (isolation_level=None gives autocommit)
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute("PRAGMA foreign_keys=ON")

        # Recover any leftover WAL from a previous unclean shutdown
        try:
            await self._db.execute("PRAGMA wal_checkpoint(PASSIVE)")
        except Exception:
            pass

        schema = SCHEMA_PATH.read_text()
        # Execute DDL statements (skip PRAGMAs - already handled above)
        for statement in schema.split(";"):
            statement = statement.strip()
            if statement and not statement.upper().startswith("PRAGMA"):
                await self._db.execute(statement)

        # Log how many events survived from previous run
        cursor = await self._db.execute("SELECT COUNT(*) as cnt FROM events")
        row = await cursor.fetchone()
        count = row["cnt"] if row else 0
        logger.info("Event store initialized at %s (%d existing events)", self.db_path, count)

    async def close(self) -> None:
        if self._db:
            # Checkpoint WAL into main DB so data persists across restarts
            try:
                await self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                logger.info("WAL checkpoint completed before shutdown")
            except Exception as e:
                logger.warning("WAL checkpoint failed: %s", e)
            await self._db.close()

    async def store_event(self, event: EDREvent) -> None:
        """Store a single event."""
        assert self._db is not None
        await self._db.execute(
            """INSERT INTO events (
                id, timestamp, category, action, severity,
                agent_type, agent_session_id, agent_pid, working_directory,
                tool_name, tool_input_json, tool_response_json,
                process_pid, process_ppid, process_name, process_cmdline,
                file_path, file_operation, file_size,
                net_direction, net_protocol, net_remote_addr, net_remote_port, net_domain,
                llm_provider, llm_model, llm_tokens_in, llm_tokens_out,
                llm_has_tools, llm_contains_credentials,
                risk_score, rule_matches_json, sensor_source, raw_json
            ) VALUES (
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?,
                ?, ?, ?, ?
            )""",
            (
                event.id,
                event.timestamp.isoformat(),
                event.category.value,
                event.action.value,
                event.severity.value,
                event.agent.agent_type.value if event.agent else None,
                event.agent.session_id if event.agent else None,
                event.agent.agent_pid if event.agent else None,
                event.agent.working_directory if event.agent else None,
                event.tool_name or (event.agent.tool_name if event.agent else None),
                event.tool_input_json or (json.dumps(event.agent.tool_input) if event.agent and event.agent.tool_input else None),
                event.tool_response_json or (json.dumps(event.agent.tool_response) if event.agent and event.agent.tool_response else None),
                event.process.pid if event.process else None,
                event.process.ppid if event.process else None,
                event.process.name if event.process else None,
                event.process.cmdline if event.process else None,
                event.file.path if event.file else None,
                event.file.operation if event.file else None,
                event.file.size if event.file else None,
                event.network.direction if event.network else None,
                event.network.protocol if event.network else None,
                event.network.remote_addr if event.network else None,
                event.network.remote_port if event.network else None,
                event.network.domain if event.network else None,
                event.llm.provider if event.llm else None,
                event.llm.model if event.llm else None,
                event.llm.tokens_in if event.llm else None,
                event.llm.tokens_out if event.llm else None,
                int(event.llm.has_tools) if event.llm else None,
                int(event.llm.contains_credentials) if event.llm else None,
                event.risk_score,
                json.dumps(event.rule_matches) if event.rule_matches else None,
                event.sensor_source,
                json.dumps(event.raw_data) if event.raw_data else None,
            ),
        )
        await self._db.commit()

    async def store_events_batch(self, events: list[EDREvent]) -> None:
        """Store multiple events in a single transaction."""
        assert self._db is not None
        for event in events:
            await self.store_event(event)

    async def query_events(
        self,
        *,
        category: str | None = None,
        action: str | None = None,
        agent_type: str | None = None,
        session_id: str | None = None,
        min_severity: int = 0,
        tool_name: str | None = None,
        file_path_pattern: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """Query events with flexible filtering."""
        assert self._db is not None
        conditions = []
        params: list = []

        if category:
            conditions.append("category = ?")
            params.append(category)
        if action:
            conditions.append("action = ?")
            params.append(action)
        if agent_type:
            conditions.append("agent_type = ?")
            params.append(agent_type)
        if session_id:
            conditions.append("agent_session_id = ?")
            params.append(session_id)
        if min_severity > 0:
            conditions.append("severity >= ?")
            params.append(min_severity)
        if tool_name:
            conditions.append("tool_name = ?")
            params.append(tool_name)
        if file_path_pattern:
            conditions.append("file_path LIKE ?")
            params.append(file_path_pattern)
        if since:
            conditions.append("timestamp >= ?")
            params.append(since.isoformat())
        if until:
            conditions.append("timestamp <= ?")
            params.append(until.isoformat())

        where = " AND ".join(conditions) if conditions else "1=1"
        query = f"SELECT * FROM events WHERE {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = await self._db.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def query_alerts(
        self,
        *,
        status: str | None = None,
        min_severity: int = 0,
        limit: int = 50,
    ) -> list[dict]:
        """Query alerts."""
        assert self._db is not None
        conditions = []
        params: list = []

        if status:
            conditions.append("status = ?")
            params.append(status)
        if min_severity > 0:
            conditions.append("severity >= ?")
            params.append(min_severity)

        where = " AND ".join(conditions) if conditions else "1=1"
        query = f"SELECT * FROM alerts WHERE {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor = await self._db.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def query_alerts_by_tool_prefix(
        self,
        *,
        tool_prefix: str,
        agent_type: str | None = None,
        limit: int = 200,
    ) -> list[dict]:
        """Query alerts whose linked events have a tool_name matching the prefix.

        Uses a JOIN through json_each to unpack event_ids_json, avoiding
        the need to load all events into memory with a limited window.
        """
        assert self._db is not None
        params: list = [f"{tool_prefix}%"]
        agent_filter = ""
        if agent_type:
            agent_filter = "AND a.agent_type = ?"
            params.append(agent_type)
        params.append(limit)

        query = f"""
            SELECT DISTINCT a.* FROM alerts a
            JOIN json_each(a.event_ids_json) j
            JOIN events e ON e.id = j.value
            WHERE e.tool_name LIKE ?
            {agent_filter}
            ORDER BY a.timestamp DESC
            LIMIT ?
        """
        cursor = await self._db.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def store_alert(
        self,
        *,
        alert_id: str,
        rule_id: str,
        rule_name: str,
        severity: Severity,
        title: str,
        description: str,
        event_ids: list[str],
        agent_session_id: str = "",
        agent_type: str = "",
    ) -> None:
        """Store a detection alert."""
        assert self._db is not None
        await self._db.execute(
            """INSERT INTO alerts (
                id, timestamp, rule_id, rule_name, severity, title, description,
                event_ids_json, agent_session_id, agent_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert_id,
                datetime.now(timezone.utc).isoformat(),
                rule_id,
                rule_name,
                severity.value,
                title,
                description,
                json.dumps(event_ids),
                agent_session_id,
                agent_type,
            ),
        )
        await self._db.commit()

    async def update_alert_status(self, alert_id: str, status: str) -> None:
        """Update alert status (open, acknowledged, resolved)."""
        assert self._db is not None
        resolved_at = datetime.now(timezone.utc).isoformat() if status == "resolved" else None
        await self._db.execute(
            "UPDATE alerts SET status = ?, resolved_at = ? WHERE id = ?",
            (status, resolved_at, alert_id),
        )
        await self._db.commit()

    async def get_event_counts(self, since: datetime | None = None) -> dict:
        """Get event count summary for dashboard."""
        assert self._db is not None
        since_iso = since.isoformat() if since else "1970-01-01T00:00:00"

        cursor = await self._db.execute(
            "SELECT COUNT(*) as total FROM events WHERE timestamp >= ?", (since_iso,)
        )
        total = (await cursor.fetchone())["total"]

        cursor = await self._db.execute(
            "SELECT category, COUNT(*) as cnt FROM events WHERE timestamp >= ? GROUP BY category",
            (since_iso,),
        )
        by_category = {row["category"]: row["cnt"] for row in await cursor.fetchall()}

        cursor = await self._db.execute(
            "SELECT severity, COUNT(*) as cnt FROM events WHERE timestamp >= ? GROUP BY severity",
            (since_iso,),
        )
        by_severity = {row["severity"]: row["cnt"] for row in await cursor.fetchall()}

        cursor = await self._db.execute(
            "SELECT COUNT(*) as cnt FROM alerts WHERE status = 'open'"
        )
        open_alerts = (await cursor.fetchone())["cnt"]

        return {
            "total_events": total,
            "by_category": by_category,
            "by_severity": by_severity,
            "open_alerts": open_alerts,
        }

    async def register_endpoint(
        self,
        *,
        endpoint_id: str,
        hostname: str,
        os_name: str = "",
        os_version: str = "",
        kernel: str = "",
        arch: str = "",
        ip_addresses: list[str] | None = None,
        username: str = "",
        cpu_count: int = 0,
        memory_total_gb: float = 0.0,
        agent_count: int = 0,
    ) -> None:
        """Register or update an endpoint (upsert)."""
        assert self._db is not None
        now = datetime.now(timezone.utc).isoformat()
        await self._db.execute(
            """INSERT INTO endpoints (
                id, hostname, os_name, os_version, kernel, arch,
                ip_addresses_json, username, cpu_count, memory_total_gb,
                agent_count, first_seen, last_heartbeat, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online')
            ON CONFLICT(id) DO UPDATE SET
                hostname=excluded.hostname, os_name=excluded.os_name,
                os_version=excluded.os_version, kernel=excluded.kernel,
                arch=excluded.arch, ip_addresses_json=excluded.ip_addresses_json,
                username=excluded.username, cpu_count=excluded.cpu_count,
                memory_total_gb=excluded.memory_total_gb,
                agent_count=excluded.agent_count,
                last_heartbeat=excluded.last_heartbeat, status='online'
            """,
            (
                endpoint_id, hostname, os_name, os_version, kernel, arch,
                json.dumps(ip_addresses or []), username, cpu_count,
                round(memory_total_gb, 1), agent_count, now, now,
            ),
        )
        await self._db.commit()

    async def get_all_endpoints(self) -> list[dict]:
        """Get all registered endpoints."""
        assert self._db is not None
        cursor = await self._db.execute(
            "SELECT * FROM endpoints ORDER BY last_heartbeat DESC"
        )
        rows = await cursor.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["ip_addresses"] = json.loads(d.pop("ip_addresses_json", "[]"))
            result.append(d)
        return result

    async def get_endpoint(self, endpoint_id: str) -> dict | None:
        """Get a single endpoint by ID."""
        assert self._db is not None
        cursor = await self._db.execute(
            "SELECT * FROM endpoints WHERE id = ?", (endpoint_id,)
        )
        row = await cursor.fetchone()
        if row:
            d = dict(row)
            d["ip_addresses"] = json.loads(d.pop("ip_addresses_json", "[]"))
            return d
        return None

    async def get_endpoint_stats(self, endpoint_id: str | None = None) -> dict:
        """Get aggregate stats, optionally filtered by endpoint."""
        assert self._db is not None
        since = (datetime.now(timezone.utc) - __import__("datetime").timedelta(hours=24)).isoformat()

        # Total events in last 24h
        cursor = await self._db.execute(
            "SELECT COUNT(*) as cnt FROM events WHERE timestamp >= ?", (since,)
        )
        total_events = (await cursor.fetchone())["cnt"]

        # Open alerts
        cursor = await self._db.execute(
            "SELECT COUNT(*) as cnt FROM alerts WHERE status = 'open'"
        )
        open_alerts = (await cursor.fetchone())["cnt"]

        # Active sessions (events in last 5 minutes)
        recent = (datetime.now(timezone.utc) - __import__("datetime").timedelta(minutes=5)).isoformat()
        cursor = await self._db.execute(
            "SELECT COUNT(DISTINCT agent_session_id) as cnt FROM events WHERE timestamp >= ?",
            (recent,),
        )
        active_sessions = (await cursor.fetchone())["cnt"]

        # Endpoint count
        cursor = await self._db.execute("SELECT COUNT(*) as cnt FROM endpoints")
        endpoint_count = (await cursor.fetchone())["cnt"]

        return {
            "total_events_24h": total_events,
            "open_alerts": open_alerts,
            "active_sessions": active_sessions,
            "endpoint_count": endpoint_count,
        }

    async def cleanup_old_events(self, retention_days: int) -> int:
        """Delete events older than retention period. Returns count deleted."""
        assert self._db is not None
        from datetime import timedelta

        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        cursor = await self._db.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        await self._db.commit()
        return cursor.rowcount or 0
