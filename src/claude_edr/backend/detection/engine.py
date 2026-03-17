"""Detection engine - evaluates events against rules and generates alerts."""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from claude_edr.backend.models.events import EDREvent, Severity
from claude_edr.backend.registry.agent_registry import AgentRegistry
from claude_edr.backend.storage.sqlite_store import EventStore

logger = logging.getLogger(__name__)


@dataclass
class DetectionRule:
    """A single detection rule."""

    id: str
    name: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    enabled: bool = True
    conditions: list[dict] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def evaluate(self, event: EDREvent) -> bool:
        """Check if event matches all conditions in this rule."""
        if not self.enabled:
            return False
        return all(self._check_condition(event, cond) for cond in self.conditions)

    def _check_condition(self, event: EDREvent, condition: dict) -> bool:
        """Evaluate a single condition against an event."""
        # OR group: match if ANY sub-condition matches
        if "any_of" in condition:
            return any(self._check_condition(event, sub) for sub in condition["any_of"])

        # Explicit AND nesting (for use inside any_of)
        if "all_of" in condition:
            return all(self._check_condition(event, sub) for sub in condition["all_of"])

        field_path = condition.get("field", "")
        value = self._resolve_field(event, field_path)

        # Check if field exists / is non-empty
        if "exists" in condition:
            present = value is not None and value != "" and value != 0
            return present == condition["exists"]

        if value is None:
            return False

        value_str = str(value)

        if "equals" in condition:
            if isinstance(condition["equals"], bool):
                return value == condition["equals"] or value_str.lower() == str(condition["equals"]).lower()
            return value_str == str(condition["equals"])
        if "not_equals" in condition:
            return value_str != str(condition["not_equals"])
        if "pattern" in condition:
            return bool(re.search(condition["pattern"], value_str, re.IGNORECASE))
        if "contains" in condition:
            return str(condition["contains"]).lower() in value_str.lower()
        if "not_contains" in condition:
            return str(condition["not_contains"]).lower() not in value_str.lower()
        if "in" in condition:
            return value_str in [str(v) for v in condition["in"]]
        if "not_in" in condition:
            return value_str not in [str(v) for v in condition["not_in"]]
        if "starts_with" in condition:
            return value_str.startswith(str(condition["starts_with"]))
        if "not_starts_with" in condition:
            return not value_str.startswith(str(condition["not_starts_with"]))
        if "ends_with" in condition:
            return value_str.endswith(str(condition["ends_with"]))
        if "greater_than" in condition:
            try:
                return float(value) > float(condition["greater_than"])
            except (ValueError, TypeError):
                return False
        if "less_than" in condition:
            try:
                return float(value) < float(condition["less_than"])
            except (ValueError, TypeError):
                return False

        return False

    def _resolve_field(self, event: EDREvent, field_path: str):
        """Resolve a dotted field path to a value on the event."""
        parts = field_path.split(".")
        obj = event

        for part in parts:
            if obj is None:
                return None
            if hasattr(obj, part):
                obj = getattr(obj, part)
            elif isinstance(obj, dict):
                obj = obj.get(part)
            else:
                return None

            # Handle enum values
            if hasattr(obj, "value"):
                obj = obj.value

        return obj


class _DictProxy:
    """Wraps a flat event dict so _resolve_field can access fields by attribute.

    Supports both top-level keys (tool_name, action, tool_response_json)
    and dotted paths (agent.tool_name) by checking the dict first.
    """

    def __init__(self, d: dict):
        self._d = d

    def __getattr__(self, name: str):
        if name.startswith("_"):
            return super().__getattribute__(name)
        val = self._d.get(name)
        if val is not None:
            return val
        # Return None for missing fields (don't raise AttributeError)
        return None


class DetectionEngine:
    """Evaluates events against loaded detection rules and generates alerts."""

    def __init__(self, store: EventStore, registry: AgentRegistry):
        self.store = store
        self.registry = registry
        self.rules: list[DetectionRule] = []
        self.alert_count = 0

    def load_rules_from_dir(self, rules_dir: Path) -> int:
        """Load YAML rule files from a directory."""
        if not rules_dir.exists():
            logger.warning("Rules directory does not exist: %s", rules_dir)
            return 0

        count = 0
        for rule_file in sorted(rules_dir.glob("*.yaml")):
            try:
                loaded = self._load_rule_file(rule_file)
                count += loaded
            except Exception:
                logger.exception("Failed to load rules from %s", rule_file)
        logger.info("Loaded %d detection rules from %s", count, rules_dir)
        return count

    def _load_rule_file(self, path: Path) -> int:
        """Load rules from a single YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)

        if not data:
            return 0

        rules_data = data if isinstance(data, list) else data.get("rules", [data])
        count = 0

        for rule_data in rules_data:
            severity_val = rule_data.get("severity", 2)
            if isinstance(severity_val, str):
                severity = Severity[severity_val.upper()]
            else:
                severity = Severity(severity_val)

            rule = DetectionRule(
                id=rule_data.get("id", str(uuid.uuid4())),
                name=rule_data.get("name", "unnamed"),
                description=rule_data.get("description", ""),
                severity=severity,
                enabled=rule_data.get("enabled", True),
                conditions=rule_data.get("conditions", []),
                tags=rule_data.get("tags", []),
            )
            self.rules.append(rule)
            count += 1

        return count

    async def evaluate(self, event: EDREvent) -> list[str]:
        """Evaluate an event against all rules. Returns list of matched rule IDs."""
        matched: list[str] = []

        for rule in self.rules:
            try:
                if rule.evaluate(event):
                    matched.append(rule.id)
                    event.rule_matches.append(rule.id)
                    event.severity = max(event.severity, rule.severity, key=lambda s: s.value)
                    event.risk_score = max(event.risk_score, rule.severity.value * 25.0)

                    await self._create_alert(rule, event)
            except Exception:
                logger.exception("Error evaluating rule %s", rule.id)

        return matched

    async def evaluate_dict(self, event_dict: dict) -> list[str]:
        """Evaluate a raw event dict (from sensor transport) against all rules.

        The _resolve_field method already handles dicts via isinstance checks,
        so we wrap the dict in a simple proxy and reuse the rule evaluation.
        """
        matched: list[str] = []
        proxy = _DictProxy(event_dict)

        for rule in self.rules:
            try:
                if rule.evaluate(proxy):
                    matched.append(rule.id)

                    # Create alert with data from the dict
                    alert_id = str(uuid.uuid4())
                    agent_type = event_dict.get("agent_type", "")
                    session_id = event_dict.get("agent_session_id", "")
                    title = f"[{rule.severity.name}] {rule.name}"

                    desc_parts = [rule.description or rule.name]
                    if agent_type:
                        desc_parts.append(f"Agent: {agent_type}")
                    tool = event_dict.get("tool_name", "")
                    if tool:
                        desc_parts.append(f"Tool: {tool}")

                    await self.store.store_alert(
                        alert_id=alert_id,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        title=title,
                        description=" | ".join(desc_parts),
                        event_ids=[event_dict.get("id", "")],
                        agent_session_id=session_id,
                        agent_type=agent_type,
                    )
                    self.alert_count += 1
                    logger.warning("ALERT: %s | Tool: %s", title, tool)
            except Exception:
                logger.exception("Error evaluating rule %s on dict event", rule.id)

        return matched

    async def _create_alert(self, rule: DetectionRule, event: EDREvent) -> None:
        """Create an alert from a rule match."""
        alert_id = str(uuid.uuid4())
        session_id = event.agent.session_id if event.agent else ""
        agent_type = event.agent.agent_type.value if event.agent else ""

        # Build descriptive title
        title = f"[{rule.severity.name}] {rule.name}"
        description = self._build_alert_description(rule, event)

        await self.store.store_alert(
            alert_id=alert_id,
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            title=title,
            description=description,
            event_ids=[event.id],
            agent_session_id=session_id,
            agent_type=agent_type,
        )

        if session_id:
            self.registry.increment_alerts(session_id)

        self.alert_count += 1
        logger.warning("ALERT: %s | %s", title, description[:200])

    def _build_alert_description(self, rule: DetectionRule, event: EDREvent) -> str:
        """Build a human-readable alert description."""
        parts = [rule.description or rule.name]

        if event.agent:
            parts.append(f"Agent: {event.agent.agent_type.value}")
            if event.agent.tool_name:
                parts.append(f"Tool: {event.agent.tool_name}")

        if event.file:
            parts.append(f"File: {event.file.path}")

        if event.process and event.process.cmdline:
            cmd = event.process.cmdline
            if len(cmd) > 200:
                cmd = cmd[:200] + "..."
            parts.append(f"Command: {cmd}")

        if event.network:
            parts.append(f"Network: {event.network.remote_addr}:{event.network.remote_port}")

        return " | ".join(parts)

    def get_rules(self) -> list[dict]:
        """Return all rules as dicts (for API)."""
        return [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity.name,
                "enabled": r.enabled,
                "conditions": r.conditions,
                "tags": r.tags,
                "source": getattr(r, "source", "default"),
            }
            for r in self.rules
        ]

    def get_rule(self, rule_id: str) -> DetectionRule | None:
        """Get a single rule by ID."""
        return next((r for r in self.rules if r.id == rule_id), None)

    def add_rule(self, rule_data: dict) -> DetectionRule:
        """Add a new custom rule."""
        severity_val = rule_data.get("severity", "MEDIUM")
        if isinstance(severity_val, str):
            severity = Severity[severity_val.upper()]
        else:
            severity = Severity(severity_val)

        rule = DetectionRule(
            id=rule_data["id"],
            name=rule_data["name"],
            description=rule_data.get("description", ""),
            severity=severity,
            enabled=rule_data.get("enabled", True),
            conditions=rule_data.get("conditions", []),
            tags=rule_data.get("tags", []),
        )
        rule.source = "custom"
        self.rules.append(rule)
        return rule

    def update_rule(self, rule_id: str, rule_data: dict) -> DetectionRule | None:
        """Update an existing rule."""
        rule = self.get_rule(rule_id)
        if not rule:
            return None

        if "name" in rule_data:
            rule.name = rule_data["name"]
        if "description" in rule_data:
            rule.description = rule_data["description"]
        if "severity" in rule_data:
            sev = rule_data["severity"]
            rule.severity = Severity[sev.upper()] if isinstance(sev, str) else Severity(sev)
        if "enabled" in rule_data:
            rule.enabled = rule_data["enabled"]
        if "conditions" in rule_data:
            rule.conditions = rule_data["conditions"]
        if "tags" in rule_data:
            rule.tags = rule_data["tags"]

        return rule

    def delete_rule(self, rule_id: str) -> bool:
        """Delete a custom rule. Returns True if deleted."""
        rule = self.get_rule(rule_id)
        if not rule or getattr(rule, "source", "default") != "custom":
            return False
        self.rules.remove(rule)
        return True

    def toggle_rule(self, rule_id: str, enabled: bool) -> bool:
        """Enable or disable a rule."""
        rule = self.get_rule(rule_id)
        if not rule:
            return False
        rule.enabled = enabled
        return True

    def save_custom_rules(self, rules_dir: Path) -> None:
        """Save all custom rules to custom.yaml."""
        custom_rules = [r for r in self.rules if getattr(r, "source", "default") == "custom"]
        if not custom_rules:
            custom_path = rules_dir / "custom.yaml"
            if custom_path.exists():
                custom_path.unlink()
            return

        rules_data = []
        for r in custom_rules:
            rules_data.append({
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity.name.lower(),
                "enabled": r.enabled,
                "conditions": r.conditions,
                "tags": r.tags,
            })

        custom_path = rules_dir / "custom.yaml"
        custom_path.write_text(yaml.dump({"rules": rules_data}, default_flow_style=False))
