"""Configuration management for Claude EDR."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "claude-edr" / "config.toml"
DEFAULT_SOCKET_PATH = Path.home() / ".local" / "share" / "claude-edr" / "edr.sock"
DEFAULT_DB_PATH = Path.home() / ".local" / "share" / "claude-edr" / "events.db"
DEFAULT_DASHBOARD_PORT = 7400
DEFAULT_RULES_DIR = Path(__file__).parent.parent.parent.parent.parent / "rules"


@dataclass
class SensorConfig:
    hooks_enabled: bool = True
    process_monitor_enabled: bool = True
    ebpf_enabled: bool = False
    log_watcher_enabled: bool = True
    poll_interval_ms: int = 500


@dataclass
class StorageConfig:
    db_path: Path = field(default_factory=lambda: DEFAULT_DB_PATH)
    retention_days: int = 7
    max_db_size_mb: int = 500


@dataclass
class DashboardConfig:
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = DEFAULT_DASHBOARD_PORT


@dataclass
class DetectionConfig:
    rules_dirs: list[Path] = field(default_factory=lambda: [DEFAULT_RULES_DIR])
    anomaly_detection: bool = False


@dataclass
class AlertConfig:
    webhook_url: str = ""
    min_severity: int = 3  # HIGH


@dataclass
class SSLCaptureConfig:
    enabled: bool = False
    capture_mode: str = "metadata"  # "metadata" | "headers" | "full"


@dataclass
class Config:
    socket_path: Path = field(default_factory=lambda: DEFAULT_SOCKET_PATH)
    sensors: SensorConfig = field(default_factory=SensorConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    ssl_capture: SSLCaptureConfig = field(default_factory=SSLCaptureConfig)

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        """Load configuration from TOML file, with defaults for missing values.

        Environment variables override config file values:
          CLAUDE_EDR_DASHBOARD_HOST, CLAUDE_EDR_DB_PATH, CLAUDE_EDR_SOCKET
        """
        import os

        config = cls()
        config_path = path or DEFAULT_CONFIG_PATH

        if config_path.exists():
            with open(config_path, "rb") as f:
                data = tomllib.load(f)

            if "socket_path" in data:
                config.socket_path = Path(data["socket_path"])

            if "sensors" in data:
                s = data["sensors"]
                config.sensors.hooks_enabled = s.get("hooks_enabled", True)
                config.sensors.process_monitor_enabled = s.get("process_monitor_enabled", True)
                config.sensors.ebpf_enabled = s.get("ebpf_enabled", False)
                config.sensors.log_watcher_enabled = s.get("log_watcher_enabled", True)
                config.sensors.poll_interval_ms = s.get("poll_interval_ms", 500)

            if "storage" in data:
                st = data["storage"]
                config.storage.db_path = Path(st.get("db_path", str(DEFAULT_DB_PATH)))
                config.storage.retention_days = st.get("retention_days", 7)
                config.storage.max_db_size_mb = st.get("max_db_size_mb", 500)

            if "dashboard" in data:
                d = data["dashboard"]
                config.dashboard.enabled = d.get("enabled", True)
                config.dashboard.host = d.get("host", "127.0.0.1")
                config.dashboard.port = d.get("port", DEFAULT_DASHBOARD_PORT)

            if "detection" in data:
                det = data["detection"]
                if "rules_dirs" in det:
                    config.detection.rules_dirs = [Path(p) for p in det["rules_dirs"]]
                config.detection.anomaly_detection = det.get("anomaly_detection", False)

            if "alerts" in data:
                a = data["alerts"]
                config.alerts.webhook_url = a.get("webhook_url", "")
                config.alerts.min_severity = a.get("min_severity", 3)

            if "ssl_capture" in data:
                ssl = data["ssl_capture"]
                config.ssl_capture.enabled = ssl.get("enabled", False)
                config.ssl_capture.capture_mode = ssl.get("capture_mode", "metadata")

        # Environment variable overrides
        if env_host := os.environ.get("CLAUDE_EDR_DASHBOARD_HOST"):
            config.dashboard.host = env_host
        if env_port := os.environ.get("CLAUDE_EDR_DASHBOARD_PORT"):
            config.dashboard.port = int(env_port)
        if env_db := os.environ.get("CLAUDE_EDR_DB_PATH"):
            config.storage.db_path = Path(env_db)
        if env_sock := os.environ.get("CLAUDE_EDR_SOCKET"):
            config.socket_path = Path(env_sock)

        return config
