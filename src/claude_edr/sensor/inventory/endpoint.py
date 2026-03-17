"""Endpoint inventory - collects machine-level information."""

from __future__ import annotations

import hashlib
import os
import platform
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone

import psutil


@dataclass
class EndpointInfo:
    """Information about this machine / endpoint."""

    endpoint_id: str = ""
    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    kernel: str = ""
    arch: str = ""
    ip_addresses: list[str] = field(default_factory=list)
    username: str = ""
    cpu_count: int = 0
    memory_total_gb: float = 0.0
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "endpoint_id": self.endpoint_id,
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "kernel": self.kernel,
            "arch": self.arch,
            "ip_addresses": self.ip_addresses,
            "username": self.username,
            "cpu_count": self.cpu_count,
            "memory_total_gb": round(self.memory_total_gb, 1),
            "last_seen": self.last_seen.isoformat(),
        }


def _get_hostname() -> str:
    """Get the actual hostname, preferring the host's name over Docker container ID."""
    # When running in Docker, /etc/host_hostname is mounted from the host
    try:
        with open("/etc/host_hostname") as f:
            name = f.read().strip()
            if name:
                return name
    except FileNotFoundError:
        pass
    return socket.gethostname()


def _generate_endpoint_id() -> str:
    """Generate a stable, unique endpoint ID from machine identifiers."""
    hostname = _get_hostname()
    # Use machine-id if available (Linux), fallback to hostname-based hash
    machine_id = ""
    try:
        with open("/etc/machine-id") as f:
            machine_id = f.read().strip()
    except FileNotFoundError:
        pass
    raw = f"{hostname}:{machine_id}" if machine_id else hostname
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def collect_endpoint_info() -> EndpointInfo:
    """Gather information about this endpoint."""
    ips = []
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    ips.append(addr.address)
    except Exception:
        pass

    mem = psutil.virtual_memory()

    return EndpointInfo(
        endpoint_id=_generate_endpoint_id(),
        hostname=_get_hostname(),
        os_name=platform.system(),
        os_version=platform.version(),
        kernel=platform.release(),
        arch=platform.machine(),
        ip_addresses=ips,
        username=os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        cpu_count=psutil.cpu_count() or 0,
        memory_total_gb=mem.total / (1024**3),
    )
