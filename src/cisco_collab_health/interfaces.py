"""CUCM interface discovery and reachability checks."""

from __future__ import annotations

import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

from cisco_collab_health.collectors.base import CollectionContext


@dataclass(frozen=True)
class InterfaceProbe:
    """Definition for one CUCM interface reachability probe."""

    name: str
    host: str
    port: int
    path: str


@dataclass(frozen=True)
class InterfaceStatus:
    """Reachability result for one CUCM interface."""

    name: str
    available: bool
    endpoint: str
    reason: str | None = None


SocketProbe = Callable[[str, int, float], bool]
PingProbe = Callable[[str, float], bool]
HttpProbe = Callable[[str, float], tuple[bool, str | None]]


@dataclass(frozen=True)
class ConnectivityStatus:
    """Reachability result for a base network or web check."""

    name: str
    available: bool
    target: str
    reason: str | None = None


@dataclass(frozen=True)
class PreflightResult:
    """Publisher preflight result used to decide which collectors can run."""

    publisher: str
    connectivity: list[ConnectivityStatus]
    interfaces: list[InterfaceStatus]

    @property
    def available_interfaces(self) -> list[str]:
        return [status.name for status in self.interfaces if status.available]


def default_cucm_probes(host: str) -> list[InterfaceProbe]:
    """Return the default API probes for a CUCM node."""

    return [
        InterfaceProbe("axl", host, 8443, "/axl/"),
        InterfaceProbe("risport70", host, 8443, "/realtimeservice2/services/RISService70?wsdl"),
        InterfaceProbe(
            "control_center",
            host,
            8443,
            "/controlcenterservice2/services/ControlCenterServices?wsdl",
        ),
        InterfaceProbe("perfmon", host, 8443, "/perfmonservice2/services/PerfmonService?wsdl"),
    ]


def probe_interfaces(
    context: CollectionContext,
    *,
    timeout_seconds: float = 3.0,
    socket_probe: SocketProbe | None = None,
) -> list[InterfaceStatus]:
    """Probe known CUCM interfaces before running interface-specific collectors."""

    host = context.publisher_ip or context.target
    if not host:
        return [
            InterfaceStatus(
                name="publisher",
                available=False,
                endpoint="",
                reason="No Publisher IP or target was provided.",
            )
        ]

    probe = socket_probe or _tcp_probe
    statuses: list[InterfaceStatus] = []
    for interface in default_cucm_probes(host):
        endpoint = f"https://{interface.host}:{interface.port}{interface.path}"
        try:
            available = probe(interface.host, interface.port, timeout_seconds)
        except OSError as exc:
            statuses.append(
                InterfaceStatus(
                    name=interface.name,
                    available=False,
                    endpoint=endpoint,
                    reason=str(exc),
                )
            )
            continue

        statuses.append(
            InterfaceStatus(
                name=interface.name,
                available=available,
                endpoint=endpoint,
                reason=None if available else "TCP connection failed.",
            )
        )

    return statuses


def run_publisher_preflight(
    context: CollectionContext,
    *,
    timeout_seconds: float = 3.0,
    ping_probe: PingProbe | None = None,
    socket_probe: SocketProbe | None = None,
    http_probe: HttpProbe | None = None,
) -> PreflightResult:
    """Run Publisher ping, base URL, and API interface reachability checks."""

    host = context.publisher_ip or context.target or ""
    connectivity: list[ConnectivityStatus] = []

    if not host:
        return PreflightResult(
            publisher="",
            connectivity=[
                ConnectivityStatus(
                    name="publisher",
                    available=False,
                    target="",
                    reason="No Publisher IP or target was provided.",
                )
            ],
            interfaces=[],
        )

    ping = ping_probe or _ping_probe
    http = http_probe or _http_probe

    try:
        ping_available = ping(host, timeout_seconds)
        connectivity.append(
            ConnectivityStatus(
                name="ping",
                available=ping_available,
                target=host,
                reason=None if ping_available else "ICMP ping failed.",
            )
        )
    except OSError as exc:
        connectivity.append(
            ConnectivityStatus(name="ping", available=False, target=host, reason=str(exc))
        )

    for scheme, port in (("http", 80), ("https", 8443)):
        url = f"{scheme}://{host}:{port}/"
        try:
            available, reason = http(url, timeout_seconds)
        except OSError as exc:
            available = False
            reason = str(exc)
        connectivity.append(
            ConnectivityStatus(
                name=f"{scheme}_base",
                available=available,
                target=url,
                reason=reason,
            )
        )

    return PreflightResult(
        publisher=host,
        connectivity=connectivity,
        interfaces=probe_interfaces(context, timeout_seconds=timeout_seconds, socket_probe=socket_probe),
    )


def _tcp_probe(host: str, port: int, timeout_seconds: float) -> bool:
    with socket.create_connection((host, port), timeout=timeout_seconds):
        return True


def _ping_probe(host: str, timeout_seconds: float) -> bool:
    if sys.platform.startswith("win"):
        command = ["ping", "-n", "1", "-w", str(int(timeout_seconds * 1000)), host]
    else:
        command = ["ping", "-c", "1", "-W", str(max(1, int(timeout_seconds))), host]

    result = subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def _http_probe(url: str, timeout_seconds: float) -> tuple[bool, str | None]:
    request = urllib.request.Request(url, method="GET")
    context = ssl._create_unverified_context() if url.startswith("https://") else None
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds, context=context) as response:
            return 200 <= response.status < 500, f"HTTP {response.status}"
    except urllib.error.HTTPError as exc:
        return exc.code < 500, f"HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return False, str(exc.reason)
