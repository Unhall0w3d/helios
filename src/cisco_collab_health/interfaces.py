"""CUCM interface discovery and reachability checks."""

from __future__ import annotations

import socket
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

from cisco_collab_health.collectors.base import CollectionContext
from cisco_collab_health.transport.tls import build_ssl_context


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
    endpoint: str
    transport_available: bool
    wsdl_available: bool | None = None
    authenticated_available: bool | None = None
    reason: str | None = None

    @property
    def available(self) -> bool:
        """Backward-compatible alias for transport availability."""

        return self.transport_available


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
    def transport_available_interfaces(self) -> list[str]:
        return [status.name for status in self.interfaces if status.transport_available]

    @property
    def available_interfaces(self) -> list[str]:
        """Backward-compatible alias for transport_available_interfaces."""

        return self.transport_available_interfaces

def default_cucm_probes(
    host: str,
    *,
    axl_port: int = 8443,
    risport_port: int = 8443,
    control_center_port: int = 8443,
    perfmon_port: int = 8443,
) -> list[InterfaceProbe]:
    """Return the default API probes for a CUCM node."""

    return [
        InterfaceProbe("axl", host, axl_port, "/axl/"),
        InterfaceProbe(
            "risport70",
            host,
            risport_port,
            "/realtimeservice2/services/RISService70?wsdl",
        ),
        InterfaceProbe(
            "control_center",
            host,
            control_center_port,
            "/controlcenterservice2/services/ControlCenterServices?wsdl",
        ),
        InterfaceProbe(
            "perfmon",
            host,
            perfmon_port,
            "/perfmonservice2/services/PerfmonService?wsdl",
        ),
    ]


def probe_interfaces(
    context: CollectionContext,
    *,
    timeout_seconds: float = 3.0,
    socket_probe: SocketProbe | None = None,
    axl_port: int = 8443,
    risport_port: int = 8443,
    control_center_port: int = 8443,
    perfmon_port: int = 8443,
) -> list[InterfaceStatus]:
    """Probe known CUCM interfaces before running interface-specific collectors."""

    host = context.publisher_ip or context.target
    if not host:
        return [
            InterfaceStatus(
                name="publisher",
                endpoint="",
                transport_available=False,
                reason="No Publisher IP or target was provided.",
            )
        ]

    probe = socket_probe or _tcp_probe
    statuses: list[InterfaceStatus] = []
    for interface in default_cucm_probes(
        host,
        axl_port=axl_port,
        risport_port=risport_port,
        control_center_port=control_center_port,
        perfmon_port=perfmon_port,
    ):
        endpoint = f"https://{interface.host}:{interface.port}{interface.path}"
        try:
            available = probe(interface.host, interface.port, timeout_seconds)
        except OSError as exc:
            statuses.append(
                InterfaceStatus(
                    name=interface.name,
                    endpoint=endpoint,
                    transport_available=False,
                    reason=str(exc),
                )
            )
            continue

        statuses.append(
            InterfaceStatus(
                name=interface.name,
                endpoint=endpoint,
                transport_available=available,
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
    base_https_ports: tuple[int, ...] = (443, 8443),
    axl_port: int = 8443,
    risport_port: int = 8443,
    control_center_port: int = 8443,
    perfmon_port: int = 8443,
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
    http = http_probe or (lambda url, timeout: _http_probe(url, timeout, context))

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

    for port in base_https_ports:
        url = f"https://{host}:{port}/"
        try:
            available, reason = http(url, timeout_seconds)
        except OSError as exc:
            available = False
            reason = str(exc)
        connectivity.append(
            ConnectivityStatus(
                name=f"https_{port}",
                available=available,
                target=url,
                reason=reason,
            )
        )

    return PreflightResult(
        publisher=host,
        connectivity=connectivity,
        interfaces=probe_interfaces(
            context,
            timeout_seconds=timeout_seconds,
            socket_probe=socket_probe,
            axl_port=axl_port,
            risport_port=risport_port,
            control_center_port=control_center_port,
            perfmon_port=perfmon_port,
        ),
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


def _http_probe(
    url: str,
    timeout_seconds: float,
    context: CollectionContext,
) -> tuple[bool, str | None]:
    request = urllib.request.Request(url, method="GET")
    ssl_context = build_ssl_context(context.tls) if url.startswith("https://") else None
    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout_seconds,
            context=ssl_context,
        ) as response:
            return 200 <= response.status < 500, f"HTTP {response.status}"
    except urllib.error.HTTPError as exc:
        return exc.code < 500, f"HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return False, str(exc.reason)
