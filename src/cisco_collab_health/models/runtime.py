"""Runtime collection context shared across orchestration layers."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cisco_collab_health.transport.tls import TlsPolicy


HostKeyApproval = Callable[[str, str, str], bool]
ProgressReporter = Callable[[str], None]
SshPasswordRetry = Callable[[str, str], str | None]


@dataclass(frozen=True)
class CollectionContext:
    """Shared runtime context passed to collectors and transport helpers."""

    target: str | None = None
    username: str | None = None
    product: str = "cucm"
    target_id: str | None = None
    publisher_ip: str | None = None
    gui_username: str | None = None
    gui_password: str | None = field(default=None, repr=False)
    os_username: str | None = None
    os_password: str | None = field(default=None, repr=False)
    node_platform_passwords: dict[str, str] = field(default_factory=dict, repr=False, compare=False)
    ssh_preflight_contexts: dict[str, "CollectionContext"] = field(
        default_factory=dict, repr=False, compare=False
    )
    timeout_seconds: int = 30
    accept_new_host_key: bool = False
    host_key_approval: HostKeyApproval | None = field(default=None, repr=False, compare=False)
    ssh_password_retry: SshPasswordRetry | None = field(default=None, repr=False, compare=False)
    progress: ProgressReporter | None = field(default=None, repr=False, compare=False)
    ssh_parallel_workers: int = 3
    artifact_store: Any | None = field(default=None, repr=False)
    tls: TlsPolicy = field(default_factory=TlsPolicy)
    axl_port: int = 8443
    risport_port: int = 8443
    control_center_port: int = 8443
    perfmon_port: int = 8443
    collect_phone_inventory: bool = False
    phone_inventory_page_size: int = 500
    phone_inventory_max_devices: int = 2000
    diagnostic_capture: bool = False
    diagnostic_max_devices: int = 2000
    diagnostic_axl_page_size: int = 250
    diagnostic_axl_max_records: int = 500
    diagnostic_cupi_max_records: int = 2000
    discovered_nodes: tuple[str, ...] = ()
    discovered_device_names: tuple[str, ...] = ()
