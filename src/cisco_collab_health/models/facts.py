"""Normalized facts collected from Cisco Collaboration systems."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypeVar


@dataclass(frozen=True)
class ClusterIdentity:
    """Basic identity facts for a CUCM or SME cluster."""

    name: str
    product: str
    version: str


@dataclass(frozen=True)
class CollaborationNode:
    """Basic node facts normalized across collection sources."""

    name: str
    address: str
    role: str
    reachable: bool | None = None


@dataclass(frozen=True)
class DeviceInventoryFact:
    """Configured device inventory facts from authoritative configuration sources."""

    name: str
    description: str | None
    model: str | None
    protocol: str | None
    device_pool: str | None
    call_manager_group: str | None
    location: str | None
    region: str | None
    configured_load: str | None
    source: str


@dataclass(frozen=True)
class DeviceRegistrationFact:
    """Runtime device registration facts from real-time sources."""

    name: str
    status: str
    registered_node: str | None
    ip_address: str | None
    model: str | None
    protocol: str | None
    source: str


@dataclass(frozen=True)
class ServiceStatusFact:
    """Service activation and running-state facts for one node."""

    node: str
    service_name: str
    activated: bool | None
    status: str
    uptime_seconds: int | None
    source: str


@dataclass(frozen=True)
class PerfCounterFact:
    """Performance counter sample normalized across PerfMon collection."""

    node: str
    object_name: str
    counter_name: str
    instance: str | None
    value: float | int | str
    sample_count: int
    source: str


@dataclass(frozen=True)
class PlatformCheckFact:
    """Platform-level health check fact from CLI or serviceability sources."""

    node: str
    check_name: str
    status: str
    details: dict[str, str]
    source: str


@dataclass
class AssessmentFacts:
    """Container for normalized assessment facts."""

    cluster: ClusterIdentity | None = None
    nodes: list[CollaborationNode] = field(default_factory=list)
    devices: list[DeviceInventoryFact] = field(default_factory=list)
    registrations: list[DeviceRegistrationFact] = field(default_factory=list)
    services: list[ServiceStatusFact] = field(default_factory=list)
    perf_counters: list[PerfCounterFact] = field(default_factory=list)
    platform_checks: list[PlatformCheckFact] = field(default_factory=list)

    def add_node(self, node: CollaborationNode) -> None:
        """Add or merge a node observation by stable node identity."""

        existing_index = self._node_index(node)
        if existing_index is None:
            self.nodes.append(node)
            return

        existing = self.nodes[existing_index]
        self.nodes[existing_index] = CollaborationNode(
            name=existing.name or node.name,
            address=existing.address or node.address,
            role=_merge_role(existing.role, node.role),
            reachable=_merge_reachability(existing.reachable, node.reachable),
        )

    def _node_index(self, node: CollaborationNode) -> int | None:
        node_keys = _node_keys(node)
        for index, existing in enumerate(self.nodes):
            if _node_keys(existing) & node_keys:
                return index
        return None

    def merge(self, other: "AssessmentFacts") -> None:
        """Merge another facts object into this one."""

        if other.cluster is not None:
            self.cluster = other.cluster
        for node in other.nodes:
            self.add_node(node)
        _merge_by_key(self.devices, other.devices, _device_inventory_key)
        _merge_by_key(self.registrations, other.registrations, _device_registration_key)
        _merge_by_key(self.services, other.services, _service_status_key)
        _merge_by_key(self.perf_counters, other.perf_counters, _perf_counter_key)
        _merge_by_key(self.platform_checks, other.platform_checks, _platform_check_key)


T = TypeVar("T")


def _merge_by_key(target: list[T], incoming: list[T], key_for: Callable[[T], object]) -> None:
    key_function = key_for
    existing_keys = {key_function(item): index for index, item in enumerate(target)}
    for item in incoming:
        key = key_function(item)
        existing_index = existing_keys.get(key)
        if existing_index is None:
            existing_keys[key] = len(target)
            target.append(item)
        else:
            target[existing_index] = item


def _node_keys(node: CollaborationNode) -> set[str]:
    return {
        key
        for key in {
            _normalize_node_key(node.address),
            _normalize_node_key(node.name),
        }
        if key
    }


def _normalize_node_key(value: str) -> str:
    return value.strip().lower()


def _merge_role(existing: str, new: str) -> str:
    if existing == new:
        return existing
    if "publisher" in {existing.lower(), new.lower()}:
        return "publisher"
    if existing:
        return existing
    return new


def _merge_reachability(existing: bool | None, new: bool | None) -> bool | None:
    if existing is False or new is False:
        return False
    if existing is True or new is True:
        return True
    return None


def _device_inventory_key(fact: DeviceInventoryFact) -> str:
    return _normalize_node_key(fact.name)


def _device_registration_key(fact: DeviceRegistrationFact) -> str:
    return _normalize_node_key(fact.name)


def _service_status_key(fact: ServiceStatusFact) -> tuple[str, str]:
    return (_normalize_node_key(fact.node), fact.service_name.strip().lower())


def _perf_counter_key(fact: PerfCounterFact) -> tuple[str, str, str, str, str]:
    return (
        _normalize_node_key(fact.node),
        fact.object_name.strip().lower(),
        fact.counter_name.strip().lower(),
        (fact.instance or "").strip().lower(),
        fact.source.strip().lower(),
    )


def _platform_check_key(fact: PlatformCheckFact) -> tuple[str, str]:
    return (_normalize_node_key(fact.node), fact.check_name.strip().lower())
