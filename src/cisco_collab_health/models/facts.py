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
class DeviceLoadDefaultFact:
    """Default firmware/load facts for one device model and protocol."""

    model: str
    protocol: str | None
    default_load: str | None
    source: str
    configured_model_count: int | None = None
    model_code: str | None = None


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
    runtime_model_code: str | None = None
    device_class: str | None = None
    active_load: str | None = None
    inactive_load: str | None = None
    download_status: str | None = None
    download_failure_reason: str | None = None
    registration_attempts: int | None = None
    status_reason: str | None = None
    directory_numbers: tuple[str, ...] = ()
    login_user_id: str | None = None
    timestamp: str | None = None


@dataclass(frozen=True)
class ServiceStatusFact:
    """Service activation and running-state facts for one node."""

    node: str
    service_name: str
    activated: bool | None
    status: str
    uptime_seconds: int | None
    source: str
    start_time: str | None = None
    reason_code: str | None = None
    reason: str | None = None
    service_type: str | None = None
    group_name: str | None = None
    product_id: str | None = None
    deployable: bool | None = None
    dependent_services: tuple[str, ...] = ()


@dataclass(frozen=True)
class ConfigurationObjectFact:
    """Bounded configuration inventory fact from an AXL list operation."""

    object_type: str
    name: str
    details: dict[str, str]
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


@dataclass(frozen=True)
class CollectorIssueFact:
    """Warning or error emitted by a collector during an assessment."""

    collector_name: str
    issue_type: str
    message: str
    exception_type: str | None = None
    source: str = "collector_result"


@dataclass(frozen=True)
class CertificateFact:
    """Normalized identity or trust certificate metadata."""

    node: str
    name: str
    service: str | None
    store: str | None
    certificate_kind: str
    subject: str | None
    issuer: str | None
    serial_number: str | None
    valid_from: str | None
    valid_until: str | None
    days_remaining: int | None
    self_signed: bool | None
    key_type: str | None
    key_size: str | None
    signature_algorithm: str | None
    subject_key_identifier: str | None
    authority_key_identifier: str | None
    intermediate: str | None
    root: str | None
    chain_status: str | None
    source: str
    fingerprint_sha256: str | None = None


@dataclass
class AssessmentFacts:
    """Container for normalized assessment facts."""

    cluster: ClusterIdentity | None = None
    nodes: list[CollaborationNode] = field(default_factory=list)
    devices: list[DeviceInventoryFact] = field(default_factory=list)
    device_load_defaults: list[DeviceLoadDefaultFact] = field(default_factory=list)
    registrations: list[DeviceRegistrationFact] = field(default_factory=list)
    services: list[ServiceStatusFact] = field(default_factory=list)
    perf_counters: list[PerfCounterFact] = field(default_factory=list)
    configuration_objects: list[ConfigurationObjectFact] = field(default_factory=list)
    platform_checks: list[PlatformCheckFact] = field(default_factory=list)
    collector_issues: list[CollectorIssueFact] = field(default_factory=list)
    certificates: list[CertificateFact] = field(default_factory=list)

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
        _merge_by_key(self.devices, other.devices, _device_inventory_key, _merge_device_inventory)
        _merge_by_key(
            self.device_load_defaults,
            other.device_load_defaults,
            _device_load_default_key,
            _merge_device_load_default,
        )
        inventory_by_name = {
            device.name.strip().lower(): device for device in self.devices if device.name.strip()
        }
        registrations = [
            _enrich_registration_from_inventory(registration, inventory_by_name)
            for registration in other.registrations
        ]
        _merge_by_key(
            self.registrations,
            registrations,
            _device_registration_key,
            _merge_device_registration,
        )
        _merge_by_key(self.services, other.services, _service_status_key, _merge_service_status)
        _merge_by_key(self.perf_counters, other.perf_counters, _perf_counter_key)
        _merge_by_key(
            self.configuration_objects,
            other.configuration_objects,
            _configuration_object_key,
            _merge_configuration_object,
        )
        _merge_by_key(
            self.platform_checks,
            other.platform_checks,
            _platform_check_key,
            _merge_platform_check,
        )
        _merge_by_key(
            self.certificates,
            other.certificates,
            lambda item: (item.node.lower(), item.name.lower(), (item.store or "").lower()),
        )
        self.collector_issues.extend(other.collector_issues)


T = TypeVar("T")


def _merge_by_key(
    target: list[T],
    incoming: list[T],
    key_for: Callable[[T], object],
    merge_item: Callable[[T, T], T] | None = None,
) -> None:
    key_function = key_for
    existing_keys = {key_function(item): index for index, item in enumerate(target)}
    for item in incoming:
        key = key_function(item)
        existing_index = existing_keys.get(key)
        if existing_index is None:
            existing_keys[key] = len(target)
            target.append(item)
        else:
            existing = target[existing_index]
            target[existing_index] = merge_item(existing, item) if merge_item else item


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


def _prefer(existing: T, incoming: T) -> T:
    if incoming not in (None, "", [], {}):
        return incoming
    return existing


def _merge_sources(existing: str, incoming: str) -> str:
    sources = []
    for source in (existing, incoming):
        if source and source not in sources:
            sources.append(source)
    return ", ".join(sources)


def _merge_device_inventory(
    existing: DeviceInventoryFact,
    incoming: DeviceInventoryFact,
) -> DeviceInventoryFact:
    return DeviceInventoryFact(
        name=_prefer(existing.name, incoming.name),
        description=_prefer(existing.description, incoming.description),
        model=_prefer(existing.model, incoming.model),
        protocol=_prefer(existing.protocol, incoming.protocol),
        device_pool=_prefer(existing.device_pool, incoming.device_pool),
        call_manager_group=_prefer(existing.call_manager_group, incoming.call_manager_group),
        location=_prefer(existing.location, incoming.location),
        region=_prefer(existing.region, incoming.region),
        configured_load=_prefer(existing.configured_load, incoming.configured_load),
        source=_merge_sources(existing.source, incoming.source),
    )


def _merge_device_load_default(
    existing: DeviceLoadDefaultFact,
    incoming: DeviceLoadDefaultFact,
) -> DeviceLoadDefaultFact:
    return DeviceLoadDefaultFact(
        model=_prefer(existing.model, incoming.model),
        protocol=_prefer(existing.protocol, incoming.protocol),
        default_load=_prefer(existing.default_load, incoming.default_load),
        source=_merge_sources(existing.source, incoming.source),
        configured_model_count=existing.configured_model_count or incoming.configured_model_count,
        model_code=_prefer(existing.model_code, incoming.model_code),
    )


def _merge_device_registration(
    existing: DeviceRegistrationFact,
    incoming: DeviceRegistrationFact,
) -> DeviceRegistrationFact:
    return DeviceRegistrationFact(
        name=_prefer(existing.name, incoming.name),
        status=_prefer(existing.status, incoming.status),
        registered_node=_prefer(existing.registered_node, incoming.registered_node),
        ip_address=_prefer(existing.ip_address, incoming.ip_address),
        model=_prefer(existing.model, incoming.model),
        protocol=_prefer(existing.protocol, incoming.protocol),
        source=_merge_sources(existing.source, incoming.source),
        runtime_model_code=_prefer(existing.runtime_model_code, incoming.runtime_model_code),
        device_class=_prefer(existing.device_class, incoming.device_class),
        active_load=_prefer(existing.active_load, incoming.active_load),
        inactive_load=_prefer(existing.inactive_load, incoming.inactive_load),
        download_status=_prefer(existing.download_status, incoming.download_status),
        download_failure_reason=_prefer(
            existing.download_failure_reason, incoming.download_failure_reason
        ),
        registration_attempts=_prefer(
            existing.registration_attempts, incoming.registration_attempts
        ),
        status_reason=_prefer(existing.status_reason, incoming.status_reason),
        directory_numbers=_prefer(existing.directory_numbers, incoming.directory_numbers),
        login_user_id=_prefer(existing.login_user_id, incoming.login_user_id),
        timestamp=_prefer(existing.timestamp, incoming.timestamp),
    )


def _merge_service_status(
    existing: ServiceStatusFact,
    incoming: ServiceStatusFact,
) -> ServiceStatusFact:
    return ServiceStatusFact(
        node=_prefer(existing.node, incoming.node),
        service_name=_prefer(existing.service_name, incoming.service_name),
        activated=_prefer(existing.activated, incoming.activated),
        status=_prefer(existing.status, incoming.status),
        uptime_seconds=_prefer(existing.uptime_seconds, incoming.uptime_seconds),
        source=_merge_sources(existing.source, incoming.source),
        start_time=_prefer(existing.start_time, incoming.start_time),
        reason_code=_prefer(existing.reason_code, incoming.reason_code),
        reason=_prefer(existing.reason, incoming.reason),
        service_type=_prefer(existing.service_type, incoming.service_type),
        group_name=_prefer(existing.group_name, incoming.group_name),
        product_id=_prefer(existing.product_id, incoming.product_id),
        deployable=_prefer(existing.deployable, incoming.deployable),
        dependent_services=_prefer(existing.dependent_services, incoming.dependent_services),
    )


def _enrich_registration_from_inventory(
    registration: DeviceRegistrationFact,
    inventory_by_name: dict[str, DeviceInventoryFact],
) -> DeviceRegistrationFact:
    device = inventory_by_name.get(registration.name.strip().lower())
    if device is None:
        return registration
    return DeviceRegistrationFact(
        name=registration.name,
        status=registration.status,
        registered_node=registration.registered_node,
        ip_address=registration.ip_address,
        model=device.model or registration.model,
        protocol=device.protocol or registration.protocol,
        source=_merge_sources(registration.source, "AXL.listPhone.summary"),
        runtime_model_code=registration.runtime_model_code or registration.model,
        device_class=registration.device_class,
        active_load=registration.active_load,
        inactive_load=registration.inactive_load,
        download_status=registration.download_status,
        download_failure_reason=registration.download_failure_reason,
        registration_attempts=registration.registration_attempts,
        status_reason=registration.status_reason,
        directory_numbers=registration.directory_numbers,
        login_user_id=registration.login_user_id,
        timestamp=registration.timestamp,
    )


def _merge_configuration_object(
    existing: ConfigurationObjectFact,
    incoming: ConfigurationObjectFact,
) -> ConfigurationObjectFact:
    return ConfigurationObjectFact(
        object_type=_prefer(existing.object_type, incoming.object_type),
        name=_prefer(existing.name, incoming.name),
        details={**existing.details, **incoming.details},
        source=_merge_sources(existing.source, incoming.source),
    )


def _merge_platform_check(
    existing: PlatformCheckFact,
    incoming: PlatformCheckFact,
) -> PlatformCheckFact:
    details = {**existing.details, **incoming.details}
    return PlatformCheckFact(
        node=_prefer(existing.node, incoming.node),
        check_name=_prefer(existing.check_name, incoming.check_name),
        status=_prefer(existing.status, incoming.status),
        details=details,
        source=_merge_sources(existing.source, incoming.source),
    )


def _device_inventory_key(fact: DeviceInventoryFact) -> str:
    return _normalize_node_key(fact.name)


def _device_load_default_key(fact: DeviceLoadDefaultFact) -> tuple[str, str]:
    return (
        fact.model.strip().lower(),
        (fact.protocol or "").strip().lower(),
    )


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


def _configuration_object_key(fact: ConfigurationObjectFact) -> tuple[str, str, str]:
    return (
        fact.object_type.strip().lower(),
        fact.name.strip().lower(),
        fact.details.get("partition", "").strip().lower(),
    )
