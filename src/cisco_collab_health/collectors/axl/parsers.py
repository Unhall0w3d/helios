"""AXL response parsers."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Protocol

from defusedxml import ElementTree as ET

from cisco_collab_health.collectors.axl.errors import AxlCollectionError
from cisco_collab_health.models.facts import (
    CollaborationNode,
    ConfigurationObjectFact,
    DeviceInventoryFact,
    DeviceLoadDefaultFact,
)

PSEUDO_PROCESS_NODE_NAMES = {"enterprisewidedata"}


@dataclass(frozen=True)
class DevicePoolRecord:
    """Transient device-pool mapping used to enrich device inventory."""

    name: str
    call_manager_group: str | None
    location: str | None
    region: str | None


class XmlElement(Protocol):
    text: str | None
    tag: str

    def iter(self) -> Iterator["XmlElement"]:
        """Iterate over this element and its descendants."""


def parse_process_nodes(response_text: str, publisher_ip: str | None) -> list[CollaborationNode]:
    try:
        root = ET.fromstring(response_text)
    except ET.ParseError as exc:
        raise AxlCollectionError(f"Unable to parse listProcessNode response: {exc}") from exc
    nodes: list[CollaborationNode] = []
    for process_node in _iter_local_name(root, "processNode"):
        name = _child_text(process_node, "name")
        if not name:
            continue
        if _is_pseudo_process_node(name):
            continue
        node_usage = (_child_text(process_node, "nodeUsage") or "").lower()
        role = "publisher" if publisher_ip and name == publisher_ip else "subscriber"
        if "publisher" in node_usage:
            role = "publisher"
        elif "subscriber" in node_usage:
            role = "subscriber"
        nodes.append(
            CollaborationNode(
                name=name,
                address=name,
                role=role,
                reachable=None,
            )
        )
    return nodes


def parse_phone_inventory(response_text: str) -> list[DeviceInventoryFact]:
    try:
        root = ET.fromstring(response_text)
    except ET.ParseError as exc:
        raise AxlCollectionError(f"Unable to parse listPhone response: {exc}") from exc

    devices: list[DeviceInventoryFact] = []
    for phone in _iter_local_name(root, "phone"):
        name = _child_text(phone, "name")
        if not name:
            continue
        devices.append(
            DeviceInventoryFact(
                name=name,
                description=_child_text(phone, "description"),
                model=_child_text(phone, "model"),
                protocol=_child_text(phone, "protocol"),
                device_pool=_child_text(phone, "devicePoolName"),
                call_manager_group=None,
                location=_child_text(phone, "locationName"),
                region=None,
                configured_load=_child_text(phone, "loadInformation"),
                source="AXL.listPhone.summary",
            )
        )
    return devices


def parse_device_load_defaults(response_text: str) -> list[DeviceLoadDefaultFact]:
    try:
        root = ET.fromstring(response_text)
    except ET.ParseError as exc:
        raise AxlCollectionError(f"Unable to parse device-default SQL response: {exc}") from exc

    defaults: list[DeviceLoadDefaultFact] = []
    for device_default in _iter_local_name(root, "row"):
        model = _child_text(device_default, "modelname")
        if not model:
            continue
        defaults.append(
            DeviceLoadDefaultFact(
                model=model,
                protocol=_device_protocol_name(_child_text(device_default, "signalingprotocol")),
                default_load=_child_text(device_default, "devicedefault"),
                configured_model_count=_optional_int(
                    _child_text(device_default, "configuredmodelcount")
                    or _child_text(device_default, "configuredcount")
                ),
                model_code=_child_text(device_default, "tkmodel"),
                source="AXL.executeSQLQuery.deviceDefaults",
            )
        )
    return defaults


def _device_protocol_name(value: str | None) -> str | None:
    return {"0": "SCCP", "11": "SIP", "99": "Media Resource"}.get(value or "", value)


def _optional_int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def parse_configuration_objects(
    response_text: str,
    operation: str,
    returned_tags: tuple[str, ...],
) -> list[ConfigurationObjectFact]:
    """Normalize the bounded, shallow fields returned by a diagnostic AXL list call."""

    try:
        root = ET.fromstring(response_text)
    except ET.ParseError as exc:
        raise AxlCollectionError(f"Unable to parse {operation} response: {exc}") from exc
    object_name = operation.removeprefix("list")
    element_name = object_name[:1].lower() + object_name[1:]
    facts = []
    for element in _iter_local_name(root, element_name):
        values = {tag: _child_text(element, tag) for tag in returned_tags}
        name = values.get("name") or values.get("pattern")
        if not name:
            continue
        details = {
            _configuration_detail_name(tag): value
            for tag, value in values.items()
            if value and tag not in {"name", "pattern"}
        }
        facts.append(
            ConfigurationObjectFact(
                object_type=object_name,
                name=name,
                details=details,
                source=f"AXL.{operation}",
            )
        )
    return facts


def _configuration_detail_name(tag: str) -> str:
    labels = {
        "routePartitionName": "partition",
        "devicePoolName": "device_pool",
        "locationName": "location",
        "sipProfileName": "sip_profile",
        "distributionAlgorithm": "distribution_algorithm",
    }
    return labels.get(tag, tag)


def parse_device_pools(response_text: str) -> list[DevicePoolRecord]:
    try:
        root = ET.fromstring(response_text)
    except ET.ParseError as exc:
        raise AxlCollectionError(f"Unable to parse listDevicePool response: {exc}") from exc

    device_pools: list[DevicePoolRecord] = []
    for device_pool in _iter_local_name(root, "devicePool"):
        name = _child_text(device_pool, "name")
        if not name:
            continue
        device_pools.append(
            DevicePoolRecord(
                name=name,
                call_manager_group=_child_text(device_pool, "callManagerGroupName"),
                location=_child_text(device_pool, "locationName"),
                region=_child_text(device_pool, "regionName"),
            )
        )
    return device_pools


def cluster_name_from_nodes(nodes: list[CollaborationNode], publisher_ip: str) -> str:
    publisher = next((node for node in nodes if node.role == "publisher"), None)
    if publisher:
        return publisher.name
    return publisher_ip


def find_first_text(response_text: str, local_name: str) -> str | None:
    try:
        root = ET.fromstring(response_text)
    except ET.ParseError as exc:
        raise AxlCollectionError(f"Unable to parse AXL response: {exc}") from exc
    element = next(_iter_local_name(root, local_name), None)
    if element is None or element.text is None:
        return None
    return str(element.text).strip()


def _child_text(element: XmlElement, local_name: str) -> str | None:
    child = next(_iter_local_name(element, local_name), None)
    if child is None or child.text is None:
        return None
    text = str(child.text).strip()
    return text or None


def _iter_local_name(element: XmlElement, local_name: str) -> Iterator[XmlElement]:
    for child in element.iter():
        if child.tag.rsplit("}", 1)[-1] == local_name:
            yield child


def _is_pseudo_process_node(name: str) -> bool:
    return name.strip().lower() in PSEUDO_PROCESS_NODE_NAMES
