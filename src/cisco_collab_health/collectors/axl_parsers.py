"""AXL response parsers."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol

from defusedxml import ElementTree as ET

from cisco_collab_health.collectors.axl_errors import AxlCollectionError
from cisco_collab_health.models.facts import CollaborationNode, DeviceInventoryFact

PSEUDO_PROCESS_NODE_NAMES = {"enterprisewidedata"}


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
    return str(child.text).strip()


def _iter_local_name(element: XmlElement, local_name: str) -> Iterator[XmlElement]:
    for child in element.iter():
        if child.tag.rsplit("}", 1)[-1] == local_name:
            yield child


def _is_pseudo_process_node(name: str) -> bool:
    return name.strip().lower() in PSEUDO_PROCESS_NODE_NAMES
