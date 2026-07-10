"""Bounded read-only diagnostic capture across CUCM service interfaces."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Iterator
from xml.sax.saxutils import escape

from defusedxml import ElementTree as ET

from cisco_collab_health.collectors.base import CollectionResult
from cisco_collab_health.models.evidence import EvidenceRef
from cisco_collab_health.models.facts import (
    AssessmentFacts,
    DeviceRegistrationFact,
    PerfCounterFact,
    ServiceStatusFact,
)
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.transport.http import CapturedHttpClient, CapturedHttpError
from cisco_collab_health.transport.soap import (
    SoapClient,
    SoapRequest,
    SoapResponse,
    SoapTransportError,
)

AST_NAMESPACE = "http://schemas.cisco.com/ast/soap"


class DiagnosticCaptureCollector:
    """Capture bounded discovery responses for future parser and collector work."""

    name = "diagnostic_capture"

    def __init__(
        self,
        available_interfaces: Iterable[str],
        *,
        soap_client: SoapClient | None = None,
        http_client: CapturedHttpClient | None = None,
    ) -> None:
        self.available_interfaces = frozenset(available_interfaces)
        self.soap_client = soap_client or SoapClient()
        self.http_client = http_client or CapturedHttpClient()

    def collect(self, context: CollectionContext) -> CollectionResult:
        facts = AssessmentFacts()
        warnings: list[str] = []
        notes: list[str] = []
        evidence: list[EvidenceRef] = []
        status_flags = ["diagnostic_capture.enabled"]

        if context.artifact_store is None:
            return CollectionResult(
                collector_name=self.name,
                facts=facts,
                warnings=[
                    "Diagnostic capture skipped because local artifact storage is disabled."
                ],
                status_flags=[*status_flags, "diagnostic_capture.skipped_no_artifacts"],
            )
        if not context.publisher_ip:
            return CollectionResult(
                collector_name=self.name,
                facts=facts,
                warnings=["Diagnostic capture skipped because Publisher IP is missing."],
                status_flags=[*status_flags, "diagnostic_capture.skipped_no_publisher"],
            )

        nodes = tuple(dict.fromkeys(context.discovered_nodes or (context.publisher_ip,)))
        self._capture_wsdls(context, nodes, evidence, warnings)

        if "risport70" in self.available_interfaces:
            self._capture_risport(context, facts, evidence, warnings)
        if "control_center" in self.available_interfaces:
            self._capture_control_center(context, nodes, facts, evidence, warnings)
        if "perfmon" in self.available_interfaces:
            self._capture_perfmon(context, nodes, facts, evidence, warnings)

        notes.append(
            "Diagnostic capture retains raw evidence and normalizes supported RISPort, "
            "Control Center, and PerfMon responses."
        )
        notes.append(
            f"Diagnostic node scope: {len(nodes)} node(s). RISPort device cap: "
            f"{context.diagnostic_max_devices}."
        )
        return CollectionResult(
            collector_name=self.name,
            facts=facts,
            warnings=warnings,
            evidence=evidence,
            notes=notes,
            status_flags=status_flags,
        )

    def _capture_wsdls(
        self,
        context: CollectionContext,
        nodes: tuple[str, ...],
        evidence: list[EvidenceRef],
        warnings: list[str],
    ) -> None:
        definitions = []
        if "risport70" in self.available_interfaces:
            definitions.append(
                (
                    "risport70",
                    context.risport_port,
                    "/realtimeservice2/services/RISService70?wsdl",
                    "wsdl",
                )
            )
        if "control_center" in self.available_interfaces:
            definitions.extend(
                [
                    (
                        "control_center",
                        context.control_center_port,
                        "/controlcenterservice2/services/ControlCenterServices?wsdl",
                        "wsdl",
                    ),
                    (
                        "control_center_ex",
                        context.control_center_port,
                        "/controlcenterservice2/services/ControlCenterServicesEx?wsdl",
                        "wsdl",
                    ),
                ]
            )
        if "perfmon" in self.available_interfaces:
            definitions.append(
                (
                    "perfmon",
                    context.perfmon_port,
                    "/perfmonservice2/services/PerfmonService?wsdl",
                    "wsdl",
                )
            )

        for node in nodes:
            for interface, port, path, operation in definitions:
                endpoint = f"https://{node}:{port}{path}"
                try:
                    response = self.http_client.get(
                        endpoint,
                        context,
                        node=node,
                        interface=interface,
                        operation=operation,
                    )
                except CapturedHttpError as exc:
                    warnings.append(f"{interface} WSDL capture failed on {node}: {exc}")
                    continue
                evidence.append(
                    EvidenceRef(
                        source=interface.upper(),
                        operation="wsdl",
                        node=node,
                        artifact_path=response.response_artifact_path,
                        parser="raw_diagnostic_capture",
                        confidence="high",
                    )
                )

    def _capture_risport(
        self,
        context: CollectionContext,
        facts: AssessmentFacts,
        evidence: list[EvidenceRef],
        warnings: list[str],
    ) -> None:
        assert context.publisher_ip is not None
        device_names = context.discovered_device_names[: context.diagnostic_max_devices]
        if device_names:
            select_items = "".join(
                "<ast:item><ast:Item>"
                f"{escape(device_name)}"
                "</ast:Item></ast:item>"
                for device_name in device_names
            )
            operation = "selectCmDeviceExt"
        else:
            select_items = "<ast:item><ast:Item>*</ast:Item></ast:item>"
            operation = "selectCmDevice"
            warnings.append(
                "RISPort diagnostic capture is using a wildcard SelectCmDevice fallback "
                "because no AXL device names were available."
            )
        body = f"""<ast:{operation}>
          <ast:StateInfo></ast:StateInfo>
          <ast:CmSelectionCriteria>
            <ast:MaxReturnedDevices>{min(context.diagnostic_max_devices, 2000)}</ast:MaxReturnedDevices>
            <ast:DeviceClass>Any</ast:DeviceClass>
            <ast:Model>255</ast:Model>
            <ast:Status>Any</ast:Status>
            <ast:NodeName></ast:NodeName>
            <ast:SelectBy>Name</ast:SelectBy>
            <ast:SelectItems>{select_items}</ast:SelectItems>
            <ast:Protocol>Any</ast:Protocol>
            <ast:DownloadStatus>Any</ast:DownloadStatus>
          </ast:CmSelectionCriteria>
        </ast:{operation}>"""
        response = self._capture_soap(
            context,
            node=context.publisher_ip,
            endpoint=(
                f"https://{context.publisher_ip}:{context.risport_port}"
                "/realtimeservice2/services/RISService70"
            ),
            interface="risport70",
            operation=operation,
            body=body,
            evidence=evidence,
            warnings=warnings,
        )
        if response is not None:
            facts.registrations.extend(_parse_risport_registrations(response.body))

    def _capture_control_center(
        self,
        context: CollectionContext,
        nodes: tuple[str, ...],
        facts: AssessmentFacts,
        evidence: list[EvidenceRef],
        warnings: list[str],
    ) -> None:
        operations = (
            (
                "getProductInformationList",
                "<ast:getProductInformationList><ast:ServiceInfo></ast:ServiceInfo>"
                "</ast:getProductInformationList>",
            ),
            (
                "soapGetServiceStatus",
                "<ast:soapGetServiceStatus><ast:ServiceStatus></ast:ServiceStatus>"
                "</ast:soapGetServiceStatus>",
            ),
        )
        for node in nodes:
            endpoint = (
                f"https://{node}:{context.control_center_port}"
                "/controlcenterservice2/services/ControlCenterServices"
            )
            for operation, body in operations:
                response = self._capture_soap(
                    context,
                    node=node,
                    endpoint=endpoint,
                    interface="control_center",
                    operation=operation,
                    body=body,
                    evidence=evidence,
                    warnings=warnings,
                )
                if response is not None and operation == "soapGetServiceStatus":
                    facts.services.extend(_parse_service_status(response.body, node))

    def _capture_perfmon(
        self,
        context: CollectionContext,
        nodes: tuple[str, ...],
        facts: AssessmentFacts,
        evidence: list[EvidenceRef],
        warnings: list[str],
    ) -> None:
        baseline_objects = ("Processor", "Memory", "Cisco CallManager")
        for node in nodes:
            escaped_node = escape(node)
            endpoint = (
                f"https://{node}:{context.perfmon_port}"
                "/perfmonservice2/services/PerfmonService"
            )
            discovery = self._capture_soap(
                context,
                node=node,
                endpoint=endpoint,
                interface="perfmon",
                operation="perfmonListCounter",
                body=(
                    "<ast:perfmonListCounter>"
                    f"<ast:Host>{escaped_node}</ast:Host>"
                    "</ast:perfmonListCounter>"
                ),
                evidence=evidence,
                warnings=warnings,
            )
            if discovery is None:
                continue
            for object_name in baseline_objects:
                artifact_operation = "perfmonCollectCounterData_" + _safe_operation(object_name)
                body = (
                    "<ast:perfmonCollectCounterData>"
                    f"<ast:Host>{escaped_node}</ast:Host>"
                    f"<ast:Object>{object_name}</ast:Object>"
                    "</ast:perfmonCollectCounterData>"
                )
                response = self._capture_soap(
                    context,
                    node=node,
                    endpoint=endpoint,
                    interface="perfmon",
                    operation="perfmonCollectCounterData",
                    artifact_operation=artifact_operation,
                    body=body,
                    evidence=evidence,
                    warnings=warnings,
                )
                if response is not None:
                    facts.perf_counters.extend(
                        _parse_perf_counters(response.body, node, object_name)
                    )

    def _capture_soap(
        self,
        context: CollectionContext,
        *,
        node: str,
        endpoint: str,
        interface: str,
        operation: str,
        body: str,
        evidence: list[EvidenceRef],
        warnings: list[str],
        artifact_operation: str | None = None,
    ) -> SoapResponse | None:
        request = SoapRequest(
            endpoint=endpoint,
            body=body,
            operation=operation,
            interface=interface,
            node=node,
            namespace=AST_NAMESPACE,
            namespace_prefix="ast",
            action=operation,
            artifact_operation=artifact_operation,
        )
        try:
            response = self.soap_client.send(request, context)
        except SoapTransportError as exc:
            warnings.append(f"{interface} {operation} failed on {node}: {exc}")
            return None
        evidence.append(_soap_evidence(response, node))
        return response


def _soap_evidence(response: SoapResponse, node: str) -> EvidenceRef:
    return EvidenceRef(
        source=response.interface.upper(),
        operation=response.operation,
        node=node,
        artifact_path=response.response_artifact_path,
        parser="raw_diagnostic_capture",
        confidence="high",
    )


def _safe_operation(value: str) -> str:
    return "_".join(value.lower().split())


def _parse_risport_registrations(response_text: str) -> list[DeviceRegistrationFact]:
    root = _xml_root(response_text)
    if root is None:
        return []
    registrations = []
    for cm_node in _elements(root, "CmNodes"):
        for node_item in _direct_children(cm_node, "item"):
            node_name = _child_text(node_item, "Name")
            for devices in _direct_children(node_item, "CmDevices"):
                for device in _direct_children(devices, "item"):
                    name = _child_text(device, "Name")
                    status = _child_text(device, "Status")
                    if not name or not status:
                        continue
                    ip_address = None
                    ip_container = next(iter(_direct_children(device, "IPAddress")), None)
                    if ip_container is not None:
                        ip_item = next(iter(_direct_children(ip_container, "item")), None)
                        if ip_item is not None:
                            ip_address = _child_text(ip_item, "IP")
                    registrations.append(DeviceRegistrationFact(
                        name=name, status=status, registered_node=node_name,
                        ip_address=ip_address, model=_child_text(device, "Model"),
                        protocol=_child_text(device, "Protocol"),
                        source="RISPort70.selectCmDeviceExt",
                    ))
    return registrations


def _parse_service_status(response_text: str, node: str) -> list[ServiceStatusFact]:
    root = _xml_root(response_text)
    if root is None:
        return []
    facts = []
    for container in _elements(root, "ServiceInfoList"):
        for item in _direct_children(container, "item"):
            name = _child_text(item, "ServiceName")
            status = _child_text(item, "ServiceStatus")
            if not name or not status:
                continue
            uptime_text = _child_text(item, "UpTime")
            try:
                uptime = int(uptime_text) if uptime_text and int(uptime_text) >= 0 else None
            except ValueError:
                uptime = None
            facts.append(ServiceStatusFact(
                node=node, service_name=name, activated=None, status=status,
                uptime_seconds=uptime, source="ControlCenter.soapGetServiceStatus",
            ))
    return facts


def _parse_perf_counters(response_text: str, node: str, object_name: str) -> list[PerfCounterFact]:
    root = _xml_root(response_text)
    if root is None:
        return []
    facts = []
    for item in _elements(root, "perfmonCollectCounterDataReturn"):
        name = _child_text(item, "Name")
        value = _child_text(item, "Value")
        status = _child_text(item, "CStatus")
        if not name or value is None or status not in {"0", "1"}:
            continue
        try:
            parsed_value: float | int | str = int(value)
        except ValueError:
            try:
                parsed_value = float(value)
            except ValueError:
                parsed_value = value
        facts.append(PerfCounterFact(
            node=node, object_name=object_name, counter_name=name.split("\\")[-1],
            instance=None, value=parsed_value, sample_count=1,
            source="PerfMon.perfmonCollectCounterData",
        ))
    return facts


def _xml_root(response_text: str) -> Any | None:
    try:
        return ET.fromstring(response_text)
    except ET.ParseError:
        return None


def _local_name(element: Any) -> str:
    return str(element.tag).rsplit("}", 1)[-1]


def _elements(root: Any, name: str) -> Iterator[Any]:
    return (element for element in root.iter() if _local_name(element) == name)


def _direct_children(element: Any, name: str) -> Iterator[Any]:
    return (child for child in element if _local_name(child) == name)


def _child_text(element: Any, name: str) -> str | None:
    child = next(_direct_children(element, name), None)
    if child is None or child.text is None:
        return None
    text = child.text.strip()
    return text or None
