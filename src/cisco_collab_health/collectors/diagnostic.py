"""Bounded read-only diagnostic capture across CUCM service interfaces."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from time import sleep as default_sleep
from typing import Any, Iterator
from xml.sax.saxutils import escape

from defusedxml import ElementTree as ET

from cisco_collab_health.collectors.base import CollectionResult
from cisco_collab_health.models.evidence import EvidenceRef
from cisco_collab_health.models.facts import (
    AssessmentFacts,
    CertificateFact,
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

MANDATORY_TRUST_STORES = {"phone-sast-trust", "phone-vpn-trust"}


def parse_certificate_snapshot(payload: str, node: str) -> list[CertificateFact]:
    """Defensively normalize certificate metadata from Cisco's versioned JSON."""

    document = json.loads(payload)
    candidates = [item for item in _walk_json(document) if _looks_like_certificate(item)]
    facts = []
    for item in candidates:
        name = _json_value(item, "name", "certificateName", "certName", "alias")
        service = _json_value(item, "service", "serviceName", "certificatePurpose", "type")
        store = _json_value(item, "store", "storeName", "trustStore", "category")
        if not name:
            name = service or store
        if not name:
            continue
        subject = _json_value(item, "subject", "subjectName", "subjectDN")
        issuer = _json_value(item, "issuer", "issuerName", "issuerDN")
        valid_until = _json_value(item, "validUntil", "notAfter", "expiryDate", "expiresOn")
        kind = "trust" if "trust" in " ".join(filter(None, (name, service, store))).lower() else "identity"
        facts.append(CertificateFact(
            node=node, name=name, service=service, store=store, certificate_kind=kind,
            subject=subject, issuer=issuer,
            serial_number=_json_value(item, "serialNumber", "serial"),
            valid_from=_json_value(item, "validFrom", "notBefore"), valid_until=valid_until,
            days_remaining=_days_remaining(valid_until),
            self_signed=(subject == issuer if subject and issuer else None),
            key_type=_json_value(item, "keyType", "publicKeyAlgorithm"),
            key_size=_json_value(item, "keySize", "keyLength"),
            signature_algorithm=_json_value(item, "signatureAlgorithm", "signatureAlg"),
            subject_key_identifier=_json_value(item, "subjectKeyIdentifier", "ski"),
            authority_key_identifier=_json_value(item, "authorityKeyIdentifier", "aki"),
            intermediate=None, root=None, chain_status=None,
            source="CertificateManagementREST.snapshot_server",
        ))
    return _resolve_certificate_chains(facts)


def _walk_json(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json(child)


def _looks_like_certificate(item: dict[str, Any]) -> bool:
    keys = {key.lower() for key in item}
    return bool(keys & {"notafter", "validuntil", "expirydate", "expireson"}) and bool(
        keys & {"name", "certificatename", "certname", "service", "servicename", "alias"}
    )


def _json_value(item: dict[str, Any], *aliases: str) -> str | None:
    normalized = {key.lower(): value for key, value in item.items()}
    for alias in aliases:
        value = normalized.get(alias.lower())
        if value is not None and not isinstance(value, (dict, list)):
            text = str(value).strip()
            if text:
                return text
    return None


def _days_remaining(value: str | None) -> int | None:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        expires = datetime.fromisoformat(text)
    except ValueError:
        for pattern in ("%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S %Y %Z"):
            try:
                expires = datetime.strptime(value, pattern).replace(tzinfo=UTC)
                break
            except ValueError:
                continue
        else:
            return None
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return (expires.astimezone(UTC).date() - datetime.now(UTC).date()).days


def _resolve_certificate_chains(facts: list[CertificateFact]) -> list[CertificateFact]:
    by_subject = {fact.subject: fact for fact in facts if fact.subject}
    resolved = []
    for fact in facts:
        if fact.self_signed:
            resolved.append(replace(fact, root=fact.subject, chain_status="self-signed"))
            continue
        issuer = by_subject.get(fact.issuer) if fact.issuer else None
        if issuer is None:
            resolved.append(replace(fact, chain_status="unresolved"))
        elif issuer.self_signed:
            resolved.append(replace(fact, root=issuer.subject, chain_status="complete"))
        else:
            root = by_subject.get(issuer.issuer) if issuer.issuer else None
            resolved.append(replace(
                fact, intermediate=issuer.subject,
                root=root.subject if root and root.self_signed else None,
                chain_status="complete" if root and root.self_signed else "incomplete",
            ))
    return resolved


class DiagnosticCaptureCollector:
    """Capture bounded discovery responses for future parser and collector work."""

    name = "diagnostic_capture"

    def __init__(
        self,
        available_interfaces: Iterable[str],
        *,
        soap_client: SoapClient | None = None,
        http_client: CapturedHttpClient | None = None,
        sleep: Callable[[float], None] = default_sleep,
    ) -> None:
        self.available_interfaces = frozenset(available_interfaces)
        self.soap_client = soap_client or SoapClient()
        self.http_client = http_client or CapturedHttpClient()
        self.sleep = sleep

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
        self._capture_certificates(context, nodes, facts, evidence, warnings)

        if "risport70" in self.available_interfaces:
            self._capture_risport(context, facts, evidence, warnings)
        if "control_center" in self.available_interfaces:
            self._capture_control_center(context, nodes, facts, evidence, warnings)
        if "perfmon" in self.available_interfaces:
            self._capture_perfmon(context, nodes, facts, evidence, warnings)

        notes.append(
            "Diagnostic capture retains raw evidence and normalizes supported RISPort, "
            "Control Center, PerfMon, and Certificate Management REST responses."
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

    def _capture_certificates(
        self,
        context: CollectionContext,
        nodes: tuple[str, ...],
        facts: AssessmentFacts,
        evidence: list[EvidenceRef],
        warnings: list[str],
    ) -> None:
        if not context.os_username or not context.os_password:
            return
        for node in nodes:
            endpoint = f"https://{node}/platformcom/api/v1/certmgr/config/snapshot/server"
            try:
                response = self.http_client.get(
                    endpoint, context, node=node, interface="certificate_management",
                    operation="snapshot_server", credential_kind="os",
                )
            except CapturedHttpError as exc:
                detail = str(exc)
                if "HTTP 401" in detail:
                    detail += (
                        " (CMPlatform Realm rejected the stored OS credentials; verify the "
                        "profile or use a read-only privilege-0 platform account)"
                    )
                warnings.append(f"Certificate Management API failed on {node}: {detail}")
                continue
            evidence.append(EvidenceRef(
                source="CertificateManagementREST", operation="snapshot_server", node=node,
                artifact_path=response.response_artifact_path,
                parser="cisco_collab_health.collectors.diagnostic.parse_certificate_snapshot",
                confidence="high",
            ))
            try:
                facts.certificates.extend(parse_certificate_snapshot(response.body, node))
            except (json.JSONDecodeError, ValueError) as exc:
                warnings.append(f"Certificate snapshot parsing failed on {node}: {exc}")

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
            catalog: dict[str, ServiceCatalogRecord] = {}
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
                if response is not None and operation == "getProductInformationList":
                    catalog = {
                        record.service_name.strip().lower(): record
                        for record in _parse_service_catalog(response.body)
                    }
                if response is not None and operation == "soapGetServiceStatus":
                    services = _parse_service_status(response.body, node)
                    facts.services.extend(
                        _enrich_service_status(service, catalog) for service in services
                    )

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
            samples: dict[tuple[str, str, str | None], PerfCounterFact] = {}
            for sample_number in (1, 2):
                if sample_number > 1:
                    self.sleep(1.0)
                for object_name in baseline_objects:
                    artifact_operation = (
                        "perfmonCollectCounterData_"
                        + _safe_operation(object_name)
                        + f"_sample_{sample_number:03d}"
                    )
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
                    if response is None:
                        continue
                    for counter in _parse_perf_counters(response.body, node, object_name):
                        key = (counter.object_name, counter.counter_name, counter.instance)
                        previous = samples.get(key)
                        samples[key] = replace(
                            counter,
                            sample_count=(previous.sample_count if previous else 0) + 1,
                        )
            facts.perf_counters.extend(samples.values())

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
                    model_code = _child_text(device, "Model")
                    registrations.append(
                        DeviceRegistrationFact(
                            name=name,
                            status=status,
                            registered_node=node_name,
                            ip_address=ip_address,
                            model=model_code,
                            protocol=_child_text(device, "Protocol"),
                            source="RISPort70.selectCmDeviceExt",
                            runtime_model_code=model_code,
                            device_class=_child_text(device, "DeviceClass"),
                            active_load=_child_text(device, "ActiveLoadID"),
                            inactive_load=_child_text(device, "InactiveLoadID"),
                            download_status=_child_text(device, "DownloadStatus"),
                            download_failure_reason=_child_text(
                                device, "DownloadFailureReason"
                            ),
                            registration_attempts=_optional_int(
                                _child_text(device, "RegistrationAttempts")
                            ),
                            status_reason=_child_text(device, "StatusReason"),
                            directory_numbers=_directory_numbers(
                                _child_text(device, "DirNumber")
                            ),
                            login_user_id=_child_text(device, "LoginUserId"),
                            timestamp=_child_text(device, "TimeStamp"),
                        )
                    )
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
                start_time=_child_text(item, "StartTime"),
                reason_code=_child_text(item, "ReasonCode"),
                reason=_child_text(item, "ReasonCodeString") or _child_text(item, "ReasonString"),
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
        counter_name, instance = _perf_counter_identity(name, object_name)
        facts.append(
            PerfCounterFact(
                node=node,
                object_name=object_name,
                counter_name=counter_name,
                instance=instance,
                value=parsed_value,
                sample_count=1,
                source="PerfMon.perfmonCollectCounterData",
            )
        )
    return facts


@dataclass(frozen=True)
class ServiceCatalogRecord:
    service_name: str
    service_type: str | None
    group_name: str | None
    product_id: str | None
    deployable: bool | None
    dependent_services: tuple[str, ...]


def _parse_service_catalog(response_text: str) -> list[ServiceCatalogRecord]:
    root = _xml_root(response_text)
    if root is None:
        return []
    records = []
    for container in _elements(root, "Services"):
        for item in _direct_children(container, "item"):
            name = _child_text(item, "ServiceName")
            if not name:
                continue
            dependent_services = tuple(
                service.text.strip()
                for dependent in _direct_children(item, "DependentServices")
                for service in _direct_children(dependent, "Service")
                if service.text and service.text.strip()
            )
            deployable_text = (_child_text(item, "Deployable") or "").lower()
            records.append(
                ServiceCatalogRecord(
                    service_name=name,
                    service_type=_child_text(item, "ServiceType"),
                    group_name=_child_text(item, "GroupName"),
                    product_id=_child_text(item, "ProductID"),
                    deployable=(
                        True if deployable_text == "true" else False if deployable_text == "false" else None
                    ),
                    dependent_services=dependent_services,
                )
            )
    return records


def _enrich_service_status(
    service: ServiceStatusFact,
    catalog: dict[str, ServiceCatalogRecord],
) -> ServiceStatusFact:
    record = catalog.get(service.service_name.strip().lower())
    if record is None:
        return service
    return replace(
        service,
        service_type=record.service_type,
        group_name=record.group_name,
        product_id=record.product_id,
        deployable=record.deployable,
        dependent_services=record.dependent_services,
    )


def _optional_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _directory_numbers(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _perf_counter_identity(name: str, object_name: str) -> tuple[str, str | None]:
    components = [component for component in name.split("\\") if component]
    counter_name = components[-1] if components else name
    object_component = components[-2] if len(components) > 1 else object_name
    prefix = object_name + "("
    if object_component.startswith(prefix) and object_component.endswith(")"):
        return counter_name, object_component[len(prefix) : -1] or None
    return counter_name, None


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
