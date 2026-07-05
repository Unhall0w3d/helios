"""AXL collector."""

from __future__ import annotations

from cisco_collab_health.collectors.axl_bodies import (
    get_ccm_version_body,
    list_phone_body,
    list_process_node_body,
)
from cisco_collab_health.collectors.axl_errors import AxlCollectionError, AxlVersionError
from cisco_collab_health.collectors.axl_parsers import (
    cluster_name_from_nodes,
    find_first_text,
    parse_phone_inventory,
    parse_process_nodes,
)
from cisco_collab_health.collectors.axl_version import (
    AxlVersionPolicy,
    is_incorrect_axl_version_response,
    response_summary,
    supported_axl_versions,
)
from cisco_collab_health.collectors.base import CollectionContext, CollectionResult
from cisco_collab_health.models.evidence import EvidenceRef
from cisco_collab_health.models.facts import (
    AssessmentFacts,
    ClusterIdentity,
    CollaborationNode,
)
from cisco_collab_health.transport.soap import (
    SoapClient,
    SoapHttpError,
    SoapRequest,
    SoapResponse,
    SoapTransportError,
)


class AxlCollector:
    """Collects CUCM facts through the Publisher AXL API.

    The first real implementation target is cluster node discovery. It should
    connect to the Publisher using GUI/API credentials from ``CollectionContext``
    and populate normalized ``CollaborationNode`` facts for the Publisher and
    Subscribers before health rules run.
    """

    name = "axl"

    def __init__(
        self,
        soap_client: SoapClient | None = None,
        version_policy: AxlVersionPolicy | None = None,
    ) -> None:
        self.soap_client = soap_client or SoapClient()
        self.version_policy = version_policy or AxlVersionPolicy()
        self._winning_axl_version: str | None = None

    def collect(self, context: CollectionContext) -> CollectionResult:
        warnings: list[str] = []
        evidence: list[EvidenceRef] = []
        notes: list[str] = []
        facts = AssessmentFacts()

        if not context.publisher_ip:
            return CollectionResult(
                collector_name=self.name,
                facts=facts,
                warnings=["AXL collection skipped because Publisher IP is missing."],
            )
        if not context.gui_username or not context.gui_password:
            return CollectionResult(
                collector_name=self.name,
                facts=facts,
                warnings=["AXL collection skipped because GUI/API credentials are missing."],
            )

        try:
            version_response = self._call_axl_response(
                context,
                "getCCMVersion",
                get_ccm_version_body(),
            )
            evidence.append(_evidence_from_soap_response(version_response, context.publisher_ip))
            version = find_first_text(version_response.body, "version") or "unknown"
            facts.cluster = ClusterIdentity(
                name=context.publisher_ip,
                product="Cisco Unified Communications Manager",
                version=version,
            )
        except AxlCollectionError as exc:
            warnings.append(f"AXL getCCMVersion failed: {exc}")

        try:
            process_node_response = self._call_axl_response(
                context,
                "listProcessNode",
                list_process_node_body(),
            )
            evidence.append(
                _evidence_from_soap_response(process_node_response, context.publisher_ip)
            )
            facts.nodes.extend(
                parse_process_nodes(process_node_response.body, context.publisher_ip)
            )
        except AxlCollectionError as exc:
            warnings.append(f"AXL listProcessNode failed: {exc}")

        if context.collect_phone_inventory:
            self._collect_phone_inventory(context, facts, warnings, evidence, notes)
            notes.append(
                "AXL listDeviceDefaults collection is temporarily disabled until the "
                "CUCM 15 search criteria are validated from live output."
            )
        else:
            notes.append(
                "AXL phone inventory skipped by default; use --collect-phone-inventory "
                "to collect bounded listPhone inventory."
            )

        if facts.cluster is not None and facts.nodes:
            facts.cluster = ClusterIdentity(
                name=cluster_name_from_nodes(facts.nodes, context.publisher_ip),
                product=facts.cluster.product,
                version=facts.cluster.version,
            )

        return CollectionResult(
            collector_name=self.name,
            facts=facts,
            warnings=warnings,
            evidence=evidence,
            notes=notes,
        )

    def discover_nodes(self, context: CollectionContext) -> list[CollaborationNode]:
        """Discover Publisher and Subscriber nodes from Publisher API data."""

        response = self._call_axl(context, "listProcessNode", list_process_node_body())
        return parse_process_nodes(response, context.publisher_ip)

    def _collect_phone_inventory(
        self,
        context: CollectionContext,
        facts: AssessmentFacts,
        warnings: list[str],
        evidence: list[EvidenceRef],
        notes: list[str],
    ) -> None:
        page_size = max(1, context.phone_inventory_page_size)
        max_devices = max(1, context.phone_inventory_max_devices)
        unique_device_names: set[str] = set()
        skip = 0

        while len(unique_device_names) < max_devices:
            first = min(page_size, max_devices - len(unique_device_names))
            artifact_operation = f"listPhone_page_{skip:06d}"
            try:
                phone_response = self._call_axl_response(
                    context,
                    "listPhone",
                    list_phone_body(first=first, skip=skip),
                    artifact_operation=artifact_operation,
                )
            except AxlCollectionError as exc:
                warnings.append(f"AXL listPhone failed: {exc}")
                return

            evidence.append(_evidence_from_soap_response(phone_response, context.publisher_ip))
            try:
                devices = parse_phone_inventory(phone_response.body)
            except AxlCollectionError as exc:
                warnings.append(f"AXL listPhone failed: {exc}")
                return
            if not devices:
                break

            new_devices = []
            for device in devices:
                device_key = device.name.strip().lower()
                if device_key in unique_device_names:
                    continue
                unique_device_names.add(device_key)
                new_devices.append(device)

            if not new_devices:
                notes.append(
                    "AXL listPhone paging returned only duplicate device names; stopping "
                    "inventory paging because first/skip was not honored by the response."
                )
                break

            facts.devices.extend(new_devices)
            if len(devices) < first:
                break
            skip += len(devices)

        if len(unique_device_names) >= max_devices:
            notes.append(
                "AXL phone inventory reached configured maximum device limit "
                f"({max_devices}); increase --phone-inventory-max-devices if needed."
            )

    def _call_axl(self, context: CollectionContext, operation: str, body: str) -> str:
        return self._call_axl_response(context, operation, body).body

    def _call_axl_response(
        self,
        context: CollectionContext,
        operation: str,
        body: str,
        *,
        artifact_operation: str | None = None,
    ) -> SoapResponse:
        if not context.publisher_ip:
            raise AxlCollectionError("Publisher IP is missing.")
        if not context.gui_username or not context.gui_password:
            raise AxlCollectionError("GUI/API credentials are missing.")

        attempted_versions: set[str] = set()
        candidates = list(self.version_policy.candidates())
        if self._winning_axl_version is not None:
            candidates = [
                self._winning_axl_version,
                *[version for version in candidates if version != self._winning_axl_version],
            ]

        last_error: Exception | None = None
        while candidates:
            axl_version = candidates.pop(0)
            if axl_version in attempted_versions:
                continue
            retry_artifact_operation = (
                None
                if not attempted_versions
                else f"{operation}_retry_axl_{axl_version}"
            )
            request_artifact_operation = artifact_operation or retry_artifact_operation
            attempted_versions.add(axl_version)
            try:
                response = self._send_axl_request(
                    context,
                    operation,
                    body,
                    axl_version,
                    artifact_operation=request_artifact_operation,
                )
                self._winning_axl_version = axl_version
                return response
            except AxlVersionError as exc:
                last_error = exc
                retry_version = self.version_policy.best_supported_version(
                    exc.supported_versions,
                    attempted_versions,
                )
                if retry_version and retry_version not in attempted_versions:
                    if retry_version not in candidates:
                        candidates.insert(0, retry_version)

        attempted = ", ".join(sorted(attempted_versions)) or "none"
        raise AxlCollectionError(
            f"No supported AXL schema version succeeded for {operation}. "
            f"Attempted versions: {attempted}. Last error: {last_error}"
        )

    def _send_axl_request(
        self,
        context: CollectionContext,
        operation: str,
        body: str,
        axl_version: str,
        *,
        artifact_operation: str | None = None,
    ) -> SoapResponse:
        publisher_ip = context.publisher_ip
        if not publisher_ip:
            raise AxlCollectionError("Publisher IP is missing.")

        endpoint = f"https://{publisher_ip}:{context.axl_port}/axl/"
        request = SoapRequest(
            endpoint,
            body=body,
            namespace=f"http://www.cisco.com/AXL/API/{axl_version}",
            operation=operation,
            interface="axl",
            node=publisher_ip,
            action=f'CUCM:DB ver={axl_version} "{operation}"',
            namespace_prefix="axl",
            artifact_operation=artifact_operation,
        )

        try:
            return self.soap_client.send(request, context)
        except SoapHttpError as exc:
            supported_versions = supported_axl_versions(exc.body)
            if is_incorrect_axl_version_response(exc.body) and supported_versions:
                raise AxlVersionError(
                    attempted_version=axl_version,
                    supported_versions=supported_versions,
                    response_summary=response_summary(exc.body),
                ) from exc
            raise AxlCollectionError(f"HTTP {exc.status}: {response_summary(exc.body)}") from exc
        except SoapTransportError as exc:
            raise AxlCollectionError(str(exc)) from exc


def _evidence_from_soap_response(response: SoapResponse, node: str | None) -> EvidenceRef:
    return EvidenceRef(
        source=response.interface.upper(),
        operation=response.operation,
        node=node,
        artifact_path=response.response_artifact_path,
        parser="cisco_collab_health.collectors.axl",
        confidence="high",
    )
