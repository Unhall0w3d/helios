"""AXL collector implementation."""

from __future__ import annotations

from dataclasses import replace
from defusedxml import ElementTree as ET

from cisco_collab_health.collectors.axl.bodies import (
    DEVICE_DEFAULTS_SQL,
    ROUTE_PATTERN_RELATIONSHIPS_SQL,
    diagnostic_get_body,
    diagnostic_list_body,
    execute_sql_query_body,
    get_ccm_version_body,
    list_device_pool_body,
    list_phone_body,
    list_process_node_body,
)
from cisco_collab_health.collectors.axl.errors import AxlCollectionError, AxlVersionError
from cisco_collab_health.collectors.axl.parsers import (
    DevicePoolRecord,
    cluster_name_from_nodes,
    find_first_text,
    parse_configuration_objects,
    parse_configuration_object_details,
    parse_device_load_defaults,
    parse_device_pools,
    parse_phone_inventory,
    parse_process_nodes,
    parse_line_forwarding,
    parse_route_pattern_relationships,
)
from cisco_collab_health.collectors.axl.version import (
    AxlVersionPolicy,
    is_incorrect_axl_version_response,
    response_summary,
    supported_axl_versions,
)
from cisco_collab_health.collectors.base import CollectionResult
from cisco_collab_health.models.evidence import EvidenceRef
from cisco_collab_health.models.facts import (
    AssessmentFacts,
    ClusterIdentity,
    CollaborationNode,
    ConfigurationObjectFact,
    DeviceInventoryFact,
)
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.transport.soap import (
    SoapClient,
    SoapHttpError,
    SoapRequest,
    SoapResponse,
    SoapTransportError,
)

STATUS_PHONE_INVENTORY_SKIPPED = "axl.phone_inventory.skipped"

DIAGNOSTIC_AXL_OPERATIONS = (
    ("listCallManagerGroup", "name", ("name",)),
    ("listRegion", "name", ("name",)),
    ("listLocation", "name", ("name",)),
    (
        "listSipTrunk",
        "name",
        (
            "name", "description", "devicePoolName", "locationName", "sipProfileName",
            "securityProfileName",
        ),
    ),
    ("listSipProfile", "name", ("name", "description")),
    (
        "listSipTrunkSecurityProfile", "name",
        ("name", "description", "deviceSecurityMode", "incomingTransport", "outgoingTransport"),
    ),
    (
        "listRoutePattern", "pattern",
        (
            "pattern", "routePartitionName", "routeFilterName", "dialPlanName",
            "gatewayOrRouteListName",
        ),
    ),
    ("listRoutePartition", "name", ("name", "description")),
    ("listCss", "name", ("name", "description", "members/member/routePartitionName")),
    ("listRouteGroup", "name", ("name", "distributionAlgorithm", "members/member/deviceName")),
    ("listRouteList", "name", ("name", "description", "members/member/routeGroupName")),
    ("listTransPattern", "pattern", ("pattern", "routePartitionName")),
    (
        "listHuntPilot", "pattern",
        ("pattern", "routePartitionName", "huntListName", "alertingName"),
    ),
    (
        "listHuntList", "name",
        ("name", "description", "callManagerGroupName"),
    ),
    (
        "listLineGroup", "name",
        ("name", "distributionAlgorithm"),
    ),
    (
        "listLdapDirectory", "name",
        ("name", "ldapDn", "userSearchBase", "active", "repeatInterval", "nextSyncTime"),
    ),
    (
        "listPhoneSecurityProfile", "name",
        ("name", "description", "deviceSecurityMode", "authenticationMode", "keySize"),
    ),
    ("listMediaResourceGroup", "name", ("name", "multicast")),
    ("listMediaResourceList", "name", ("name",)),
    ("listConferenceBridge", "name", ("name", "devicePoolName")),
    ("listTranscoder", "name", ("name", "devicePoolName")),
    ("listMtp", "name", ("name", "devicePoolName")),
)

DIAGNOSTIC_AXL_GET_RELATIONSHIPS = {
    "Css": ("getCss", ("members/member/routePartitionName",)),
    "RouteGroup": ("getRouteGroup", ("members/member/deviceName",)),
    "RouteList": ("getRouteList", ("members/member/routeGroupName",)),
    "SipTrunk": (
        "getSipTrunk",
        ("securityProfileName", "destinations/destination/address", "destinations/destination/port"),
    ),
    "HuntList": ("getHuntList", ("members/member/lineGroupName",)),
    "LineGroup": (
        "getLineGroup",
        ("members/member/directoryNumber", "members/member/routePartitionName"),
    ),
    "MediaResourceGroup": ("getMediaResourceGroup", ("members/member/deviceName",)),
    "MediaResourceList": (
        "getMediaResourceList", ("members/member/mediaResourceGroupName",),
    ),
}


LINE_FORWARDING_SQL = """select first 500
n.pkid as lineuuid, n.dnorpattern as pattern, rp.name as partition,
cfd.cfadestination as forwardall, cfd.cfavoicemailenabled as forwardallvoicemail
from numplan as n
inner join callforwarddynamic as cfd on cfd.fknumplan=n.pkid
left join routepartition as rp on rp.pkid=n.fkroutepartition
where cfd.cfadestination is not null and cfd.cfadestination != ''
order by n.pkid"""


class AxlCollector:
    """Collects CUCM facts through the Publisher AXL API."""

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
        status_flags: list[str] = []
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

        if context.collect_phone_inventory or context.diagnostic_capture:
            self._collect_phone_inventory(context, facts, warnings, evidence, notes)
            if facts.devices:
                self._collect_device_pool_enrichment(context, facts, warnings, evidence)
            self._collect_device_load_defaults(context, facts, warnings, evidence)
        else:
            status_flags.append(STATUS_PHONE_INVENTORY_SKIPPED)
            notes.append(
                "AXL phone inventory skipped by default; use --collect-phone-inventory "
                "to collect bounded listPhone inventory."
            )

        if context.diagnostic_capture:
            self._collect_diagnostic_axl(context, facts, warnings, evidence, notes)
            self._collect_line_forwarding_sql(context, facts, warnings, evidence, notes)
            self._enrich_diagnostic_relationships(context, facts, warnings, evidence, notes)
            self._enrich_route_pattern_relationships_sql(
                context, facts, warnings, evidence, notes,
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
            status_flags=status_flags,
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
                    "AXL listPhone broad query returned duplicate device names on a later "
                    "page; treating the first unique result set as complete."
                )
                break

            facts.devices.extend(new_devices)
            if len(devices) > first:
                notes.append(
                    "AXL listPhone broad query returned more devices than the requested "
                    "page size; treating the returned unique result set as complete."
                )
                break
            if len(devices) < first:
                break
            skip += len(devices)

        if len(unique_device_names) >= max_devices:
            notes.append(
                "AXL phone inventory reached configured maximum device limit "
                f"({max_devices}); increase --phone-inventory-max-devices if needed."
            )

    def _collect_device_pool_enrichment(
        self,
        context: CollectionContext,
        facts: AssessmentFacts,
        warnings: list[str],
        evidence: list[EvidenceRef],
    ) -> None:
        try:
            device_pool_response = self._call_axl_response(
                context,
                "listDevicePool",
                list_device_pool_body(),
            )
        except AxlCollectionError as exc:
            warnings.append(f"AXL listDevicePool failed: {exc}")
            return

        evidence.append(_evidence_from_soap_response(device_pool_response, context.publisher_ip))
        try:
            device_pools = parse_device_pools(device_pool_response.body)
        except AxlCollectionError as exc:
            warnings.append(f"AXL listDevicePool failed: {exc}")
            return

        facts.devices = _enrich_devices_from_device_pools(facts.devices, device_pools)
        facts.configuration_objects.extend(
            ConfigurationObjectFact(
                object_type="DevicePool",
                name=device_pool.name,
                details={
                    key: value
                    for key, value in {
                        "call_manager_group": device_pool.call_manager_group,
                        "location": device_pool.location,
                        "region": device_pool.region,
                    }.items()
                    if value
                },
                source="AXL.listDevicePool",
            )
            for device_pool in device_pools
        )

    def _collect_device_load_defaults(
        self,
        context: CollectionContext,
        facts: AssessmentFacts,
        warnings: list[str],
        evidence: list[EvidenceRef],
    ) -> None:
        if not facts.devices:
            return
        try:
            defaults_response = self._call_axl_response(
                context,
                "executeSQLQuery",
                execute_sql_query_body(DEVICE_DEFAULTS_SQL),
                artifact_operation="deviceDefaults_executeSQLQuery",
            )
        except AxlCollectionError as exc:
            warnings.append(f"AXL device-default SQL query failed: {exc}")
            return
        evidence.append(_evidence_from_soap_response(defaults_response, context.publisher_ip))
        try:
            facts.device_load_defaults.extend(
                parse_device_load_defaults(defaults_response.body)
            )
        except AxlCollectionError as exc:
            warnings.append(f"AXL device-default SQL query failed: {exc}")

    def _collect_diagnostic_axl(
        self,
        context: CollectionContext,
        facts: AssessmentFacts,
        warnings: list[str],
        evidence: list[EvidenceRef],
        notes: list[str],
    ) -> None:
        page_size = max(1, context.diagnostic_axl_page_size)
        max_records = max(1, context.diagnostic_axl_max_records)
        for operation, criteria_tag, returned_tags in DIAGNOSTIC_AXL_OPERATIONS:
            captured = 0
            while captured < max_records:
                first = min(page_size, max_records - captured)
                artifact_operation = f"diagnostic_{operation}_page_{captured:06d}"
                try:
                    response = self._call_axl_response(
                        context,
                        operation,
                        diagnostic_list_body(
                            operation,
                            criteria_tag=criteria_tag,
                            returned_tags=returned_tags,
                            first=first,
                            skip=captured,
                        ),
                        artifact_operation=artifact_operation,
                    )
                except AxlCollectionError as exc:
                    warnings.append(f"Diagnostic AXL {operation} failed: {exc}")
                    break
                evidence.append(_evidence_from_soap_response(response, context.publisher_ip))
                facts.configuration_objects.extend(
                    parse_configuration_objects(response.body, operation, returned_tags)
                )
                record_count = _list_response_record_count(response.body)
                if record_count is None:
                    notes.append(
                        f"Diagnostic AXL {operation} response was captured but its record "
                        "count could not be determined; paging stopped."
                    )
                    break
                captured += record_count
                if record_count > first:
                    notes.append(
                        f"Diagnostic AXL {operation} returned {record_count} records despite "
                        f"a requested page size of {first}; CUCM did not enforce the page limit."
                    )
                    break
                if record_count < first:
                    break
            scope = "server-unbounded response" if captured > max_records else "bounded"
            notes.append(
                f"Diagnostic AXL {operation} captured up to {captured} record(s), "
                f"{scope} at {max_records}."
            )

    def _call_axl(self, context: CollectionContext, operation: str, body: str) -> str:
        return self._call_axl_response(context, operation, body).body

    def _enrich_diagnostic_relationships(
        self, context: CollectionContext, facts: AssessmentFacts, warnings: list[str],
        evidence: list[EvidenceRef], notes: list[str],
    ) -> None:
        """Fill nested relationship fields CUCM may omit from list responses."""

        limit = min(max(1, context.diagnostic_axl_max_records), 500)
        attempted = succeeded = 0
        failures: list[str] = []
        enriched: list[ConfigurationObjectFact] = []
        for fact in facts.configuration_objects:
            specification = DIAGNOSTIC_AXL_GET_RELATIONSHIPS.get(fact.object_type)
            if specification is None or attempted >= limit:
                enriched.append(fact)
                continue
            operation, tags = specification
            key_fields = {"uuid": fact.uuid} if fact.uuid else {"name": fact.name}
            attempted += 1
            try:
                response = self._call_axl_response(
                    context, operation,
                    diagnostic_get_body(operation, key_fields=key_fields, returned_tags=tags),
                    artifact_operation=f"diagnostic_{operation}_{attempted:06d}",
                )
                evidence.append(_evidence_from_soap_response(response, context.publisher_ip))
                details = parse_configuration_object_details(response.body, operation, tags)
                if details is None:
                    enriched.append(replace(
                        fact,
                        details={**fact.details, "relationship_collection": "unavailable"},
                    ))
                    failures.append(f"{operation} returned no {fact.object_type} object")
                    continue
                enriched.append(replace(
                    fact,
                    details={
                        **fact.details,
                        **details,
                        "relationship_collection": "collected",
                    },
                ))
                succeeded += 1
            except AxlCollectionError as exc:
                enriched.append(fact)
                failures.append(str(exc))
        facts.configuration_objects = enriched
        if failures:
            warnings.append(
                f"Diagnostic AXL relationship enrichment failed for {len(failures)} of "
                f"{attempted} object(s); list data was preserved. First failure: {failures[0]}"
            )
        notes.append(
            f"Diagnostic AXL relationship enrichment completed {succeeded} of {attempted} "
            f"bounded get request(s); request limit {limit}."
        )

    def _collect_line_forwarding_sql(
        self, context: CollectionContext, facts: AssessmentFacts, warnings: list[str],
        evidence: list[EvidenceRef], notes: list[str],
    ) -> None:
        """Collect configured CFA destinations without an unbounded listLine request."""

        try:
            response = self._call_axl_response(
                context, "executeSQLQuery", execute_sql_query_body(LINE_FORWARDING_SQL),
                artifact_operation="diagnostic_lineForwarding_executeSQLQuery",
            )
            evidence.append(_evidence_from_soap_response(response, context.publisher_ip))
            forwarding = parse_line_forwarding(response.body)
        except AxlCollectionError as exc:
            warnings.append(f"Diagnostic line-forwarding SQL failed: {exc}")
            return
        facts.configuration_objects.extend(forwarding)
        notes.append(
            f"Diagnostic line-forwarding SQL collected {len(forwarding)} configured CFA "
            "destination(s), server-bounded to the first 500 rows."
        )

    def _enrich_route_pattern_relationships_sql(
        self, context: CollectionContext, facts: AssessmentFacts, warnings: list[str],
        evidence: list[EvidenceRef], notes: list[str],
    ) -> None:
        """Recover route-pattern destinations omitted by standard AXL responses."""

        route_patterns = [
            item for item in facts.configuration_objects
            if item.object_type == "RoutePattern" and item.uuid
        ]
        if not route_patterns or all(item.details.get("destination") for item in route_patterns):
            return
        try:
            response = self._call_axl_response(
                context, "executeSQLQuery",
                execute_sql_query_body(ROUTE_PATTERN_RELATIONSHIPS_SQL),
                artifact_operation="diagnostic_routePatternRelationships_executeSQLQuery",
            )
            evidence.append(_evidence_from_soap_response(response, context.publisher_ip))
            relationships = parse_route_pattern_relationships(response.body)
        except AxlCollectionError as exc:
            warnings.append(f"Diagnostic route-pattern relationship SQL failed: {exc}")
            return
        enriched: list[ConfigurationObjectFact] = []
        matched = 0
        for fact in facts.configuration_objects:
            uuid = (fact.uuid or "").strip().strip("{}").lower()
            relationship = relationships.get(uuid)
            if fact.object_type != "RoutePattern" or relationship is None:
                enriched.append(fact)
                continue
            details = {**fact.details, "destination": relationship.destination}
            if relationship.route_groups:
                details["route_groups"] = ", ".join(relationship.route_groups)
            enriched.append(replace(fact, details=details))
            matched += 1
        facts.configuration_objects = enriched
        notes.append(
            f"Diagnostic route-pattern SQL enrichment matched {matched} of "
            f"{len(route_patterns)} route pattern(s), bounded to 500 relationship rows."
        )

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
            request_artifact_operation: str | None
            if attempted_versions:
                base_operation = artifact_operation or operation
                request_artifact_operation = f"{base_operation}_retry_axl_{axl_version}"
            else:
                request_artifact_operation = artifact_operation
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


def _enrich_devices_from_device_pools(
    devices: list[DeviceInventoryFact],
    device_pools: list[DevicePoolRecord],
) -> list[DeviceInventoryFact]:
    pool_by_name = {
        device_pool.name.strip().lower(): device_pool
        for device_pool in device_pools
        if device_pool.name.strip()
    }
    enriched_devices = []
    for device in devices:
        if not device.device_pool:
            enriched_devices.append(device)
            continue

        device_pool = pool_by_name.get(device.device_pool.strip().lower())
        if device_pool is None:
            enriched_devices.append(device)
            continue

        source = device.source
        if "AXL.listDevicePool" not in source:
            source = f"{source}, AXL.listDevicePool"
        enriched_devices.append(
            DeviceInventoryFact(
                name=device.name,
                description=device.description,
                model=device.model,
                protocol=device.protocol,
                device_pool=device.device_pool,
                call_manager_group=device.call_manager_group or device_pool.call_manager_group,
                location=device.location or device_pool.location,
                region=device.region or device_pool.region,
                configured_load=device.configured_load,
                source=source,
            )
        )
    return enriched_devices


def _list_response_record_count(response_text: str) -> int | None:
    try:
        root = ET.fromstring(response_text)
    except ET.ParseError:
        return None
    return_element = next(
        (element for element in root.iter() if element.tag.rsplit("}", 1)[-1] == "return"),
        None,
    )
    if return_element is None:
        return 0
    return sum(1 for child in list(return_element) if isinstance(child.tag, str))
