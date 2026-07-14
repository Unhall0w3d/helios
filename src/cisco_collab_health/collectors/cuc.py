"""Read-only Cisco Unity Connection CUPI collection."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterator
import json
import re
from typing import Any

from defusedxml import ElementTree as ET

from cisco_collab_health.collectors.base import CollectionResult
from cisco_collab_health.models.evidence import EvidenceRef
from cisco_collab_health.models.facts import (
    AssessmentFacts,
    ClusterIdentity,
    ConfigurationObjectFact,
)
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.transport.http import CapturedHttpClient, CapturedHttpError


@dataclass(frozen=True)
class CupiProbe:
    """One reviewed, read-only CUPI collection resource."""

    object_type: str
    label: str
    path: str
    record_names: tuple[str, ...] = ()
    identity_fields: tuple[str, ...] = ("displayname", "name")
    detail_fields: tuple[tuple[str, tuple[str, ...]], ...] = ()
    singleton: bool = False
    alternate_paths: tuple[str, ...] = ()


BASE_PROBES = (
    CupiProbe("CucMailboxInventory", "Mailboxes", "/vmrest/users"),
    CupiProbe(
        "CucUnifiedMessagingServiceInventory",
        "Unified messaging services",
        "/vmrest/externalservices",
    ),
)

DIAGNOSTIC_COUNT_PROBES = (
    CupiProbe("CucContactInventory", "Contacts", "/vmrest/contacts"),
    CupiProbe("CucDistributionListInventory", "Distribution lists", "/vmrest/distributionlists"),
    CupiProbe("CucCallHandlerInventory", "Call handlers", "/vmrest/handlers/callhandlers"),
    CupiProbe("CucClassOfServiceInventory", "Classes of service", "/vmrest/coses"),
    CupiProbe(
        "CucConfigurationValueInventory",
        "System configuration values",
        "/vmrest/configurationvalues",
    ),
)

# Only explicitly allowlisted, non-secret fields are normalized. CUPI response names vary
# slightly by release, so aliases are compared case-insensitively without punctuation.
DIAGNOSTIC_CONFIGURATION_PROBES = (
    CupiProbe(
        "CucPhoneSystem",
        "Phone systems",
        "/vmrest/phonesystems",
        ("PhoneSystem",),
        detail_fields=(
            ("integration_type", ("integrationtype", "phonesystemtype")),
            ("mwi_always_update", ("mwialwaysupdate",)),
            ("mwi_port_memory", ("mwiportmemory",)),
            ("port_count", ("portcount",)),
            ("default_trap_switch", ("defaulttrapswitch",)),
            ("mwi_force_off", ("mwiforceoff",)),
            ("phone_applications_enabled", ("enablephoneapplications",)),
            ("enable_trap_connection", ("enabletrapconnection",)),
        ),
    ),
    CupiProbe(
        "CucPortGroup",
        "Port groups",
        "/vmrest/portgroups",
        ("PortGroup",),
        detail_fields=(
            ("phone_system", ("phonesystemdisplayname", "phonesystemname", "phonesystemobjectid")),
            ("media_switch", ("mediaswitchdisplayname", "mediaswitchobjectid")),
            ("port_count", ("portcount", "numberofports")),
            ("mwi_enabled", ("enablemwi",)),
            ("integration_method", ("telephonyintegrationmethodenum",)),
            ("sip_transport", ("siptransportprotocolenum",)),
            ("sip_srtp", ("sipdosrtp",)),
            ("sip_tls_mode", ("siptlsmodeenum",)),
            ("next_generation_security", ("sipenablenextgensecurity",)),
            ("sip_authentication", ("sipdoauthenticate",)),
        ),
    ),
    CupiProbe(
        "CucPort",
        "Ports",
        "/vmrest/ports",
        ("Port",),
        identity_fields=("displayname", "name", "portnumber"),
        detail_fields=(
            ("enabled", ("capenabled", "enabled", "isenabled")),
            ("media_switch", ("mediaswitchdisplayname",)),
            ("port_group", ("mediaportgroupdisplayname", "portgroupdisplayname")),
            ("server", ("vmsservername",)),
            ("answer_calls", ("capanswer", "answercalls")),
            ("send_mwi_requests", ("capmwi", "sendmwirequests")),
            ("message_notification", ("capnotification", "messagenotification")),
            ("trap_connection", ("captrapconnection",)),
        ),
    ),
    CupiProbe(
        "CucSipSecurityProfile",
        "SIP security profiles",
        "/vmrest/sipsecurityprofiles",
        ("SipSecurityProfile", "SIPSecurityProfile"),
        detail_fields=(
            ("port", ("port", "incomingport")),
            ("tls_enabled", ("dotls",)),
            ("transport", ("transporttype", "transport")),
            ("outgoing_port", ("outgoingport",)),
            ("digest_authentication", ("enabledigestauthentication", "digestauthentication")),
        ),
    ),
    CupiProbe(
        "CucRoutingRule",
        "Routing rules",
        "/vmrest/routingrules",
        ("RoutingRule",),
        identity_fields=("displayname", "rulename", "name"),
        detail_fields=(
            ("state", ("state",)),
            ("rule_type", ("type", "ruletype")),
            ("order", ("ruleindex", "ruleorder", "order", "sequence")),
            ("action", ("routeaction", "action", "actiontype")),
            ("target", ("routetargethandlerdisplayname", "destinationdisplayname")),
            ("target_conversation", ("routetargetconversation",)),
            ("target_object_type", ("routetargethandlerobjecttype",)),
            ("call_type", ("calltype",)),
        ),
    ),
    CupiProbe(
        "CucScheduleSet",
        "Schedule sets",
        "/vmrest/schedulesets",
        ("ScheduleSet",),
        detail_fields=(
            ("schedule_count", ("schedulecount", "membercount")),
            ("undeletable", ("undeletable",)),
        ),
    ),
    CupiProbe(
        "CucSchedule",
        "Schedules",
        "/vmrest/schedules",
        ("Schedule",),
        detail_fields=(
            ("schedule_set", ("schedulesetdisplayname", "schedulesetobjectid")),
            ("detail_count", ("scheduledetailcount", "membercount")),
            ("holiday", ("isholiday",)),
            ("undeletable", ("undeletable",)),
        ),
    ),
    CupiProbe(
        "CucMailboxStore",
        "Voicemail mailbox stores",
        "/vmrest/mailboxstores",
        ("MailboxStore", "VoiceMailBoxStore", "VoicemailBoxStore"),
        detail_fields=(
            ("server", ("server", "serverdisplayname", "serverobjectid")),
            ("mounted", ("mounted",)),
            ("status", ("status",)),
            ("maximum_size_mb", ("maxsizemb", "maximumsize", "maxsize")),
            ("total_size", ("totalsizeofmailbox",)),
        ),
        alternate_paths=("/vmrest/voicemailboxstores",),
    ),
    CupiProbe(
        "CucMessageAgingPolicy",
        "Message-aging policies",
        "/vmrest/messageagingpolicies",
        ("MessageAgingPolicy",),
        detail_fields=(
            ("enabled", ("enabled", "isenabled")),
            ("new_message_days", ("newmessageretentiondays", "newmessagedays")),
            ("saved_message_days", ("savedmessageretentiondays", "savedmessagedays")),
            ("deleted_message_days", ("deletedmessageretentiondays", "deletedmessagedays")),
        ),
    ),
    CupiProbe(
        "CucSmtpConfiguration",
        "SMTP server configuration",
        "/vmrest/smtpserver/serverconfigs",
        ("SmtpServerConfig", "SMTPServerConfig"),
        detail_fields=(
            ("port", ("port",)),
            ("domain", ("domainname",)),
            ("allow_untrusted", ("allowconnectionsfromuntrustedipaddresses",)),
            ("require_auth_untrusted", ("requireauthenticationfromuntrustedipaddresses",)),
            ("require_tls_untrusted", ("requiretlsfromuntrustedipaddresses",)),
        ),
        singleton=True,
    ),
)

MESSAGE_AGING_RULE_PROBE = CupiProbe(
    "CucMessageAgingRule",
    "Message-aging rules",
    "",
    ("MessageAgingRule",),
    identity_fields=("ruledescription", "agingruletype", "objectid"),
    detail_fields=(
        ("days", ("days",)),
        ("enabled", ("enabled",)),
        ("secure", ("secure",)),
        ("send_notification", ("sendnotification",)),
        ("notification_days", ("notificationdays",)),
        ("action", ("action",)),
        ("aging_rule_type", ("agingruletype",)),
        ("aging_time_type", ("agingtimetype",)),
    ),
)


class CucCollector:
    """Collect bounded CUC inventory and sanitized configuration through CUPI GETs."""

    name = "cuc"

    def __init__(
        self,
        http_client: CapturedHttpClient | None = None,
        *,
        diagnostic_capture: bool = False,
    ) -> None:
        self.http_client = http_client or CapturedHttpClient()
        self.diagnostic_capture = diagnostic_capture

    def collect(self, context: CollectionContext) -> CollectionResult:
        facts = AssessmentFacts()
        warnings: list[str] = []
        evidence: list[EvidenceRef] = []
        notes = ["Unity Connection CUPI collection uses bounded, read-only GET requests."]
        node = context.publisher_ip or context.target
        if not node:
            return CollectionResult(self.name, facts, warnings=["CUC target is missing."])
        facts.cluster = ClusterIdentity(node, "Cisco Unity Connection", "unknown")

        probes = [*BASE_PROBES]
        if self.diagnostic_capture:
            probes.extend(DIAGNOSTIC_COUNT_PROBES)
            probes.extend(DIAGNOSTIC_CONFIGURATION_PROBES)

        configuration_types = {probe.object_type for probe in DIAGNOSTIC_CONFIGURATION_PROBES}
        max_records = max(1, context.diagnostic_cupi_max_records)
        page_size = min(max_records, 500)
        for probe in probes:
            requested_rows = page_size if probe.object_type in configuration_types else 1
            operation = f"{probe.object_type}_bounded_get"
            response = None
            selected_path = probe.path
            failure: CapturedHttpError | None = None
            for path_index, path in enumerate((probe.path, *probe.alternate_paths)):
                endpoint = f"https://{node}{path}?rowsPerPage={requested_rows}&pageNumber=1"
                try:
                    response = self.http_client.get(
                        endpoint,
                        context,
                        node=node,
                        interface="cuc_cupi",
                        operation=(operation if path_index == 0 else f"{operation}_fallback"),
                    )
                    selected_path = path
                    break
                except CapturedHttpError as exc:
                    failure = exc
                    if exc.status != 404:
                        break
            if response is None:
                final_error = failure or CapturedHttpError("No supported endpoint succeeded.")
                warnings.append(f"CUC CUPI {probe.label.lower()} GET failed: {final_error}")
                continue
            if selected_path != probe.path:
                notes.append(
                    f"CUC CUPI {probe.label.lower()} used compatibility endpoint "
                    f"{selected_path} after {probe.path} returned HTTP 404."
                )
            evidence.append(
                EvidenceRef(
                    source="CUC.CUPI",
                    operation=operation,
                    node=node,
                    artifact_path=response.response_artifact_path,
                    confidence="high",
                )
            )
            total = _cupi_total(response.body)
            records = (
                _cupi_configuration_records(response.body, probe, source_path=selected_path)
                if probe.record_names
                else []
            )
            pages_collected = 1
            collection_limit = max_records if probe.object_type in configuration_types else requested_rows
            records = records[:collection_limit]
            target_records = min(total, collection_limit) if total is not None else len(records)
            previous_payload = response.body
            while records and len(records) < target_records:
                page_number = pages_collected + 1
                page_operation = f"{operation}_page_{page_number:06d}"
                endpoint = (
                    f"https://{node}{selected_path}?rowsPerPage={requested_rows}"
                    f"&pageNumber={page_number}"
                )
                try:
                    page_response = self.http_client.get(
                        endpoint,
                        context,
                        node=node,
                        interface="cuc_cupi",
                        operation=page_operation,
                    )
                except CapturedHttpError as exc:
                    warnings.append(
                        f"CUC CUPI {probe.label.lower()} page {page_number} GET failed: {exc}"
                    )
                    break
                if page_response.body == previous_payload:
                    notes.append(
                        f"CUC CUPI {probe.label.lower()} stopped after page {pages_collected}; "
                        "the server repeated the previous page."
                    )
                    break
                evidence.append(
                    EvidenceRef(
                        source="CUC.CUPI",
                        operation=page_operation,
                        node=node,
                        artifact_path=page_response.response_artifact_path,
                        confidence="high",
                    )
                )
                page_records = _cupi_configuration_records(
                    page_response.body,
                    probe,
                    source_path=selected_path,
                )
                if not page_records:
                    break
                remaining = target_records - len(records)
                records.extend(page_records[:remaining])
                previous_payload = page_response.body
                pages_collected += 1
            inventory_details = {
                "total": str(total) if total is not None else "unknown",
                "requested_rows": str(requested_rows),
            }
            if probe.record_names:
                inventory_details["normalized_records"] = str(len(records))
                inventory_details["collection_limit"] = str(collection_limit)
                inventory_details["pages_collected"] = str(pages_collected)
                if total is not None:
                    inventory_details["collection_status"] = (
                        "partial" if len(records) < total else "complete"
                    )
                    inventory_details["coverage"] = f"{len(records)} of {total}"
                    if len(records) < total:
                        notes.append(
                            f"CUC CUPI {probe.label.lower()} normalized {len(records)} of "
                            f"{total} record(s); collection was bounded to {collection_limit}."
                        )
                else:
                    inventory_details["collection_status"] = "collected"
            facts.configuration_objects.append(
                ConfigurationObjectFact(
                    object_type=(
                        probe.object_type
                        if probe.object_type.endswith("Inventory")
                        else f"{probe.object_type}Inventory"
                    ),
                    name=probe.label,
                    details=inventory_details,
                    source=f"CUC.CUPI{selected_path}",
                )
            )
            facts.configuration_objects.extend(records)
            if probe.object_type == "CucMessageAgingPolicy":
                self._collect_message_aging_rules(
                    response.body,
                    node,
                    context,
                    page_size,
                    facts,
                    warnings,
                    evidence,
                    notes,
                )

        if self.diagnostic_capture:
            notes.append(
                "Detailed CUPI configuration collection retained only reviewed non-secret fields; "
                f"each resource was bounded to {max_records} record(s), collected in pages of "
                f"up to {page_size}."
            )
        return CollectionResult(self.name, facts, warnings=warnings, evidence=evidence, notes=notes)

    def _collect_message_aging_rules(
        self,
        payload: str,
        node: str,
        context: CollectionContext,
        max_rows: int,
        facts: AssessmentFacts,
        warnings: list[str],
        evidence: list[EvidenceRef],
        notes: list[str],
    ) -> None:
        """Collect the bounded child rules linked from each message-aging policy."""

        collected = 0
        links = _message_aging_rule_links(payload)[:max_rows]
        for index, (policy, path) in enumerate(links, start=1):
            endpoint = f"https://{node}{path}?rowsPerPage={max_rows}&pageNumber=1"
            operation = f"CucMessageAgingRule_bounded_get_{index:06d}"
            try:
                response = self.http_client.get(
                    endpoint,
                    context,
                    node=node,
                    interface="cuc_cupi",
                    operation=operation,
                )
            except CapturedHttpError as exc:
                warnings.append(f"CUC CUPI message-aging rules GET failed for {policy}: {exc}")
                continue
            evidence.append(
                EvidenceRef(
                    source="CUC.CUPI",
                    operation=operation,
                    node=node,
                    artifact_path=response.response_artifact_path,
                    confidence="high",
                )
            )
            records = _cupi_configuration_records(
                response.body,
                MESSAGE_AGING_RULE_PROBE,
                source_path=path,
            )
            facts.configuration_objects.extend(
                ConfigurationObjectFact(
                    object_type=item.object_type,
                    name=item.name,
                    details={"policy": policy, **item.details},
                    source=item.source,
                    uuid=item.uuid,
                )
                for item in records
            )
            collected += len(records)
        if links:
            notes.append(
                f"CUC CUPI collected {collected} message-aging rule(s) from "
                f"{len(links)} bounded policy child resource(s)."
            )


def _cupi_total(payload: str) -> int | None:
    """Read the CUPI collection total from JSON or XML."""

    try:
        document = json.loads(payload)
        if isinstance(document, dict):
            for key in ("total", "Total", "@total"):
                if key in document:
                    return int(document[key])
            for value in document.values():
                if isinstance(value, dict):
                    for key in ("total", "Total", "@total"):
                        if key in value:
                            return int(value[key])
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    try:
        root = ET.fromstring(payload)
        value = root.attrib.get("total") or root.attrib.get("Total")
        return int(value) if value is not None else None
    except (ET.ParseError, ValueError):
        return None


def _message_aging_rule_links(payload: str) -> list[tuple[str, str]]:
    """Return policy display names and same-server child rule paths."""

    candidates: list[dict[str, str]] = []
    try:
        document = json.loads(payload)
        candidates = [_flatten_json_scalars(item) for item in _walk_json_dicts(document)]
    except (json.JSONDecodeError, TypeError):
        try:
            root = ET.fromstring(payload)
            for element in _iter_xml_records(root, "messageagingpolicy"):
                candidates.append(
                    {
                        _key(child.tag.rsplit("}", 1)[-1]): (child.text or "").strip()
                        for child in element.iter()
                        if child is not element and (child.text or "").strip()
                    }
                )
        except ET.ParseError:
            return []
    links: list[tuple[str, str]] = []
    for record in candidates:
        path = _first(record, ("messageagingruleuri",))
        policy = _first(record, ("displayname", "name", "objectid"))
        if not path or not policy or not path.startswith("/vmrest/"):
            continue
        link = (policy, path)
        if link not in links:
            links.append(link)
    return links


def _iter_xml_records(root: Any, normalized_name: str) -> Iterator[Any]:
    for element in root.iter():
        if _key(element.tag.rsplit("}", 1)[-1]) == normalized_name:
            yield element


def _cupi_configuration_records(
    payload: str,
    probe: CupiProbe,
    *,
    source_path: str | None = None,
) -> list[ConfigurationObjectFact]:
    """Normalize allowlisted CUPI fields without retaining arbitrary response content."""

    records: list[dict[str, str]] = []
    try:
        document = json.loads(payload)
        records = [
            flattened
            for candidate in _walk_json_dicts(document)
            if _json_record_matches(candidate, probe)
            and (flattened := _flatten_json_scalars(candidate))
        ]
    except (json.JSONDecodeError, TypeError):
        try:
            root = ET.fromstring(payload)
            record_names = {_key(name) for name in probe.record_names}
            for element in root.iter():
                if _key(element.tag.rsplit("}", 1)[-1]) not in record_names:
                    continue
                records.append(
                    {
                        _key(child.tag.rsplit("}", 1)[-1]): (child.text or "").strip()
                        for child in element.iter()
                        if child is not element and (child.text or "").strip()
                    }
                )
        except ET.ParseError:
            return []

    normalized: list[ConfigurationObjectFact] = []
    for record in records:
        identity = _first(record, probe.identity_fields)
        if not identity and probe.singleton:
            identity = probe.label
        if not identity:
            continue
        details = {
            label: value
            for label, aliases in probe.detail_fields
            if (value := _first(record, aliases)) is not None
        }
        normalized.append(
            ConfigurationObjectFact(
                object_type=probe.object_type,
                name=identity,
                details=details,
                source=f"CUC.CUPI{source_path or probe.path}",
                uuid=_first(record, ("objectid",)) or None,
            )
        )
    return normalized


def _walk_json_dicts(value: Any) -> Iterator[dict[Any, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_json_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json_dicts(child)


def _json_record_matches(record: dict[Any, Any], probe: CupiProbe) -> bool:
    keys = {_key(str(key)) for key in record}
    identity_keys = {_key(field) for field in (*probe.identity_fields, "objectid")}
    detail_keys = {_key(alias) for _, aliases in probe.detail_fields for alias in aliases}
    return bool(keys & identity_keys) or bool(probe.singleton and keys & detail_keys)


def _flatten_json_scalars(record: dict[Any, Any]) -> dict[str, str]:
    return {
        _key(str(key)): str(value)
        for key, value in record.items()
        if isinstance(value, (str, int, float, bool)) and str(value).strip()
    }


def _first(record: dict[str, str], aliases: tuple[str, ...]) -> str | None:
    return next((record[_key(alias)] for alias in aliases if record.get(_key(alias))), None)


def _key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())
