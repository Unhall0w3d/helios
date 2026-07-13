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
        "CucPhoneSystem", "Phone systems", "/vmrest/phonesystems",
        ("PhoneSystem",),
        detail_fields=(
            ("integration_type", ("integrationtype", "phonesystemtype")),
            ("enable_mwi", ("enablemwi", "mwiisenabled")),
            ("enable_trap_connection", ("enabletrapconnection",)),
        ),
    ),
    CupiProbe(
        "CucPortGroup", "Port groups", "/vmrest/portgroups", ("PortGroup",),
        detail_fields=(
            ("phone_system", ("phonesystemdisplayname", "phonesystemname", "phonesystemobjectid")),
            ("media_switch", ("mediaswitchdisplayname", "mediaswitchobjectid")),
            ("port_count", ("portcount", "numberofports")),
        ),
    ),
    CupiProbe(
        "CucPort", "Ports", "/vmrest/ports", ("Port",),
        identity_fields=("displayname", "name", "portnumber"),
        detail_fields=(
            ("enabled", ("enabled", "isenabled")),
            ("phone_system", ("phonesystemdisplayname", "phonesystemobjectid")),
            ("port_group", ("portgroupdisplayname", "portgroupobjectid")),
            ("answer_calls", ("answercalls",)),
            ("send_mwi_requests", ("sendmwirequests",)),
            ("message_notification", ("messagenotification",)),
        ),
    ),
    CupiProbe(
        "CucSipSecurityProfile", "SIP security profiles", "/vmrest/sipsecurityprofiles",
        ("SipSecurityProfile", "SIPSecurityProfile"),
        detail_fields=(
            ("transport", ("transporttype", "transport")),
            ("incoming_port", ("incomingport",)),
            ("outgoing_port", ("outgoingport",)),
            ("digest_authentication", ("enabledigestauthentication", "digestauthentication")),
        ),
    ),
    CupiProbe(
        "CucRoutingRule", "Routing rules", "/vmrest/routingrules", ("RoutingRule",),
        identity_fields=("displayname", "rulename", "name"),
        detail_fields=(
            ("enabled", ("enabled", "isenabled", "state")),
            ("rule_type", ("ruletype",)),
            ("order", ("ruleorder", "order", "sequence")),
            ("action", ("action", "actiontype")),
            ("destination", ("destinationdisplayname", "destinationobjectid")),
        ),
    ),
    CupiProbe(
        "CucScheduleSet", "Schedule sets", "/vmrest/schedulesets", ("ScheduleSet",),
        detail_fields=(("schedule_count", ("schedulecount", "membercount")),),
    ),
    CupiProbe(
        "CucSchedule", "Schedules", "/vmrest/schedules", ("Schedule",),
        detail_fields=(
            ("schedule_set", ("schedulesetdisplayname", "schedulesetobjectid")),
            ("detail_count", ("scheduledetailcount", "membercount")),
        ),
    ),
    CupiProbe(
        "CucMailboxStore", "Voicemail mailbox stores", "/vmrest/voicemailboxstores",
        ("VoiceMailBoxStore", "VoicemailBoxStore"),
        detail_fields=(
            ("server", ("serverdisplayname", "serverobjectid")),
            ("maximum_size", ("maximumsize", "maxsize")),
        ),
    ),
    CupiProbe(
        "CucMessageAgingPolicy", "Message-aging policies", "/vmrest/messageagingpolicies",
        ("MessageAgingPolicy",),
        detail_fields=(
            ("enabled", ("enabled", "isenabled")),
            ("new_message_days", ("newmessageretentiondays", "newmessagedays")),
            ("saved_message_days", ("savedmessageretentiondays", "savedmessagedays")),
            ("deleted_message_days", ("deletedmessageretentiondays", "deletedmessagedays")),
        ),
    ),
    CupiProbe(
        "CucSmtpConfiguration", "SMTP server configuration", "/vmrest/smtpserver/serverconfigs",
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
        max_rows = min(max(1, context.diagnostic_axl_max_records), 500)
        for probe in probes:
            requested_rows = max_rows if probe.object_type in configuration_types else 1
            endpoint = f"https://{node}{probe.path}?rowsPerPage={requested_rows}&pageNumber=1"
            operation = f"{probe.object_type}_bounded_get"
            try:
                response = self.http_client.get(
                    endpoint, context, node=node, interface="cuc_cupi", operation=operation,
                )
            except CapturedHttpError as exc:
                warnings.append(f"CUC CUPI {probe.label.lower()} GET failed: {exc}")
                continue
            evidence.append(EvidenceRef(
                source="CUC.CUPI", operation=operation, node=node,
                artifact_path=response.response_artifact_path, confidence="high",
            ))
            total = _cupi_total(response.body)
            facts.configuration_objects.append(ConfigurationObjectFact(
                object_type=(
                    probe.object_type
                    if probe.object_type.endswith("Inventory")
                    else f"{probe.object_type}Inventory"
                ),
                name=probe.label,
                details={
                    "total": str(total) if total is not None else "unknown",
                    "requested_rows": str(requested_rows),
                },
                source=f"CUC.CUPI{probe.path}",
            ))
            if probe.record_names:
                facts.configuration_objects.extend(_cupi_configuration_records(response.body, probe))

        if self.diagnostic_capture:
            notes.append(
                "Detailed CUPI configuration collection retained only reviewed non-secret fields; "
                f"each resource was bounded to {max_rows} record(s)."
            )
        return CollectionResult(self.name, facts, warnings=warnings, evidence=evidence, notes=notes)


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


def _cupi_configuration_records(payload: str, probe: CupiProbe) -> list[ConfigurationObjectFact]:
    """Normalize allowlisted CUPI fields without retaining arbitrary response content."""

    records: list[dict[str, str]] = []
    try:
        document = json.loads(payload)
        records = [
            flattened for candidate in _walk_json_dicts(document)
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
                records.append({
                    _key(child.tag.rsplit("}", 1)[-1]): (child.text or "").strip()
                    for child in element.iter()
                    if child is not element and (child.text or "").strip()
                })
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
        normalized.append(ConfigurationObjectFact(
            object_type=probe.object_type,
            name=identity,
            details=details,
            source=f"CUC.CUPI{probe.path}",
            uuid=_first(record, ("objectid",)) or None,
        ))
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
    detail_keys = {
        _key(alias) for _, aliases in probe.detail_fields for alias in aliases
    }
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
