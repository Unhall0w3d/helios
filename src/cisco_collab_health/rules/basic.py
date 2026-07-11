"""Initial conservative health rules for alpha testing."""

from __future__ import annotations

from collections import Counter

from cisco_collab_health.models.evidence import EvidenceRef
from cisco_collab_health.models.facts import AssessmentFacts, CertificateFact, DeviceRegistrationFact
from cisco_collab_health.models.findings import (
    FindingSeverity,
    HealthFinding,
    RecommendationKind,
)


class ClusterIdentityRule:
    """Checks whether a cluster identity was collected."""

    rule_id = "core.cluster_identity"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        if facts.cluster is not None:
            return [
                HealthFinding(
                    rule_id=self.rule_id,
                    title="Cluster identity collected",
                    severity=FindingSeverity.INFO,
                    recommendation_kind=RecommendationKind.INFORMATIONAL,
                    facts=[
                        f"Product: {facts.cluster.product}",
                        f"Version: {facts.cluster.version}",
                        f"Cluster anchor: {facts.cluster.name}",
                    ],
                    reasoning="The assessment has enough identity data to anchor later findings.",
                    evidence=[
                        EvidenceRef(
                            source="normalized_facts",
                            operation="cluster_identity",
                        )
                    ],
                )
            ]

        return [
            HealthFinding(
                rule_id=self.rule_id,
                title="Cluster identity was not collected",
                severity=FindingSeverity.WARNING,
                recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                facts=["No normalized cluster identity facts were produced by collectors."],
                reasoning=(
                    "Most health findings need product and version context before they can be "
                    "interpreted accurately."
                ),
                recommendation="Verify that at least one identity-capable collector is configured.",
            )
        ]


class NodeReachabilityRule:
    """Reports nodes with explicit unreachable status."""

    rule_id = "core.node_reachability"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        if not facts.nodes:
            return [
                HealthFinding(
                    rule_id=self.rule_id,
                    title="No collaboration nodes were collected",
                    severity=FindingSeverity.WARNING,
                    recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                    facts=["No normalized node facts were produced by collectors."],
                    reasoning=(
                        "Cluster health cannot be evaluated until the Publisher API or another "
                        "authoritative source returns cluster node inventory."
                    ),
                    recommendation=(
                        "Verify API reachability and collector warnings for cluster discovery."
                    ),
                )
            ]

        unreachable_nodes = [node for node in facts.nodes if node.reachable is False]
        if not unreachable_nodes:
            return [
                HealthFinding(
                    rule_id=self.rule_id,
                    title="No nodes explicitly reported unreachable",
                    severity=FindingSeverity.INFO,
                    recommendation_kind=RecommendationKind.INFORMATIONAL,
                    facts=[f"Nodes evaluated: {len(facts.nodes)}"],
                    reasoning=(
                        "No collector reported an explicit unreachable status for any "
                        "normalized node."
                    ),
                )
            ]

        node_names = ", ".join(node.name for node in unreachable_nodes)
        return [
            HealthFinding(
                rule_id=self.rule_id,
                title="One or more nodes were reported unreachable",
                severity=FindingSeverity.CRITICAL,
                recommendation_kind=RecommendationKind.REQUIREMENT,
                facts=[f"Unreachable nodes: {node_names}"],
                reasoning=(
                    "Unreachable collaboration nodes can indicate service disruption, "
                    "network issues, "
                    "or collection credential problems that require investigation."
                ),
                recommendation=(
                    "Validate node reachability and distinguish service impact from "
                    "collection failure."
                ),
                evidence=[
                    EvidenceRef(
                        source="normalized_facts",
                        operation="node_reachability",
                        node=node.name,
                    )
                    for node in unreachable_nodes
                ],
            )
        ]


class CollectorHealthRule:
    """Reports collector warnings and errors as assessment findings."""

    rule_id = "core.collector_health"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        if not facts.collector_issues:
            return []

        has_error = any(issue.issue_type == "error" for issue in facts.collector_issues)
        severity = FindingSeverity.CRITICAL if has_error else FindingSeverity.WARNING
        return [
            HealthFinding(
                rule_id=self.rule_id,
                title="One or more collectors reported issues",
                severity=severity,
                recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                facts=[
                    f"{issue.collector_name}: {issue.issue_type}: {issue.message}"
                    for issue in facts.collector_issues
                ],
                reasoning=(
                    "Collector warnings or failures can make the assessment incomplete or reduce "
                    "confidence in related findings."
                ),
                recommendation=(
                    "Review collector warnings/errors and raw artifacts before relying on the "
                    "assessment."
                ),
                evidence=[
                    EvidenceRef(
                        source=issue.source,
                        operation="collector_health",
                        confidence="high",
                    )
                    for issue in facts.collector_issues
                ],
            )
        ]


class DeviceLoadRule:
    """Reports every explicitly configured static phone-load override."""

    rule_id = "inventory.device_loads"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        if not facts.devices:
            return []

        default_by_key = {
            _model_protocol_key(default.model, default.protocol): default.default_load
            for default in facts.device_load_defaults
            if default.default_load
        }
        static_loads: list[tuple[str, str, str | None, str]] = []
        for device in facts.devices:
            default_load = default_by_key.get(_model_protocol_key(device.model, device.protocol))
            if not device.configured_load:
                continue
            if not default_load:
                classification = "default unavailable"
            elif _loads_equal(device.configured_load, default_load):
                classification = "matches current default but remains statically pinned"
            else:
                classification = "differs from current default"
            static_loads.append(
                (device.name, device.configured_load, default_load, classification)
            )

        if not static_loads:
            return []

        return [
            HealthFinding(
                rule_id=self.rule_id,
                title="One or more devices use static phone-load overrides",
                severity=FindingSeverity.INFO,
                recommendation_kind=RecommendationKind.INFORMATIONAL,
                facts=[
                    f"{name}: static load {configured_load}; {classification}"
                    + (f" ({default_load})" if default_load else "")
                    for name, configured_load, default_load, classification in static_loads
                ],
                reasoning=(
                    "Any nonblank Phone Load is a static override. Even when it currently matches "
                    "the Device Default, it remains pinned and may not follow a future default change."
                ),
                recommendation=(
                    "Review static phone-load overrides and confirm they are intentional before "
                    "upgrade or firmware standardization work."
                ),
                evidence=[
                    EvidenceRef(
                        source="normalized_facts",
                        operation="device_load_defaults",
                        confidence="medium",
                    )
                ],
            )
        ]


class FirmwareDownloadRule:
    """Reports explicit runtime firmware download failures from RISPort."""

    rule_id = "runtime.firmware_downloads"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        failures = [
            registration
            for registration in facts.registrations
            if (registration.download_status or "").strip().lower() == "failed"
        ]
        if not failures:
            return []
        devices = {device.name.strip().lower(): device for device in facts.devices}
        defaults = {
            _model_protocol_key(item.model, item.protocol): item.default_load
            for item in facts.device_load_defaults
        }
        impacted = []
        status_only = []
        for registration in failures:
            device = devices.get(registration.name.strip().lower())
            default = defaults.get(_model_protocol_key(registration.model, registration.protocol))
            intended = (device.configured_load if device else None) or default
            if intended and _loads_equal(registration.active_load, intended):
                status_only.append(registration)
            else:
                impacted.append(registration)

        findings = []
        if impacted:
            findings.append(
                _firmware_download_finding(
                    registrations=impacted,
                    rule_id=f"{self.rule_id}.active_mismatch",
                    title="Firmware downloads failed and devices are not running the intended load",
                    severity=FindingSeverity.WARNING,
                    reasoning=(
                        "RISPort reports a failed download and the active firmware does not match "
                        "the configured static override or current Device Default."
                    ),
                )
            )
        if status_only:
            findings.append(
                _firmware_download_finding(
                    registrations=status_only,
                    rule_id=f"{self.rule_id}.status_only",
                    title="Firmware failure status persists while active loads match",
                    severity=FindingSeverity.INFO,
                    reasoning=(
                        "RISPort reports a failed download, but the active firmware already matches "
                        "the intended load. The status may reflect a persistent or historical failure."
                    ),
                )
            )
        return findings


def _firmware_download_finding(
    *, registrations: list[DeviceRegistrationFact], rule_id: str, title: str,
    severity: FindingSeverity, reasoning: str,
) -> HealthFinding:
    reasons = Counter(item.download_failure_reason or "Reason unavailable" for item in registrations)
    return HealthFinding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        recommendation_kind=(
            RecommendationKind.ENGINEERING_RECOMMENDATION
            if severity == FindingSeverity.WARNING else RecommendationKind.INFORMATIONAL
        ),
        facts=[f"Devices: {len(registrations)}", *[f"{reason}: {count}" for reason, count in sorted(reasons.items())]],
        reasoning=reasoning,
        recommendation=(
            "Review TFTP availability, firmware files, device configuration, and the detailed "
            "firmware exception table."
        ),
        evidence=[EvidenceRef(source="RISPort70", operation="selectCmDeviceExt", confidence="high")],
    )


def _model_protocol_key(model: str | None, protocol: str | None) -> tuple[str, str]:
    return ((model or "").strip().lower(), (protocol or "").strip().lower())


def _loads_equal(left: str | None, right: str | None) -> bool:
    return bool(left and right and left.strip().lower() == right.strip().lower())


class DeviceInventorySummaryRule:
    """Summarizes configured device inventory facts."""

    rule_id = "cucm.device_inventory_summary"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        if not facts.devices:
            return []

        models = {device.model for device in facts.devices if device.model}
        sip_count = sum(
            1 for device in facts.devices if _protocol_key(device.protocol) == "sip"
        )
        sccp_count = sum(
            1 for device in facts.devices if _protocol_key(device.protocol) == "sccp"
        )
        return [
            _info_finding(
                rule_id=self.rule_id,
                title="Device inventory collected",
                facts=[
                    f"Devices evaluated: {len(facts.devices)}",
                    f"Models observed: {len(models)}",
                    f"SIP devices: {sip_count}",
                    f"SCCP devices: {sccp_count}",
                ],
                operation="device_inventory_summary",
            )
        ]


class RegistrationSummaryRule:
    """Summarizes runtime registration facts."""

    rule_id = "cucm.registration_summary"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        if not facts.registrations:
            return []

        registered = 0
        unregistered = 0
        other = 0
        for registration in facts.registrations:
            status = registration.status.strip().lower()
            if status == "registered":
                registered += 1
            elif status == "unregistered":
                unregistered += 1
            else:
                other += 1
        return [
            _info_finding(
                rule_id=self.rule_id,
                title="Device registration data collected",
                facts=[
                    f"Registration records: {len(facts.registrations)}",
                    f"Registered: {registered}",
                    f"Unregistered: {unregistered}",
                    f"Other: {other}",
                ],
                operation="registration_summary",
            )
        ]


class ServiceSummaryRule:
    """Summarizes service status facts."""

    rule_id = "cucm.service_summary"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        if not facts.services:
            return []

        started = sum(
            1 for service in facts.services if service.status.strip().lower() == "started"
        )
        non_started = len(facts.services) - started
        return [
            _info_finding(
                rule_id=self.rule_id,
                title="Service status data collected",
                facts=[
                    f"Services evaluated: {len(facts.services)}",
                    f"Started services: {started}",
                    f"Non-started services: {non_started}",
                ],
                operation="service_summary",
            )
        ]


class ServiceRuntimeRule:
    """Flags stopped services whose reason is not a known intentional state."""

    rule_id = "cucm.service_runtime"
    intentional_reasons = {"service not activated", "commanded out of service"}

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        unexpected = [
            service for service in facts.services
            if service.status.strip().lower() != "started"
            and (service.reason or "").strip().lower() not in self.intentional_reasons
        ]
        if not unexpected:
            return []
        by_reason = Counter(service.reason or "Reason unavailable" for service in unexpected)
        by_node = Counter(service.node for service in unexpected)
        return [
            HealthFinding(
                rule_id=self.rule_id,
                title="One or more stopped services require review",
                severity=FindingSeverity.WARNING,
                recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                facts=[
                    f"Unexpected stopped services: {len(unexpected)}",
                    *[f"Reason {reason}: {count}" for reason, count in sorted(by_reason.items())],
                    *[f"Node {node}: {count}" for node, count in sorted(by_node.items())],
                ],
                reasoning=(
                    "Stopped services explicitly marked not activated or commanded out of service "
                    "are treated as intentional. Other stopped states may indicate service failure."
                ),
                recommendation=(
                    "Review the affected services in Control Center and confirm whether each state "
                    "is expected for the node role and deployment design."
                ),
                evidence=[EvidenceRef(source="ControlCenter", operation="soapGetServiceStatus", confidence="high")],
            )
        ]


class CertificateValidityRule:
    """Report expired/60-day certificates and mandatory phone trust stores."""

    rule_id = "security.certificate_validity"
    mandatory = {"phone-sast-trust", "phone-vpn-trust"}

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        if not facts.certificates:
            return []
        expired = [item for item in facts.certificates if item.days_remaining is not None and item.days_remaining < 0]
        soon = [item for item in facts.certificates if item.days_remaining is not None and 0 <= item.days_remaining <= 60]
        observed = {
            value.lower() for item in facts.certificates
            for value in (item.name, item.store, item.service) if value
        }
        missing = sorted(name for name in self.mandatory if not any(name in value for value in observed))
        findings = []
        if expired:
            findings.append(_certificate_finding(
                f"{self.rule_id}.expired", "One or more certificates are expired",
                FindingSeverity.CRITICAL, expired,
            ))
        if soon:
            findings.append(_certificate_finding(
                f"{self.rule_id}.expiring", "One or more certificates expire within 60 days",
                FindingSeverity.WARNING, soon,
            ))
        if missing:
            findings.append(HealthFinding(
                rule_id=f"{self.rule_id}.mandatory_trust_coverage",
                title="Mandatory phone trust-store coverage is incomplete",
                severity=FindingSeverity.WARNING,
                recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                facts=[f"Not observed: {name}" for name in missing],
                reasoning="phone-sast-trust and phone-vpn-trust must always be reviewed.",
                recommendation="Verify the Certificate Management API trust snapshot or use read-only CLI fallback.",
                evidence=[EvidenceRef(source="CertificateManagementREST", operation="snapshot_server")],
            ))
        return findings


def _certificate_finding(
    rule_id: str, title: str, severity: FindingSeverity, certificates: list[CertificateFact],
) -> HealthFinding:
    return HealthFinding(
        rule_id=rule_id, title=title, severity=severity,
        recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
        facts=[
            f"{item.node} / {item.service or item.store or item.name}: {item.days_remaining} days remaining"
            for item in certificates
        ],
        reasoning="Certificate expiration can disrupt secured CUCM services and trust relationships.",
        recommendation="Renew or replace affected certificates and validate the issuer chain before expiration.",
        evidence=[EvidenceRef(source="CertificateManagementREST", operation="snapshot_server", confidence="high")],
    )


class PlatformCheckSummaryRule:
    """Summarizes platform check facts."""

    rule_id = "cucm.platform_check_summary"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        if not facts.platform_checks:
            return []

        statuses = sorted({check.status for check in facts.platform_checks if check.status})
        status_text = ", ".join(statuses) if statuses else "none"
        return [
            _info_finding(
                rule_id=self.rule_id,
                title="Platform check data collected",
                facts=[
                    f"Platform checks evaluated: {len(facts.platform_checks)}",
                    f"Status values observed: {status_text}",
                ],
                operation="platform_check_summary",
            )
        ]


class DeviceLoadSummaryRule:
    """Summarizes device load facts."""

    rule_id = "cucm.device_load_summary"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        if not facts.device_load_defaults:
            return []

        with_configured_load = sum(1 for device in facts.devices if device.configured_load)
        return [
            _info_finding(
                rule_id=self.rule_id,
                title="Device load data collected",
                facts=[
                    f"Device load defaults: {len(facts.device_load_defaults)}",
                    f"Devices with configured loads: {with_configured_load}",
                ],
                operation="device_load_summary",
            )
        ]


class ConfigurationInventorySummaryRule:
    """Summarizes bounded AXL configuration objects without policy judgment."""

    rule_id = "cucm.configuration_inventory_summary"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        if not facts.configuration_objects:
            return []
        counts = Counter(item.object_type for item in facts.configuration_objects)
        return [
            _info_finding(
                rule_id=self.rule_id,
                title="Configuration inventory data collected",
                facts=[
                    f"Configuration objects: {len(facts.configuration_objects)}",
                    *[
                        f"{object_type}: {count}"
                        for object_type, count in sorted(counts.items())
                    ],
                ],
                operation="configuration_inventory_summary",
            )
        ]


def _info_finding(
    *,
    rule_id: str,
    title: str,
    facts: list[str],
    operation: str,
) -> HealthFinding:
    return HealthFinding(
        rule_id=rule_id,
        title=title,
        severity=FindingSeverity.INFO,
        recommendation_kind=RecommendationKind.INFORMATIONAL,
        facts=facts,
        reasoning="Collected facts are summarized for assessment review.",
        evidence=[
            EvidenceRef(
                source="normalized_facts",
                operation=operation,
                confidence="medium",
            )
        ],
    )


def _protocol_key(protocol: str | None) -> str:
    return (protocol or "").strip().lower()
