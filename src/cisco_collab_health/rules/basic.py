"""Initial conservative health rules for alpha testing."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from cisco_collab_health.lifecycle import lifecycle_for, lifecycle_status, technology_for_product
from cisco_collab_health.models.evidence import EvidenceRef
from cisco_collab_health.models.facts import (
    AssessmentFacts,
    CertificateFact,
    DeviceRegistrationFact,
    PlatformCheckFact,
    ServiceStatusFact,
)
from cisco_collab_health.models.findings import (
    FindingSeverity,
    HealthFinding,
    RecommendationKind,
)


class ClusterIdentityRule:
    """Checks whether a cluster identity was collected."""

    rule_id = "core.cluster_identity"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        clusters = [*facts.clusters]
        if facts.cluster is not None and facts.cluster not in clusters:
            clusters.append(facts.cluster)
        if clusters:
            return [
                HealthFinding(
                    rule_id=self.rule_id,
                    title=(
                        "Cluster identity collected"
                        if len(clusters) == 1
                        else "Cluster identities collected"
                    ),
                    severity=FindingSeverity.INFO,
                    recommendation_kind=RecommendationKind.INFORMATIONAL,
                    facts=[
                        f"{cluster.product}: version {cluster.version}; cluster anchor {cluster.name}"
                        for cluster in clusters
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

        ssh_issues = [
            issue for issue in facts.collector_issues if "SSH session failed on" in issue.message
        ]
        remaining = [issue for issue in facts.collector_issues if issue not in ssh_issues]
        findings: list[HealthFinding] = []
        if ssh_issues:
            nodes = sorted(
                {
                    issue.message.split("SSH session failed on ", 1)[1].split(":", 1)[0]
                    for issue in ssh_issues
                }
            )
            findings.append(
                HealthFinding(
                    rule_id=f"{self.rule_id}.platform_coverage",
                    title="Platform checks were not collected from one or more nodes",
                    severity=FindingSeverity.WARNING,
                    recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                    facts=[
                        f"Nodes without platform CLI evidence: {len(nodes)}",
                        f"Affected nodes: {', '.join(nodes)}",
                    ],
                    reasoning="The assessment completed its available API collection, but platform CLI evidence is incomplete for the listed nodes.",
                    recommendation="Verify each node's SSH host key out of band, enroll it with the explicit first-use option, then rerun diagnostic capture to complete platform coverage.",
                    evidence=[
                        EvidenceRef(
                            source=issue.source, operation="collector_health", confidence="high"
                        )
                        for issue in ssh_issues
                    ],
                )
            )
        if not remaining:
            return findings

        has_error = any(issue.issue_type == "error" for issue in remaining)
        severity = FindingSeverity.CRITICAL if has_error else FindingSeverity.WARNING
        findings.append(
            HealthFinding(
                rule_id=self.rule_id,
                title="One or more collectors reported issues",
                severity=severity,
                recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                facts=[
                    f"{issue.collector_name}: {issue.issue_type}: {issue.message}"
                    for issue in remaining
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
                    for issue in remaining
                ],
            )
        )
        return findings


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
            static_loads.append((device.name, device.configured_load, default_load, classification))

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
                        "Some devices report a failed firmware download and are running a "
                        "different version from the one assigned to them. This can create "
                        "inconsistent features, behavior, and supportability."
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
    *,
    registrations: list[DeviceRegistrationFact],
    rule_id: str,
    title: str,
    severity: FindingSeverity,
    reasoning: str,
) -> HealthFinding:
    reasons = Counter(
        item.download_failure_reason or "Reason unavailable" for item in registrations
    )
    return HealthFinding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        recommendation_kind=(
            RecommendationKind.ENGINEERING_RECOMMENDATION
            if severity == FindingSeverity.WARNING
            else RecommendationKind.INFORMATIONAL
        ),
        facts=[
            f"Devices: {len(registrations)}",
            f"Affected devices: {', '.join(sorted(item.name for item in registrations)[:20])}",
            *[f"{reason}: {count}" for reason, count in sorted(reasons.items())],
        ],
        reasoning=reasoning,
        recommendation=(
            "Confirm the intended device firmware, then have the UC administrator review TFTP "
            "reachability, the firmware files, and the affected device configuration before "
            "retrying the update."
        ),
        evidence=[
            EvidenceRef(source="RISPort70", operation="selectCmDeviceExt", confidence="high")
        ],
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
        sip_count = sum(1 for device in facts.devices if _protocol_key(device.protocol) == "sip")
        sccp_count = sum(1 for device in facts.devices if _protocol_key(device.protocol) == "sccp")
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


class SipTrunkRuntimeRule:
    """Identify SIP trunks that are not currently registered in RIS."""

    rule_id = "cucm.sip_trunk_runtime"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        trunks = [
            registration for registration in facts.registrations if _is_sip_trunk(registration)
        ]
        affected = [
            registration
            for registration in trunks
            if registration.status.strip().lower() not in {"registered", "registered/matched"}
        ]
        if not affected:
            return []

        states = Counter(registration.status.strip() or "Unknown" for registration in affected)
        names = ", ".join(sorted(registration.name for registration in affected))
        operation = (
            "selectCmDevice"
            if any(registration.source == "RISPort70.selectCmDevice" for registration in affected)
            else "selectCmDeviceExt"
        )
        return [
            HealthFinding(
                rule_id=self.rule_id,
                title="One or more SIP trunks are not currently registered",
                severity=FindingSeverity.WARNING,
                recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                facts=[
                    f"SIP trunks checked: {len(trunks)}",
                    f"Affected trunks: {names}",
                    *[f"{state}: {count}" for state, count in sorted(states.items())],
                ],
                reasoning=(
                    "A trunk that is not registered may be unable to place or receive calls. "
                    "RIS provides a point-in-time registration state; it does not establish "
                    "how long that state has persisted or whether the trunk is intentionally idle."
                ),
                recommendation=(
                    "Confirm whether each affected trunk is expected to be in service. If it is, "
                    "have the UC administrator check the far-end or CUBE, SIP reachability and "
                    "security, and the CUCM trunk and route configuration."
                ),
                evidence=[EvidenceRef(source="RISPort70", operation=operation, confidence="high")],
            )
        ]


def _is_sip_trunk(registration: DeviceRegistrationFact) -> bool:
    device_class = (registration.device_class or "").strip().lower()
    if device_class in {"siptrunk", "sip trunk"}:
        return True
    return (
        "trunk"
        in " ".join(
            value
            for value in (registration.name, registration.model, registration.protocol)
            if value
        ).lower()
    )


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
            service
            for service in facts.services
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
                evidence=[
                    EvidenceRef(
                        source="ControlCenter", operation="soapGetServiceStatus", confidence="high"
                    )
                ],
            )
        ]


class CertificateValidityRule:
    """Report certificates that are expired or within the 60-day window."""

    rule_id = "security.certificate_validity"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        if not facts.certificates:
            return []
        itl_recovery = [
            item
            for item in facts.certificates
            if "itlrecovery" in item.name.lower()
            and item.certificate_kind == "identity"
            and item.days_remaining is not None
            and item.days_remaining <= 60
        ]
        expired_identity = [
            item
            for item in facts.certificates
            if item.certificate_kind == "identity"
            and item not in itl_recovery
            and item.days_remaining is not None
            and item.days_remaining < 0
        ]
        soon_identity = [
            item
            for item in facts.certificates
            if item.certificate_kind == "identity"
            and item not in itl_recovery
            and item.days_remaining is not None
            and 0 <= item.days_remaining <= 60
        ]
        expired_trust = [
            item
            for item in facts.certificates
            if item.certificate_kind != "identity"
            and item.days_remaining is not None
            and item.days_remaining < 0
        ]
        soon_trust = [
            item
            for item in facts.certificates
            if item.certificate_kind != "identity"
            and item.days_remaining is not None
            and 0 <= item.days_remaining <= 60
        ]
        findings: list[HealthFinding] = []
        if itl_recovery:
            findings.append(
                HealthFinding(
                rule_id=f"{self.rule_id}.itl_recovery",
                title=(
                    "ITLRecovery certificate is expired"
                    if any(item.days_remaining is not None and item.days_remaining < 0 for item in itl_recovery)
                    else "ITLRecovery certificate expires within 60 days"
                ),
                    severity=FindingSeverity.WARNING,
                    recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                    facts=_certificate_occurrence_summaries(itl_recovery),
                    reasoning=(
                        "ITLRecovery supports trust-list recovery and signing workflows. Its expiry "
                        "does not by itself prove a current calling or service outage."
                    ),
                    recommendation=(
                        "Verify current phone ITL/CTL trust and cluster security state, then follow "
                        "the Cisco-controlled ITLRecovery regeneration procedure in a change window."
                    ),
                    evidence=[
                        EvidenceRef(
                            source="CertificateManagementREST",
                            operation="snapshot_server",
                            confidence="high",
                        )
                    ],
                )
            )
        if expired_identity:
            findings.append(
                _certificate_finding(
                    f"{self.rule_id}.identity_expired",
                    "One or more active service certificates are expired",
                    FindingSeverity.CRITICAL,
                    expired_identity,
                    "identity",
                )
            )
        if soon_identity:
            findings.append(
                _certificate_finding(
                    f"{self.rule_id}.identity_expiring",
                    "One or more active service certificates expire within 60 days",
                    FindingSeverity.WARNING,
                    soon_identity,
                    "identity",
                )
            )
        if expired_trust:
            findings.append(
                _certificate_finding(
                    f"{self.rule_id}.trust_expired",
                    "Expired trust certificates should be reviewed",
                    FindingSeverity.WARNING,
                    expired_trust,
                    "trust",
                )
            )
        if soon_trust:
            findings.append(
                _certificate_finding(
                    f"{self.rule_id}.trust_expiring",
                    "Trust certificates expire within 60 days",
                    FindingSeverity.INFO,
                    soon_trust,
                    "trust",
                )
            )
        return findings


def _certificate_finding(
    rule_id: str,
    title: str,
    severity: FindingSeverity,
    certificates: list[CertificateFact],
    certificate_scope: str,
) -> HealthFinding:
    if certificate_scope == "identity":
        reasoning = "An active service certificate is expired or approaching expiry and can interrupt secure UC services or integrations."
        recommendation = "Have the UC administrator renew or replace the affected service certificates, validate dependent services, and confirm trust after the change."
    else:
        reasoning = "Trust-store entries can remain after a peer certificate is replaced. Their presence does not by itself prove an active service outage."
        recommendation = "Review the affected trust entries against the current UC topology and integrations. Remove or replace only entries confirmed obsolete or required by an expiring peer certificate."
    return HealthFinding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
        facts=_certificate_occurrence_summaries(certificates),
        reasoning=reasoning,
        recommendation=recommendation,
        evidence=[
            EvidenceRef(
                source="CertificateManagementREST", operation="snapshot_server", confidence="high"
            )
        ],
    )


def _certificate_occurrence_summaries(certificates: Iterable[CertificateFact]) -> list[str]:
    grouped: dict[str, list[CertificateFact]] = {}
    for item in certificates:
        key = item.fingerprint_sha256 or "|".join(
            filter(None, (item.subject, item.serial_number, item.valid_until, item.name))
        )
        grouped.setdefault(key, []).append(item)
    summaries = []
    for occurrences in grouped.values():
        item = occurrences[0]
        nodes = ", ".join(sorted({entry.node for entry in occurrences}))
        locations = ", ".join(
            sorted(
                {entry.store or entry.service or entry.certificate_kind for entry in occurrences}
            )
        )
        names = ", ".join(sorted({entry.name for entry in occurrences}))
        summaries.append(f"{names} [{locations}] on {nodes}: {item.days_remaining} days remaining")
    return summaries


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


class SoftwareConsistencyRule:
    """Compare UCOS active versions and installed software options across cluster nodes."""

    rule_id = "platform.software_consistency"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        checks = [
            item
            for item in facts.platform_checks
            if item.check_name == "show version active"
            and item.source in {"CUCM.UCOS.CLI", "CUC.UCOS.CLI"}
            and item.status == "collected"
        ]
        findings: list[HealthFinding] = []
        for group_key in sorted({(item.target_id or item.source, item.source) for item in checks}):
            target_id, source = group_key
            group = [
                item for item in checks if (item.target_id or item.source, item.source) == group_key
            ]
            if len(group) < 2:
                continue
            publisher_keys = {
                value.strip().lower()
                for node in facts.nodes
                if (node.target_id or source) == target_id and node.role.lower() == "publisher"
                for value in (node.name, node.address)
                if value.strip()
            }
            publisher = next(
                (item for item in group if item.node.strip().lower() in publisher_keys), group[0]
            )
            expected_version = publisher.details.get("active_version", "unknown")
            mismatched_versions = [
                item
                for item in group
                if expected_version != "unknown"
                and item.details.get("active_version", "unknown") != expected_version
            ]
            if mismatched_versions:
                findings.append(
                    HealthFinding(
                        rule_id=f"{self.rule_id}.version_mismatch.{target_id}",
                        title="Cluster nodes are running different active software versions",
                        severity=FindingSeverity.WARNING,
                        recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                        facts=[
                            f"Publisher baseline ({publisher.node}): {expected_version}",
                            *[
                                f"{item.node}: {item.details.get('active_version', 'unknown')}"
                                for item in sorted(mismatched_versions, key=lambda item: item.node.lower())
                            ],
                        ],
                        reasoning=(
                            "Cluster nodes should normally run the same active application version. "
                            "A mismatch can indicate an incomplete upgrade, delayed switch version, or "
                            "a node requiring engineering review."
                        ),
                        recommendation=(
                            "Validate the cluster upgrade state and maintenance history before making "
                            "any version or service changes."
                        ),
                        evidence=[
                            EvidenceRef(source=source, operation="show_version_active", confidence="high")
                        ],
                    )
                )
            publisher_options = _software_options(publisher)
            option_differences = []
            for item in group:
                if item is publisher:
                    continue
                options = _software_options(item)
                missing = sorted(publisher_options - options)
                extra = sorted(options - publisher_options)
                if missing or extra:
                    description = []
                    if missing:
                        description.append("missing " + ", ".join(missing))
                    if extra:
                        description.append("additional " + ", ".join(extra))
                    option_differences.append(f"{item.node}: " + "; ".join(description))
            if option_differences:
                findings.append(
                    HealthFinding(
                        rule_id=f"{self.rule_id}.software_options.{target_id}",
                        title="Installed software options differ across cluster nodes",
                        severity=FindingSeverity.WARNING,
                        recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                        facts=[f"Publisher baseline: {publisher.node}", *option_differences],
                        reasoning=(
                            "Installed software options reported by UCOS are not consistent across "
                            "collected nodes. This can leave nodes at different patch or COP levels."
                        ),
                        recommendation=(
                            "Confirm each listed option against the approved cluster maintenance plan "
                            "before installing, removing, or switching software."
                        ),
                        evidence=[
                            EvidenceRef(source=source, operation="show_version_active", confidence="high")
                        ],
                    )
                )
        return findings


def _software_options(check: PlatformCheckFact) -> set[str]:
    return {
        value
        for value in check.details.get("installed_software_options", "").split("|")
        if value
    }


class SoftwareLifecycleRule:
    """Flag known Cisco UC releases that need lifecycle planning or action."""

    rule_id = "core.software_lifecycle"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        clusters = [*facts.clusters]
        if facts.cluster is not None and facts.cluster not in clusters:
            clusters.append(facts.cluster)

        findings: list[HealthFinding] = []
        for cluster in sorted(clusters, key=lambda item: (item.product.casefold(), item.name.casefold())):
            technology = technology_for_product(cluster.product)
            record = lifecycle_for(technology or "", cluster.version) if technology else None
            if record is None:
                continue
            status = lifecycle_status(record)
            if not status.attention_needed:
                continue
            findings.append(
                HealthFinding(
                    rule_id=f"{self.rule_id}.{technology}.{record.release}",
                    title=f"{cluster.product} {cluster.version}: {status.label.lower()}",
                    severity=FindingSeverity.WARNING,
                    recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                    facts=[
                        f"Cluster anchor: {cluster.name}",
                        f"Cisco end of sale: {record.end_of_sale.isoformat()}",
                        f"Cisco end of software maintenance: {record.end_of_maintenance.isoformat()}",
                        f"Cisco last date of support: {record.last_support.isoformat()}",
                    ],
                    reasoning=(
                        "The collected version matches a curated Cisco lifecycle notice. "
                        f"{status.detail}"
                    ),
                    recommendation=(
                        "Confirm the installed release and entitlement with Cisco, then plan the "
                        "appropriate supported upgrade path. Official lifecycle notice: "
                        f"{record.source_url}"
                    ),
                    evidence=[
                        EvidenceRef(source="normalized_facts", operation="cluster_identity", confidence="high")
                    ],
                )
            )
        return findings


class CucPlatformHealthRule:
    """Conservative findings from normalized Unity Connection UCOS summaries."""

    rule_id = "cuc.platform_health"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        checks = {
            item.check_name: item for item in facts.platform_checks if item.source == "CUC.UCOS.CLI"
        }
        findings: list[HealthFinding] = []
        diagnostic = checks.get("utils diagnose test")
        if diagnostic and int(diagnostic.details.get("failed", "0")):
            findings.append(
                _cuc_finding(
                    "diagnostic_failures",
                    FindingSeverity.WARNING,
                    "Unity Connection diagnostic tests failed",
                    [f"Failed tests: {diagnostic.details['failed']}"],
                )
            )
        services = checks.get("utils service list")
        if services and int(services.details.get("stopped", "0")) > int(
            services.details.get("not_activated", "0")
        ):
            findings.append(
                _cuc_finding(
                    "unexpected_stopped_services",
                    FindingSeverity.WARNING,
                    "Unity Connection services are unexpectedly stopped",
                    [
                        f"Stopped: {services.details.get('stopped')}",
                        f"Not activated: {services.details.get('not_activated')}",
                    ],
                )
            )
        core = checks.get("utils core active list")
        if core and core.details.get("core_files") == "present":
            findings.append(
                _cuc_finding(
                    "core_files",
                    FindingSeverity.WARNING,
                    "Unity Connection active core files found",
                    ["Review core files before removal or escalation."],
                )
            )
        cluster = checks.get("show cuc cluster status")
        if cluster and int(cluster.details.get("unhealthy_states", "0")):
            findings.append(
                _cuc_finding(
                    "replication",
                    FindingSeverity.CRITICAL,
                    "Unity Connection cluster replication reports unhealthy state",
                    [f"Unhealthy states: {cluster.details['unhealthy_states']}"],
                )
            )
        network = checks.get("show network eth0 detail")
        if network and (
            network.details.get("link_status") != "up"
            or network.details.get("duplicate_ip") == "yes"
        ):
            findings.append(
                _cuc_finding(
                    "network",
                    FindingSeverity.CRITICAL,
                    "Unity Connection Ethernet 0 health issue",
                    [
                        f"Link: {network.details.get('link_status')}",
                        f"Duplicate IP: {network.details.get('duplicate_ip')}",
                    ],
                )
            )
        return findings


class CucmPlatformHealthRule:
    """Conservative health findings from bounded CUCM UCOS CLI summaries."""

    rule_id = "cucm.platform_health"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        checks = [check for check in facts.platform_checks if check.source == "CUCM.UCOS.CLI"]
        findings: list[HealthFinding] = []
        common_disk = _partition_usage_above(checks, "common_partition_usage_percent", 90)
        if common_disk:
            findings.append(
                _cucm_cli_finding(
                    "common_partition_usage",
                    FindingSeverity.CRITICAL if any(value >= 95 for _, value in common_disk) else FindingSeverity.WARNING,
                    "CUCM common/logging partition utilization is critically high",
                    [
                        f"{check.node}: {value}% common/logging partition"
                        for check, value in sorted(common_disk, key=lambda item: item[0].node)
                    ],
                    "High common/logging-partition utilization can interrupt logging and leave insufficient upgrade staging space.",
                    "Optional operator action: record the current RTMT LogPartition low/high watermarks, temporarily set low to 45% and high to 50%, allow one to two hours for oldest-first log cleanup, verify capacity, then restore the original values. This tool never changes watermarks. Follow Cisco's procedure: https://www.cisco.com/c/en/us/support/docs/unified-communications/unified-communications-manager-callmanager/221038-troubleshoot-full-common-partition-in-cu.html . If space remains insufficient, review Cisco's maintenance-window guidance for the Free Common Space COP.",
                )
            )
        active_disk = _partition_usage_above(checks, "active_partition_usage_percent", 90)
        if active_disk:
            findings.append(
                _cucm_cli_finding(
                    "active_partition_usage",
                    FindingSeverity.CRITICAL if any(value >= 95 for _, value in active_disk) else FindingSeverity.WARNING,
                    "CUCM active partition utilization is critically high",
                    [
                        f"{check.node}: {value}% active partition"
                        for check, value in sorted(active_disk, key=lambda item: item[0].node)
                    ],
                    "High active-partition utilization requires engineering review and is not addressed by common/logging watermark cleanup.",
                    "Preserve required evidence and follow Cisco's partition troubleshooting procedure before deleting files or changing system storage. https://www.cisco.com/c/en/us/support/docs/unified-communications/unified-communications-manager-callmanager/221038-troubleshoot-full-common-partition-in-cu.html",
                )
            )
        ntp_unsynced = [
            check.node
            for check in checks
            if check.check_name == "utils ntp status"
            and check.details.get("synchronized") == "false"
        ]
        if ntp_unsynced:
            findings.append(
                _cucm_cli_finding(
                    "ntp",
                    FindingSeverity.CRITICAL,
                    "One or more CUCM nodes are not synchronized to NTP",
                    ["Affected nodes: " + ", ".join(sorted(ntp_unsynced))],
                    "Time synchronization is required for reliable certificates, logging, and clustered service behavior.",
                    "Have the UC administrator restore NTP reachability and confirm each affected node synchronizes before making other cluster changes.",
                )
            )
        drs_unavailable = [
            check.node
            for check in checks
            if check.check_name.startswith("utils disaster_recovery")
            and check.details.get("drs_unavailable") == "true"
        ]
        if drs_unavailable:
            findings.append(
                _cucm_cli_finding(
                    "drs_unavailable",
                    FindingSeverity.WARNING,
                    "CUCM Disaster Recovery status could not be verified",
                    ["Affected nodes: " + ", ".join(sorted(set(drs_unavailable)))],
                    "The DRS Master Agent may be unavailable or busy, leaving backup status uncertain.",
                    "Review DRS status and the Master Agent, then confirm a recent successful backup before relying on recovery readiness.",
                )
            )
        no_backup = [
            check.node
            for check in checks
            if check.check_name == "utils disaster_recovery history backup"
            and check.details.get("successful_backup_entries") == "0"
            and check.details.get("drs_unavailable") != "true"
        ]
        if no_backup:
            findings.append(
                _cucm_cli_finding(
                    "backup_history",
                    FindingSeverity.WARNING,
                    "No successful CUCM backup was found in collected history",
                    ["Affected nodes: " + ", ".join(sorted(no_backup))],
                    "Without a confirmed successful backup, recovery readiness cannot be demonstrated from this assessment.",
                    "Review the DRS schedule, destination, and most recent job result; run or repair a backup if needed.",
                )
            )
        replication = [
            check
            for check in checks
            if check.check_name == "utils dbreplication runtimestate"
            and int(check.details.get("replication_bad_rows", "0")) > 0
        ]
        if replication:
            findings.append(
                _cucm_cli_finding(
                    "replication",
                    FindingSeverity.CRITICAL,
                    "CUCM database replication needs review",
                    [
                        f"Nodes reporting incomplete replication rows: {', '.join(sorted(check.node for check in replication))}"
                    ],
                    "One or more collected replication rows did not report Setup Completed.",
                    "Review the replication runtime output and Cisco-supported remediation procedure before changing cluster services or database state.",
                )
            )
        cores = [
            check.node
            for check in checks
            if check.check_name == "utils core active list"
            and check.details.get("core_files") == "present"
        ]
        if cores:
            findings.append(
                _cucm_cli_finding(
                    "core_files",
                    FindingSeverity.WARNING,
                    "Active CUCM core files were found",
                    ["Affected nodes: " + ", ".join(sorted(cores))],
                    "Core files can indicate an application or platform process failure requiring engineering review.",
                    "Preserve the artifacts and review the core files with Cisco TAC or the responsible engineering team before removal.",
                )
            )
        return findings


def _cucm_cli_finding(
    suffix: str,
    severity: FindingSeverity,
    title: str,
    facts: list[str],
    reasoning: str,
    recommendation: str,
) -> HealthFinding:
    return HealthFinding(
        rule_id=f"cucm.platform_health.{suffix}",
        title=title,
        severity=severity,
        recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
        facts=facts,
        reasoning=reasoning,
        recommendation=recommendation,
        evidence=[
            EvidenceRef(source="CUCM.UCOS.CLI", operation="platform_summary", confidence="high")
        ],
    )


def _partition_usage_above(
    checks: list[PlatformCheckFact], detail_name: str, threshold: int
) -> list[tuple[PlatformCheckFact, int]]:
    return [
        (check, int(check.details[detail_name]))
        for check in checks
        if check.check_name == "show status"
        and check.details.get(detail_name, "").isdigit()
        and int(check.details[detail_name]) > threshold
    ]


class CucPlatformStatusRule:
    """Evaluate normalized Unity Connection status data already captured over UCOS CLI."""

    rule_id = "cuc.platform_status"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        checks = [
            check
            for check in facts.platform_checks
            if check.source == "CUC.UCOS.CLI" and check.check_name == "show status"
        ]
        findings: list[HealthFinding] = []
        for check in checks:
            critical = int(check.details.get("disk_critical_count", "0"))
            warning = int(check.details.get("disk_warning_count", "0"))
            max_usage = check.details.get("max_disk_usage_percent", "unknown")
            if critical:
                findings.append(
                    _cuc_finding(
                        "disk_critical",
                        FindingSeverity.CRITICAL,
                        "Unity Connection disk usage is critically high",
                        [f"Node: {check.node}", f"Highest partition usage: {max_usage}%"],
                    )
                )
            elif warning:
                findings.append(
                    _cuc_finding(
                        "disk_warning",
                        FindingSeverity.WARNING,
                        "Unity Connection disk usage needs attention",
                        [f"Node: {check.node}", f"Highest partition usage: {max_usage}%"],
                    )
                )
            uptime = check.details.get("uptime_days", "unknown")
            if uptime.isdigit() and int(uptime) >= 365:
                findings.append(
                    HealthFinding(
                        rule_id=f"{self.rule_id}.uptime",
                        title="Unity Connection has been running for more than one year",
                        severity=FindingSeverity.INFO,
                        recommendation_kind=RecommendationKind.BEST_PRACTICE,
                        facts=[f"Node: {check.node}", f"Reported uptime: {uptime} days"],
                        reasoning=(
                            "Long uptime is not itself a fault, but planned maintenance helps keep "
                            "the platform current and validates a controlled restart path."
                        ),
                        recommendation=(
                            "Review maintenance history and include this server in the next approved "
                            "maintenance window if a restart is appropriate."
                        ),
                        evidence=[
                            EvidenceRef(
                                source="CUC.UCOS.CLI", operation="show_status", node=check.node
                            )
                        ],
                    )
                )
        return findings


class CucmServicePolicyRule:
    """Apply high-confidence CUCM placement checks to collected CLI service facts."""

    rule_id = "cucm.service_policy"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        services = [service for service in facts.services if service.source == "CUCM.UCOS.CLI"]
        if not services:
            return []
        by_node: dict[str, dict[str, ServiceStatusFact]] = {}
        for service in services:
            by_node.setdefault(service.node.casefold(), {})[service.service_name.casefold()] = service
        findings: list[HealthFinding] = []
        tftp_started = [
            node for node, items in by_node.items()
            if (tftp_service := items.get("cisco tftp")) and tftp_service.status.casefold() == "started"
        ]
        if not tftp_started:
            findings.append(_cucm_service_policy_finding(
                "tftp_unavailable", "No Cisco TFTP service was started in collected CUCM nodes",
                [f"CLI service lists evaluated: {len(by_node)}"],
                "Endpoints need at least one reachable Cisco TFTP service for configuration and firmware files.",
                "Confirm the designated TFTP node and its service state. If CLI coverage is partial, collect the remaining call-processing or dedicated TFTP nodes before changing service activation.",
            ))
        issues: list[str] = []
        for node, items in sorted(by_node.items()):
            callmanager = items.get("cisco callmanager")
            if callmanager and callmanager.activated is not False and callmanager.status.casefold() != "started":
                issues.append(f"{node}: Cisco CallManager")
            if callmanager and callmanager.status.casefold() == "started":
                for name in ("Cisco RIS Data Collector", "Cisco Database Layer Monitor"):
                    dependency = items.get(name.casefold())
                    if dependency and dependency.status.casefold() != "started":
                        issues.append(f"{node}: {name}")
        if issues:
            findings.append(_cucm_service_policy_finding(
                "call_processing_dependencies", "Collected CUCM call-processing service dependencies need review",
                issues,
                "Cisco documents CallManager, RIS Data Collector, and Database Layer Monitor as related call-processing services.",
                "Review Control Center and the intended node role before starting or restarting services; optional services that are not activated are not treated as failures.",
            ))
        return findings


def _cucm_service_policy_finding(
    suffix: str, title: str, facts: list[str], reasoning: str, recommendation: str
) -> HealthFinding:
    return HealthFinding(
        rule_id=f"cucm.service_policy.{suffix}", title=title,
        severity=FindingSeverity.WARNING,
        recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
        facts=facts, reasoning=reasoning, recommendation=recommendation,
        evidence=[EvidenceRef(source="CUCM.UCOS.CLI", operation="utils_service_list", confidence="high")],
    )


class CucServicePolicyRule:
    """Apply CUC critical-service expectations to every successfully collected active node."""

    rule_id = "cuc.service_policy"
    required_services = {
        "A Cisco DB",
        "A Cisco DB Replicator",
        "Cisco Tomcat",
        "Connection Conversation Manager",
        "Connection Mixer",
    }
    primary_services = {
        "Connection Notifier",
        "Connection Message Transfer Agent",
    }

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        services = [service for service in facts.services if service.source == "CUC.UCOS.CLI"]
        if not services:
            return []
        by_node: dict[str, dict[str, ServiceStatusFact]] = {}
        for service in services:
            by_node.setdefault(service.node.casefold(), {})[service.service_name.casefold()] = service
        failures: list[str] = []
        for node, node_services in sorted(by_node.items()):
            for name in sorted(self.required_services):
                node_service = node_services.get(name.casefold())
                if node_service is None or node_service.status.strip().lower() != "started":
                    failures.append(f"{node}: {name}")
        primary_nodes = {
            item.name.casefold()
            for item in facts.configuration_objects
            if item.object_type == "CucClusterRuntimeNode"
            and item.details.get("server_state", "").casefold() == "primary"
        }
        primary_services_failed: list[str] = []
        for node, node_services in sorted(by_node.items()):
            if primary_nodes and not any(key in node or node in key for key in primary_nodes):
                continue
            for name in sorted(self.primary_services):
                node_service = node_services.get(name.casefold())
                if node_service is None or node_service.status.strip().lower() != "started":
                    primary_services_failed.append(f"{node}: {name}")
        if not failures and not primary_services_failed:
            return []
        facts_list = []
        if failures:
            facts_list.append(
                "Required services not started: " + ", ".join(failures)
            )
        if primary_services_failed:
            facts_list.append(
                "Primary-role services not started: " + ", ".join(primary_services_failed)
            )
        return [
            HealthFinding(
                rule_id=self.rule_id,
                title="Unity Connection services do not meet expected publisher policy",
                severity=FindingSeverity.WARNING,
                recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                facts=facts_list,
                reasoning=(
                    "Cisco identifies these services as necessary for CUC call handling, media, "
                    "message delivery, or notifications. Only successfully collected nodes are evaluated."
                ),
                recommendation=(
                    "Confirm whether the stopped service is intentional. If not, review service "
                    "dependencies and alarms in Unity Connection before starting or restarting it."
                ),
                evidence=[
                    EvidenceRef(
                        source="CUC.UCOS.CLI", operation="utils_service_list", confidence="high"
                    )
                ],
            )
        ]


class CucClusterRoleRule:
    """Interpret CUC Primary/Secondary roles from ``show cuc cluster status``."""

    rule_id = "cuc.cluster_role"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        runtime = [
            item for item in facts.configuration_objects if item.object_type == "CucClusterRuntimeNode"
        ]
        if not runtime:
            return []
        states = [item.details.get("server_state", "unknown") for item in runtime]
        primary = [item.name for item in runtime if item.details.get("server_state") == "Primary"]
        secondary = [item.name for item in runtime if item.details.get("server_state") == "Secondary"]
        failed = [item.name for item in runtime if item.details.get("server_state") == "Not Functioning"]
        if failed or len(primary) > 1 or (len(runtime) > 1 and not primary):
            return [
                HealthFinding(
                    rule_id=self.rule_id,
                    title="Unity Connection cluster role state needs immediate review",
                    severity=FindingSeverity.CRITICAL,
                    recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                    facts=[
                        f"Primary: {', '.join(primary) or 'none'}",
                        f"Secondary: {', '.join(secondary) or 'none'}",
                        *([f"Not functioning: {', '.join(failed)}"] if failed else []),
                    ],
                    reasoning="A two-node CUC cluster should have one active Primary role; multiple Primary roles can indicate split-brain behavior.",
                    recommendation="Review show cuc cluster status and Cluster Management before making service changes; preserve the diagnostic bundle for Cisco TAC if split-brain or node failure is present.",
                    evidence=[EvidenceRef(source="CUC.UCOS.CLI", operation="show_cuc_cluster_status", confidence="high")],
                )
            ]
        transitional = [state for state in states if state in {"Starting", "Replicating Data", "Split Brain Recovery"}]
        if transitional:
            return [_info_finding(
                rule_id=self.rule_id,
                title="Unity Connection cluster is in a transitional role state",
                facts=[f"Observed states: {', '.join(states)}"],
                operation="show_cuc_cluster_status",
            )]
        return [_info_finding(
            rule_id=self.rule_id,
            title="Unity Connection cluster roles are coherent",
            facts=[f"Primary: {', '.join(primary)}", f"Secondary: {', '.join(secondary) or 'not applicable'}"],
            operation="show_cuc_cluster_status",
        )]


def _cuc_finding(
    suffix: str, severity: FindingSeverity, title: str, facts: list[str]
) -> HealthFinding:
    return HealthFinding(
        rule_id=f"cuc.platform_health.{suffix}",
        title=title,
        severity=severity,
        recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
        facts=facts,
        reasoning="UCOS platform summaries reported a condition requiring engineering review.",
        recommendation="Review the retained UCOS evidence and correct the affected platform condition.",
        evidence=[
            EvidenceRef(source="CUC.UCOS.CLI", operation="platform_summary", confidence="high")
        ],
    )


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


class CucSmtpSecurityRule:
    """Flag explicitly permissive untrusted SMTP settings reported by CUPI."""

    rule_id = "cuc.smtp_untrusted_security"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        exposed = []
        for item in facts.configuration_objects:
            if item.object_type != "CucSmtpConfiguration":
                continue
            details = item.details
            if not _is_true(details.get("allow_untrusted")):
                continue
            missing = [
                control
                for control, field in (
                    ("authentication", "require_auth_untrusted"),
                    ("TLS", "require_tls_untrusted"),
                )
                if _is_false(details.get(field))
            ]
            if missing:
                exposed.append(", ".join(missing))
        if not exposed:
            return []
        return [
            HealthFinding(
                rule_id=self.rule_id,
                title="Unity Connection accepts untrusted SMTP without all protective controls",
                severity=FindingSeverity.WARNING,
                recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                facts=[f"Missing controls for untrusted SMTP: {value}" for value in exposed],
                reasoning=(
                    "CUPI explicitly reports that connections from untrusted IP addresses are "
                    "allowed while authentication or TLS is disabled."
                ),
                recommendation=(
                    "Confirm the integration requirement, then require authentication and TLS or "
                    "restrict the permitted SMTP source addresses."
                ),
                evidence=[
                    EvidenceRef(
                        source="CUC.CUPI",
                        operation="CucSmtpConfiguration_bounded_get",
                        confidence="high",
                    )
                ],
            )
        ]


class CucInformixDialPlanRule:
    """Assess experimental CUC SQL dial-plan and transfer-path results."""

    rule_id = "cuc.experimental_sql_dial_plan"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        duplicates = [
            item for item in facts.configuration_objects
            if item.object_type == "CucSqlDuplicateExtension"
        ]
        transfers = [
            item for item in facts.configuration_objects
            if item.object_type in {
                "CucSqlAlternateContactTransfer", "CucSqlSystemTransferTarget",
            }
        ]
        findings = []
        if duplicates:
            findings.append(HealthFinding(
                rule_id=f"{self.rule_id}.duplicate_extensions",
                title="Duplicate Unity Connection directory extensions detected",
                severity=FindingSeverity.WARNING,
                recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                facts=[
                    f"Extension {item.name}: {item.details.get('occurrencecount', 'multiple')} records"
                    for item in duplicates
                ],
                reasoning=(
                    "The bounded experimental query found DTMF access IDs assigned more than "
                    "once. Unintended duplicates can make addressing and MWI troubleshooting "
                    "ambiguous."
                ),
                recommendation=(
                    "Review each duplicate against the intended Unity Connection dial plan and "
                    "remove or reassign only unintended collisions."
                ),
                evidence=[EvidenceRef(
                    source="CUC.INFORMIX.SQL", operation="cuc.sql.duplicate_extensions",
                    confidence="medium",
                )],
            ))
        if transfers:
            findings.append(HealthFinding(
                rule_id=f"{self.rule_id}.transfer_paths",
                title="Unity Connection call-handler transfer paths require policy review",
                severity=FindingSeverity.INFO,
                recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                facts=[
                    f"{item.name}: key {item.details.get('touchtonekey', '—')}; target "
                    f"{item.details.get('transfernumber') or item.details.get('targetconversation') or '—'}"
                    for item in transfers
                ],
                reasoning=(
                    "Alternate-contact and system-transfer paths can be intentional, but they "
                    "expand the set of destinations reachable through Unity Connection."
                ),
                recommendation=(
                    "Confirm each path is required and that the applicable restriction tables, "
                    "calling permissions, and toll-fraud controls constrain it appropriately."
                ),
                evidence=[EvidenceRef(
                    source="CUC.INFORMIX.SQL", operation="cuc.sql.transfer_targets",
                    confidence="medium",
                )],
            ))
        return findings


class CucmTopologyCompletenessRule:
    """Report collected routing/media containers that have no configured members."""

    rule_id = "cucm.topology_empty_membership"
    membership_fields = {
        "HuntList": "line_groups",
        "LineGroup": "directory_numbers",
        "MediaResourceGroup": "devices",
        "MediaResourceList": "media_resource_groups",
    }

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        empty = [
            item
            for item in facts.configuration_objects
            if (field := self.membership_fields.get(item.object_type))
            and item.details.get("relationship_collection") == "collected"
            and not item.details.get(field)
        ]
        if not empty:
            return []
        return [
            HealthFinding(
                rule_id=self.rule_id,
                title="One or more call-routing or media-resource containers have no members",
                severity=FindingSeverity.WARNING,
                recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                facts=[f"{item.object_type}: {item.name}" for item in empty],
                reasoning=(
                    "The bounded AXL get response completed successfully but returned no members "
                    "for the listed container. Calls depending on it may have no usable destination."
                ),
                recommendation=(
                    "Verify whether each empty object is unused; populate active dependencies or "
                    "remove obsolete references through the normal change process."
                ),
                evidence=[
                    EvidenceRef(
                        source="AXL",
                        operation="diagnostic_relationship_enrichment",
                        confidence="high",
                    )
                ],
            )
        ]


class ConfigurationInventorySummaryRule:
    """Summarizes bounded AXL configuration objects without policy judgment."""

    rule_id = "cucm.configuration_inventory_summary"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        cucm_objects = [
            item for item in facts.configuration_objects
            if item.source.strip().upper().startswith("AXL")
        ]
        if not cucm_objects:
            return []
        counts = Counter(item.object_type for item in cucm_objects)
        return [
            _info_finding(
                rule_id=self.rule_id,
                title="Configuration inventory data collected",
                facts=[
                    f"CUCM configuration objects: {len(cucm_objects)}",
                    *[f"{object_type}: {count}" for object_type, count in sorted(counts.items())],
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


def _is_true(value: str | None) -> bool:
    return (value or "").strip().lower() in {"true", "1", "yes", "enabled"}


def _is_false(value: str | None) -> bool:
    return (value or "").strip().lower() in {"false", "0", "no", "disabled"}
