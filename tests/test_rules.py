"""Tests for health rules."""

from __future__ import annotations

import unittest

from cisco_collab_health.models.facts import (
    AssessmentFacts,
    CertificateFact,
    ClusterIdentity,
    CollaborationNode,
    ConfigurationObjectFact,
    CollectorIssueFact,
    DeviceInventoryFact,
    DeviceLoadDefaultFact,
    DeviceRegistrationFact,
    PlatformCheckFact,
    ServiceStatusFact,
)
from cisco_collab_health.models.findings import FindingSeverity
from cisco_collab_health.rules.basic import (
    CollectorHealthRule,
    CertificateValidityRule,
    CucPlatformStatusRule,
    CucClusterRoleRule,
    CucInformixDialPlanRule,
    CucSmtpSecurityRule,
    CucmPlatformHealthRule,
    CucmServicePolicyRule,
    CucmTopologyCompletenessRule,
    CucServicePolicyRule,
    DeviceInventorySummaryRule,
    DeviceLoadRule,
    DeviceLoadSummaryRule,
    FirmwareDownloadRule,
    NodeReachabilityRule,
    PlatformCheckSummaryRule,
    RegistrationSummaryRule,
    RegistrationBalanceRule,
    ServiceSummaryRule,
    ServiceRuntimeRule,
    SipTrunkRuntimeRule,
    SoftwareLifecycleRule,
    SoftwareConsistencyRule,
)


class ConfigurationSecurityRuleTests(unittest.TestCase):
    def test_cuc_smtp_rule_flags_untrusted_connection_without_auth_or_tls(self) -> None:
        facts = AssessmentFacts(
            configuration_objects=[
                ConfigurationObjectFact(
                    object_type="CucSmtpConfiguration",
                    name="SMTP server configuration",
                    details={
                        "allow_untrusted": "true",
                        "require_auth_untrusted": "false",
                        "require_tls_untrusted": "false",
                    },
                    source="CUC.CUPI/vmrest/smtpserver/serverconfigs",
                )
            ]
        )

        findings = CucSmtpSecurityRule().evaluate(facts)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.WARNING)
        self.assertIn("authentication, TLS", findings[0].facts[0])

    def test_topology_rule_only_flags_successfully_collected_empty_membership(self) -> None:
        facts = AssessmentFacts(
            configuration_objects=[
                ConfigurationObjectFact(
                    object_type="HuntList",
                    name="Empty-HL",
                    details={"relationship_collection": "collected"},
                    source="AXL.getHuntList",
                ),
                ConfigurationObjectFact(
                    object_type="LineGroup",
                    name="Unknown-LG",
                    details={},
                    source="AXL.listLineGroup",
                ),
            ]
        )

        findings = CucmTopologyCompletenessRule().evaluate(facts)

        self.assertEqual(len(findings), 1)
        self.assertIn("HuntList: Empty-HL", findings[0].facts)
        self.assertNotIn("LineGroup: Unknown-LG", findings[0].facts)


class FirmwareDownloadRuleTests(unittest.TestCase):
    def test_explicit_download_failures_are_warning_findings(self) -> None:
        facts = AssessmentFacts(
            registrations=[
                DeviceRegistrationFact(
                    name="SEP001",
                    status="Registered",
                    registered_node="sub-1",
                    ip_address="192.0.2.50",
                    model="Cisco 8841",
                    protocol="SIP",
                    source="RISPort70.selectCmDeviceExt",
                    download_status="Failed",
                    download_failure_reason="File Not Found",
                )
            ]
        )

        findings = FirmwareDownloadRule().evaluate(facts)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.WARNING)
        self.assertIn("File Not Found: 1", findings[0].facts)
        self.assertIn("Affected devices: SEP001", findings[0].facts)


class SoftwareConsistencyRuleTests(unittest.TestCase):
    def test_flags_version_and_software_option_differences_from_publisher(self) -> None:
        facts = AssessmentFacts(
            nodes=[
                CollaborationNode("pub", "10.0.0.1", "publisher", target_id="cluster-a"),
                CollaborationNode("sub", "10.0.0.2", "subscriber", target_id="cluster-a"),
            ],
            platform_checks=[
                PlatformCheckFact(
                    "pub", "show version active", "collected",
                    {"active_version": "15.0.1.12900-43", "installed_software_options": "patch-a.cop"},
                    "CUCM.UCOS.CLI", target_id="cluster-a",
                ),
                PlatformCheckFact(
                    "sub", "show version active", "collected",
                    {"active_version": "15.0.1.12900-234", "installed_software_options": "patch-b.cop"},
                    "CUCM.UCOS.CLI", target_id="cluster-a",
                ),
            ],
        )

        findings = SoftwareConsistencyRule().evaluate(facts)

        self.assertEqual(len(findings), 2)
        self.assertIn("15.0.1.12900-234", findings[0].facts[1])
        self.assertIn("missing patch-a.cop", findings[1].facts[1])


class SoftwareLifecycleRuleTests(unittest.TestCase):
    def test_known_unsupported_release_creates_source_linked_finding(self) -> None:
        facts = AssessmentFacts(
            cluster=ClusterIdentity("pub", "Cisco Unified Communications Manager", "12.5.1.11900-146")
        )

        findings = SoftwareLifecycleRule().evaluate(facts)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.WARNING)
        self.assertIn("support ended", findings[0].title)
        self.assertIn("cisco.com", findings[0].recommendation or "")

    def test_unknown_release_is_not_reported_as_a_lifecycle_finding(self) -> None:
        facts = AssessmentFacts(
            cluster=ClusterIdentity("pub", "Cisco Unified Communications Manager", "15.0.1.12900-43")
        )

        self.assertEqual(SoftwareLifecycleRule().evaluate(facts), [])


class CucPlatformRulesTests(unittest.TestCase):
    def test_cuc_cluster_role_rule_flags_multiple_primary_roles(self) -> None:
        findings = CucClusterRoleRule().evaluate(
            AssessmentFacts(
                configuration_objects=[
                    ConfigurationObjectFact("CucClusterRuntimeNode", "pub", {"server_state": "Primary"}, "CUC.UCOS.CLI"),
                    ConfigurationObjectFact("CucClusterRuntimeNode", "sub", {"server_state": "Primary"}, "CUC.UCOS.CLI"),
                ]
            )
        )

        self.assertEqual(findings[0].severity, FindingSeverity.CRITICAL)
    def test_disk_and_long_uptime_findings_are_derived_from_cuc_show_status(self) -> None:
        findings = CucPlatformStatusRule().evaluate(
            AssessmentFacts(
                platform_checks=[
                    PlatformCheckFact(
                        node="cuc-pub",
                        check_name="show status",
                        status="collected",
                        details={
                            "max_disk_usage_percent": "95",
                            "disk_warning_count": "1",
                            "disk_critical_count": "1",
                            "uptime_days": "400",
                        },
                        source="CUC.UCOS.CLI",
                    )
                ]
            )
        )

        self.assertEqual(
            [finding.severity for finding in findings],
            [FindingSeverity.CRITICAL, FindingSeverity.INFO],
        )
        self.assertIn("Highest partition usage: 95%", findings[0].facts)

    def test_cuc_service_policy_flags_missing_required_service_but_not_inactive_optional_service(
        self,
    ) -> None:
        findings = CucServicePolicyRule().evaluate(
            AssessmentFacts(
                services=[
                    ServiceStatusFact(
                        "cuc-pub", "A Cisco DB", True, "Started", None, "CUC.UCOS.CLI"
                    ),
                    ServiceStatusFact(
                        "cuc-pub", "A Cisco DB Replicator", True, "Started", None, "CUC.UCOS.CLI"
                    ),
                    ServiceStatusFact(
                        "cuc-pub", "Cisco Tomcat", True, "Started", None, "CUC.UCOS.CLI"
                    ),
                    ServiceStatusFact(
                        "cuc-pub",
                        "Connection Conversation Manager",
                        True,
                        "Stopped",
                        None,
                        "CUC.UCOS.CLI",
                    ),
                    ServiceStatusFact(
                        "cuc-pub", "Connection Mixer", True, "Started", None, "CUC.UCOS.CLI"
                    ),
                    ServiceStatusFact(
                        "cuc-pub", "Connection Mailbox Sync", False, "Stopped", None, "CUC.UCOS.CLI"
                    ),
                ]
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.WARNING)
        self.assertIn("Connection Conversation Manager", findings[0].facts[0])
        self.assertNotIn("Connection Mailbox Sync", " ".join(findings[0].facts))

    def test_cuc_service_policy_checks_singleton_services_only_on_primary(self) -> None:
        findings = CucServicePolicyRule().evaluate(
            AssessmentFacts(
                configuration_objects=[
                    ConfigurationObjectFact(
                        "CucClusterRuntimeNode", "cuc-pub", {"server_state": "Primary"},
                        "CUC.UCOS.CLI",
                    ),
                    ConfigurationObjectFact(
                        "CucClusterRuntimeNode", "cuc-sub", {"server_state": "Secondary"},
                        "CUC.UCOS.CLI",
                    ),
                ],
                services=[
                    *[
                        ServiceStatusFact("cuc-pub", name, True, "Started", None, "CUC.UCOS.CLI")
                        for name in CucServicePolicyRule.required_services
                    ],
                    *[
                        ServiceStatusFact("cuc-sub", name, True, "Started", None, "CUC.UCOS.CLI")
                        for name in CucServicePolicyRule.required_services
                    ],
                    ServiceStatusFact(
                        "cuc-pub", "Connection Notifier", True, "Stopped", None, "CUC.UCOS.CLI"
                    ),
                    ServiceStatusFact(
                        "cuc-pub", "Connection Message Transfer Agent", True, "Started", None,
                        "CUC.UCOS.CLI",
                    ),
                ],
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertIn("cuc-pub: Connection Notifier", findings[0].facts[0])
        self.assertNotIn("cuc-sub: Connection Notifier", " ".join(findings[0].facts))

    def test_cuc_cluster_role_rule_reports_transitional_state_as_information(self) -> None:
        findings = CucClusterRoleRule().evaluate(
            AssessmentFacts(
                configuration_objects=[
                    ConfigurationObjectFact(
                        "CucClusterRuntimeNode", "cuc-pub", {"server_state": "Starting"},
                        "CUC.UCOS.CLI",
                    ),
                    ConfigurationObjectFact(
                        "CucClusterRuntimeNode", "cuc-sub", {"server_state": "Secondary"},
                        "CUC.UCOS.CLI",
                    ),
                ]
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.INFO)

    def test_cucm_platform_rule_flags_unsynced_ntp_and_replication(self) -> None:
        findings = CucmPlatformHealthRule().evaluate(
            AssessmentFacts(
                platform_checks=[
                    PlatformCheckFact(
                        "cucm-sub",
                        "utils ntp status",
                        "collected",
                        {"synchronized": "false"},
                        "CUCM.UCOS.CLI",
                    ),
                    PlatformCheckFact(
                        "cucm-pub",
                        "utils dbreplication runtimestate",
                        "collected",
                        {"replication_bad_rows": "1"},
                        "CUCM.UCOS.CLI",
                    ),
                ]
            )
        )

        self.assertEqual(
            [finding.severity for finding in findings],
            [FindingSeverity.CRITICAL, FindingSeverity.CRITICAL],
        )

    def test_cucm_platform_rule_flags_high_disk_usage(self) -> None:
        findings = CucmPlatformHealthRule().evaluate(
            AssessmentFacts(
                platform_checks=[
                    PlatformCheckFact(
                        "cucm-sub", "show status", "collected",
                        {"common_partition_usage_percent": "99"}, "CUCM.UCOS.CLI",
                    )
                ]
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.CRITICAL)
        self.assertIn("cucm-sub: 99% common/logging", findings[0].facts[0])

    def test_cucm_platform_rule_flags_stale_unambiguous_backup(self) -> None:
        findings = CucmPlatformHealthRule().evaluate(
            AssessmentFacts(
                platform_checks=[
                    PlatformCheckFact(
                        "cucm-pub",
                        "utils disaster_recovery history backup",
                        "collected",
                        {
                            "completion": "complete",
                            "successful_backup_entries": "4",
                            "latest_successful_backup": "2026-07-10",
                            "latest_successful_backup_age_days": "6",
                        },
                        "CUCM.UCOS.CLI",
                    )
                ]
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "cucm.platform_health.backup_recency")
        self.assertEqual(findings[0].severity, FindingSeverity.WARNING)
        self.assertIn("cucm-pub: 2026-07-10 (6 days ago)", findings[0].facts)

    def test_cucm_platform_rule_does_not_call_incomplete_history_no_backup(self) -> None:
        findings = CucmPlatformHealthRule().evaluate(
            AssessmentFacts(
                platform_checks=[
                    PlatformCheckFact(
                        "cucm-pub",
                        "utils disaster_recovery history backup",
                        "incomplete",
                        {
                            "completion": "prompt timeout",
                            "successful_backup_entries": "0",
                        },
                        "CUCM.UCOS.CLI",
                    )
                ]
            )
        )

        self.assertEqual(findings, [])


class CucInformixDialPlanRuleTests(unittest.TestCase):
    def test_duplicate_extensions_and_transfer_paths_are_assessed(self) -> None:
        facts = AssessmentFacts(configuration_objects=[
            ConfigurationObjectFact(
                object_type="CucSqlDuplicateExtension", name="1000",
                details={"occurrencecount": "2", "experimental": "true"},
                source="CUC.INFORMIX.SQL",
            ),
            ConfigurationObjectFact(
                object_type="CucSqlAlternateContactTransfer", name="Main Menu",
                details={"touchtonekey": "9", "transfernumber": "90115551212"},
                source="CUC.INFORMIX.SQL",
            ),
        ])

        findings = CucInformixDialPlanRule().evaluate(facts)

        self.assertEqual(
            [item.severity for item in findings],
            [FindingSeverity.WARNING, FindingSeverity.INFO],
        )
        self.assertIn("Extension 1000", findings[0].facts[0])
        self.assertIn("90115551212", findings[1].facts[0])


class CertificateValidityRuleTests(unittest.TestCase):
    def test_expired_certificate_is_reported_without_missing_store_warning(self) -> None:
        fact = CertificateFact(
            node="pub",
            name="CallManager.pem",
            service="CallManager",
            store=None,
            certificate_kind="identity",
            subject="CN=pub",
            issuer="CN=pub",
            serial_number="1",
            valid_from=None,
            valid_until="2026-01-01T00:00:00Z",
            days_remaining=-1,
            self_signed=True,
            key_type="RSA",
            key_size="2048",
            signature_algorithm="SHA256",
            subject_key_identifier=None,
            authority_key_identifier=None,
            intermediate=None,
            root="CN=pub",
            chain_status="self-signed",
            source="fixture",
        )

        findings = CertificateValidityRule().evaluate(AssessmentFacts(certificates=[fact]))

        self.assertEqual(findings[0].severity, FindingSeverity.CRITICAL)
        self.assertEqual(len(findings), 1)
        self.assertIn("CallManager.pem [CallManager] on pub", findings[0].facts[0])

    def test_expired_trust_certificate_is_not_reported_as_service_outage(self) -> None:
        fact = CertificateFact(
            node="pub",
            name="old-peer.pem",
            service="tomcat-trust",
            store="tomcat-trust",
            certificate_kind="trust",
            subject="CN=old-peer",
            issuer="CN=old-peer",
            serial_number="2",
            valid_from=None,
            valid_until="2020-01-01T00:00:00Z",
            days_remaining=-1,
            self_signed=True,
            key_type="RSA",
            key_size="2048",
            signature_algorithm="SHA256",
            subject_key_identifier=None,
            authority_key_identifier=None,
            intermediate=None,
            root="CN=old-peer",
            chain_status="self-signed",
            source="fixture",
        )

        finding = CertificateValidityRule().evaluate(AssessmentFacts(certificates=[fact]))[0]

        self.assertEqual(finding.severity, FindingSeverity.WARNING)
        self.assertIn("trust", finding.rule_id)
        self.assertIn("does not by itself prove", finding.reasoning)

    def test_expired_itl_recovery_has_specific_non_outage_guidance(self) -> None:
        fact = CertificateFact(
            node="pub",
            name="ITLRecovery.pem",
            service="ITLRecovery",
            store=None,
            certificate_kind="identity",
            subject="CN=ITLRecovery",
            issuer="CN=ITLRecovery",
            serial_number="3",
            valid_from=None,
            valid_until="2020-01-01T00:00:00Z",
            days_remaining=-100,
            self_signed=True,
            key_type="RSA",
            key_size="2048",
            signature_algorithm="SHA256",
            subject_key_identifier=None,
            authority_key_identifier=None,
            intermediate=None,
            root="CN=ITLRecovery",
            chain_status="self-signed",
            source="fixture",
        )

        finding = CertificateValidityRule().evaluate(AssessmentFacts(certificates=[fact]))[0]

        self.assertEqual(finding.severity, FindingSeverity.WARNING)
        self.assertIn("ITLRecovery", finding.title)
        self.assertIn("does not by itself prove", finding.reasoning)

    def test_download_failure_with_intended_active_load_is_informational(self) -> None:
        facts = AssessmentFacts(
            devices=[
                DeviceInventoryFact(
                    name="SEP001",
                    description=None,
                    model="Cisco 8841",
                    protocol="SIP",
                    device_pool=None,
                    call_manager_group=None,
                    location=None,
                    region=None,
                    configured_load=None,
                    source="fixture",
                )
            ],
            device_load_defaults=[
                DeviceLoadDefaultFact(
                    model="Cisco 8841",
                    protocol="SIP",
                    default_load="sip88.current",
                    source="fixture",
                )
            ],
            registrations=[
                DeviceRegistrationFact(
                    name="SEP001",
                    status="Registered",
                    registered_node="sub-1",
                    ip_address=None,
                    model="Cisco 8841",
                    protocol="SIP",
                    source="fixture",
                    active_load="sip88.current",
                    download_status="Failed",
                    download_failure_reason="File Not Found",
                )
            ],
        )

        findings = FirmwareDownloadRule().evaluate(facts)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.INFO)
        self.assertTrue(findings[0].rule_id.endswith("status_only"))


class ServiceRuntimeRuleTests(unittest.TestCase):
    def test_intentional_stopped_service_reasons_do_not_create_findings(self) -> None:
        facts = AssessmentFacts(
            services=[
                ServiceStatusFact(
                    node="sub-1",
                    service_name="Cisco DRF Master",
                    activated=None,
                    status="Stopped",
                    uptime_seconds=None,
                    source="fixture",
                    reason="Commanded Out of Service",
                ),
                ServiceStatusFact(
                    node="sub-1",
                    service_name="Cisco WebDialer",
                    activated=None,
                    status="Stopped",
                    uptime_seconds=None,
                    source="fixture",
                    reason="Service Not Activated",
                ),
            ]
        )

        self.assertEqual(ServiceRuntimeRule().evaluate(facts), [])

    def test_unexpected_stopped_service_is_warning(self) -> None:
        facts = AssessmentFacts(
            services=[
                ServiceStatusFact(
                    node="sub-1",
                    service_name="Cisco CallManager",
                    activated=None,
                    status="Stopped",
                    uptime_seconds=None,
                    source="fixture",
                    reason="Service failed",
                )
            ]
        )

        findings = ServiceRuntimeRule().evaluate(facts)

        self.assertEqual(findings[0].severity, FindingSeverity.WARNING)


class CucmServicePolicyRuleTests(unittest.TestCase):
    def test_missing_tftp_and_stopped_call_processing_dependency_are_actionable(self) -> None:
        findings = CucmServicePolicyRule().evaluate(
            AssessmentFacts(
                services=[
                    ServiceStatusFact(
                        "cucm-pub", "Cisco CallManager", True, "Started", None, "CUCM.UCOS.CLI"
                    ),
                    ServiceStatusFact(
                        "cucm-pub", "Cisco RIS Data Collector", True, "Stopped", None,
                        "CUCM.UCOS.CLI",
                    ),
                    ServiceStatusFact(
                        "cucm-pub", "Cisco Database Layer Monitor", False, "Stopped", None,
                        "CUCM.UCOS.CLI",
                    ),
                ]
            )
        )

        self.assertEqual(len(findings), 2)
        self.assertTrue(findings[0].rule_id.endswith("tftp_unavailable"))
        self.assertIn("cucm-pub: Cisco RIS Data Collector", findings[1].facts)
        self.assertIn("cucm-pub: Cisco Database Layer Monitor", findings[1].facts)

    def test_merged_cli_and_control_center_tftp_fact_is_recognized(self) -> None:
        findings = CucmServicePolicyRule().evaluate(
            AssessmentFacts(
                services=[
                    ServiceStatusFact(
                        "cucm-pub", "Cisco Tftp", True, "Started", None,
                        "ControlCenter.soapGetServiceStatus, CUCM.UCOS.CLI",
                    )
                ]
            )
        )

        self.assertEqual(findings, [])


class RegistrationBalanceRuleTests(unittest.TestCase):
    def test_balanced_subscriber_registration_does_not_create_advisory(self) -> None:
        facts = AssessmentFacts(
            registrations=[
                *[
                    DeviceRegistrationFact(
                        f"SEPsub1{number}", "Registered", "cucm-sub-1", None, "Cisco 8841", "SIP", "RISPort70"
                    )
                    for number in range(10)
                ],
                *[
                    DeviceRegistrationFact(
                        f"SEPsub2{number}", "Registered", "cucm-sub-2", None, "Cisco 8841", "SIP", "RISPort70"
                    )
                    for number in range(10)
                ],
            ]
        )

        self.assertEqual(RegistrationBalanceRule().evaluate(facts), [])

    def test_skew_and_publisher_registrations_create_advisory(self) -> None:
        facts = AssessmentFacts(
            nodes=[CollaborationNode("cucm-pub", "10.0.0.1", "publisher")],
            registrations=[
                *[
                    DeviceRegistrationFact(
                        f"SEPpub{number}", "Registered", "cucm-pub", None, "Cisco 8841", "SIP", "RISPort70"
                    )
                    for number in range(2)
                ],
                *[
                    DeviceRegistrationFact(
                        f"SEPsub{number}", "Registered", "cucm-sub", None, "Cisco 8841", "SIP", "RISPort70"
                    )
                    for number in range(20)
                ],
            ],
        )

        findings = RegistrationBalanceRule().evaluate(facts)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.INFO)
        self.assertIn("Publisher registrations observed: 2", findings[0].facts)


class NodeReachabilityRuleTests(unittest.TestCase):
    def test_unreachable_node_is_critical(self) -> None:
        facts = AssessmentFacts(
            nodes=[
                CollaborationNode(
                    name="cucm-sub-02",
                    address="192.0.2.12",
                    role="subscriber",
                    reachable=False,
                )
            ]
        )

        findings = NodeReachabilityRule().evaluate(facts)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.CRITICAL)
        self.assertIn("cucm-sub-02", findings[0].facts[0])


class CollectorHealthRuleTests(unittest.TestCase):
    def test_warning_issue_creates_warning_finding(self) -> None:
        findings = CollectorHealthRule().evaluate(
            AssessmentFacts(
                collector_issues=[
                    CollectorIssueFact(
                        collector_name="axl",
                        issue_type="warning",
                        message="phone inventory skipped",
                    )
                ]
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.WARNING)
        self.assertIn("axl: warning: phone inventory skipped", findings[0].facts[0])

    def test_error_issue_creates_critical_finding(self) -> None:
        findings = CollectorHealthRule().evaluate(
            AssessmentFacts(
                collector_issues=[
                    CollectorIssueFact(
                        collector_name="axl",
                        issue_type="error",
                        message="transport failed",
                        exception_type="RuntimeError",
                    )
                ]
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.CRITICAL)

    def test_platform_ssh_coverage_has_a_specific_actionable_finding(self) -> None:
        finding = CollectorHealthRule().evaluate(
            AssessmentFacts(
                collector_issues=[
                    CollectorIssueFact(
                        "cucm",
                        "warning",
                        "cucm_platform_cli: CUCM SSH session failed on cucm-sub: Server not found in known_hosts",
                    ),
                ]
            )
        )[0]

        self.assertEqual(finding.title, "Platform checks were not collected from one or more nodes")
        self.assertIn("Affected nodes: cucm-sub", finding.facts)


class DeviceLoadRuleTests(unittest.TestCase):
    def test_manual_load_is_informational(self) -> None:
        findings = DeviceLoadRule().evaluate(
            AssessmentFacts(
                devices=[
                    DeviceInventoryFact(
                        name="SEP001122334455",
                        description=None,
                        model="Cisco 8845",
                        protocol="SIP",
                        device_pool="Default",
                        call_manager_group=None,
                        location=None,
                        region=None,
                        configured_load="sip8845.custom",
                        source="AXL.listPhone.summary",
                    )
                ],
                device_load_defaults=[
                    DeviceLoadDefaultFact(
                        model="Cisco 8845",
                        protocol="SIP",
                        default_load="sip8845.14-2-1",
                        source="AXL.listDeviceDefaults",
                    )
                ],
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.INFO)
        self.assertIn("SEP001122334455", findings[0].facts[0])

    def test_matching_default_load_is_still_a_static_override_finding(self) -> None:
        findings = DeviceLoadRule().evaluate(
            AssessmentFacts(
                devices=[
                    DeviceInventoryFact(
                        name="SEP001122334455",
                        description=None,
                        model="Cisco 8845",
                        protocol="SIP",
                        device_pool="Default",
                        call_manager_group=None,
                        location=None,
                        region=None,
                        configured_load="sip8845.14-2-1",
                        source="AXL.listPhone.summary",
                    )
                ],
                device_load_defaults=[
                    DeviceLoadDefaultFact(
                        model="Cisco 8845",
                        protocol="SIP",
                        default_load="sip8845.14-2-1",
                        source="AXL.listDeviceDefaults",
                    )
                ],
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertIn("remains statically pinned", findings[0].facts[0])


class SummaryRuleTests(unittest.TestCase):
    def test_summary_rules_do_not_fire_without_relevant_facts(self) -> None:
        facts = AssessmentFacts()

        self.assertEqual(DeviceInventorySummaryRule().evaluate(facts), [])
        self.assertEqual(RegistrationSummaryRule().evaluate(facts), [])
        self.assertEqual(ServiceSummaryRule().evaluate(facts), [])
        self.assertEqual(PlatformCheckSummaryRule().evaluate(facts), [])
        self.assertEqual(DeviceLoadSummaryRule().evaluate(facts), [])

    def test_device_inventory_summary_is_informational(self) -> None:
        findings = DeviceInventorySummaryRule().evaluate(
            AssessmentFacts(
                devices=[
                    DeviceInventoryFact(
                        name="SEP001122334455",
                        description=None,
                        model="Cisco 8845",
                        protocol="SIP",
                        device_pool="Default",
                        call_manager_group=None,
                        location=None,
                        region=None,
                        configured_load=None,
                        source="fixture",
                    ),
                    DeviceInventoryFact(
                        name="SEP00AABBCCDDEE",
                        description=None,
                        model="Cisco 7945",
                        protocol="SCCP",
                        device_pool="Default",
                        call_manager_group=None,
                        location=None,
                        region=None,
                        configured_load=None,
                        source="fixture",
                    ),
                ]
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.INFO)
        self.assertIn("SIP devices: 1", findings[0].facts)
        self.assertIn("SCCP devices: 1", findings[0].facts)

    def test_registration_summary_is_informational(self) -> None:
        findings = RegistrationSummaryRule().evaluate(
            AssessmentFacts(
                registrations=[
                    DeviceRegistrationFact(
                        name="SEP001122334455",
                        status="registered",
                        registered_node="cucm-pub-01",
                        ip_address="192.0.2.50",
                        model="Cisco 8845",
                        protocol="SIP",
                        source="fixture",
                    ),
                    DeviceRegistrationFact(
                        name="ITSP-SIP-TRUNK",
                        status="unregistered",
                        registered_node=None,
                        ip_address=None,
                        model="SIP Trunk",
                        protocol="SIP",
                        source="fixture",
                    ),
                ]
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.INFO)
        self.assertIn("Registered: 1", findings[0].facts)
        self.assertIn("Unregistered: 1", findings[0].facts)

    def test_unregistered_sip_trunks_create_an_actionable_warning(self) -> None:
        findings = SipTrunkRuntimeRule().evaluate(
            AssessmentFacts(
                registrations=[
                    DeviceRegistrationFact(
                        name="provider-trunk",
                        status="UnRegistered",
                        registered_node="cucm-pub",
                        ip_address=None,
                        model="SIP Trunk",
                        protocol="SIP",
                        source="RISPort70.selectCmDevice",
                        device_class="SIPTrunk",
                    ),
                    DeviceRegistrationFact(
                        name="unity-trunk",
                        status="Registered",
                        registered_node="cucm-pub",
                        ip_address=None,
                        model="SIP Trunk",
                        protocol="SIP",
                        source="RISPort70.selectCmDevice",
                        device_class="SIPTrunk",
                    ),
                ]
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.WARNING)
        self.assertIn("Affected trunks: provider-trunk", findings[0].facts)
        self.assertIn("UnRegistered: 1", findings[0].facts)
        self.assertEqual(findings[0].evidence[0].operation, "selectCmDevice")

    def test_service_summary_is_informational(self) -> None:
        findings = ServiceSummaryRule().evaluate(
            AssessmentFacts(
                services=[
                    ServiceStatusFact(
                        node="cucm-pub-01",
                        service_name="Cisco CallManager",
                        activated=True,
                        status="STARTED",
                        uptime_seconds=42,
                        source="fixture",
                    ),
                    ServiceStatusFact(
                        node="cucm-pub-01",
                        service_name="Cisco Tftp",
                        activated=False,
                        status="STOPPED",
                        uptime_seconds=None,
                        source="fixture",
                    ),
                ]
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.INFO)
        self.assertIn("Started services: 1", findings[0].facts)
        self.assertIn("Non-started services: 1", findings[0].facts)

    def test_platform_check_summary_is_informational(self) -> None:
        findings = PlatformCheckSummaryRule().evaluate(
            AssessmentFacts(
                platform_checks=[
                    PlatformCheckFact(
                        node="cucm-pub-01",
                        check_name="ntp",
                        status="synchronized",
                        details={"peer": "192.0.2.1"},
                        source="fixture",
                    )
                ]
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.INFO)
        self.assertIn("Status values observed: synchronized", findings[0].facts)

    def test_device_load_summary_is_informational(self) -> None:
        findings = DeviceLoadSummaryRule().evaluate(
            AssessmentFacts(
                devices=[
                    DeviceInventoryFact(
                        name="SEP001122334455",
                        description=None,
                        model="Cisco 8845",
                        protocol="SIP",
                        device_pool="Default",
                        call_manager_group=None,
                        location=None,
                        region=None,
                        configured_load="sip8845.14-2-1",
                        source="fixture",
                    )
                ],
                device_load_defaults=[
                    DeviceLoadDefaultFact(
                        model="Cisco 8845",
                        protocol="SIP",
                        default_load="sip8845.14-2-1",
                        source="fixture",
                    )
                ],
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.INFO)
        self.assertIn("Device load defaults: 1", findings[0].facts)
        self.assertIn("Devices with configured loads: 1", findings[0].facts)


if __name__ == "__main__":
    unittest.main()
