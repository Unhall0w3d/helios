"""Tests for health rules."""

from __future__ import annotations

import unittest

from cisco_collab_health.models.facts import (
    AssessmentFacts,
    CertificateFact,
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
    CucInformixDialPlanRule,
    CucSmtpSecurityRule,
    CucmPlatformHealthRule,
    CucmTopologyCompletenessRule,
    CucServicePolicyRule,
    DeviceInventorySummaryRule,
    DeviceLoadRule,
    DeviceLoadSummaryRule,
    FirmwareDownloadRule,
    NodeReachabilityRule,
    PlatformCheckSummaryRule,
    RegistrationSummaryRule,
    ServiceSummaryRule,
    ServiceRuntimeRule,
    SipTrunkRuntimeRule,
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


class CucPlatformRulesTests(unittest.TestCase):
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
                        {"max_disk_usage_percent": "99"}, "CUCM.UCOS.CLI",
                    )
                ]
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.CRITICAL)
        self.assertIn("cucm-sub: 99%", findings[0].facts[0])


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
