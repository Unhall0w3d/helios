"""Tests for health rules."""

from __future__ import annotations

import unittest

from cisco_collab_health.models.facts import (
    AssessmentFacts,
    CollaborationNode,
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
    DeviceInventorySummaryRule,
    DeviceLoadRule,
    DeviceLoadSummaryRule,
    NodeReachabilityRule,
    PlatformCheckSummaryRule,
    RegistrationSummaryRule,
    ServiceSummaryRule,
)


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

    def test_matching_default_load_is_not_a_finding(self) -> None:
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

        self.assertEqual(findings, [])


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
