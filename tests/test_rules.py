"""Tests for health rules."""

from __future__ import annotations

import unittest

from cisco_collab_health.models.facts import (
    AssessmentFacts,
    CollaborationNode,
    CollectorIssueFact,
    DeviceInventoryFact,
    DeviceLoadDefaultFact,
)
from cisco_collab_health.models.findings import FindingSeverity
from cisco_collab_health.rules.basic import CollectorHealthRule, DeviceLoadRule, NodeReachabilityRule


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


if __name__ == "__main__":
    unittest.main()
