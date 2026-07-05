"""Tests for normalized fact containers."""

from __future__ import annotations

import unittest

from cisco_collab_health.models.facts import (
    AssessmentFacts,
    CollaborationNode,
    DeviceInventoryFact,
    DeviceLoadDefaultFact,
    DeviceRegistrationFact,
    PerfCounterFact,
    PlatformCheckFact,
    ServiceStatusFact,
)


class AssessmentFactsTests(unittest.TestCase):
    def test_merge_deduplicates_nodes_by_address(self) -> None:
        facts = AssessmentFacts(
            nodes=[
                CollaborationNode(
                    name="cucm-pub-01",
                    address="192.0.2.10",
                    role="subscriber",
                    reachable=None,
                )
            ]
        )
        other = AssessmentFacts(
            nodes=[
                CollaborationNode(
                    name="CUCM-PUB-01",
                    address="192.0.2.10",
                    role="publisher",
                    reachable=True,
                )
            ]
        )

        facts.merge(other)

        self.assertEqual(len(facts.nodes), 1)
        self.assertEqual(facts.nodes[0].role, "publisher")
        self.assertTrue(facts.nodes[0].reachable)

    def test_merge_deduplicates_nodes_by_name(self) -> None:
        facts = AssessmentFacts(
            nodes=[
                CollaborationNode(
                    name="cucm-sub-01",
                    address="cucm-sub-01.example.test",
                    role="subscriber",
                    reachable=True,
                )
            ]
        )
        other = AssessmentFacts(
            nodes=[
                CollaborationNode(
                    name="CUCM-SUB-01",
                    address="192.0.2.11",
                    role="subscriber",
                    reachable=False,
                )
            ]
        )

        facts.merge(other)

        self.assertEqual(len(facts.nodes), 1)
        self.assertFalse(facts.nodes[0].reachable)

    def test_merge_preserves_distinct_nodes(self) -> None:
        facts = AssessmentFacts(
            nodes=[
                CollaborationNode(
                    name="cucm-pub-01",
                    address="192.0.2.10",
                    role="publisher",
                    reachable=True,
                )
            ]
        )
        other = AssessmentFacts(
            nodes=[
                CollaborationNode(
                    name="cucm-sub-01",
                    address="192.0.2.11",
                    role="subscriber",
                    reachable=True,
                )
            ]
        )

        facts.merge(other)

        self.assertEqual(len(facts.nodes), 2)

    def test_merge_deduplicates_device_inventory_by_name(self) -> None:
        facts = AssessmentFacts(
            devices=[
                DeviceInventoryFact(
                    name="SEP001122334455",
                    description=None,
                    model="Cisco 8845",
                    protocol="SIP",
                    device_pool="Default",
                    call_manager_group="Default",
                    location=None,
                    region=None,
                    configured_load=None,
                    source="AXL.listPhone",
                )
            ]
        )
        other = AssessmentFacts(
            devices=[
                DeviceInventoryFact(
                    name="sep001122334455",
                    description="Lobby phone",
                    model="Cisco 8845",
                    protocol="SIP",
                    device_pool="Lobby",
                    call_manager_group="Default",
                    location="Hub_None",
                    region="Default",
                    configured_load=None,
                    source="AXL.getPhone",
                )
            ]
        )

        facts.merge(other)

        self.assertEqual(len(facts.devices), 1)
        self.assertEqual(facts.devices[0].description, "Lobby phone")
        self.assertEqual(facts.devices[0].device_pool, "Lobby")

    def test_merge_preserves_richer_device_inventory_when_duplicate_is_sparse(self) -> None:
        facts = AssessmentFacts(
            devices=[
                DeviceInventoryFact(
                    name="SEP001122334455",
                    description="Lobby phone",
                    model="Cisco 8845",
                    protocol="SIP",
                    device_pool="Default",
                    call_manager_group="Default",
                    location="Hub_None",
                    region="Default",
                    configured_load="sip8845.14-2-1",
                    source="AXL.listPhone.summary",
                )
            ]
        )
        other = AssessmentFacts(
            devices=[
                DeviceInventoryFact(
                    name="sep001122334455",
                    description=None,
                    model=None,
                    protocol=None,
                    device_pool=None,
                    call_manager_group=None,
                    location=None,
                    region=None,
                    configured_load=None,
                    source="AXL.listPhone.summary",
                )
            ]
        )

        facts.merge(other)

        self.assertEqual(len(facts.devices), 1)
        self.assertEqual(facts.devices[0].description, "Lobby phone")
        self.assertEqual(facts.devices[0].model, "Cisco 8845")
        self.assertEqual(facts.devices[0].configured_load, "sip8845.14-2-1")

    def test_merge_deduplicates_runtime_fact_types_by_stable_keys(self) -> None:
        facts = AssessmentFacts(
            registrations=[
                DeviceRegistrationFact(
                    name="SEP001122334455",
                    status="Unknown",
                    registered_node=None,
                    ip_address=None,
                    model=None,
                    protocol=None,
                    source="RISPort70.SelectCmDeviceExt",
                )
            ],
            services=[
                ServiceStatusFact(
                    node="cucm-pub-01",
                    service_name="Cisco CallManager",
                    activated=True,
                    status="Starting",
                    uptime_seconds=None,
                    source="ControlCenter.soapGetServiceStatus",
                )
            ],
            perf_counters=[
                PerfCounterFact(
                    node="cucm-pub-01",
                    object_name="Cisco CallManager",
                    counter_name="RegisteredHardwarePhones",
                    instance=None,
                    value=1,
                    sample_count=1,
                    source="PerfMon.perfmonCollectSessionData",
                )
            ],
            platform_checks=[
                PlatformCheckFact(
                    node="cucm-pub-01",
                    check_name="dbreplication",
                    status="unknown",
                    details={},
                    source="CLI.utils dbreplication runtimestate",
                )
            ],
        )
        other = AssessmentFacts(
            registrations=[
                DeviceRegistrationFact(
                    name="sep001122334455",
                    status="Registered",
                    registered_node="cucm-pub-01",
                    ip_address="192.0.2.20",
                    model="Cisco 8845",
                    protocol="SIP",
                    source="RISPort70.SelectCmDeviceExt",
                )
            ],
            services=[
                ServiceStatusFact(
                    node="CUCM-PUB-01",
                    service_name="Cisco CallManager",
                    activated=True,
                    status="Started",
                    uptime_seconds=3600,
                    source="ControlCenter.soapGetServiceStatus",
                )
            ],
            perf_counters=[
                PerfCounterFact(
                    node="CUCM-PUB-01",
                    object_name="Cisco CallManager",
                    counter_name="RegisteredHardwarePhones",
                    instance=None,
                    value=2,
                    sample_count=2,
                    source="PerfMon.perfmonCollectSessionData",
                )
            ],
            platform_checks=[
                PlatformCheckFact(
                    node="CUCM-PUB-01",
                    check_name="dbreplication",
                    status="good",
                    details={"state": "2"},
                    source="CLI.utils dbreplication runtimestate",
                )
            ],
        )

        facts.merge(other)

        self.assertEqual(len(facts.registrations), 1)
        self.assertEqual(facts.registrations[0].status, "Registered")
        self.assertEqual(len(facts.services), 1)
        self.assertEqual(facts.services[0].status, "Started")
        self.assertEqual(len(facts.perf_counters), 1)
        self.assertEqual(facts.perf_counters[0].sample_count, 2)
        self.assertEqual(len(facts.platform_checks), 1)
        self.assertEqual(facts.platform_checks[0].status, "good")

    def test_merge_deduplicates_device_load_defaults_by_model_and_protocol(self) -> None:
        facts = AssessmentFacts(
            device_load_defaults=[
                DeviceLoadDefaultFact(
                    model="Cisco 8845",
                    protocol="SIP",
                    default_load=None,
                    source="AXL.listDeviceDefaults",
                )
            ]
        )
        other = AssessmentFacts(
            device_load_defaults=[
                DeviceLoadDefaultFact(
                    model="cisco 8845",
                    protocol="sip",
                    default_load="sip8845.14-2-1",
                    source="fixture",
                )
            ]
        )

        facts.merge(other)

        self.assertEqual(len(facts.device_load_defaults), 1)
        self.assertEqual(facts.device_load_defaults[0].default_load, "sip8845.14-2-1")
        self.assertEqual(
            facts.device_load_defaults[0].source,
            "AXL.listDeviceDefaults, fixture",
        )


if __name__ == "__main__":
    unittest.main()
