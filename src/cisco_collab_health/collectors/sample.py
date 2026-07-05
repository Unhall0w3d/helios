"""Offline sample collector for alpha testing."""

from __future__ import annotations

from cisco_collab_health.models.evidence import EvidenceRef
from cisco_collab_health.collectors.base import CollectionContext, CollectionResult
from cisco_collab_health.models.facts import (
    AssessmentFacts,
    ClusterIdentity,
    CollaborationNode,
    DeviceInventoryFact,
    DeviceRegistrationFact,
    PerfCounterFact,
    PlatformCheckFact,
    ServiceStatusFact,
)


class SampleCollector:
    """Returns deterministic facts without connecting to external systems."""

    name = "sample"

    def collect(self, context: CollectionContext) -> CollectionResult:
        del context
        return CollectionResult(
            collector_name=self.name,
            facts=AssessmentFacts(
                cluster=ClusterIdentity(
                    name="alpha-lab",
                    product="Cisco Unified Communications Manager",
                    version="14.0",
                ),
                nodes=[
                    CollaborationNode(
                        name="cucm-pub-01",
                        address="192.0.2.10",
                        role="publisher",
                        reachable=True,
                    ),
                    CollaborationNode(
                        name="cucm-sub-01",
                        address="192.0.2.11",
                        role="subscriber",
                        reachable=True,
                    ),
                ],
                devices=[
                    DeviceInventoryFact(
                        name="SEP001122334455",
                        description="Synthetic lobby phone",
                        model="Cisco 8845",
                        protocol="SIP",
                        device_pool="Default",
                        call_manager_group="Default",
                        location="HQ",
                        region="Default",
                        configured_load="sip8845.14-2-1",
                        source="sample.synthetic",
                    ),
                    DeviceInventoryFact(
                        name="CSFALICE",
                        description="Synthetic Jabber softphone",
                        model="Cisco Unified Client Services Framework",
                        protocol="SIP",
                        device_pool="Softphone",
                        call_manager_group="Default",
                        location="Remote",
                        region="Default",
                        configured_load=None,
                        source="sample.synthetic",
                    ),
                    DeviceInventoryFact(
                        name="SEP00AABBCCDDEE",
                        description="Synthetic hallway phone",
                        model="Cisco 7945",
                        protocol="SCCP",
                        device_pool="Default",
                        call_manager_group="Default",
                        location="HQ",
                        region="Default",
                        configured_load="SCCP45.9-4-2SR4-3",
                        source="sample.synthetic",
                    ),
                ],
                registrations=[
                    DeviceRegistrationFact(
                        name="SEP001122334455",
                        status="registered",
                        registered_node="cucm-pub-01",
                        ip_address="192.0.2.50",
                        model="Cisco 8845",
                        protocol="SIP",
                        source="sample.synthetic",
                    ),
                    DeviceRegistrationFact(
                        name="CSFALICE",
                        status="unregistered",
                        registered_node=None,
                        ip_address=None,
                        model="Cisco Unified Client Services Framework",
                        protocol="SIP",
                        source="sample.synthetic",
                    ),
                    DeviceRegistrationFact(
                        name="SEP00AABBCCDDEE",
                        status="registered",
                        registered_node="cucm-sub-01",
                        ip_address="192.0.2.52",
                        model="Cisco 7945",
                        protocol="SCCP",
                        source="sample.synthetic",
                    ),
                    DeviceRegistrationFact(
                        name="HQ-VG01",
                        status="registered",
                        registered_node="cucm-pub-01",
                        ip_address="192.0.2.60",
                        model="Cisco VG Gateway",
                        protocol="MGCP",
                        source="sample.synthetic",
                    ),
                    DeviceRegistrationFact(
                        name="ITSP-SIP-TRUNK",
                        status="unregistered",
                        registered_node=None,
                        ip_address=None,
                        model="SIP Trunk",
                        protocol="SIP",
                        source="sample.synthetic",
                    ),
                ],
                services=[
                    ServiceStatusFact(
                        node="cucm-pub-01",
                        service_name="Cisco CallManager",
                        activated=True,
                        status="STARTED",
                        uptime_seconds=86400,
                        source="sample.synthetic",
                    ),
                    ServiceStatusFact(
                        node="cucm-pub-01",
                        service_name="Cisco Tftp",
                        activated=True,
                        status="STARTED",
                        uptime_seconds=86390,
                        source="sample.synthetic",
                    ),
                    ServiceStatusFact(
                        node="cucm-sub-01",
                        service_name="Cisco CallManager",
                        activated=True,
                        status="STARTED",
                        uptime_seconds=86120,
                        source="sample.synthetic",
                    ),
                ],
                perf_counters=[
                    PerfCounterFact(
                        node="cucm-pub-01",
                        object_name="Processor",
                        counter_name="% CPU Time",
                        instance=None,
                        value=12.5,
                        sample_count=2,
                        source="sample.synthetic",
                    ),
                    PerfCounterFact(
                        node="cucm-pub-01",
                        object_name="Memory",
                        counter_name="% Used",
                        instance=None,
                        value=61.2,
                        sample_count=1,
                        source="sample.synthetic",
                    ),
                ],
                platform_checks=[
                    PlatformCheckFact(
                        node="cucm-pub-01",
                        check_name="dbreplication",
                        status="healthy",
                        details={"state": "2", "description": "synthetic synchronized state"},
                        source="sample.synthetic",
                    ),
                    PlatformCheckFact(
                        node="cucm-pub-01",
                        check_name="ntp",
                        status="synchronized",
                        details={"stratum": "3", "peer": "192.0.2.1"},
                        source="sample.synthetic",
                    ),
                ],
            ),
            evidence=[
                EvidenceRef(
                    source="sample.synthetic",
                    operation="sample_fixture",
                    node="cucm-pub-01",
                    parser="cisco_collab_health.collectors.sample",
                    confidence="low",
                )
            ],
            notes=[
                "Sample data is synthetic and intended only to exercise report layout."
            ],
        )
