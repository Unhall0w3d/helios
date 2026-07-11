"""Tests for bounded cross-interface diagnostic capture."""

from __future__ import annotations

import unittest
from pathlib import Path

from cisco_collab_health.collectors.diagnostic import (
    DiagnosticCaptureCollector,
    _enrich_service_status,
    _parse_perf_counters,
    _parse_risport_registrations,
    _parse_service_catalog,
    _parse_service_status,
    parse_certificate_snapshot,
)
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.transport.http import CapturedHttpResponse
from cisco_collab_health.transport.soap import SoapResponse


class FakeHttpClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def get(self, endpoint, context, *, node, interface, operation):
        del context
        self.calls.append((node, interface, endpoint))
        return CapturedHttpResponse(
            200,
            "OK",
            "<wsdl />",
            Path(f"{node}/{interface}/{operation}/response.txt"),
        )


class FakeSoapClient:
    def __init__(self) -> None:
        self.requests = []

    def send(self, request, context):
        del context
        self.requests.append(request)
        return SoapResponse(
            status=200,
            reason="OK",
            headers={},
            body="<response />",
            operation=request.operation,
            interface=request.interface,
            artifact_request="request",
            artifact_response="response",
            response_artifact_path=Path(
                f"{request.node}/{request.interface}/"
                f"{request.artifact_operation or request.operation}/response.txt"
            ),
        )


class DiagnosticCaptureCollectorTests(unittest.TestCase):
    def test_certificate_snapshot_normalizes_expiry_signing_and_chain(self) -> None:
        payload = """{"certificates":[
          {"certificateName":"Root CA","service":"tomcat-trust","subject":"CN=Root",
           "issuer":"CN=Root","notAfter":"2030-01-01T00:00:00Z"},
          {"certificateName":"node.pem","service":"tomcat","subject":"CN=node",
           "issuer":"CN=Root","notAfter":"2030-01-01T00:00:00Z"}
        ]}"""

        facts = parse_certificate_snapshot(payload, "node1")

        self.assertEqual(len(facts), 2)
        self.assertTrue(facts[0].self_signed)
        self.assertEqual(facts[1].chain_status, "complete")
        self.assertEqual(facts[1].root, "CN=Root")

    def test_parsers_normalize_risport_serviceability_and_perfmon_data(self) -> None:
        risport = """<Envelope><CmNodes><item><Name>sub-1</Name><CmDevices><item>
        <Name>SEP001</Name><Status>Registered</Status><Model>683</Model><Protocol>SIP</Protocol>
        <DeviceClass>Phone</DeviceClass><ActiveLoadID>sip88xx.14-3-1</ActiveLoadID>
        <InactiveLoadID>sip88xx.14-2-1</InactiveLoadID><RegistrationAttempts>2</RegistrationAttempts>
        <StatusReason>0</StatusReason><DirNumber>1001-Registered,1002-Registered</DirNumber>
        <IPAddress><item><IP>192.0.2.50</IP></item></IPAddress>
        </item></CmDevices></item></CmNodes></Envelope>"""
        services = """<Envelope><ServiceInfoList><item><ServiceName>Cisco CallManager</ServiceName>
        <ServiceStatus>Started</ServiceStatus><UpTime>123</UpTime><StartTime>today</StartTime>
        </item></ServiceInfoList></Envelope>"""
        catalog_xml = """<Envelope><Services><item><ServiceName>Cisco CallManager</ServiceName>
        <ServiceType>Service</ServiceType><GroupName>CM Services</GroupName>
        <ProductID>CallManager</ProductID><Deployable>true</Deployable>
        <DependentServices><Service>Cisco DB</Service></DependentServices>
        </item></Services></Envelope>"""
        perfmon = """<Envelope><perfmonCollectCounterDataReturn><Name>\\sub-1\\Processor(_Total)\\% CPU Time</Name>
        <Value>17</Value><CStatus>0</CStatus></perfmonCollectCounterDataReturn></Envelope>"""

        registrations = _parse_risport_registrations(risport)
        catalog = {
            item.service_name.lower(): item for item in _parse_service_catalog(catalog_xml)
        }
        service_facts = [
            _enrich_service_status(item, catalog)
            for item in _parse_service_status(services, "sub-1")
        ]
        perf_facts = _parse_perf_counters(perfmon, "sub-1", "Processor")

        self.assertEqual(registrations[0].name, "SEP001")
        self.assertEqual(registrations[0].ip_address, "192.0.2.50")
        self.assertEqual(registrations[0].active_load, "sip88xx.14-3-1")
        self.assertEqual(registrations[0].registration_attempts, 2)
        self.assertEqual(
            registrations[0].directory_numbers,
            ("1001-Registered", "1002-Registered"),
        )
        self.assertEqual(service_facts[0].uptime_seconds, 123)
        self.assertEqual(service_facts[0].group_name, "CM Services")
        self.assertEqual(service_facts[0].dependent_services, ("Cisco DB",))
        self.assertEqual(perf_facts[0].counter_name, "% CPU Time")
        self.assertEqual(perf_facts[0].instance, "_Total")
        self.assertEqual(perf_facts[0].value, 17)

    def test_capture_queries_all_discovered_nodes_with_bounded_operations(self) -> None:
        http = FakeHttpClient()
        soap = FakeSoapClient()
        collector = DiagnosticCaptureCollector(
            ["risport70", "control_center", "perfmon"],
            soap_client=soap,
            http_client=http,
            sleep=lambda _: None,
        )
        context = CollectionContext(
            publisher_ip="192.0.2.10",
            gui_username="apiuser",
            gui_password="secret",
            artifact_store=object(),
            discovered_nodes=("192.0.2.10", "192.0.2.11"),
            discovered_device_names=("SEP001", "SEP002"),
            diagnostic_max_devices=321,
        )

        result = collector.collect(context)

        self.assertEqual(result.warnings, [])
        self.assertIn("diagnostic_capture.enabled", result.status_flags)
        self.assertEqual(len(http.calls), 8)
        self.assertEqual(len(soap.requests), 19)
        risport = next(
            request for request in soap.requests if request.operation == "selectCmDeviceExt"
        )
        self.assertIn("<ast:MaxReturnedDevices>321</ast:MaxReturnedDevices>", risport.body)
        self.assertIn("<ast:Item>SEP001</ast:Item>", risport.body)
        control_nodes = {
            request.node
            for request in soap.requests
            if request.operation == "soapGetServiceStatus"
        }
        self.assertEqual(control_nodes, {"192.0.2.10", "192.0.2.11"})
        self.assertTrue(
            any(
                request.artifact_operation
                == "perfmonCollectCounterData_processor_sample_002"
                for request in soap.requests
            )
        )

    def test_capture_skips_network_calls_when_artifacts_are_disabled(self) -> None:
        http = FakeHttpClient()
        soap = FakeSoapClient()
        collector = DiagnosticCaptureCollector(
            ["risport70"],
            soap_client=soap,
            http_client=http,
        )

        result = collector.collect(CollectionContext(publisher_ip="192.0.2.10"))

        self.assertEqual(http.calls, [])
        self.assertEqual(soap.requests, [])
        self.assertIn("artifact storage is disabled", result.warnings[0])


if __name__ == "__main__":
    unittest.main()
