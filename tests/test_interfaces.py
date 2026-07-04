"""Tests for CUCM interface probes."""

from __future__ import annotations

import unittest

from cisco_collab_health.collectors.base import CollectionContext
from cisco_collab_health.interfaces import probe_interfaces, run_publisher_preflight


class InterfaceProbeTests(unittest.TestCase):
    def test_probe_interfaces_reports_default_cucm_interfaces(self) -> None:
        context = CollectionContext(publisher_ip="192.0.2.10")

        statuses = probe_interfaces(
            context,
            socket_probe=lambda host, port, timeout: host == "192.0.2.10" and port == 8443,
        )

        self.assertEqual(
            [status.name for status in statuses],
            ["axl", "risport70", "control_center", "perfmon"],
        )
        self.assertTrue(all(status.available for status in statuses))

    def test_probe_interfaces_reports_missing_publisher(self) -> None:
        statuses = probe_interfaces(CollectionContext())

        self.assertEqual(len(statuses), 1)
        self.assertEqual(statuses[0].name, "publisher")
        self.assertFalse(statuses[0].available)

    def test_publisher_preflight_combines_connectivity_and_api_status(self) -> None:
        context = CollectionContext(publisher_ip="192.0.2.10")

        result = run_publisher_preflight(
            context,
            ping_probe=lambda host, timeout: True,
            http_probe=lambda url, timeout: (url.endswith(":8443/"), "checked"),
            socket_probe=lambda host, port, timeout: True,
        )

        self.assertEqual(result.publisher, "192.0.2.10")
        self.assertEqual(
            [check.name for check in result.connectivity],
            ["ping", "https_443", "https_8443"],
        )
        self.assertEqual(
            result.available_interfaces,
            ["axl", "risport70", "control_center", "perfmon"],
        )
        self.assertFalse(result.connectivity[1].available)
        self.assertTrue(result.connectivity[2].available)

    def test_publisher_preflight_supports_alternate_api_ports(self) -> None:
        context = CollectionContext(publisher_ip="192.0.2.10")

        result = run_publisher_preflight(
            context,
            ping_probe=lambda host, timeout: True,
            http_probe=lambda url, timeout: (True, "checked"),
            socket_probe=lambda host, port, timeout: port in {9443, 9444, 9445, 9446},
            axl_port=9443,
            risport_port=9444,
            control_center_port=9445,
            perfmon_port=9446,
        )

        self.assertEqual(
            [status.endpoint for status in result.interfaces],
            [
                "https://192.0.2.10:9443/axl/",
                "https://192.0.2.10:9444/realtimeservice2/services/RISService70?wsdl",
                "https://192.0.2.10:9445/controlcenterservice2/services/ControlCenterServices?wsdl",
                "https://192.0.2.10:9446/perfmonservice2/services/PerfmonService?wsdl",
            ],
        )
        self.assertEqual(
            result.available_interfaces,
            ["axl", "risport70", "control_center", "perfmon"],
        )


if __name__ == "__main__":
    unittest.main()
