"""Tests for the bounded Cisco Unity Connection foundation."""

from __future__ import annotations

import unittest
from pathlib import Path

from cisco_collab_health.collectors.cuc import CucCollector, _cupi_total
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.transport.http import CapturedHttpResponse


class FakeHttpClient:
    def get(self, endpoint, context, **kwargs):
        del context, kwargs
        if "rowsPerPage=1" not in endpoint:
            raise AssertionError("CUC probe must remain bounded")
        return CapturedHttpResponse(200, "OK", '<Users total="42" />', Path("response.txt"))


class CucCollectorTests(unittest.TestCase):
    def test_total_parser_supports_xml_and_json(self) -> None:
        self.assertEqual(_cupi_total('<Users total="42" />'), 42)
        self.assertEqual(_cupi_total('{"total": 7}'), 7)

    def test_collector_captures_bounded_mailbox_inventory(self) -> None:
        result = CucCollector(http_client=FakeHttpClient()).collect(CollectionContext(
            product="cuc", publisher_ip="192.0.2.20",
            gui_username="admin", gui_password="secret",
        ))

        self.assertEqual(result.facts.cluster.product, "Cisco Unity Connection")
        self.assertEqual(result.facts.configuration_objects[0].details["total"], "42")
        self.assertEqual(len(result.evidence), 1)
