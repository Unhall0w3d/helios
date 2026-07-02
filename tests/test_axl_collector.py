"""Tests for AXL collection."""

from __future__ import annotations

import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from cisco_collab_health.artifacts import ArtifactStore
from cisco_collab_health.collectors.axl import AxlCollector
from cisco_collab_health.collectors.base import CollectionContext


GET_VERSION_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <ns:getCCMVersionResponse xmlns:ns="http://www.cisco.com/AXL/API/11.5">
      <return>
        <componentVersion>
          <version>14.0.1.10000-20</version>
        </componentVersion>
      </return>
    </ns:getCCMVersionResponse>
  </soapenv:Body>
</soapenv:Envelope>
"""


LIST_PROCESS_NODE_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <ns:listProcessNodeResponse xmlns:ns="http://www.cisco.com/AXL/API/11.5">
      <return>
        <processNode>
          <name>10.51.200.8</name>
          <description>CUCM Publisher</description>
          <nodeUsage>Publisher</nodeUsage>
        </processNode>
        <processNode>
          <name>10.51.200.9</name>
          <description>CUCM Subscriber</description>
          <nodeUsage>Subscriber</nodeUsage>
        </processNode>
      </return>
    </ns:listProcessNodeResponse>
  </soapenv:Body>
</soapenv:Envelope>
"""


class AxlCollectorTests(unittest.TestCase):
    def test_axl_collector_normalizes_version_and_process_nodes(self) -> None:
        context = CollectionContext(
            publisher_ip="10.51.200.8",
            gui_username="apiuser",
            gui_password="secret",
        )
        collector = AxlCollector()

        with patch.object(
            collector,
            "_call_axl",
            side_effect=[GET_VERSION_RESPONSE, LIST_PROCESS_NODE_RESPONSE],
        ):
            result = collector.collect(context)

        self.assertEqual(result.warnings, [])
        self.assertIsNotNone(result.facts.cluster)
        self.assertEqual(result.facts.cluster.version, "14.0.1.10000-20")
        self.assertEqual(result.facts.cluster.name, "10.51.200.8")
        self.assertEqual([node.address for node in result.facts.nodes], ["10.51.200.8", "10.51.200.9"])
        self.assertEqual([node.role for node in result.facts.nodes], ["publisher", "subscriber"])

    def test_axl_collector_returns_warning_without_credentials(self) -> None:
        result = AxlCollector().collect(CollectionContext(publisher_ip="10.51.200.8"))

        self.assertEqual(result.facts.nodes, [])
        self.assertIn("credentials are missing", result.warnings[0])

    def test_axl_call_writes_raw_request_and_response_artifacts(self) -> None:
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self) -> bytes:
                return GET_VERSION_RESPONSE.encode("utf-8")

        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab")
            context = CollectionContext(
                publisher_ip="10.51.200.8",
                gui_username="apiuser",
                gui_password="secret",
                artifact_store=store,
            )

            with patch("cisco_collab_health.collectors.axl.urllib.request.urlopen", return_value=FakeResponse()):
                AxlCollector()._call_axl(context, "getCCMVersion", "<axl:getCCMVersion />")

            request = store.root / "nodes" / "10.51.200.8" / "api" / "axl" / "getCCMVersion" / "request.txt"
            response = store.root / "nodes" / "10.51.200.8" / "api" / "axl" / "getCCMVersion" / "response.txt"
            self.assertTrue(request.exists())
            self.assertTrue(response.exists())


if __name__ == "__main__":
    unittest.main()
