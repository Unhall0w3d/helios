"""Tests for AXL collection."""

from __future__ import annotations

import io
import urllib.error
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from cisco_collab_health.artifacts import ArtifactStore
from cisco_collab_health.collectors.axl import AxlCollector, AxlVersionPolicy
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


LIST_PROCESS_NODE_WITH_ENTERPRISE_DATA_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <ns:listProcessNodeResponse xmlns:ns="http://www.cisco.com/AXL/API/14.0">
      <return>
        <processNode uuid="{00000000-1111-0000-0000-000000000000}">
          <name>EnterpriseWideData</name>
          <description />
          <nodeUsage>Subscriber</nodeUsage>
        </processNode>
        <processNode uuid="{100425D0-8780-F699-9C0F-9BA20D7C8DB7}">
          <name>HS-UCM-SUB.Yorktown.org</name>
          <description>HS-UCM-SUB</description>
          <nodeUsage>Subscriber</nodeUsage>
        </processNode>
        <processNode uuid="{953D3FCA-EAB5-4B3C-928B-450C6884CE26}">
          <name>YT-CUCM-PUB.yorktown.org</name>
          <description>UCM-PUB</description>
          <nodeUsage>Publisher</nodeUsage>
        </processNode>
      </return>
    </ns:listProcessNodeResponse>
  </soapenv:Body>
</soapenv:Envelope>
"""


INCORRECT_AXL_VERSION_RESPONSE = """<!-- custom Cisco error page --><html>
<body>
<div id="content-header">HTTP Status 599 - Incorrect axl version. Supported axl versions are 12.x, 14.0 and 15.0</div>
<p><b>Message:</b> Incorrect axl version. Supported axl versions are 12.x, 14.0 and 15.0</p>
</body>
</html>"""


class FakeResponse:
    status = 200
    reason = "OK"
    headers = {"content-type": "text/xml"}

    def __init__(self, body: str):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self) -> bytes:
        return self.body.encode("utf-8")


class AxlCollectorTests(unittest.TestCase):
    def test_axl_version_policy_prefers_discovered_supported_version(self) -> None:
        policy = AxlVersionPolicy()

        candidates = policy.candidates("15.0.1.12900(234)")

        self.assertEqual(candidates[:2], ("15.0", "14.0"))

    def test_axl_version_policy_selects_best_helios_supported_cucm_version(self) -> None:
        policy = AxlVersionPolicy()

        retry = policy.best_supported_version(["12.x", "14.0", "15.0"], {"14.0"})

        self.assertEqual(retry, "15.0")

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

    def test_axl_collector_ignores_enterprise_wide_data_process_node(self) -> None:
        context = CollectionContext(
            publisher_ip="10.51.200.8",
            gui_username="apiuser",
            gui_password="secret",
        )
        collector = AxlCollector()

        with patch.object(
            collector,
            "_call_axl",
            side_effect=[GET_VERSION_RESPONSE, LIST_PROCESS_NODE_WITH_ENTERPRISE_DATA_RESPONSE],
        ):
            result = collector.collect(context)

        self.assertEqual(result.warnings, [])
        self.assertEqual(
            [node.name for node in result.facts.nodes],
            ["HS-UCM-SUB.Yorktown.org", "YT-CUCM-PUB.yorktown.org"],
        )
        self.assertEqual(result.facts.cluster.name, "YT-CUCM-PUB.yorktown.org")

    def test_axl_collector_returns_warning_without_credentials(self) -> None:
        result = AxlCollector().collect(CollectionContext(publisher_ip="10.51.200.8"))

        self.assertEqual(result.facts.nodes, [])
        self.assertIn("credentials are missing", result.warnings[0])

    def test_axl_call_writes_raw_request_and_response_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab")
            context = CollectionContext(
                publisher_ip="10.51.200.8",
                gui_username="apiuser",
                gui_password="secret",
                artifact_store=store,
            )

            with patch(
                "cisco_collab_health.transport.soap.urllib.request.urlopen",
                return_value=FakeResponse(GET_VERSION_RESPONSE),
            ):
                AxlCollector()._call_axl(context, "getCCMVersion", "<axl:getCCMVersion />")

            request = store.root / "nodes" / "10.51.200.8" / "api" / "axl" / "getCCMVersion" / "request.txt"
            response = store.root / "nodes" / "10.51.200.8" / "api" / "axl" / "getCCMVersion" / "response.txt"
            self.assertTrue(request.exists())
            self.assertTrue(response.exists())
            self.assertIn("POST https://10.51.200.8:8443/axl/ HTTP/1.1", request.read_text(encoding="utf-8"))
            self.assertNotIn("Authorization", request.read_text(encoding="utf-8"))
            self.assertIn("CUCM:DB ver=14.0", request.read_text(encoding="utf-8"))
            self.assertIn("http://www.cisco.com/AXL/API/14.0", request.read_text(encoding="utf-8"))
            self.assertIn("HTTP 200 OK", response.read_text(encoding="utf-8"))

    def test_axl_call_retries_with_highest_supported_version(self) -> None:
        http_error = urllib.error.HTTPError(
            url="https://10.51.200.8:8443/axl/",
            code=599,
            msg="",
            hdrs={"content-type": "text/html"},
            fp=io.BytesIO(INCORRECT_AXL_VERSION_RESPONSE.encode("utf-8")),
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab")
            context = CollectionContext(
                publisher_ip="10.51.200.8",
                gui_username="apiuser",
                gui_password="secret",
                artifact_store=store,
            )

            with patch(
                "cisco_collab_health.transport.soap.urllib.request.urlopen",
                side_effect=[http_error, FakeResponse(GET_VERSION_RESPONSE)],
            ) as urlopen:
                response = AxlCollector()._call_axl(
                    context,
                    "getCCMVersion",
                    "<axl:getCCMVersion />",
                )
                http_error.close()

            first_request = (
                store.root
                / "nodes"
                / "10.51.200.8"
                / "api"
                / "axl"
                / "getCCMVersion"
                / "request.txt"
            )
            retry_request = (
                store.root
                / "nodes"
                / "10.51.200.8"
                / "api"
                / "axl"
                / "getCCMVersion_retry_axl_15.0"
                / "request.txt"
            )
            first_request_text = first_request.read_text(encoding="utf-8")
            retry_request_text = retry_request.read_text(encoding="utf-8")

        self.assertEqual(response, GET_VERSION_RESPONSE)
        self.assertEqual(urlopen.call_count, 2)
        self.assertIn("CUCM:DB ver=14.0", first_request_text)
        self.assertIn("CUCM:DB ver=15.0", retry_request_text)
        self.assertIn("http://www.cisco.com/AXL/API/15.0", retry_request_text)

    def test_axl_call_reuses_winning_schema_version(self) -> None:
        http_error = urllib.error.HTTPError(
            url="https://10.51.200.8:8443/axl/",
            code=599,
            msg="",
            hdrs={"content-type": "text/html"},
            fp=io.BytesIO(INCORRECT_AXL_VERSION_RESPONSE.encode("utf-8")),
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab")
            context = CollectionContext(
                publisher_ip="10.51.200.8",
                gui_username="apiuser",
                gui_password="secret",
                artifact_store=store,
            )
            collector = AxlCollector()

            with patch(
                "cisco_collab_health.transport.soap.urllib.request.urlopen",
                side_effect=[
                    http_error,
                    FakeResponse(GET_VERSION_RESPONSE),
                    FakeResponse(LIST_PROCESS_NODE_RESPONSE),
                ],
            ) as urlopen:
                collector._call_axl(context, "getCCMVersion", "<axl:getCCMVersion />")
                http_error.close()
                collector._call_axl(context, "listProcessNode", "<axl:listProcessNode />")

            list_request = (
                store.root
                / "nodes"
                / "10.51.200.8"
                / "api"
                / "axl"
                / "listProcessNode"
                / "request.txt"
            )
            list_request_text = list_request.read_text(encoding="utf-8")

        self.assertEqual(urlopen.call_count, 3)
        self.assertIn("CUCM:DB ver=15.0", list_request_text)


if __name__ == "__main__":
    unittest.main()
