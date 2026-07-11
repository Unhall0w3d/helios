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
from cisco_collab_health.collectors.axl_errors import AxlCollectionError, AxlVersionError
from cisco_collab_health.collectors.axl_bodies import (
    DEVICE_DEFAULTS_SQL,
    execute_sql_query_body,
)
from cisco_collab_health.collectors.axl_parsers import parse_configuration_objects
from cisco_collab_health.collectors.base import CollectionContext
from cisco_collab_health.transport.soap import SoapResponse


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
          <name>192.0.2.10</name>
          <description>CUCM Publisher</description>
          <nodeUsage>Publisher</nodeUsage>
        </processNode>
        <processNode>
          <name>192.0.2.11</name>
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


LIST_PHONE_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <ns:listPhoneResponse xmlns:ns="http://www.cisco.com/AXL/API/14.0">
      <return>
        <phone uuid="{11111111-1111-1111-1111-111111111111}">
          <name>SEP001122334455</name>
          <description>Lobby phone</description>
          <model>Cisco 8845</model>
          <protocol>SIP</protocol>
          <devicePoolName uuid="{22222222-2222-2222-2222-222222222222}">Default</devicePoolName>
          <locationName uuid="{33333333-3333-3333-3333-333333333333}">Hub_None</locationName>
          <loadInformation>sip8845.14-2-1</loadInformation>
        </phone>
        <phone uuid="{44444444-4444-4444-4444-444444444444}">
          <name>CSFALICE</name>
          <description />
          <model>Cisco Unified Client Services Framework</model>
          <protocol>SIP</protocol>
          <devicePoolName>Remote</devicePoolName>
          <locationName />
          <loadInformation />
        </phone>
      </return>
    </ns:listPhoneResponse>
  </soapenv:Body>
</soapenv:Envelope>
"""


LIST_PHONE_SECOND_PAGE_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <ns:listPhoneResponse xmlns:ns="http://www.cisco.com/AXL/API/14.0">
      <return>
        <phone uuid="{55555555-5555-5555-5555-555555555555}">
          <name>SEP00AABBCCDDEE</name>
          <description>Hallway phone</description>
          <model>Cisco 7945</model>
          <protocol>SCCP</protocol>
          <devicePoolName>Default</devicePoolName>
          <locationName>Hub_None</locationName>
          <loadInformation>SCCP45.9-4-2SR4-3</loadInformation>
        </phone>
      </return>
    </ns:listPhoneResponse>
  </soapenv:Body>
</soapenv:Envelope>
"""


LIST_PHONE_EMPTY_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <ns:listPhoneResponse xmlns:ns="http://www.cisco.com/AXL/API/14.0">
      <return />
    </ns:listPhoneResponse>
  </soapenv:Body>
</soapenv:Envelope>
"""


LIST_DEVICE_POOL_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <ns:listDevicePoolResponse xmlns:ns="http://www.cisco.com/AXL/API/14.0">
      <return>
        <devicePool uuid="{77777777-7777-7777-7777-777777777777}">
          <name>Default</name>
          <callManagerGroupName uuid="{88888888-8888-8888-8888-888888888888}">CMG-PubSub</callManagerGroupName>
          <locationName uuid="{99999999-9999-9999-9999-999999999999}">HQ-Loc</locationName>
          <regionName uuid="{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}">Region-HQ</regionName>
        </devicePool>
        <devicePool uuid="{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}">
          <name>Remote</name>
          <callManagerGroupName>CMG-Remote</callManagerGroupName>
          <locationName>Remote-Loc</locationName>
          <regionName>Region-Remote</regionName>
        </devicePool>
      </return>
    </ns:listDevicePoolResponse>
  </soapenv:Body>
</soapenv:Envelope>
"""


LIST_DEVICE_DEFAULTS_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <ns:executeSQLQueryResponse xmlns:ns="http://www.cisco.com/AXL/API/15.0">
      <return>
        <row><configuredmodelcount>12</configuredmodelcount><modelname>Cisco 8845</modelname>
          <signalingprotocol>11</signalingprotocol><devicedefault>sip8845.14-2-1</devicedefault><tkmodel>616</tkmodel></row>
        <row><configuredmodelcount>4</configuredmodelcount><modelname>Cisco 7945</modelname>
          <signalingprotocol>0</signalingprotocol><devicedefault>SCCP45.9-4-2SR4-3</devicedefault><tkmodel>434</tkmodel></row>
        <row><configuredmodelcount>2</configuredmodelcount><modelname>Conference Bridge</modelname>
          <signalingprotocol>99</signalingprotocol><devicedefault>media-load</devicedefault><tkmodel>42</tkmodel></row>
      </return>
    </ns:executeSQLQueryResponse>
  </soapenv:Body>
</soapenv:Envelope>
"""


INCORRECT_AXL_VERSION_RESPONSE = """<!-- custom Cisco error page --><html>
<body>
<div id="content-header">
HTTP Status 599 - Incorrect axl version. Supported axl versions are 12.x, 14.0 and 15.0
</div>
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


def soap_response(body: str, operation: str = "operation") -> SoapResponse:
    return SoapResponse(
        status=200,
        reason="OK",
        headers={},
        body=body,
        operation=operation,
        interface="axl",
        artifact_request="request",
        artifact_response="response",
    )


class AxlCollectorTests(unittest.TestCase):
    def test_device_defaults_sql_is_bounded_to_configured_models_and_xml_safe(self) -> None:
        body = execute_sql_query_body(DEVICE_DEFAULTS_SQL)

        self.assertIn("from device as d", body)
        self.assertIn("inner join defaults as df", body)
        self.assertIn("group by d.tkmodel", body)
        self.assertIn('!= ""', body)
        self.assertIn("&amp;", execute_sql_query_body("select '&' from table"))

    def test_diagnostic_axl_parser_normalizes_configuration_objects(self) -> None:
        response = """<Envelope><return><routePattern><pattern>9.!#</pattern>
        <routePartitionName>PT-PSTN</routePartitionName></routePattern></return></Envelope>"""

        facts = parse_configuration_objects(
            response,
            "listRoutePattern",
            ("pattern", "routePartitionName"),
        )

        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].object_type, "RoutePattern")
        self.assertEqual(facts[0].name, "9.!#")
        self.assertEqual(facts[0].details["partition"], "PT-PSTN")

    def test_axl_version_policy_prefers_discovered_supported_version(self) -> None:
        policy = AxlVersionPolicy()

        candidates = policy.candidates("15.0.1.12900(234)")

        self.assertEqual(candidates[:2], ("15.0", "14.0"))

    def test_axl_version_policy_selects_best_aletheiauc_supported_cucm_version(self) -> None:
        policy = AxlVersionPolicy()

        retry = policy.best_supported_version(["12.x", "14.0", "15.0"], {"14.0"})

        self.assertEqual(retry, "15.0")

    def test_axl_collector_normalizes_version_and_process_nodes(self) -> None:
        context = CollectionContext(
            publisher_ip="192.0.2.10",
            gui_username="apiuser",
            gui_password="secret",
        )
        collector = AxlCollector()

        with patch.object(
            collector,
            "_call_axl_response",
            side_effect=[
                soap_response(GET_VERSION_RESPONSE, "getCCMVersion"),
                soap_response(LIST_PROCESS_NODE_RESPONSE, "listProcessNode"),
            ],
        ):
            result = collector.collect(context)

        self.assertEqual(result.warnings, [])
        self.assertTrue(any("phone inventory skipped" in note for note in result.notes))
        self.assertIn("axl.phone_inventory.skipped", result.status_flags)
        self.assertIsNotNone(result.facts.cluster)
        self.assertEqual(result.facts.cluster.version, "14.0.1.10000-20")
        self.assertEqual(result.facts.cluster.name, "192.0.2.10")
        self.assertEqual(
            [node.address for node in result.facts.nodes],
            ["192.0.2.10", "192.0.2.11"],
        )
        self.assertEqual([node.role for node in result.facts.nodes], ["publisher", "subscriber"])
        self.assertEqual(result.facts.devices, [])

    def test_axl_collector_collects_phone_inventory_when_enabled(self) -> None:
        context = CollectionContext(
            publisher_ip="192.0.2.10",
            gui_username="apiuser",
            gui_password="secret",
            collect_phone_inventory=True,
        )
        collector = AxlCollector()

        with patch.object(
            collector,
            "_call_axl_response",
            side_effect=[
                soap_response(GET_VERSION_RESPONSE, "getCCMVersion"),
                soap_response(LIST_PROCESS_NODE_RESPONSE, "listProcessNode"),
                soap_response(LIST_PHONE_RESPONSE, "listPhone"),
                soap_response(LIST_DEVICE_POOL_RESPONSE, "listDevicePool"),
                soap_response(LIST_DEVICE_DEFAULTS_RESPONSE, "executeSQLQuery"),
            ],
        ):
            result = collector.collect(context)

        self.assertEqual(result.warnings, [])
        self.assertEqual(
            [evidence.operation for evidence in result.evidence],
            [
                "getCCMVersion",
                "listProcessNode",
                "listPhone",
                "listDevicePool",
                "executeSQLQuery",
            ],
        )
        self.assertEqual(
            [device.name for device in result.facts.devices],
            ["SEP001122334455", "CSFALICE"],
        )
        self.assertEqual(result.facts.devices[0].device_pool, "Default")
        self.assertEqual(result.facts.devices[0].call_manager_group, "CMG-PubSub")
        self.assertEqual(result.facts.devices[0].region, "Region-HQ")
        self.assertEqual(result.facts.devices[0].configured_load, "sip8845.14-2-1")
        self.assertEqual(
            result.facts.devices[0].source,
            "AXL.listPhone.summary, AXL.listDevicePool",
        )
        self.assertEqual(result.facts.devices[1].location, "Remote-Loc")
        self.assertEqual(len(result.facts.device_load_defaults), 3)
        self.assertEqual(result.facts.device_load_defaults[0].source, "AXL.executeSQLQuery.deviceDefaults")
        self.assertEqual(result.facts.device_load_defaults[0].configured_model_count, 12)
        self.assertEqual(result.facts.device_load_defaults[0].model_code, "616")
        self.assertEqual(result.facts.device_load_defaults[2].protocol, "Media Resource")
        self.assertEqual(result.status_flags, [])

    def test_axl_collector_pages_phone_inventory_with_configured_bounds(self) -> None:
        context = CollectionContext(
            publisher_ip="192.0.2.10",
            gui_username="apiuser",
            gui_password="secret",
            collect_phone_inventory=True,
            phone_inventory_page_size=2,
            phone_inventory_max_devices=3,
        )
        collector = AxlCollector()

        with patch.object(
            collector,
            "_call_axl_response",
            side_effect=[
                soap_response(GET_VERSION_RESPONSE, "getCCMVersion"),
                soap_response(LIST_PROCESS_NODE_RESPONSE, "listProcessNode"),
                soap_response(LIST_PHONE_RESPONSE, "listPhone"),
                soap_response(LIST_PHONE_SECOND_PAGE_RESPONSE, "listPhone"),
                soap_response(LIST_DEVICE_POOL_RESPONSE, "listDevicePool"),
                soap_response(LIST_DEVICE_DEFAULTS_RESPONSE, "executeSQLQuery"),
            ],
        ) as call:
            result = collector.collect(context)

        self.assertEqual(
            [device.name for device in result.facts.devices],
            ["SEP001122334455", "CSFALICE", "SEP00AABBCCDDEE"],
        )
        phone_bodies = [
            call_args.args[2]
            for call_args in call.call_args_list
            if call_args.args[1] == "listPhone"
        ]
        self.assertIn('first="2" skip="0"', phone_bodies[0])
        self.assertIn('first="1" skip="2"', phone_bodies[1])
        self.assertTrue(any("maximum device limit" in note for note in result.notes))

    def test_axl_collector_stops_phone_paging_on_duplicate_page(self) -> None:
        context = CollectionContext(
            publisher_ip="192.0.2.10",
            gui_username="apiuser",
            gui_password="secret",
            collect_phone_inventory=True,
            phone_inventory_page_size=2,
            phone_inventory_max_devices=10,
        )
        collector = AxlCollector()

        with patch.object(
            collector,
            "_call_axl_response",
            side_effect=[
                soap_response(GET_VERSION_RESPONSE, "getCCMVersion"),
                soap_response(LIST_PROCESS_NODE_RESPONSE, "listProcessNode"),
                soap_response(LIST_PHONE_RESPONSE, "listPhone"),
                soap_response(LIST_PHONE_RESPONSE, "listPhone"),
                soap_response(LIST_DEVICE_POOL_RESPONSE, "listDevicePool"),
                soap_response(LIST_DEVICE_DEFAULTS_RESPONSE, "executeSQLQuery"),
            ],
        ) as call:
            result = collector.collect(context)

        self.assertEqual(
            [device.name for device in result.facts.devices],
            ["SEP001122334455", "CSFALICE"],
        )
        phone_calls = [
            call_args
            for call_args in call.call_args_list
            if call_args.args[1] == "listPhone"
        ]
        self.assertEqual(len(phone_calls), 2)
        self.assertTrue(any("first unique result set as complete" in note for note in result.notes))

    def test_axl_collector_treats_overfilled_broad_phone_page_as_complete(self) -> None:
        context = CollectionContext(
            publisher_ip="192.0.2.10",
            gui_username="apiuser",
            gui_password="secret",
            collect_phone_inventory=True,
            phone_inventory_page_size=1,
            phone_inventory_max_devices=10,
        )
        collector = AxlCollector()

        with patch.object(
            collector,
            "_call_axl_response",
            side_effect=[
                soap_response(GET_VERSION_RESPONSE, "getCCMVersion"),
                soap_response(LIST_PROCESS_NODE_RESPONSE, "listProcessNode"),
                soap_response(LIST_PHONE_RESPONSE, "listPhone"),
                soap_response(LIST_DEVICE_POOL_RESPONSE, "listDevicePool"),
                soap_response(LIST_DEVICE_DEFAULTS_RESPONSE, "executeSQLQuery"),
            ],
        ) as call:
            result = collector.collect(context)

        self.assertEqual(
            [device.name for device in result.facts.devices],
            ["SEP001122334455", "CSFALICE"],
        )
        phone_calls = [
            call_args
            for call_args in call.call_args_list
            if call_args.args[1] == "listPhone"
        ]
        self.assertEqual(len(phone_calls), 1)
        self.assertTrue(any("broad query returned more devices" in note for note in result.notes))

    def test_axl_collector_stops_phone_paging_on_empty_page(self) -> None:
        context = CollectionContext(
            publisher_ip="192.0.2.10",
            gui_username="apiuser",
            gui_password="secret",
            collect_phone_inventory=True,
            phone_inventory_page_size=2,
            phone_inventory_max_devices=10,
        )
        collector = AxlCollector()

        with patch.object(
            collector,
            "_call_axl_response",
            side_effect=[
                soap_response(GET_VERSION_RESPONSE, "getCCMVersion"),
                soap_response(LIST_PROCESS_NODE_RESPONSE, "listProcessNode"),
                soap_response(LIST_PHONE_EMPTY_RESPONSE, "listPhone"),
                soap_response(LIST_DEVICE_DEFAULTS_RESPONSE, "executeSQLQuery"),
            ],
        ):
            result = collector.collect(context)

        self.assertEqual(result.facts.devices, [])
        self.assertEqual(result.facts.device_load_defaults, [])

    def test_axl_collector_ignores_enterprise_wide_data_process_node(self) -> None:
        context = CollectionContext(
            publisher_ip="192.0.2.10",
            gui_username="apiuser",
            gui_password="secret",
            collect_phone_inventory=True,
        )
        collector = AxlCollector()

        with patch.object(
            collector,
            "_call_axl_response",
            side_effect=[
                soap_response(GET_VERSION_RESPONSE, "getCCMVersion"),
                soap_response(LIST_PROCESS_NODE_WITH_ENTERPRISE_DATA_RESPONSE, "listProcessNode"),
                soap_response(LIST_PHONE_RESPONSE, "listPhone"),
                soap_response(LIST_DEVICE_POOL_RESPONSE, "listDevicePool"),
                soap_response(LIST_DEVICE_DEFAULTS_RESPONSE, "executeSQLQuery"),
            ],
        ):
            result = collector.collect(context)

        self.assertEqual(result.warnings, [])
        self.assertEqual(
            [node.name for node in result.facts.nodes],
            ["HS-UCM-SUB.Yorktown.org", "YT-CUCM-PUB.yorktown.org"],
        )
        self.assertEqual(result.facts.cluster.name, "YT-CUCM-PUB.yorktown.org")

    def test_axl_collector_warns_when_phone_inventory_fails(self) -> None:
        context = CollectionContext(
            publisher_ip="192.0.2.10",
            gui_username="apiuser",
            gui_password="secret",
            collect_phone_inventory=True,
        )
        collector = AxlCollector()

        with patch.object(
            collector,
            "_call_axl_response",
            side_effect=[
                soap_response(GET_VERSION_RESPONSE, "getCCMVersion"),
                soap_response(LIST_PROCESS_NODE_RESPONSE, "listProcessNode"),
                soap_response("<not-xml", "listPhone"),
                soap_response(LIST_DEVICE_DEFAULTS_RESPONSE, "executeSQLQuery"),
            ],
        ):
            result = collector.collect(context)

        self.assertEqual(result.facts.devices, [])
        self.assertIn("AXL listPhone failed", result.warnings[0])

    def test_axl_collector_warns_when_device_pool_enrichment_fails(self) -> None:
        context = CollectionContext(
            publisher_ip="192.0.2.10",
            gui_username="apiuser",
            gui_password="secret",
            collect_phone_inventory=True,
        )
        collector = AxlCollector()

        with patch.object(
            collector,
            "_call_axl_response",
            side_effect=[
                soap_response(GET_VERSION_RESPONSE, "getCCMVersion"),
                soap_response(LIST_PROCESS_NODE_RESPONSE, "listProcessNode"),
                soap_response(LIST_PHONE_RESPONSE, "listPhone"),
                soap_response("<not-xml", "listDevicePool"),
                soap_response(LIST_DEVICE_DEFAULTS_RESPONSE, "executeSQLQuery"),
            ],
        ):
            result = collector.collect(context)

        self.assertIn("AXL listDevicePool failed", result.warnings[0])
        self.assertEqual(result.facts.devices[0].call_manager_group, None)

    def test_axl_collector_warns_when_device_defaults_fail(self) -> None:
        context = CollectionContext(
            publisher_ip="192.0.2.10",
            gui_username="apiuser",
            gui_password="secret",
            collect_phone_inventory=True,
        )
        collector = AxlCollector()

        with patch.object(
            collector,
            "_call_axl_response",
            side_effect=[
                soap_response(GET_VERSION_RESPONSE, "getCCMVersion"),
                soap_response(LIST_PROCESS_NODE_RESPONSE, "listProcessNode"),
                soap_response(LIST_PHONE_RESPONSE, "listPhone"),
                soap_response(LIST_DEVICE_POOL_RESPONSE, "listDevicePool"),
                soap_response("<not-xml", "deviceDefaults_executeSQLQuery"),
                soap_response("<not-xml", "deviceDefaults_executeSQLQuery"),
                soap_response("<not-xml", "deviceDefaults_executeSQLQuery"),
            ],
        ):
            result = collector.collect(context)

        self.assertIn("AXL device-default SQL query failed", result.warnings[0])
        self.assertEqual(result.facts.device_load_defaults, [])

    def test_axl_phone_inventory_writes_page_specific_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab")
            context = CollectionContext(
                publisher_ip="192.0.2.10",
                gui_username="apiuser",
                gui_password="secret",
                artifact_store=store,
                collect_phone_inventory=True,
                phone_inventory_page_size=2,
                phone_inventory_max_devices=3,
            )

            with patch(
                "cisco_collab_health.transport.soap.urllib.request.urlopen",
                side_effect=[
                    FakeResponse(GET_VERSION_RESPONSE),
                    FakeResponse(LIST_PROCESS_NODE_RESPONSE),
                    FakeResponse(LIST_PHONE_RESPONSE),
                    FakeResponse(LIST_PHONE_SECOND_PAGE_RESPONSE),
                    FakeResponse(LIST_DEVICE_POOL_RESPONSE),
                    FakeResponse(LIST_DEVICE_DEFAULTS_RESPONSE),
                ],
            ):
                result = AxlCollector().collect(context)

            first_page = (
                store.root
                / "nodes"
                / "192.0.2.10"
                / "api"
                / "axl"
                / "listPhone_page_000000"
                / "response.txt"
            )
            second_page = (
                store.root
                / "nodes"
                / "192.0.2.10"
                / "api"
                / "axl"
                / "listPhone_page_000002"
                / "response.txt"
            )

            self.assertTrue(first_page.exists())
            self.assertTrue(second_page.exists())
            self.assertTrue(
                str(result.evidence[2].artifact_path).endswith(
                    "listPhone_page_000000/response.txt"
                )
            )
            self.assertTrue(
                str(result.evidence[3].artifact_path).endswith(
                    "listPhone_page_000002/response.txt"
                )
            )
            self.assertTrue(
                str(result.evidence[4].artifact_path).endswith(
                    "listDevicePool/response.txt"
                )
            )
            self.assertTrue(
                str(result.evidence[5].artifact_path).endswith(
                    "deviceDefaults_executeSQLQuery/response.txt"
                )
            )

    def test_axl_collector_evidence_references_response_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab")
            context = CollectionContext(
                publisher_ip="192.0.2.10",
                gui_username="apiuser",
                gui_password="secret",
                artifact_store=store,
            )

            with patch(
                "cisco_collab_health.transport.soap.urllib.request.urlopen",
                side_effect=[
                    FakeResponse(GET_VERSION_RESPONSE),
                    FakeResponse(LIST_PROCESS_NODE_RESPONSE),
                ],
            ):
                result = AxlCollector().collect(context)

        self.assertEqual(
            [evidence.operation for evidence in result.evidence],
            ["getCCMVersion", "listProcessNode"],
        )
        self.assertTrue(result.evidence[0].artifact_path)
        self.assertTrue(
            str(result.evidence[0].artifact_path).endswith("getCCMVersion/response.txt")
        )
        self.assertTrue(result.evidence[1].artifact_path)
        self.assertTrue(
            str(result.evidence[1].artifact_path).endswith("listProcessNode/response.txt")
        )

    def test_axl_collector_returns_warning_without_credentials(self) -> None:
        result = AxlCollector().collect(CollectionContext(publisher_ip="192.0.2.10"))

        self.assertEqual(result.facts.nodes, [])
        self.assertIn("credentials are missing", result.warnings[0])

    def test_axl_call_writes_raw_request_and_response_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab")
            context = CollectionContext(
                publisher_ip="192.0.2.10",
                gui_username="apiuser",
                gui_password="secret",
                artifact_store=store,
            )

            with patch(
                "cisco_collab_health.transport.soap.urllib.request.urlopen",
                return_value=FakeResponse(GET_VERSION_RESPONSE),
            ):
                AxlCollector()._call_axl(context, "getCCMVersion", "<axl:getCCMVersion />")

            request = (
                store.root
                / "nodes"
                / "192.0.2.10"
                / "api"
                / "axl"
                / "getCCMVersion"
                / "request.txt"
            )
            response = (
                store.root
                / "nodes"
                / "192.0.2.10"
                / "api"
                / "axl"
                / "getCCMVersion"
                / "response.txt"
            )
            self.assertTrue(request.exists())
            self.assertTrue(response.exists())
            self.assertIn(
                "POST https://192.0.2.10:8443/axl/ HTTP/1.1",
                request.read_text(encoding="utf-8"),
            )
            self.assertNotIn("Authorization", request.read_text(encoding="utf-8"))
            self.assertIn("CUCM:DB ver=14.0", request.read_text(encoding="utf-8"))
            self.assertIn("http://www.cisco.com/AXL/API/14.0", request.read_text(encoding="utf-8"))
            self.assertIn("HTTP 200 OK", response.read_text(encoding="utf-8"))

    def test_axl_call_retries_with_highest_supported_version(self) -> None:
        http_error = urllib.error.HTTPError(
            url="https://192.0.2.10:8443/axl/",
            code=599,
            msg="",
            hdrs={"content-type": "text/html"},
            fp=io.BytesIO(INCORRECT_AXL_VERSION_RESPONSE.encode("utf-8")),
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab")
            context = CollectionContext(
                publisher_ip="192.0.2.10",
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
                / "192.0.2.10"
                / "api"
                / "axl"
                / "getCCMVersion"
                / "request.txt"
            )
            retry_request = (
                store.root
                / "nodes"
                / "192.0.2.10"
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

    def test_axl_paged_retry_preserves_the_initial_attempt_artifact(self) -> None:
        http_error = urllib.error.HTTPError(
            url="https://192.0.2.10:8443/axl/",
            code=599,
            msg="",
            hdrs={"content-type": "text/html"},
            fp=io.BytesIO(INCORRECT_AXL_VERSION_RESPONSE.encode("utf-8")),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab")
            context = CollectionContext(
                publisher_ip="192.0.2.10",
                gui_username="apiuser",
                gui_password="secret",
                artifact_store=store,
            )
            collector = AxlCollector()
            with patch(
                "cisco_collab_health.transport.soap.urllib.request.urlopen",
                side_effect=[http_error, FakeResponse(LIST_PHONE_RESPONSE)],
            ):
                collector._call_axl_response(
                    context,
                    "listPhone",
                    "<axl:listPhone />",
                    artifact_operation="listPhone_page_000000",
                )
            http_error.close()

            first = (
                store.root
                / "nodes/192.0.2.10/api/axl/listPhone_page_000000/response.txt"
            )
            retry = (
                store.root
                / "nodes/192.0.2.10/api/axl/"
                "listPhone_page_000000_retry_axl_15.0/response.txt"
            )
            self.assertTrue(first.exists())
            self.assertTrue(retry.exists())

    def test_axl_call_raises_clean_error_when_supported_retry_version_fails(self) -> None:
        context = CollectionContext(
            publisher_ip="192.0.2.10",
            gui_username="apiuser",
            gui_password="secret",
        )
        collector = AxlCollector(
            version_policy=AxlVersionPolicy(supported=("15.0", "14.0"))
        )

        with patch.object(
            collector,
            "_send_axl_request",
            side_effect=[
                AxlVersionError(
                    attempted_version="14.0",
                    supported_versions=["15.0"],
                    response_summary="Incorrect axl version",
                ),
                AxlVersionError(
                    attempted_version="15.0",
                    supported_versions=["15.0"],
                    response_summary="Incorrect axl version",
                ),
            ],
        ) as send:
            with self.assertRaises(AxlCollectionError) as exc:
                collector._call_axl(context, "getCCMVersion", "<axl:getCCMVersion />")

        self.assertEqual(
            [call.args[3] for call in send.call_args_list],
            ["14.0", "15.0"],
        )
        self.assertIn("No supported AXL schema version succeeded", str(exc.exception))
        self.assertIn("Attempted versions: 14.0, 15.0", str(exc.exception))

    def test_axl_call_reuses_winning_schema_version(self) -> None:
        http_error = urllib.error.HTTPError(
            url="https://192.0.2.10:8443/axl/",
            code=599,
            msg="",
            hdrs={"content-type": "text/html"},
            fp=io.BytesIO(INCORRECT_AXL_VERSION_RESPONSE.encode("utf-8")),
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab")
            context = CollectionContext(
                publisher_ip="192.0.2.10",
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
                / "192.0.2.10"
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
