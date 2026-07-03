"""Tests for shared SOAP transport behavior."""

from __future__ import annotations

import io
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from cisco_collab_health.artifacts import ArtifactStore
from cisco_collab_health.collectors.base import CollectionContext
from cisco_collab_health.transport.soap import SoapClient, SoapHttpError, SoapRequest


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


class SoapTransportTests(unittest.TestCase):
    def test_send_writes_redacted_request_and_response_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab")
            context = CollectionContext(
                publisher_ip="192.0.2.10",
                gui_username="apiuser",
                gui_password="secret",
                artifact_store=store,
            )
            request = SoapRequest(
                endpoint="https://192.0.2.10:8443/axl/",
                body="<axl:getCCMVersion />",
                namespace="http://www.cisco.com/AXL/API/14.0",
                operation="getCCMVersion",
                interface="axl",
                node="192.0.2.10",
                action='CUCM:DB ver=14.0 "getCCMVersion"',
            )

            with patch(
                "cisco_collab_health.transport.soap.urllib.request.urlopen",
                return_value=FakeResponse("<response />"),
            ):
                response = SoapClient().send(request, context)

            request_artifact = (
                store.root / "nodes" / "192.0.2.10" / "api" / "axl" / "getCCMVersion" / "request.txt"
            )
            response_artifact = (
                store.root / "nodes" / "192.0.2.10" / "api" / "axl" / "getCCMVersion" / "response.txt"
            )
            request_text = request_artifact.read_text(encoding="utf-8")
            response_text = response_artifact.read_text(encoding="utf-8")

        self.assertEqual(response.body, "<response />")
        self.assertIn("POST https://192.0.2.10:8443/axl/ HTTP/1.1", request_text)
        self.assertNotIn("Authorization", request_text)
        self.assertIn("http://www.cisco.com/AXL/API/14.0", request_text)
        self.assertIn("HTTP 200 OK", response_text)

    def test_send_writes_http_error_artifact_before_raising(self) -> None:
        http_error = urllib.error.HTTPError(
            url="https://192.0.2.10:8443/axl/",
            code=599,
            msg="Incorrect axl version",
            hdrs={"content-type": "text/html"},
            fp=io.BytesIO(b"<html>bad version</html>"),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab")
            context = CollectionContext(
                publisher_ip="192.0.2.10",
                gui_username="apiuser",
                gui_password="secret",
                artifact_store=store,
            )
            request = SoapRequest(
                endpoint="https://192.0.2.10:8443/axl/",
                body="<axl:getCCMVersion />",
                namespace="http://www.cisco.com/AXL/API/14.0",
                operation="getCCMVersion",
                interface="axl",
                node="192.0.2.10",
            )

            with patch(
                "cisco_collab_health.transport.soap.urllib.request.urlopen",
                side_effect=http_error,
            ):
                with self.assertRaises(SoapHttpError):
                    SoapClient().send(request, context)
            http_error.close()

            response_artifact = (
                store.root / "nodes" / "192.0.2.10" / "api" / "axl" / "getCCMVersion" / "response.txt"
            )
            response_text = response_artifact.read_text(encoding="utf-8")

        self.assertIn("HTTP 599 Incorrect axl version", response_text)
        self.assertIn("<html>bad version</html>", response_text)


if __name__ == "__main__":
    unittest.main()
