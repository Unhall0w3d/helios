"""Tests for local assessment artifact storage."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cisco_collab_health.artifacts import ArtifactStore, RunLogStore, write_log_bundle
from cisco_collab_health.collectors.base import CollectionResult, CollectorError
from cisco_collab_health.models.assessment import AssessmentReport
from cisco_collab_health.models.facts import AssessmentFacts


class ArtifactStoreTests(unittest.TestCase):
    def test_artifact_store_writes_manifest_and_node_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "Lab Cluster")
            manifest = store.write_manifest({"publisher_ip": "192.0.2.10"})
            preflight = store.write_node_json(
                "192.0.2.10",
                "preflight",
                "publisher_preflight.json",
                {"status": "ok"},
            )
            command = store.write_command_output(
                "192.0.2.10",
                "utils dbreplication runtimestate",
                "Replication status output",
            )

            manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))

        self.assertEqual(manifest_payload["profile_name"], "Lab Cluster")
        self.assertTrue(str(preflight).endswith("nodes/192.0.2.10/preflight/publisher_preflight.json"))
        self.assertIn("utils_dbreplication_runtimestate.txt", str(command))

    def test_api_exchange_is_stored_by_node_interface_and_operation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab")
            request, response = store.write_api_exchange(
                "192.0.2.10",
                "axl",
                "getCCMVersion",
                request="<request />",
                response="<response />",
            )

        self.assertTrue(str(request).endswith("nodes/192.0.2.10/api/axl/getCCMVersion/request.txt"))
        self.assertTrue(str(response).endswith("nodes/192.0.2.10/api/axl/getCCMVersion/response.txt"))

    def test_api_exchange_redacts_secret_headers_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab")
            request, response = store.write_api_exchange(
                "192.0.2.10",
                "axl",
                "getCCMVersion",
                request="POST /axl HTTP/1.1\nAuthorization: Basic abc123\n\n<password>secret</password>",
                response="HTTP 200\nset-cookie: SESSION=abc123\n\n<token>secret</token>",
            )

            request_text = request.read_text(encoding="utf-8")
            response_text = response.read_text(encoding="utf-8")

        self.assertIn("Authorization: <redacted>", request_text)
        self.assertIn("<password><redacted></password>", request_text)
        self.assertIn("set-cookie: <redacted>", response_text)
        self.assertIn("<token><redacted></token>", response_text)
        self.assertNotIn("abc123", request_text)
        self.assertNotIn("abc123", response_text)

    def test_api_exchange_can_disable_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab", redaction_mode="none")
            request, _ = store.write_api_exchange(
                "192.0.2.10",
                "axl",
                "getCCMVersion",
                request="POST /axl HTTP/1.1\nAuthorization: Basic abc123\n",
                response="HTTP 200\n",
            )
            request_text = request.read_text(encoding="utf-8")

        self.assertIn("Authorization: Basic abc123", request_text)

    def test_log_bundle_contains_summary_report_and_artifact_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            artifact_store = ArtifactStore.create(Path(tmpdir) / "assessment_runs", "lab")
            artifact_store.write_text("nodes/192.0.2.10/api/axl/getCCMVersion/response.txt", "<xml />")
            log_store = RunLogStore.create(Path(tmpdir) / "logs", "lab")
            html_report = Path(tmpdir) / "report.html"
            html_report.write_text("<html></html>", encoding="utf-8")
            report = AssessmentReport(
                facts=AssessmentFacts(),
                collector_results=[
                    CollectionResult(
                        collector_name="axl",
                        facts=AssessmentFacts(),
                        warnings=["AXL call failed"],
                        errors=[
                            CollectorError(
                                message="simulated collector failure",
                                exception_type="RuntimeError",
                            )
                        ],
                    )
                ],
                findings=[],
            )

            write_log_bundle(
                log_store,
                report=report,
                summary_text="Executive Summary\n",
                artifact_store=artifact_store,
                html_report_path=html_report,
            )

            summary = log_store.root / "executive_summary.txt"
            warnings = log_store.root / "collector_warnings.json"
            artifact_index = log_store.root / "artifact_index.txt"
            artifact_copy = (
                log_store.root
                / "artifacts"
                / "nodes"
                / "192.0.2.10"
                / "api"
                / "axl"
                / "getCCMVersion"
                / "response.txt"
            )
            report_copy = log_store.root / "report.html"

            self.assertTrue(summary.exists())
            self.assertTrue(warnings.exists())
            warning_payload = json.loads(warnings.read_text(encoding="utf-8"))
            self.assertEqual(warning_payload[0]["type"], "warning")
            self.assertEqual(warning_payload[0]["message"], "AXL call failed")
            self.assertEqual(warning_payload[1]["type"], "error")
            self.assertEqual(warning_payload[1]["exception_type"], "RuntimeError")
            self.assertIn("response.txt", artifact_index.read_text(encoding="utf-8"))
            self.assertEqual(artifact_copy.read_text(encoding="utf-8"), "<xml />")
            self.assertTrue(report_copy.exists())


if __name__ == "__main__":
    unittest.main()
