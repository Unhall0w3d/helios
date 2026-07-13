"""Tests for local assessment artifact storage."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from cisco_collab_health.artifacts import (
    ArtifactStore,
    RunLogStore,
    export_review_zip,
    write_log_bundle,
)
from cisco_collab_health.collectors.base import CollectionResult, CollectorError
from cisco_collab_health.models.assessment import AssessmentReport
from cisco_collab_health.models.facts import AssessmentFacts


class ArtifactStoreTests(unittest.TestCase):
    def test_review_zip_exports_self_contained_log_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            log_store = RunLogStore.create(root / "logs", "Lab Cluster")
            log_store.write_text("assessment_report.json", "{}\n")
            log_store.write_text("artifacts/operation_attempts.jsonl", "{}\n")

            zip_path = export_review_zip(log_store, root / "Downloads")

            self.assertEqual(
                zip_path.name,
                f"aletheiauc-review-Lab_Cluster-{log_store.run_id}.zip",
            )
            with ZipFile(zip_path) as archive:
                names = set(archive.namelist())
            prefix = f"logs/{log_store.run_id}/"
            self.assertIn(prefix + "assessment_report.json", names)
            self.assertIn(prefix + "artifacts/operation_attempts.jsonl", names)

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
        self.assertTrue(
            str(preflight).endswith("nodes/192.0.2.10/preflight/publisher_preflight.json")
        )
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
        self.assertTrue(
            str(response).endswith("nodes/192.0.2.10/api/axl/getCCMVersion/response.txt")
        )

    def test_api_exchange_redacts_secret_headers_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab")
            request, response = store.write_api_exchange(
                "192.0.2.10",
                "axl",
                "getCCMVersion",
                request=(
                    "POST /axl HTTP/1.1\nAuthorization: Basic abc123\n\n<password>secret</password>"
                ),
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
        self.assertNotIn("secret", request_text)
        self.assertNotIn("secret", response_text)

    def test_api_exchange_redacts_json_secrets_and_additional_auth_headers(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab")
            request, response = store.write_api_exchange(
                "192.0.2.10",
                "cupi",
                "users",
                request="GET /vmrest/users HTTP/1.1\nProxy-Authorization: Basic proxy-secret\n",
                response=(
                    "HTTP 200\nX-API-Key: header-secret\n\n"
                    '{"password": "json-secret", "nested": {"token": "nested-secret"}}'
                ),
            )

            request_text = request.read_text(encoding="utf-8")
            response_text = response.read_text(encoding="utf-8")

        for secret in ("proxy-secret", "header-secret", "json-secret", "nested-secret"):
            self.assertNotIn(secret, request_text + response_text)
        self.assertIn('"password": "<redacted>"', response_text)
        self.assertIn('"token": "<redacted>"', response_text)

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

    @unittest.skipUnless(os.name == "posix", "POSIX permissions are platform-specific")
    def test_created_artifacts_and_logs_are_private(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            store = ArtifactStore.create(root / "assessment_runs", "lab")
            artifact = store.write_command_output("192.0.2.10", "show status", "ok")
            log_store = RunLogStore.create(root / "logs", "lab")
            log = log_store.write_text("run.log", "ok\n")

            self.assertEqual(store.root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
            self.assertEqual(log_store.root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)

    def test_same_timestamp_never_reuses_artifact_or_log_directories(self) -> None:
        started_at = datetime(2026, 7, 13, 12, 0, 0)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first_artifacts = ArtifactStore.create(root / "assessment_runs", "lab", started_at)
            second_artifacts = ArtifactStore.create(root / "assessment_runs", "lab", started_at)
            first_logs = RunLogStore.create(root / "logs", "first", started_at)
            second_logs = RunLogStore.create(root / "logs", "second", started_at)

        self.assertNotEqual(first_artifacts.root, second_artifacts.root)
        self.assertNotEqual(first_artifacts.run_id, second_artifacts.run_id)
        self.assertNotEqual(first_logs.root, second_logs.root)
        self.assertNotEqual(first_logs.run_id, second_logs.run_id)

    def test_cli_output_uses_the_configured_secret_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore.create(Path(tmpdir), "lab")
            output = store.write_command_output(
                "192.0.2.10",
                "show status",
                "password=hidden\nAuthorization: Bearer abc123\n"
                "-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----",
            )

            content = output.read_text(encoding="utf-8")

        self.assertNotIn("hidden", content)
        self.assertNotIn("abc123", content)
        self.assertNotIn("\nprivate\n", content)

    def test_log_bundle_contains_summary_report_and_artifact_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            artifact_store = ArtifactStore.create(Path(tmpdir) / "assessment_runs", "lab")
            artifact_store.write_text(
                "nodes/192.0.2.10/api/axl/getCCMVersion/response.txt",
                "<xml />",
            )
            log_store = RunLogStore.create(Path(tmpdir) / "logs", "lab")
            html_report = Path(tmpdir) / "report.html"
            html_report.write_text("<html></html>", encoding="utf-8")
            customer_safe_html_report = Path(tmpdir) / "report-customer-safe.html"
            customer_safe_html_report.write_text("<html>safe</html>", encoding="utf-8")
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

            with patch(
                "cisco_collab_health.reports.html.available_report_templates",
                return_value=("aletheiauc",),
            ):
                write_log_bundle(
                    log_store,
                    report=report,
                    summary_text="Executive Summary\n",
                    artifact_store=artifact_store,
                    html_report_path=html_report,
                    customer_safe_html_report_path=customer_safe_html_report,
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
            customer_safe_report_copy = log_store.root / "customer_safe_report.html"

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
            self.assertEqual(
                customer_safe_report_copy.read_text(encoding="utf-8"), "<html>safe</html>"
            )
            manifest = json.loads((log_store.root / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["sensitivity_classification"], "private diagnostic")
            self.assertTrue(manifest["raw_evidence_included"])
            self.assertTrue(manifest["customer_safe_html_included"])
            self.assertTrue(
                (log_store.root / "reports" / "aletheiauc" / "engineering.html").exists()
            )
            self.assertTrue(
                (log_store.root / "reports" / "aletheiauc" / "customer-facing.html").exists()
            )
            self.assertFalse((log_store.root / "reports" / "comsource").exists())


if __name__ == "__main__":
    unittest.main()
