"""Tests for bounded Unity Connection UCOS CLI collection."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cisco_collab_health.artifacts import ArtifactStore
from cisco_collab_health.collectors.cuc_platform import (
    CUC_COMMAND_CATALOG,
    CUC_INFORMIX_PROBE_CATALOG,
    CUC_SAFE_CLI_COMMANDS,
    CucInformixProbe,
    CucPlatformCollector,
    _cuc_cluster_nodes,
    _cuc_cluster_runtime,
    _cuc_cli_summary,
    _cuc_dbquery_zero_rows,
    _parse_cuc_dbquery_rows,
    _cuc_service_status,
    _cuc_version,
    _validate_cuc_informix_probe,
)
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.models.assessment import AssessmentReport
from cisco_collab_health.reports.html import HtmlReportBuilder
from cisco_collab_health.transport.ssh import SshCommandResult, SshCommandTimeout


class FakeSession:
    def __init__(self, context: CollectionContext, commands: list[str]) -> None:
        del context
        self.commands = commands

    def __enter__(self) -> "FakeSession":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, command: str, *, timeout_seconds: int | None = None) -> SshCommandResult:
        del timeout_seconds
        self.commands.append(command)
        return SshCommandResult(command, f"output for {command}")


class CucPlatformCollectorTests(unittest.TestCase):
    def test_command_catalog_has_unique_stable_ids_and_bounded_timeouts(self) -> None:
        self.assertEqual(
            len({item.command_id for item in CUC_COMMAND_CATALOG}), len(CUC_COMMAND_CATALOG)
        )
        self.assertTrue(all(item.timeout_seconds > 0 for item in CUC_COMMAND_CATALOG))
        self.assertEqual(tuple(item.command for item in CUC_COMMAND_CATALOG), CUC_SAFE_CLI_COMMANDS)

    def test_cli_summaries_parse_diagnostics_services_and_core_state(self) -> None:
        self.assertEqual(
            _cuc_cli_summary("utils diagnose test", "test - a : Passed\nskip - b : later")[
                "passed"
            ],
            "1",
        )
        self.assertEqual(
            _cuc_cli_summary("utils service list", "A[STARTED]\nB[STOPPED]  Service Not Activated")[
                "stopped"
            ],
            "1",
        )
        self.assertEqual(
            _cuc_cli_summary("utils core active list", "No core files found")["core_files"], "0"
        )
        status = _cuc_cli_summary(
            "show status",
            "21:08:27 up 328 days, 5:41\nDisk/active 10K 1K 9K (90%)\nDisk/logging 10K 1K 9K (95%)",
        )
        self.assertEqual(status["max_disk_usage_percent"], "95")
        self.assertEqual(status["disk_warning_count"], "2")
        self.assertEqual(status["disk_critical_count"], "1")
        self.assertEqual(status["uptime_days"], "328")
        self.assertEqual(_cuc_version("Active Master Version: 15.0.1.12900-43"), "15.0.1.12900-43")

    def test_service_list_normalizes_states_and_intentional_inactive_reason(self) -> None:
        services = _cuc_service_status(
            "cuc-pub",
            "A Cisco DB[STARTED]\nCisco DirSync[STOPPED] Service Not Activated",
        )

        self.assertEqual(services[0].status, "Started")
        self.assertTrue(services[0].activated)
        self.assertEqual(services[1].status, "Stopped")
        self.assertFalse(services[1].activated)

    def test_network_cluster_output_normalizes_cuc_members(self) -> None:
        nodes = _cuc_cluster_nodes(
            "\n".join(
                (
                    "10.51.200.9 YT-UCX-PUB.example.org YT-UCX-PUB Publisher connection DBPub authenticated",
                    "10.51.202.14 UCX-SUB.example.org UCX-SUB Subscriber connection DBSub authenticated",
                )
            ),
            target_id="cuc-example",
        )

        self.assertEqual(
            [(node.role, node.address) for node in nodes],
            [("publisher", "10.51.200.9"), ("subscriber", "10.51.202.14")],
        )
        self.assertTrue(all(node.technology == "cuc" for node in nodes))

    def test_cluster_status_normalizes_primary_secondary_roles(self) -> None:
        runtime = _cuc_cluster_runtime(
            "cuc-pub 0 Primary Pri Active Normal\ncuc-sub 1 Secondary Sec Active Normal"
        )

        self.assertEqual([item.details["server_state"] for item in runtime], ["Primary", "Secondary"])
        self.assertEqual(runtime[0].details["internal_state"], "Pri Active")

    def test_collector_records_only_safe_commands_and_artifacts(self) -> None:
        commands: list[str] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            artifacts = ArtifactStore.create(Path(tmpdir), "cuc", None)
            result = CucPlatformCollector(
                session_factory=lambda context: FakeSession(context, commands)
            ).collect(CollectionContext(publisher_ip="192.0.2.20", artifact_store=artifacts))

            self.assertEqual(
                commands,
                [
                    "show network cluster",
                    *[
                        command
                        for command in CUC_SAFE_CLI_COMMANDS
                        if command != "show network cluster"
                    ],
                    *[probe.command for probe in CUC_INFORMIX_PROBE_CATALOG],
                ],
            )
            expected = len(CUC_SAFE_CLI_COMMANDS) + len(CUC_INFORMIX_PROBE_CATALOG)
            self.assertEqual(len(result.facts.platform_checks), expected)
            self.assertEqual(len(list(artifacts.root.rglob("*.txt"))), expected)

    def test_collector_applies_platform_catalog_to_discovered_cuc_members(self) -> None:
        commands: list[str] = []

        class ClusterSession(FakeSession):
            def execute(
                self, command: str, *, timeout_seconds: int | None = None
            ) -> SshCommandResult:
                self.commands.append(f"{self.context.publisher_ip}:{command}")
                if command == "show network cluster":
                    return SshCommandResult(
                        command,
                        "192.0.2.20 cuc-pub.example cuc-pub Publisher\n192.0.2.21 cuc-sub.example cuc-sub Subscriber",
                    )
                return SshCommandResult(command, f"output for {command}")

            def __init__(self, context: CollectionContext, commands: list[str]) -> None:
                self.context = context
                self.commands = commands

        result = CucPlatformCollector(
            session_factory=lambda context: ClusterSession(context, commands)
        ).collect(CollectionContext(publisher_ip="192.0.2.20"))

        self.assertIn("192.0.2.21:show status", commands)
        self.assertEqual(
            len(result.facts.platform_checks),
            1 + (len(CUC_SAFE_CLI_COMMANDS) - 1) * 2 + len(CUC_INFORMIX_PROBE_CATALOG),
        )
        self.assertFalse(any("192.0.2.21:run cuc dbquery" in item for item in commands))

    def test_informix_catalog_is_fixed_bounded_and_read_only(self) -> None:
        for probe in CUC_INFORMIX_PROBE_CATALOG:
            _validate_cuc_informix_probe(probe)
            self.assertTrue(probe.query.lower().startswith("select first 100 "))
        duplicate_probe = CUC_INFORMIX_PROBE_CATALOG[0]
        self.assertIn("having count(dtmfaccessid) != 1", duplicate_probe.query.lower())
        self.assertNotIn(">", duplicate_probe.query)

        unsafe = CucInformixProbe(
            "unsafe",
            "unitydirdb",
            "select first 100 objectid from vw_user; delete from vw_user",
            "Unsafe",
            "objectid",
            (),
        )
        with self.assertRaises(ValueError):
            _validate_cuc_informix_probe(unsafe)

    def test_informix_fixed_width_rows_are_normalized(self) -> None:
        output = """dtmfaccessid occurrencecount
------------ ---------------
1000         2
2000         3

rows: 2"""

        rows = _parse_cuc_dbquery_rows(output)

        self.assertEqual(
            rows,
            [
                {"dtmfaccessid": "1000", "occurrencecount": "2"},
                {"dtmfaccessid": "2000", "occurrencecount": "3"},
            ],
        )
        self.assertTrue(_cuc_dbquery_zero_rows("No records found"))
        self.assertTrue(_cuc_dbquery_zero_rows("rows: 0"))
        self.assertFalse(_cuc_dbquery_zero_rows("output for query"))

    def test_informix_results_become_experimental_configuration_facts(self) -> None:
        class SqlSession(FakeSession):
            def execute(
                self,
                command: str,
                *,
                timeout_seconds: int | None = None,
            ) -> SshCommandResult:
                self.commands.append(command)
                if "duplicate_extensions" in command:
                    raise AssertionError("probe IDs are not sent as SQL")
                if command.startswith("run cuc dbquery") and "vw_user" in command:
                    return SshCommandResult(
                        command,
                        """dtmfaccessid occurrencecount
------------ ---------------
1000         2

rows: 1""",
                    )
                return SshCommandResult(command, f"output for {command}")

        commands: list[str] = []
        result = CucPlatformCollector(
            session_factory=lambda context: SqlSession(context, commands)
        ).collect(CollectionContext(publisher_ip="192.0.2.20"))

        duplicate = next(
            item
            for item in result.facts.configuration_objects
            if item.object_type == "CucSqlDuplicateExtension"
        )
        self.assertEqual(duplicate.name, "1000")
        self.assertEqual(duplicate.details["occurrencecount"], "2")
        self.assertEqual(duplicate.details["experimental"], "true")

        engineering = HtmlReportBuilder().build(AssessmentReport(result.facts, [result], []))
        customer = HtmlReportBuilder(customer_safe=True).build(
            AssessmentReport(result.facts, [result], [])
        )
        self.assertIn("Unity Connection Experimental SQL Validation", engineering)
        self.assertIn("Duplicate directory extensions", engineering)
        self.assertIn(">1000<", engineering)
        self.assertNotIn("Unity Connection Experimental SQL Validation", customer)

    def test_collector_retains_partial_output_from_long_running_command(self) -> None:
        class PartialSession(FakeSession):
            def execute(
                self, command: str, *, timeout_seconds: int | None = None
            ) -> SshCommandResult:
                if command == "utils diagnose test":
                    self.commands.append(command)
                    if timeout_seconds != 300:
                        raise AssertionError("long-running timeout was not applied")
                    raise SshCommandTimeout("diagnostic output in progress", False)
                return super().execute(command, timeout_seconds=timeout_seconds)

        commands: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            artifacts = ArtifactStore.create(Path(tmpdir), "cuc", None)
            result = CucPlatformCollector(
                session_factory=lambda context: PartialSession(context, commands)
            ).collect(CollectionContext(publisher_ip="192.0.2.20", artifact_store=artifacts))

            check = next(
                item
                for item in result.facts.platform_checks
                if item.check_name == "utils diagnose test"
            )
            self.assertEqual(check.status, "incomplete")
            self.assertEqual(check.details["output_length"], "29")
            self.assertIn("exceeded its 300-second budget", result.warnings[0])
            self.assertIn(
                "diagnostic output in progress",
                (
                    artifacts.root / "nodes" / "192.0.2.20" / "cli" / "utils_diagnose_test.txt"
                ).read_text(),
            )
