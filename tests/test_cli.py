"""Tests for CLI error handling."""

from __future__ import annotations

import io
import unittest
from unittest.mock import patch

from cisco_collab_health import cli


class CliTests(unittest.TestCase):
    def test_no_arguments_opens_menu_and_can_quit(self) -> None:
        output = io.StringIO()
        with (
            patch("cisco_collab_health.cli.StatusPrinter._should_color", return_value=False),
            patch("cisco_collab_health.cli.sys.stdout", output),
            patch("builtins.input", return_value="q"),
        ):
            result = cli.main([])

        self.assertEqual(result, 0)
        self.assertIn("Helios Main Menu", output.getvalue())
        self.assertIn("[INFO] Exiting Helios", output.getvalue())

    def test_temp_menu_can_run_sample_assessment(self) -> None:
        output = io.StringIO()
        with (
            patch("cisco_collab_health.cli.StatusPrinter._should_color", return_value=False),
            patch("cisco_collab_health.cli.sys.stdout", output),
            patch("builtins.input", side_effect=["t", "s"]),
            patch("cisco_collab_health.cli.run_assessment", return_value=0) as run_assessment,
        ):
            result = cli.main([])

        self.assertEqual(result, 0)
        self.assertIn("TEMP Test Options", output.getvalue())
        run_assessment.assert_called_once()

    def test_keyboard_interrupt_returns_130(self) -> None:
        with patch(
            "cisco_collab_health.application.AssessmentEngine.run",
            side_effect=KeyboardInterrupt,
        ):
            result = cli.main(["--skip-profile", "--no-html-report", "--no-artifacts", "--no-logs"])

        self.assertEqual(result, 130)

    def test_customer_data_redaction_mode_is_not_exposed_until_implemented(self) -> None:
        with self.assertRaises(SystemExit) as exc:
            cli.build_parser().parse_args(["--artifact-redaction", "customer-data"])

        self.assertEqual(exc.exception.code, 2)

    def test_skip_profile_runs_sample_collector(self) -> None:
        output = io.StringIO()
        with (
            patch("cisco_collab_health.cli.StatusPrinter._should_color", return_value=False),
            patch("cisco_collab_health.cli.sys.stdout", output),
        ):
            result = cli.main(["--skip-profile", "--no-html-report", "--no-artifacts", "--no-logs"])

        self.assertEqual(result, 0)
        self.assertIn("[INFO] Collectors enabled: sample", output.getvalue())
        self.assertIn("Cluster: alpha-lab", output.getvalue())
        self.assertIn("Nodes discovered: 2", output.getvalue())

    def test_collect_phone_inventory_flag_reaches_collection_context(self) -> None:
        contexts = []

        def capture_context(self, context=None):
            del self
            contexts.append(context)
            raise KeyboardInterrupt

        with patch("cisco_collab_health.application.AssessmentEngine.run", capture_context):
            result = cli.main(
                [
                    "--skip-profile",
                    "--collect-phone-inventory",
                    "--no-html-report",
                    "--no-artifacts",
                    "--no-logs",
                ]
            )

        self.assertEqual(result, 130)
        self.assertEqual(len(contexts), 1)
        self.assertTrue(contexts[0].collect_phone_inventory)

    def test_value_error_returns_failure(self) -> None:
        with patch(
            "cisco_collab_health.application.AssessmentEngine.run",
            side_effect=ValueError("bad input"),
        ):
            result = cli.main(["--skip-profile", "--no-html-report", "--no-artifacts", "--no-logs"])

        self.assertEqual(result, 1)

    def test_html_write_failure_does_not_block_summary(self) -> None:
        output = io.StringIO()
        with (
            patch("cisco_collab_health.cli.StatusPrinter._should_color", return_value=False),
            patch("cisco_collab_health.cli.sys.stdout", output),
            patch(
                "cisco_collab_health.application.Path.write_text",
                side_effect=OSError("disk full"),
            ),
        ):
            result = cli.main(
                [
                    "--skip-profile",
                    "--html-report",
                    "/tmp/report.html",
                    "--no-artifacts",
                    "--no-logs",
                ]
            )

        self.assertEqual(result, 0)
        self.assertIn("[FAIL] Unable to write HTML report: disk full", output.getvalue())
        self.assertIn("Executive Summary", output.getvalue())


if __name__ == "__main__":
    unittest.main()
