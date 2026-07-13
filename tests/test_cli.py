"""Tests for CLI error handling."""

from __future__ import annotations

import io
import unittest
from unittest.mock import patch

from cisco_collab_health import cli
from cisco_collab_health import menu


class CliTests(unittest.TestCase):
    def test_multi_target_arguments_are_repeatable(self) -> None:
        args = cli.build_parser().parse_args(
            [
                "--assessment-profile",
                "district",
                "--assessment-target",
                "call-control:cucm:YorktownCSD",
                "--assessment-target",
                "voicemail:cuc:YorktownCUC",
            ]
        )

        self.assertEqual(args.assessment_profile, "district")
        self.assertEqual(len(args.assessment_target), 2)

    def test_review_zip_requires_troubleshooting_logs(self) -> None:
        with self.assertRaises(SystemExit) as exc:
            cli.main(
                [
                    "--skip-profile",
                    "--export-review-zip",
                    "--no-logs",
                ]
            )

        self.assertEqual(exc.exception.code, 2)

    def test_customer_safe_html_flag_is_available(self) -> None:
        args = cli.build_parser().parse_args(["--customer-safe-report"])

        self.assertTrue(args.customer_safe_report)

    def test_default_html_template_is_aletheiauc(self) -> None:
        args = cli.build_parser().parse_args([])

        self.assertEqual(args.html_template, "aletheiauc")

    def test_html_template_choices_are_discovered_from_installed_assets(self) -> None:
        with patch(
            "cisco_collab_health.cli.available_report_templates",
            return_value=("aletheiauc",),
        ):
            parser = cli.build_parser()
            args = parser.parse_args(["--html-template", "aletheiauc"])

        self.assertEqual(args.html_template, "aletheiauc")
        template_action = next(
            action for action in parser._actions if action.dest == "html_template"
        )
        self.assertEqual(template_action.choices, ("aletheiauc",))

    def test_start_key_uses_recommended_diagnostic_and_review_options(self) -> None:
        args = cli.build_parser().parse_args([])
        with patch("builtins.input", return_value="s"):
            run_args = menu._prompt_run_mode(args)

        self.assertIsNotNone(run_args)
        self.assertTrue(run_args.diagnostic_capture)
        self.assertTrue(run_args.export_review_zip)

    def test_no_arguments_opens_menu_and_can_quit(self) -> None:
        output = io.StringIO()
        with (
            patch("cisco_collab_health.cli.StatusPrinter._should_color", return_value=False),
            patch("cisco_collab_health.cli.sys.stdout", output),
            patch("builtins.input", return_value="q"),
        ):
            result = cli.main([])

        self.assertEqual(result, 0)
        self.assertIn("AletheiaUC Main Menu", output.getvalue())
        self.assertIn("[INFO] Exiting AletheiaUC", output.getvalue())

    def test_temp_menu_can_run_sample_assessment(self) -> None:
        output = io.StringIO()
        with (
            patch("cisco_collab_health.cli.StatusPrinter._should_color", return_value=False),
            patch("cisco_collab_health.cli.sys.stdout", output),
            patch("builtins.input", side_effect=["4", "s"]),
            patch("cisco_collab_health.cli.run_assessment", return_value=0) as run_assessment,
        ):
            result = cli.main([])

        self.assertEqual(result, 0)
        self.assertIn("TEMP Test Options", output.getvalue())
        run_assessment.assert_called_once()

    def test_menu_selects_multiple_cluster_profiles_for_one_assessment(self) -> None:
        output = io.StringIO()
        with (
            patch("cisco_collab_health.cli.StatusPrinter._should_color", return_value=False),
            patch("cisco_collab_health.cli.sys.stdout", output),
            patch("builtins.input", side_effect=["1", "1,2", "n", ""]),
            patch(
                "cisco_collab_health.menu.load_profile_names",
                return_value=["CallControl", "Voicemail"],
            ),
            patch(
                "cisco_collab_health.menu.load_connection_profile_details",
                side_effect=[
                    {"cucm": type("Profile", (), {"publisher_ip": "192.0.2.10"})()},
                    {"cuc": type("Profile", (), {"publisher_ip": "192.0.2.20"})()},
                ],
            ),
            patch(
                "cisco_collab_health.menu.resolve_assessment_targets",
                side_effect=lambda assessment, **_kwargs: [
                    (target, None) for target in assessment.targets
                ],
            ),
            patch("cisco_collab_health.cli.run_multi_assessment", return_value=0) as run_multi,
        ):
            result = cli.main([])

        self.assertEqual(result, 0)
        targets = run_multi.call_args.args[3]
        self.assertEqual({target.technology for target, _runtime in targets}, {"cucm", "cuc"})
        run_args = run_multi.call_args.args[0]
        self.assertTrue(run_args.diagnostic_capture)
        self.assertTrue(run_args.export_review_zip)

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
                    "--phone-inventory-page-size",
                    "25",
                    "--phone-inventory-max-devices",
                    "100",
                    "--no-html-report",
                    "--no-artifacts",
                    "--no-logs",
                ]
            )

        self.assertEqual(result, 130)
        self.assertEqual(len(contexts), 1)
        self.assertTrue(contexts[0].collect_phone_inventory)
        self.assertEqual(contexts[0].phone_inventory_page_size, 25)
        self.assertEqual(contexts[0].phone_inventory_max_devices, 100)

    def test_phone_inventory_bounds_must_be_positive(self) -> None:
        with self.assertRaises(SystemExit) as exc:
            cli.main(["--skip-profile", "--phone-inventory-page-size", "0"])

        self.assertEqual(exc.exception.code, 2)

    def test_diagnostic_capture_arguments_reach_collection_context(self) -> None:
        contexts = []

        def capture_context(self, context=None):
            del self
            contexts.append(context)
            raise KeyboardInterrupt

        with patch("cisco_collab_health.application.AssessmentEngine.run", capture_context):
            result = cli.main(
                [
                    "--skip-profile",
                    "--diagnostic-capture",
                    "--diagnostic-max-devices",
                    "250",
                    "--diagnostic-axl-page-size",
                    "50",
                    "--diagnostic-axl-max-records",
                    "100",
                    "--no-html-report",
                    "--no-artifacts",
                    "--no-logs",
                ]
            )

        self.assertEqual(result, 130)
        self.assertTrue(contexts[0].diagnostic_capture)
        self.assertEqual(contexts[0].diagnostic_max_devices, 250)
        self.assertEqual(contexts[0].diagnostic_axl_page_size, 50)
        self.assertEqual(contexts[0].diagnostic_axl_max_records, 100)

    def test_diagnostic_capture_bounds_are_validated(self) -> None:
        for arguments in (
            ["--diagnostic-max-devices", "2001"],
            ["--diagnostic-axl-page-size", "0"],
            ["--diagnostic-axl-max-records", "0"],
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(SystemExit) as exc:
                    cli.main(["--skip-profile", *arguments])
                self.assertEqual(exc.exception.code, 2)

        with self.assertRaises(SystemExit) as exc:
            cli.main(["--skip-profile", "--phone-inventory-max-devices", "0"])

        self.assertEqual(exc.exception.code, 2)

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
