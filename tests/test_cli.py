"""Tests for CLI error handling."""

from __future__ import annotations

import io
import unittest
from unittest.mock import patch

from cisco_collab_health import cli


class CliTests(unittest.TestCase):
    def test_keyboard_interrupt_returns_130(self) -> None:
        with patch("cisco_collab_health.cli.AssessmentEngine.run", side_effect=KeyboardInterrupt):
            result = cli.main(["--skip-profile", "--no-html-report"])

        self.assertEqual(result, 130)

    def test_value_error_returns_failure(self) -> None:
        with patch("cisco_collab_health.cli.AssessmentEngine.run", side_effect=ValueError("bad input")):
            result = cli.main(["--skip-profile", "--no-html-report"])

        self.assertEqual(result, 1)

    def test_html_write_failure_does_not_block_summary(self) -> None:
        output = io.StringIO()
        with (
            patch("cisco_collab_health.cli.StatusPrinter._should_color", return_value=False),
            patch("cisco_collab_health.cli.sys.stdout", output),
            patch("cisco_collab_health.cli.Path.write_text", side_effect=OSError("disk full")),
        ):
            result = cli.main(["--skip-profile", "--html-report", "/tmp/report.html"])

        self.assertEqual(result, 0)
        self.assertIn("[FAIL] Unable to write HTML report: disk full", output.getvalue())
        self.assertIn("Executive Summary", output.getvalue())


if __name__ == "__main__":
    unittest.main()
