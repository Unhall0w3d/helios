"""Tests for optional local PDF rendering."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from cisco_collab_health.reports.pdf import PdfRenderError, render_html_to_pdf


class PdfRendererTests(unittest.TestCase):
    def test_missing_playwright_explains_both_required_install_steps(self) -> None:
        with TemporaryDirectory() as tmpdir:
            html = Path(tmpdir) / "report.html"
            html.write_text("<html></html>", encoding="utf-8")
            with patch(
                "cisco_collab_health.reports.pdf.import_module",
                side_effect=ModuleNotFoundError,
            ), self.assertRaisesRegex(PdfRenderError, "pip install -r requirements.txt") as error:
                render_html_to_pdf(html, html.with_suffix(".pdf"))

        self.assertIn("playwright install chromium", str(error.exception))
