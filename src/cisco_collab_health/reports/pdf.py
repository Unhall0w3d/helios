"""PDF rendering for self-contained HTML assessment reports."""

from __future__ import annotations

from importlib import import_module
from pathlib import Path
from typing import Any


class PdfRenderError(RuntimeError):
    """Raised when the optional local Chromium PDF renderer is unavailable."""


def render_html_to_pdf(html_path: Path, pdf_path: Path) -> Path:
    """Render an HTML report through local Playwright Chromium.

    HTML reports are intentionally self-contained, so a local ``file:`` URL is
    sufficient and no report data leaves the workstation.
    """

    try:
        sync_api: Any = import_module("playwright.sync_api")
    except ModuleNotFoundError as exc:
        raise PdfRenderError(
            "PDF rendering requires Playwright. Run: python -m pip install -r requirements.txt "
            "then python -m playwright install chromium"
        ) from exc

    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with sync_api.sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            try:
                page = browser.new_page()
                page.goto(html_path.resolve().as_uri(), wait_until="load")
                page.emulate_media(media="screen")
                page.add_style_tag(
                    content="""
                        html, body { min-width: 0 !important; }
                        table {
                            width: 100% !important;
                            min-width: 0 !important;
                            max-width: 100% !important;
                            table-layout: fixed !important;
                            font-size: 9px !important;
                        }
                        th, td {
                            white-space: normal !important;
                            min-width: 0 !important;
                            overflow-wrap: anywhere !important;
                            word-break: break-word !important;
                        }
                    """
                )
                page.pdf(
                    path=str(pdf_path),
                    format="Letter",
                    print_background=True,
                    margin={
                        "top": "0.35in",
                        "right": "0.35in",
                        "bottom": "0.45in",
                        "left": "0.35in",
                    },
                    prefer_css_page_size=True,
                )
            finally:
                browser.close()
    except Exception as exc:
        raise PdfRenderError(
            "Unable to render PDF with local Chromium. Run: python -m playwright install chromium"
        ) from exc
    return pdf_path
