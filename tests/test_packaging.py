"""Regression checks for distributable runtime requirements."""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


class PackagingMetadataTests(unittest.TestCase):
    def test_ssh_dependency_is_declared_in_project_metadata(self) -> None:
        metadata = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
        dependencies = metadata["project"]["dependencies"]

        self.assertTrue(any(requirement.startswith("paramiko>=") for requirement in dependencies))

    def test_report_assets_are_declared_as_package_data(self) -> None:
        metadata = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
        package_data = metadata["tool"]["setuptools"]["package-data"]

        self.assertIn("reports/assets/*.png", package_data["cisco_collab_health"])
        self.assertIn(
            "reports/assets/comsource/*.svg",
            package_data["cisco_collab_health"],
        )
