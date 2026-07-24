"""Contract tests for the source-based portable release builder."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PortableReleaseTests(unittest.TestCase):
    def test_builder_creates_bootstrap_release_with_launchers(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "release"
            completed = subprocess.run(
                [sys.executable, "scripts/build_portable_release.py", "--output-dir", str(output)],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            archive = Path(completed.stdout.strip())
            self.assertTrue(archive.is_file())
            with zipfile.ZipFile(archive) as release:
                names = set(release.namelist())

        expected = {
            "AletheiaUC/aletheiauc.py",
            "AletheiaUC/requirements-runtime.txt",
            "AletheiaUC/install.sh",
            "AletheiaUC/install.ps1",
            "AletheiaUC/aletheiauc",
            "AletheiaUC/aletheiauc.ps1",
            "AletheiaUC/activate",
            "AletheiaUC/Activate.ps1",
            "AletheiaUC/src/cisco_collab_health/cli.py",
            "AletheiaUC/docs/PORTABLE_RELEASE.md",
        }
        self.assertTrue(expected <= names)
        self.assertFalse(any(".venv/" in name for name in names))
