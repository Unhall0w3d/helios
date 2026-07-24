#!/usr/bin/env python3
"""Build a source-based, no-git portable AletheiaUC release ZIP."""

from __future__ import annotations

import argparse
import shutil
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_ROOT_NAME = "AletheiaUC"
INCLUDED_PATHS = (
    "aletheiauc.py",
    "requirements-runtime.txt",
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "src",
    "docs",
)
PORTABLE_FILES = (
    "install.sh",
    "install.ps1",
    "aletheiauc",
    "aletheiauc.ps1",
    "activate",
    "Activate.ps1",
)


def version() -> str:
    for line in (ROOT / "pyproject.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("version = "):
            return line.split('"', 2)[1]
    raise RuntimeError("Could not determine project version from pyproject.toml")


def copy_release_tree(destination: Path) -> None:
    for relative in INCLUDED_PATHS:
        source = ROOT / relative
        target = destination / relative
        if source.is_dir():
            shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            shutil.copy2(source, target)
    for filename in PORTABLE_FILES:
        source = ROOT / "portable" / filename
        target = destination / filename
        shutil.copy2(source, target)
        if target.suffix != ".ps1":
            target.chmod(0o755)


def build_archive(output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_stem = output_dir / f"aletheiauc-portable-{version()}"
    with tempfile.TemporaryDirectory(prefix="aletheiauc-portable-") as temp:
        staging_root = Path(temp) / RELEASE_ROOT_NAME
        staging_root.mkdir()
        copy_release_tree(staging_root)
        return Path(shutil.make_archive(str(archive_stem), "zip", temp, RELEASE_ROOT_NAME))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    archive = build_archive(args.output_dir.resolve())
    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
