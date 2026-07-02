#!/usr/bin/env python3
"""Repository-local launcher for Helios."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parent
    src_path = repo_root / "src"
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))

    from cisco_collab_health.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
