#!/usr/bin/env bash
# Create the local runtime virtual environment for an extracted portable release.
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [[ -d "$SCRIPT_DIR/src" ]]; then ROOT="$SCRIPT_DIR"; else ROOT="$(dirname "$SCRIPT_DIR")"; fi
PYTHON_BIN="${PYTHON_BIN:-python3}"
INSTALL_PDF=1

usage() {
  cat <<'EOF'
Usage: ./install.sh [--no-pdf]

Creates .venv in this extracted AletheiaUC release, installs runtime Python
dependencies, and by default downloads the local Chromium used for PDF reports.
Use --no-pdf to install an HTML-only runtime. Run ./install.sh again
without --no-pdf later to add PDF support.

Set PYTHON_BIN to select a different Python 3.11+ executable.
EOF
}

while (($#)); do
  case "$1" in
    --no-pdf) INSTALL_PDF=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'; then
  echo "AletheiaUC requires Python 3.11 or newer. Set PYTHON_BIN if needed." >&2
  exit 1
fi

cd "$ROOT"
"$PYTHON_BIN" -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements-runtime.txt

if ((INSTALL_PDF)); then
  if .venv/bin/python -m playwright install chromium; then
    echo "PDF support installed."
  else
    echo "WARNING: Chromium could not be installed. HTML reports are ready; run AletheiaUC with --no-pdf-report." >&2
    echo "Retry ./install.sh later to add PDF support." >&2
  fi
else
  echo "HTML-only runtime installed. Run ./install.sh later to add PDF support."
fi

echo "Ready. Run ./aletheiauc or source ./activate."
