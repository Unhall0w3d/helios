# Portable bootstrap release

AletheiaUC can be distributed without Git as a source-based portable release
ZIP. The ZIP contains the application, runtime dependency manifest, documents,
and small operating-system launchers. It intentionally does **not** contain a
prebuilt virtual environment or a browser binary.

This is a bootstrap release: the target host needs Python 3.11 or later and
network access to install Python packages. The installer attempts to download
Playwright Chromium for PDF output, but automatically leaves a working
HTML-only installation when that browser download is blocked or unavailable.
A virtual environment is created after extraction because virtual environments
are not reliably relocatable and cannot cross Linux, macOS, and Windows.

## Build a release ZIP

From a maintained source checkout:

```bash
python scripts/build_portable_release.py
```

The command writes `dist/aletheiauc-portable-<version>.zip`. Give that ZIP to
the operator; Git is not required on the target host.

## Linux or macOS operator workflow

Extract the ZIP, enter the extracted `AletheiaUC` directory, and run:

```bash
./install.sh
./aletheiauc
```

`install.sh` creates `.venv`, installs `requirements-runtime.txt`, and attempts
to install the matching Playwright Chromium runtime. If that browser download
fails, setup still completes for HTML-only reporting. Run AletheiaUC with
`--no-pdf-report` until Chromium can be installed. To use the virtual
environment directly instead, run:

```bash
source ./activate
python aletheiauc.py
```

## Windows PowerShell operator workflow

Extract the ZIP, open PowerShell in the extracted `AletheiaUC` directory, and
run:

```powershell
.\install.ps1
.\aletheiauc.ps1
```

If local PowerShell policy blocks the installer, use a process-only policy:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1
```

To activate the environment directly, run `. .\Activate.ps1`, then
`python .\aletheiauc.py`.

## HTML-only installation and later PDF enablement

To intentionally skip the browser download:

```bash
./install.sh --no-pdf
```

```powershell
.\install.ps1 -NoPdf
```

Run AletheiaUC with `--no-pdf-report` in HTML-only mode. Re-run the installer
without the no-PDF option later to retry Chromium installation and enable PDF
output. A browser download failure is treated the same way: it does not block a
working HTML-only installation.

## Operational notes

- The bootstrap uses the target host's selected Python. On Linux/macOS, set
  `PYTHON_BIN` when `python3` is not the desired Python 3.11+ executable.
- On Windows, use `-Python` with `install.ps1` to select a Python launcher or
  executable other than `py`.
- A corporate proxy, firewall, or TLS interception can block the Playwright
  browser download. The installer surfaces Playwright's error and preserves the
  HTML-only fallback.
- Rebuilding the release after a dependency upgrade is preferred. Each
  Playwright release can require a matching browser download.
