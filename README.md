# Cisco Collaboration Health Assessment Tool

An early alpha framework for assessing Cisco Collaboration environments.

The project is currently focused on Cisco Unified Communications Manager
and CUCM Session Management Edition environments, with an initial target of
CUCM 11.5 and later.

This repository is in the early API-collection stage and defines the core
assessment pipeline:

```text
Collectors -> Data Models -> Health Rules -> Report Builders
```

Collectors gather facts, data models normalize them, rules interpret them, and
report builders present the results.

The project is intentionally CLI/report focused. A GUI wrapper may be possible
after the scripting engine matures, but it is not a current concern.

## Status

This is not yet a production-ready assessment tool.

Current capabilities:

- Core pipeline contracts
- Initial AXL collector for `getCCMVersion` and `listProcessNode`
- Publisher preflight and interface reachability checks
- Initial health rule runner for collected identity/node facts
- Terminal Executive Summary output
- Styled HTML report builder
- JSON output for development and automation
- Placeholder RISPort, Serviceability, and CLI fallback collectors

The current real API implementation is limited to initial AXL collection.

## Quick Start

Install runtime dependencies:

```bash
python -m pip install -r requirements.txt
```

Make the launcher executable:

```bash
chmod +x helios.py
```

Run Helios:

```bash
./helios.py
```

This launcher is the main user entry point for a cloned repository. It opens the
interactive menu by default and loads the package from `src/` directly, so an
editable package install is optional.

Main menu options:

- Load Profile
- New Profile
- Generate Report
- TEMP Test Options
- Quit

When a health assessment runs, Helios prints an Executive Summary in the
terminal, writes a styled HTML report under `reports/`, and writes local
parser/debug artifacts under `assessment_runs/` by default. It also writes a
shareable troubleshooting log bundle under `logs/`.

On startup, the CLI checks for saved connection profiles. If any exist, it asks
whether to load an existing profile. Answering `Y` lets you choose the saved
profile. Answering `N` starts new profile creation. If no profile exists, it
prompts for a new profile name before collecting connection details.

For a new profile, the CLI prompts for:

- Publisher IP address or FQDN
- CUCM GUI/API username and password
- CUCM OS/SSH username and password

If an FQDN is entered, it is resolved and the resulting IP address is used for
collector context.

After a profile is loaded, Helios runs a Publisher preflight:

- ping reachability
- HTTPS base URL check on port 443
- HTTPS base URL check on port 8443
- AXL endpoint reachability
- RISPort70 endpoint reachability
- Control Center Services endpoint reachability
- PerfMon endpoint reachability

Progress is shown with bracketed status messages such as `[STAGE]`, `[OK]`,
`[WARN]`, and `[INFO]`. Raw command or API output should be stored as evidence
for parsing/reporting rather than streamed directly to the terminal.

Run tests with the standard library:

```bash
PYTHONPATH=src python -m unittest discover -s tests
```

To run a framework smoke test without prompting for connection details:

```bash
./helios.py --skip-profile
```

To choose an explicit HTML report path:

```bash
./helios.py --html-report reports/lab-assessment.html
```

To choose an explicit artifact directory:

```bash
./helios.py --artifact-dir assessment_runs
```

To disable local artifact writing:

```bash
./helios.py --no-artifacts
```

To choose an explicit troubleshooting log directory:

```bash
./helios.py --log-dir logs
```

To disable troubleshooting log writing:

```bash
./helios.py --no-logs
```

To print JSON instead of the terminal Executive Summary:

```bash
./helios.py --format json
```

Publisher preflight runs automatically after profile load. The legacy
`--probe-interfaces` flag is currently accepted as a compatibility alias but is
no longer required:

```bash
./helios.py --probe-interfaces
```

Future collectors will use preflight status to avoid running collectors for
interfaces that are unavailable.

If a lab uses alternate API ports, override them at startup:

```bash
./helios.py --axl-port 9443 --risport-port 9444 --control-center-port 9445 --perfmon-port 9446
```

If you prefer installing Helios as a Python package during development, the
`ccha` console command is also available after an editable install:

```bash
python -m pip install -e .
ccha
```

## Development

Optional development dependencies are declared in `pyproject.toml`:

```bash
python -m pip install -e ".[dev]"
```

The project uses a `src/` package layout and currently requires Python 3.11 or
newer.

## Local Profiles and Credentials

When the operating system credential store is available through Python
`keyring`, the CLI stores the full reusable connection profile there, including
Publisher address, usernames, and passwords.

If a secure credential backend is unavailable, only non-secret profile details,
such as Publisher address and usernames, are saved in the current user's local
configuration directory. Passwords are not written to disk and will be requested
again on future runs.

Use `--reset-profile` to replace the saved profile:

```bash
./helios.py --reset-profile
```

Use `--no-save-credentials` to avoid storing passwords for the current run:

```bash
./helios.py --no-save-credentials
```

## Local Artifacts

Helios writes local per-run artifacts for parser development, debugging, manual
review, and future evidence traceability. These files are intentionally ignored
by git and are separate from the human HTML files in `reports/`.

Default layout:

```text
assessment_runs/
  <profile>/
    <timestamp>/
      manifest.json
      normalized/
      nodes/
        <node>/
          preflight/
          normalized/
          api/
          cli/
```

Current artifacts include Publisher preflight data, raw AXL SOAP request/response
artifacts when AXL collection runs, normalized collector output, and per-node
facts. Future SSH collectors should write raw command and stdout/stderr
artifacts here before parsing.

Reusable credentials should not be written to artifact files.

## Troubleshooting Logs

Helios also writes a run-specific troubleshooting bundle under `logs/`.

Default layout:

```text
logs/
  <timestamp>/
    manifest.json
    run.log
    executive_summary.txt
    report.html
    assessment_report.json
    collector_warnings.json
    artifact_index.txt
```

Use this folder when you want to provide a compact troubleshooting package for
analysis. It contains status messages, collector warnings, a copy of the HTML
report, the normalized assessment JSON, and an index of the raw artifact files
stored in `assessment_runs/`.

## Cluster Discovery Direction

The first API collector target is Publisher-based cluster discovery. The tool
will connect to the CUCM Publisher using the GUI/API credentials from the active
profile, query an authoritative Publisher API source, and normalize the
Publisher plus Subscriber nodes into the assessment facts model.

Health rules should then evaluate every discovered server in the cluster, not
only the Publisher node.

## Repository Notes

The local `Soul/` directory is used as private working context and persistent
project guidance. It is intentionally excluded from version control and should
not be published with the public repository.

## Trademark Notice

Cisco, Cisco Unified Communications Manager, CUCM, and related product names
are trademarks or registered trademarks of Cisco Systems, Inc. This project is
not affiliated with, endorsed by, or sponsored by Cisco.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
