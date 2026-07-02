# Cisco Collaboration Health Assessment Tool

An early alpha framework for assessing Cisco Collaboration environments.

The project is currently focused on Cisco Unified Communications Manager
and CUCM Session Management Edition environments, with an initial target of
CUCM 11.5 and later.

This repository is in the skeleton/prototyping stage. The current code is
intentionally offline-first and defines the core assessment pipeline:

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
- Sample in-memory collector
- Initial health rule runner
- Terminal Executive Summary output
- Styled HTML report builder
- JSON output for development and automation
- Placeholder AXL, RISPort, Serviceability, and CLI fallback collectors

External Cisco API implementations are intentionally not included yet.

## Quick Start

Install the package in editable mode:

```bash
python -m pip install -e .
```

Run the alpha sample assessment:

```bash
ccha
```

When the assessment completes, Helios prints an Executive Summary in the
terminal and writes a styled HTML report under `reports/` by default.

On startup, the CLI checks for saved connection profiles. If any exist, it asks
whether to use an existing profile or create a new one. If no profile exists, it
prompts for a new profile name before collecting connection details.

For a new profile, the CLI prompts for:

- Publisher IP address or FQDN
- CUCM GUI/API username and password
- CUCM OS/SSH username and password

If an FQDN is entered, it is resolved and the resulting IP address is used for
collector context.

Run tests with the standard library:

```bash
PYTHONPATH=src python -m unittest discover -s tests
```

To run the offline sample without prompting for connection details:

```bash
PYTHONPATH=src python -m cisco_collab_health.cli --skip-profile
```

To choose an explicit HTML report path:

```bash
ccha --html-report reports/lab-assessment.html
```

To print JSON instead of the terminal Executive Summary:

```bash
ccha --format json
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
ccha --reset-profile
```

Use `--no-save-credentials` to avoid storing passwords for the current run:

```bash
ccha --no-save-credentials
```

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
