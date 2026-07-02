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

The project is intentionally CLI/report focused. A GUI is not currently planned.

## Status

This is not yet a production-ready assessment tool.

Current capabilities:

- Core pipeline contracts
- Sample in-memory collector
- Initial health rule runner
- JSON and Markdown report builders
- Placeholder AXL, RISPort, Serviceability, and CLI fallback collectors

External Cisco API implementations are intentionally not included yet.

## Quick Start

Run the alpha sample assessment without installing package dependencies:

```bash
PYTHONPATH=src python -m cisco_collab_health.cli --format markdown
```

Run tests with the standard library:

```bash
PYTHONPATH=src python -m unittest discover -s tests
```

## Development

Optional development dependencies are declared in `pyproject.toml`:

```bash
python -m pip install -e ".[dev]"
```

The project uses a `src/` package layout and currently requires Python 3.11 or
newer.

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
