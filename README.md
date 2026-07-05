<p align="center">
  <img src="assets/brand/png/aletheiauc-readme-header.png" alt="AletheiaUC - Bringing UC Health to Light" width="100%">
</p>

<p align="center">
  <strong>Bringing UC Health to Light</strong><br>
  Assess · Diagnose · Improve · Optimize
</p>

# AletheiaUC

An early alpha framework for assessing Cisco Collaboration environments.

AletheiaUC was originally developed under the Helios working name.

AletheiaUC is named from *Aletheia*, meaning truth, disclosure, or
unconcealedness. For this tool, that means surfacing real UC system health
through repeatable checks, transparent reporting, and actionable findings.

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

## Documentation

- [Branding and visual identity](docs/BRANDING.md)

## Report-First Development Workflow

AletheiaUC uses the generated report as the primary development feedback loop.
When adding a collector operation:

1. Capture raw artifact evidence.
2. Parse the artifact into normalized facts.
3. Add or update conservative health rules.
4. Add or update the HTML report section that displays the facts.
5. Verify JSON contains the normalized facts and evidence references needed for automation.
6. Add fixture tests for parser, rules, JSON, summary, and HTML behavior.
7. Verify a sample or fixture report visibly shows the new data.

The current report renders executive metrics, collection coverage, cluster
identity, discovered nodes, device inventory, device registration, services,
performance counters, platform checks, collector issues, collector notes,
collector evidence, and findings.

Registration, service, performance, and platform sections are intentionally
present before their real collectors are implemented. Empty sections, skipped
scope, and not-yet-implemented coverage rows are expected to make missing data
visible during review. Sample-mode data is synthetic and exists only to exercise
the report layout.

## Status

This is not yet a production-ready assessment tool.

Current capabilities:

- Core pipeline contracts
- Initial AXL collector for `getCCMVersion`, `listProcessNode`, and opt-in summary `listPhone`
- AXL schema retry when CUCM reports that the requested AXL version is unsupported
- Publisher preflight and interface reachability checks
- Initial health rule runner for collected identity/node facts
- Terminal Executive Summary output
- Styled HTML report builder
- JSON output for development and automation
- Placeholder RISPort, Serviceability, and CLI fallback collectors

The current real API implementation is limited to initial AXL collection.
AXL requests start with schema version `14.0`. If CUCM returns an
`Incorrect axl version` response that lists supported versions, AletheiaUC retries
the operation once with the highest version reported by the Publisher.

## Quick Start

Install runtime dependencies:

```bash
python -m pip install -r requirements.txt
```

Make the launcher executable:

```bash
chmod +x aletheiauc.py
```

Run AletheiaUC:

```bash
./aletheiauc.py
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

When a health assessment runs, AletheiaUC prints an Executive Summary in the
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

After a profile is loaded, AletheiaUC runs a Publisher preflight:

- ping reachability
- HTTPS base URL check on port 443
- HTTPS base URL check on port 8443
- AXL HTTPS transport reachability
- RISPort70 HTTPS transport reachability
- Control Center Services HTTPS transport reachability
- PerfMon HTTPS transport reachability

Preflight currently proves transport reachability only. It does not yet claim
that WSDL retrieval or authenticated API operations succeeded. AXL
authentication/operation validity is established when the AXL collector runs.

Progress is shown with bracketed status messages such as `[STAGE]`, `[OK]`,
`[WARN]`, and `[INFO]`. Raw command or API output should be stored as evidence
for parsing/reporting rather than streamed directly to the terminal.

Run tests with the standard library:

```bash
PYTHONPATH=src python -m unittest discover -s tests
```

To run a framework smoke test without prompting for connection details:

```bash
./aletheiauc.py --skip-profile
```

To choose an explicit HTML report path:

```bash
./aletheiauc.py --html-report reports/lab-assessment.html
```

To choose an explicit artifact directory:

```bash
./aletheiauc.py --artifact-dir assessment_runs
```

API request/response artifacts redact secret headers and password-like XML tags
by default. To choose a different local artifact redaction mode:

```bash
./aletheiauc.py --artifact-redaction secrets
./aletheiauc.py --artifact-redaction none
```

To disable local artifact writing:

```bash
./aletheiauc.py --no-artifacts
```

To choose an explicit troubleshooting log directory:

```bash
./aletheiauc.py --log-dir logs
```

To disable troubleshooting log writing:

```bash
./aletheiauc.py --no-logs
```

To print JSON instead of the terminal Executive Summary:

```bash
./aletheiauc.py --format json
```

Publisher preflight runs automatically after profile load. The legacy
`--probe-interfaces` flag is currently accepted as a compatibility alias but is
no longer required:

```bash
./aletheiauc.py --probe-interfaces
```

Future collectors will use preflight status to avoid running collectors for
interfaces that are unavailable.

AXL phone inventory uses `listPhone` summary data and is disabled by default to
avoid unnecessary full-cluster inventory requests on large systems. When enabled,
collection uses bounded `first`/`skip` paging and also collects AXL device
defaults for load comparison:

```bash
./aletheiauc.py --collect-phone-inventory
```

Tune the inventory page size and maximum device count for lab/debug runs:

```bash
./aletheiauc.py --collect-phone-inventory --phone-inventory-page-size 500 --phone-inventory-max-devices 2000
```

If a lab uses alternate API ports, override them at startup:

```bash
./aletheiauc.py --axl-port 9443 --risport-port 9444 --control-center-port 9445 --perfmon-port 9446
```

By default, AletheiaUC allows CUCM self-signed or privately issued HTTPS
certificates during alpha testing. To verify CUCM HTTPS certificates:

```bash
./aletheiauc.py --verify-tls
./aletheiauc.py --verify-tls --ca-bundle /path/to/ca.pem
```

Use `--insecure` to explicitly keep certificate verification disabled.

If you prefer installing AletheiaUC as a Python package during development, the
`aletheiauc` and `ccha` console commands are available after an editable install:

```bash
python -m pip install -e .
aletheiauc
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
./aletheiauc.py --reset-profile
```

Use `--no-save-credentials` to avoid storing passwords for the current run:

```bash
./aletheiauc.py --no-save-credentials
```

## Local Artifacts

AletheiaUC writes local per-run artifacts for parser development, debugging, manual
review, and future evidence traceability. These files are intentionally ignored
by git and are separate from the human HTML files in `reports/`.

Generated artifacts, troubleshooting logs, JSON reports, and HTML reports may
contain customer-sensitive infrastructure data, including hostnames, IP
addresses, device names, directory numbers, route patterns, CSS and partition
names, user identifiers, and cluster topology. Do not commit or publish
generated output from real customer environments.

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

AletheiaUC also writes a run-specific troubleshooting bundle under `logs/`.

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
    artifact_source.txt
    artifacts/
      manifest.json
      normalized/
      nodes/
```

Use this folder when you want to provide a compact troubleshooting package for
analysis. It contains status messages, collector warnings, a copy of the HTML
report, the normalized assessment JSON, and a copy of the raw and normalized
artifact files from the matching `assessment_runs/` entry. Raw API artifacts are
stored below `artifacts/nodes/<node>/api/<interface>/<operation>/` as
`request.txt` and `response.txt`; request artifacts omit reusable credentials.

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

AletheiaUC is currently proprietary software. All rights reserved.

This project is under private development and is not currently licensed for
public use, redistribution, modification, or commercial use by third parties.
