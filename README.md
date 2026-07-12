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

## Report-Integrated Development Workflow

AletheiaUC develops reporting alongside data collection and parsing. When adding
a collector operation, the feature is not considered complete until raw evidence
is captured, data is parsed into normalized facts, relevant rules are evaluated,
and the HTML/JSON reports visibly expose the new data.

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
collector evidence, reconciliation, and findings. Empty, skipped, unavailable,
and not-yet-implemented states are deliberately distinct. Sample-mode data is
synthetic and exists only to exercise the report layout.

## Status

This is not yet a production-ready assessment tool.

Current capabilities:

- Core pipeline contracts
- AXL collector for `getCCMVersion`, `listProcessNode`, opt-in summary `listPhone`, and `listDevicePool` inventory enrichment
- Bounded `executeSQLQuery` collection of configured-model Device Defaults and firmware facts
- Inventory-only summaries by model and device pool
- Diagnostic dial-plan relationships for route-pattern destinations, route-list/route-group membership, and CSS partitions
- Per-node UC Certificate Management REST snapshots using OS read credentials
- PEM/X.509 identity and trust parsing with SHA-256 deduplication, validity, key,
  signer, AKI/SKI, and best-available chain metadata
- Active 60-day expiry policy for every returned identity and trust certificate,
  including `phone-sast-trust` and `phone-vpn-trust` when those optional stores exist
- Automatic encrypted-profile upgrade when legacy profiles lack OS/SSH credentials
- Explicit encrypted marker prevents API credentials from being mistaken for Platform/CLI credentials
- AXL schema retry when CUCM reports that the requested AXL version is unsupported
- Publisher preflight and interface reachability checks
- Read-only diagnostic capture with normalized RISPort70 registration, Control Center service-status, and PerfMon counter facts
- Static Phone Load override classification, configured/runtime firmware correlation, runtime firmware distribution, and explicit download-failure reporting
- Reason-aware service summaries by node and service group
- Observed service deployment comparison across nodes without assumed role policy
- Zero-only CPU suppression so invalid snapshots are reported as unavailable
- Conservative summary rules for collected inventory, runtime registration, service, configuration, and device-load facts
- Terminal Executive Summary output
- Styled HTML report builder
- JSON output for development and automation
- Raw evidence capture, normalized artifacts, and per-attempt API accounting
- Collapsible detail tables and an identifier-masked customer-safe HTML mode
- Responsive horizontal overflow handling for wide report tables

The current production-oriented API implementation is AXL plus the bounded
diagnostic capture path. RISPort70, Control Center, and PerfMon facts are
normalized only when `--diagnostic-capture` is enabled; they are not yet
independent baseline collectors with full policy/threshold coverage. CLI
platform checks remain unimplemented.

Current CUCM 15 validation status: AXL inventory and Device Defaults SQL,
RISPort registration/firmware, Control Center services, PerfMon snapshots,
static Phone Loads, firmware findings, service-state policy, evidence export,
and encrypted Platform credential migration are live-validated. Certificate
Management REST authentication and raw snapshots are also validated. PEM/X.509
normalization, trust-store deduplication, phone trust-store coverage reporting,
and bounded AXL `get` relationship enrichment are implemented and awaiting a
fresh CUCM 15 validation run. After CUCM 15 stabilizes, validation proceeds to
CUCM 14.x, 12.x, and 11.x before expanding to Cisco Unity Connection.

AXL requests start with schema version `14.0`. If CUCM returns an
`Incorrect axl version` response that lists supported versions, AletheiaUC
selects the highest mutually supported schema version, retries with that
version, and caches the winning schema version for later AXL operations during
the same run.

## Quick Start

Install runtime dependencies:

```bash
python -m pip install -r requirements.txt
```

Make the launcher executable:

```bash
chmod +x aletheiauc.py
```

Run AletheiaUC from a cloned repository:

```bash
./aletheiauc.py
```

This launcher is the main user entry point for a cloned repository. It opens the
interactive menu by default and loads the package from `src/` directly, so an
editable package install is optional.

If you install the package, the module and console-script entry points are also
available:

```bash
python -m cisco_collab_health --help
aletheiauc --help
ccha --help
```

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

Run the complete test suite:

```bash
PYTHONPATH=src python -m pytest -q
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

To export the completed self-contained troubleshooting bundle to the current
user's Downloads folder for the test/review/iterate workflow:

```bash
./aletheiauc.py --diagnostic-capture --export-review-zip
```

The generated filename has the form
`aletheiauc-review-<profile>-<timestamp>.zip`. The archive contains the matching
`logs/<timestamp>/` bundle: report HTML, normalized assessment JSON, collector
warnings, manifests, attempt ledger, and copied raw/normalized artifacts.
`--export-review-zip` cannot be combined with `--no-logs`.

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
collection uses bounded `first`/`skip` paging with duplicate-page detection:

```bash
./aletheiauc.py --collect-phone-inventory
```

Tune the inventory page size and maximum device count for lab/debug runs:

```bash
./aletheiauc.py --collect-phone-inventory --phone-inventory-page-size 500 --phone-inventory-max-devices 2000
```

Phone inventory starts with a broad AXL query so user-generated device names are
included. Prefix-based collection may be added later as a fallback for oversized
clusters, but expected Cisco prefixes are not treated as the authoritative
inventory boundary.

When phone inventory is enabled, AletheiaUC runs one bounded, aggregate
`executeSQLQuery` across `device`, `typeproduct`, and `defaults`. It returns
default loads only for models configured in the cluster, plus configured counts,
protocol codes, and `tkmodel`. This is a deliberate API-first exception after
CUCM 15 rejected the available `listDeviceDefaults` criteria. The complete SOAP
request and response are retained when artifact capture is enabled. If no default facts are available, the report
marks load comparison unavailable rather than inferring missing or manual
loads.

The AXL `listPhone` `loadInformation` field is treated as the explicitly
configured Phone Load. Every nonblank value is a static override—even when it
currently equals the model/protocol Device Default—because it remains pinned
across later default changes. Reports distinguish matching, differing, and
default-unavailable overrides, summarize them by model/load, and correlate them
with RISPort active firmware when diagnostic capture supplies runtime data.
Firmware reporting excludes non-firmware runtime objects such as CTI Ports,
identifies mixed active-load populations by model/protocol, separates failed
downloads that remain on the wrong load from failures already showing the
intended load, and provides an exception table with configured, default, active,
status, reason, and node context.
Firmware health output separates active mismatches (warning) from persistent
failure status where the intended load is already active (informational). Mixed
population rows include both runtime and configured counts. Service analysis
treats `Service Not Activated` and `Commanded Out of Service` as intentional
context and warns only on other stopped-state reasons.

## Diagnostic Capture Mode

Use diagnostic capture when a controlled lab run should retain additional
read-only interface evidence for future parser and collector development:

```bash
./aletheiauc.py --diagnostic-capture
```

Diagnostic capture automatically includes the bounded AXL phone inventory and
adds raw request/response evidence for:

- Supported-interface WSDL retrieval on every discovered node
- Per-node `/platformcom/api/v1/certmgr/config/snapshot/server` certificate metadata
- RISPort70 `selectCmDeviceExt` registration snapshot using the AXL device list
  (or a bounded wildcard `selectCmDevice` fallback if AXL inventory is unavailable)
- Control Center `getProductInformationList` and `soapGetServiceStatus` on every discovered node
- PerfMon object/counter discovery plus two samples of `Processor`, `Memory`, and `Cisco CallManager` counters on every discovered node
- Bounded AXL configuration discovery for call-manager groups, regions, locations,
  SIP trunks, route patterns, partitions, CSSes, route groups/lists, translation
  patterns and media resources. Full line inventory is intentionally excluded
  because CUCM may ignore AXL paging limits and return an unbounded response.
- Up to 500 bounded AXL `get` reads to recover route-list, route-group, and CSS
  relationships that CUCM omits from list responses
- One `first 500` read-only SQL relationship query for route-pattern destinations
  and ordered route-group membership, keyed back to the AXL list UUID
- UUID-preserving configuration normalization, including route-filter and dial-plan
  distinctions for otherwise identical route-pattern/partition combinations

All diagnostic calls are read-only. Supported RISPort70, Control Center, and
PerfMon responses are normalized into registration, service-status, and
performance-counter facts and displayed in HTML/JSON. Bounded AXL configuration
discovery is normalized into configuration inventory facts, with bounded
relationship enrichment and raw responses retained for deeper dependency
parsers. Diagnostic facts are snapshots: they support conservative
collection summaries and reconciliation, not full service policy or performance
threshold findings. Unsupported operations and authentication failures are
captured as artifacts and collector warnings.

Diagnostic collection can produce large, customer-sensitive output. Keep the
default bounds unless you are deliberately testing a lab with known capacity:

```bash
./aletheiauc.py --diagnostic-capture \
  --diagnostic-max-devices 2000 \
  --diagnostic-axl-page-size 250 \
  --diagnostic-axl-max-records 500
```

`--diagnostic-max-devices` is limited to the documented RISPort maximum of
2,000. `--diagnostic-axl-max-records` is a per-operation cap; CUCM can return
more than the requested AXL page size, in which case AletheiaUC records an
explicit server-unbounded note and preserves the response. Diagnostic capture
is evidence-oriented and is not a claim of complete configuration inventory.

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

To generate an HTML report intended for controlled sharing, mask node/profile
identifiers and omit detailed device, registration, configuration, and artifact
paths:

```bash
./aletheiauc.py --customer-safe-report
```

To establish a bounded Cisco Unity Connection CUPI baseline with a dedicated
CUC profile:

```bash
./aletheiauc.py --product cuc --profile MyCucProfile --diagnostic-capture
```

The initial CUC collector requests one user row from `/vmrest/users`, records
the aggregate total and raw exchange, and does not collect mailbox identities.
CUCM remains the default product. CUC Platform credentials are stored through
the existing encrypted OS/SSH credential path for upcoming CLI collection.

This option affects HTML presentation only. Raw artifacts, troubleshooting
logs, and normalized JSON remain private diagnostic output and can contain
customer identifiers.

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

When diagnostic capture is enabled, `operation_attempts.jsonl` is also written
at the run root. Each line records one SOAP or HTTP attempt: interface,
operation, endpoint, node, schema/action metadata, timestamps, duration, HTTP
outcome, byte counts, and request/response artifact paths. Retries use separate
artifact directories so an initial error response is never overwritten by a
successful retry.

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

Review ZIP exports contain this same customer-sensitive diagnostic material.
Transfer and retain them accordingly; `--customer-safe-report` changes HTML
presentation only and does not sanitize the exported raw or JSON evidence.

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
