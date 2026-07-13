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
- [Security and data handling](docs/SECURITY_AND_DATA_HANDLING.md)
- [Transport trust](docs/TRANSPORT_TRUST.md)
- [Collector safety catalog](docs/COLLECTOR_SAFETY_CATALOG.md)
- [HTML report templates](docs/REPORT_TEMPLATES.md)
- [Technology modularization plan](docs/TECHNOLOGY_MODULARIZATION_PLAN.md)

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
collector evidence, CUC inventory/configuration, CUCM hunt and line topology,
integration/security configuration, media-resource topology, reconciliation,
and findings. Empty, skipped, unavailable,
and not-yet-implemented states are deliberately distinct. Sample-mode data is
synthetic and exists only to exercise the report layout.

## Status

This is not yet a production-ready assessment tool.

Current capabilities:

- Core pipeline contracts
- AXL collector for `getCCMVersion`, `listProcessNode`, opt-in summary `listPhone`, and `listDevicePool` inventory enrichment
- Bounded `executeSQLQuery` collection of configured-model Device Defaults and firmware facts
- Inventory-only summaries by model and device pool
- Diagnostic dial-plan relationships for route-pattern destinations, line-group
  directory numbers, route-list/route-group membership, and CSS partitions
- Diagnostic CUCM hunt, server-bounded configured call-forward-all, SIP trunk
  destinations/profile security, LDAP, phone-security, and media-resource
  configuration with bounded relationship reads
- Diagnostic CUC telephony integration, routing, schedule, mailbox-policy/rules,
  Unified Messaging, and SMTP-security configuration through bounded CUPI GETs
- Per-node UC Certificate Management REST snapshots using OS read credentials
- PEM/X.509 identity and trust parsing with SHA-256 deduplication, validity, key,
  signer, AKI/SKI, and best-available chain metadata
- Separate service-certificate and trust-store expiry policy, including
  `phone-sast-trust` and `phone-vpn-trust` when those optional stores exist;
  stale trust entries are not presented as proof of a service outage
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
- Collapsible detail tables and a customer-deliverable HTML mode that retains
  operational identifiers while omitting private artifact paths
- Responsive horizontal overflow handling for wide report tables

The current production-oriented API implementation is AXL plus the bounded
diagnostic capture path. RISPort70, Control Center, and PerfMon facts are
normalized only when `--diagnostic-capture` is enabled; they are not yet
independent baseline collectors with full policy/threshold coverage. Bounded
CUCM and CUC diagnostic CLI platform collection is available when diagnostic
capture is enabled; output variants and additional policy thresholds continue to
be validated against fresh customer-approved evidence.

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

Create a cross-platform development/test environment from a checkout:

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

`requirements.txt` explicitly contains the runtime dependencies and local build/
quality tools needed for a Windows or Linux test virtual environment. It does
not install the local checkout. `pyproject.toml` remains authoritative for
package metadata; use `python -m pip install .` for a non-editable package
installation or `python -m pip install -e .` for editable console commands.

If you install the package, the module and console-script entry points are also
available:

```bash
python -m cisco_collab_health --help
aletheiauc --help
ccha --help
```

Main menu options:

- Run an assessment by selecting one or more clusters
- Manage saved assessment sets
- Manage connection profiles
- Test/framework options
- Quit

When a health assessment runs, AletheiaUC prints an Executive Summary in the
terminal, writes a styled HTML report under `reports/`, and writes local
parser/debug artifacts under `assessment_runs/` by default. It also writes a
shareable troubleshooting log bundle under `logs/`.

Connection profiles are the single source of truth for cluster addresses,
usernames, and encrypted credentials. A saved assessment set only references
one or more connection profiles; it never duplicates credentials.

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

API request/response artifacts redact authentication headers and password-,
secret-, token-, and API-key-like values in XML, JSON, and key/value text by
default. To choose a different local artifact redaction mode:

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
`aletheiauc-review-<profile>-<run-id>.zip`. The archive contains the matching
`logs/<run-id>/` bundle: report HTML, normalized assessment JSON, collector
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
  patterns, hunt pilots/lists, line groups,
  LDAP directories, SIP/device security profiles, and media resources. Every list
  operation uses the configured per-operation cap; a CUCM response that ignores
  the page size is retained and explicitly marked server-unbounded. Broad
  `listLine` is deliberately excluded because live CUCM ignored its page bound.
- Up to 500 bounded AXL `get` reads to recover route-list, route-group, CSS, SIP
  trunk destination/security, hunt-list/line-group, and MRG/MRGL relationships
  that CUCM may omit from list responses. Shared nested returned tags are emitted
  as one AXL tree, and an empty-membership finding requires the expected object
  to be present in the successful response.
- One `first 500` read-only SQL relationship query for route-pattern destinations
  and ordered route-group membership, keyed back to the AXL list UUID
- `first 500` read-only SQL relationship queries for line-group directory-number
  membership and SIP trunk destination addresses when CUCM returns only UUIDs or
  ports through standard AXL relationship reads
- One `first 500` read-only SQL query for lines with a configured call-forward-all
  destination; this replaces the CUCM-unbounded wildcard `listLine` request
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

To generate an HTML report intended for controlled sharing with the assessed
customer, retain operational identifiers and configuration while omitting private
artifact paths:

```bash
./aletheiauc.py --customer-safe-report
```

## HTML Report Templates

HTML reports use the `aletheiauc` template by default. It draws on the project
palette—midnight, violet, blue, cyan, and horizon gold—to create a beacon-like
engineering brief without embedding or reproducing the repository artwork. The
same visual system is used by both the full engineering report and the customer
deliverable. The customer edition retains target names, hostnames, IP addresses,
devices, dial-plan values, and configuration so customer engineers can interpret
the assessment.

The template is selected with `--html-template aletheiauc`. Template selection
is intentionally explicit in the report builder and CLI so customer or partner
templates can be added without changing collection or report facts.

`comsource` is an optional customer-facing template. It uses the supplied
ComSource logo and purple/cyan print-friendly visual system, with no AletheiaUC
name, marks, capability row, or attribution in its rendered output. It retains
the same report facts and customer-deliverable data policy:

```bash
./aletheiauc.py --html-template comsource --customer-safe-report
```

Both templates embed their assets in the generated HTML, so reports have no
remote font, script, image, analytics, or CDN dependency.

When `--export-review-zip` is used, the troubleshooting bundle includes both
`report.html` and `customer_safe_report.html`. The latter applies the
customer-deliverable policy with the selected template and is included for review;
the ZIP itself remains private diagnostic material because it can also contain
raw evidence and engineering artifacts.

To establish a bounded Cisco Unity Connection CUPI baseline with a dedicated
CUC profile:

```bash
./aletheiauc.py --product cuc --profile MyCucProfile --diagnostic-capture
```

The baseline CUC collector requests one row each from `/vmrest/users` and
`/vmrest/externalservices`, records aggregate totals and raw exchanges, and does
not normalize mailbox identities. Diagnostic capture adds one-row count probes
for contacts, distribution lists, call handlers, classes of service, and system
configuration values. It also performs bounded, read-only CUPI GETs for phone
systems, port groups/ports, SIP security profiles, routing rules, schedules,
mailbox stores, message-aging policies and their linked rule resources, and SMTP
configuration. Child rule GETs are same-server, policy-discovered, and bounded.
Only an explicit
allowlist of non-secret configuration fields is normalized; credentials, mailbox
identities, addresses, and message content are excluded. Unsupported
version-specific resources are reported as collection warnings. Inventory tables
show normalized-record coverage and explicitly label resources whose totals exceed
the bounded capture. Mailbox-store
collection uses Cisco's documented `/vmrest/mailboxstores` path and retries the
legacy `/vmrest/voicemailboxstores` alias only after a 404. Repeated schedule
names are aggregated in the report detail table while raw records remain intact.

The same diagnostic mode runs the following read-only Unity Connection UCOS SSH
commands when the platform account and `paramiko` dependency are available:
`show status`, `show version active`, `show version inactive`, `show hardware`,
`show network cluster`, `show network eth0 detail`,
`utils diagnose test`, `utils service list`, `utils core active list`, and
`show cuc cluster status`.
Each output is retained as a command artifact for offline review. The shared UCOS SSH layer uses a PTY-backed interactive shell
and waits for the `admin:` prompt after each command; it is intended for CUCM,
CUC, IM&P, and CER collectors. SSH host keys must already be trusted by the
local system. On first connection to an assessment target, the collector stores
the presented key in the user's `~/.ssh/known_hosts`; subsequent connections
verify that saved key and fail if it changes.
CUCM remains the default product. CUC Platform credentials are stored through
the existing encrypted OS/SSH credential path for upcoming CLI collection.

### Technology-scoped loading

Implemented CUCM and CUC technology plugins load their collectors and rules
only when the selected assessment includes that technology. Shared transport,
normalized facts, artifacts, and the HTML report shell remain common. This keeps
CUCM SOAP/API code out of CUC-only runs and CUC CLI code out of CUCM-only runs.
The staged migration and future report-section ownership are documented in
[Technology Modularization Plan](docs/TECHNOLOGY_MODULARIZATION_PLAN.md).

During CUCM diagnostic capture, the technology plugin also performs bounded
per-node UCOS CLI collection after AXL node discovery. It captures NTP, DRS,
database replication, status, version, core-file, and service evidence for
offline review and conservative priority findings.

During CUC diagnostic capture, AletheiaUC first uses `show network cluster` on
the publisher, then applies its bounded, read-only platform catalog to each
discovered member. Newly discovered SSH hosts remain rejected by default; use
the explicit first-use enrollment choice only after verifying their fingerprints
out of band.

Multi-technology migration has started with an assessment-profile model. An
assessment profile groups named targets such as `call-control` and `voicemail`;
each target references its own connection profile and therefore its own GUI/API
and Platform/SSH credentials. Group files contain no passwords. Existing
single-target commands remain supported alongside combined orchestration and
consolidated reporting.

To re-capture only the CUC section of a shared legacy profile, use:

```powershell
.\aletheiauc.py --profile YorktownCSD --product cuc --reset-technology cuc `
  --diagnostic-capture --export-review-zip
```

This preserves the CUCM section and re-prompts for the CUC address, GUI/API
credentials, and Platform/SSH credentials.

Combined runs validate target addresses before collection. If CUCM, CUC, IMP,
CER, or another technology resolves to the same address as another target, the
run stops with the target IDs that must be corrected. A 401 does not trigger an
unsolicited credential prompt; credentials are changed through the explicit
technology reset flow.

Create or replace a combined assessment profile and run it:

```bash
./aletheiauc.py --assessment-profile District \
  --assessment-target call-control:cucm:YorktownCSD \
  --assessment-target voicemail:cuc:YorktownCUC \
  --diagnostic-capture --export-review-zip
```

Later runs can reuse the saved composition without repeating targets:

```bash
./aletheiauc.py --assessment-profile District --diagnostic-capture --export-review-zip
```

Targets execute with isolated credentials, discovery state, and artifact
namespaces. Their facts, evidence, findings, and coverage are rendered into one
HTML/JSON assessment and one review ZIP. A failure on one target is recorded
without preventing other target pipelines from completing.

Running `./aletheiauc.py` with no arguments opens the assessment workflow. It can:

- Show every saved cluster as `<technology> <Publisher IP> <profile name>` and
  let you select one cluster for a single-cluster assessment or any number of
  clusters for a consolidated assessment
- Save an ad-hoc selection as a reusable assessment set
- Create, run, edit cluster membership for, or delete saved assessment sets
- Create a connection profile and prompt once for its address, GUI/API
  credentials, and Platform/SSH credentials
- Combine diagnostic capture and Downloads-folder review ZIP export into one
  recommended menu choice
- Configure the same report, artifact, log, diagnostic, inventory, port, and TLS
  settings available as command-line options before starting an assessment

The **Manage connection profiles** menu lets you select a profile and view its
non-secret address and username details, edit the full connection details for
CUCM, CUC, CER, or IM&P (including replacement passwords), or delete it. Editing one
technology preserves the other technology section of a shared profile.
Passwords are never displayed. Deleting a profile also removes saved combined
assessments that reference it, after explicit `DELETE` confirmation.

CER and IM&P connection profiles can be stored now so that the profile model is
ready for multi-cluster environments. Their assessment collectors are not yet
implemented; selecting either in an assessment gives a clear availability error
instead of producing an empty or misleading report.

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

For an existing named profile, `--reset-technology cuc` re-prompts only for
that technology's full connection details. The interactive equivalent is
**Manage connection profiles → Edit connection details**.

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
    <unique-run-id>/
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
facts. Run IDs include microseconds and receive a numeric suffix on collision,
so an existing run directory is never reused. SSH collectors write redacted raw
command output here before parsing.

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
  <unique-run-id>/
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
