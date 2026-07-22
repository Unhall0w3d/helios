# Collector safety catalog

All collection is read-only and bounded. CUC UCOS commands run only during
diagnostic capture and are defined in `collectors.cuc_platform.CUC_COMMAND_CATALOG`.
Each command has a stable ID, an explicit timeout, diagnostic-only scope, and a
sensitive-output classification. Output is retained as private diagnostic
evidence after configured redaction.

## Reporting boundary

Reports describe only checks AletheiaUC actually performs and evidence it
actually collects. A configured feature is not described as tested unless its
result was collected as assessment evidence.

The optional CUCM endpoint HTTPS sample is disabled by default. It uses the
already collected RIS runtime snapshot to select a bounded, deterministic sample
across endpoint model, registration node, and active firmware strata. Each probe
performs an unauthenticated HTTPS `GET /` with a configured per-endpoint timeout;
CUCM credentials are never sent to endpoint addresses. An unobserved endpoint is
reported as sample evidence only, not as an endpoint-health, ITL, or TVS failure.

The normal CUC CUPI pass records only bounded inventory counts for mailboxes
and unified-messaging services. Diagnostic capture uses GET only and caps each
reviewed configuration resource at 500 records (or the lower configured AXL
diagnostic record cap). Phone systems, port groups/ports, SIP security profiles,
routing rules, schedules, mailbox stores, message-aging policies and their linked
rule resources, and SMTP configuration normalize only explicit non-secret field
allowlists. Linked rule URLs must be same-server `/vmrest/` paths and every child
GET remains capped at 500 rows. Per-user
external-service accounts, email addresses, credentials, and message content are
not normalized.

CUCM diagnostic AXL permits only `list*`, `get*`, and the fixed
`executeSQLQuery` statements defined in the source catalog. Added discovery
offers hunt pilots/lists, line groups, server-bounded configured CFA,
SIP trunk/profile security, LDAP directories, phone-security profiles, and
MRG/MRGL membership. A successful relationship GET is marked before empty
membership can generate a finding, preventing a failed or unsupported API call
from being interpreted as an empty configuration.

Live CUCM validation showed that wildcard `listLine` can ignore AXL `first` and
return the entire line inventory. That operation is no longer used. Configured
call-forward-all coverage comes from a fixed `select first 500` read-only query.
Nested returned tags with common parents are merged into one request tree so SIP
destinations and line-group members are requested together correctly. A get
response that lacks the expected object is marked unavailable, not empty. A
line-group response containing member UUIDs is recognized as populated even when
AXL omits the directory-number text.

No general SQL input is accepted. Diagnostic CUC collection includes an
experimental, publisher-only Informix catalog. Every entry is restricted to
`unitydirdb`, must begin with `SELECT FIRST`, is capped at 100 rows, has a
30-second timeout, and is rejected if it contains comments, separators, or SQL
mutation/administration keywords. The initial probes cover duplicate directory
extensions, call-handler alternate-contact transfers, and call-handler system
transfer targets. Mailbox-database queries remain deferred because Cisco warns
that complex cross-database message queries can run for extended periods.

CUCM SQL remains limited to fixed Device Defaults and
`first 500` route-pattern, line-group member, SIP trunk destination, and configured
CFA queries;
standard AXL list/get calls are preferred wherever they remain reliably bounded.

| ID | Command | Timeout |
| --- | --- | --- |
| `cuc.show_status` | `show status` | 30s |
| `cuc.show_version_active` | `show version active` | 30s |
| `cuc.show_version_inactive` | `show version inactive` | 30s |
| `cuc.show_hardware` | `show hardware` | 30s |
| `cuc.show_network_cluster` | `show network cluster` | 30s |
| `cuc.show_network_eth0_detail` | `show network eth0 detail` | 30s |
| `cuc.utils_drs_history` | `utils disaster_recovery history backup` (publisher only) | 60s |
| `cuc.utils_diagnose_test` | `utils diagnose test` | 300s |
| `cuc.utils_service_list` | `utils service list` | 120s |
| `cuc.utils_core_active_list` | `utils core active list` | 120s |
| `cuc.show_cluster_status` | `show cuc cluster status` | 30s |

### Experimental CUC Informix validation

| ID | Database and scope | Limit | Timeout |
| --- | --- | --- | --- |
| `cuc.sql.duplicate_extensions` | `unitydirdb`; duplicate `dtmfaccessid` aggregates | 100 | 30s |
| `cuc.sql.alternate_contact_transfers` | `unitydirdb`; call-handler alternate-contact targets | 100 | 30s |
| `cuc.sql.system_transfer_targets` | `unitydirdb`; call-handler system-transfer conversations | 100 | 30s |

Probe completion is reported as validation coverage. Successful rows are
normalized as explicitly experimental configuration. Duplicate extension rows
produce a conservative warning and configured transfer paths produce an
informational policy review. Query/schema errors and timeouts are shown only as
collection limitations and cannot generate those findings. SQL artifacts retain
the exact fixed query and raw output only in the private engineering bundle.

An unsupported command must be omitted by selection logic, not executed and
misreported as a health failure. CUC command behavior is fixture-tested; exact
output and runtime require live validation on supported Unity Connection versions.

Normalized diagnostic failures, unexpected stopped services, active core files,
unhealthy replication state, duplicate IP detection, link-down state, disk usage,
and long uptime produce conservative CUC platform findings. `show status` raises
disk warnings at 90% and critical findings at 95%; uptime beyond 365 days is a
maintenance-planning advisory. Core publisher service policies distinguish
required services from explicitly inactive services, which are reported as
inventory state rather than failures.

`show network cluster` also provides bounded, normalized CUC publisher and
subscriber node facts for the shared cluster-member report table. A prior
`show perf query class Processor|Memory` probe was removed after live CUC output
showed the appliance parses it as an invalid `ProcessorMemory` class; it did not
produce usable assessment data.

## CUCM diagnostic CLI pilot

When a CUCM diagnostic assessment has already discovered cluster nodes through
AXL, the CUCM plugin runs bounded, read-only commands on each discovered node:
`show status`, active/inactive version, NTP status, DRS history/status,
database-replication runtime state, active core files, and service list. The
collector retains raw output and only promotes conservative NTP, DRS,
replication, and core-file conditions into findings. Fresh CUCM artifacts remain
required to validate output variants and thresholds before expanding this pilot.

`show status` additionally supplies CUCM common/logging (`/common`) capacity
for local upgrade-readiness evaluation. Less than 25 GiB free is a critical
condition because it is below Cisco's published pre-upgrade minimum; 25--32
GiB is a warning based on AletheiaUC's conservative planning target. The target
is not presented as a universal Cisco requirement because actual space needs
vary with the release and installed content. Active and inactive partition
utilization is retained as engineering evidence only and is not used as an
upgrade-readiness finding.

For DRS backup history, ISO and U.S.-style dates are considered only on rows
that explicitly report success. AletheiaUC does not infer dates from failed,
ambiguous, or unrecognized localized rows; those remain available only as
private raw evidence. A clearly parsed newest success older than three days is
reported as a recovery-readiness warning. An unavailable, incomplete, or
unparseable history is explicitly marked not evaluated rather than being
reported as a missing backup.

CUC first obtains its bounded `show network cluster` listing from the publisher,
then applies its read-only platform catalog to each discovered cluster member.
DRS history is intentionally collected only from the CUC publisher. Its result
uses the same explicit-success/date recognition boundary as CUCM and reports a
stale newest success only when a date is unambiguous.
An unknown SSH host key remains rejected unless the operator explicitly enables
first-use enrollment after out-of-band fingerprint verification.

## IM&P and CER diagnostic scaffolding

IM&P and CER collection is technology-gated and runs only when diagnostic capture
is selected. Both use bounded, read-only UCOS publisher commands: `show status`,
active/inactive version, `show network cluster`, `show network eth0 detail`, NTP
status, service list, active cores, and `utils diagnose test`. Each command has
an explicit timeout and retains raw output privately for later parser validation.

CER also calls only its documented HTTPS read-only authentication-status resource,
`/cerappservices/export/authenticate/status`, with XML acceptance. The initial
implementation records response status as evidence and does not treat an API
response as a service-health determination. IM&P's published interfaces are
client/presence oriented, so this slice intentionally avoids unvalidated API
health queries. No CER or IM&P collector writes configuration or runs state-
changing CLI commands.

When a diagnostic assessment includes both CUCM and IM&P, CUCM's bounded AXL
catalog additionally reads presence redundancy groups, presence groups, and
IM-enabled user/presence-group configuration. These are read-only configuration
facts from the CUCM Publisher; they do not query or alter user presence state.
