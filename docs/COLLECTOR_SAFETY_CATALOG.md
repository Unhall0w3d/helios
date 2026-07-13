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

The normal CUC CUPI pass records only bounded inventory counts for mailboxes
and unified-messaging services. It does not retrieve per-user external-service
account details, email addresses, or stored credentials.

| ID | Command | Timeout |
| --- | --- | --- |
| `cuc.show_status` | `show status` | 30s |
| `cuc.show_version_active` | `show version active` | 30s |
| `cuc.show_version_inactive` | `show version inactive` | 30s |
| `cuc.show_hardware` | `show hardware` | 30s |
| `cuc.show_network_cluster` | `show network cluster` | 30s |
| `cuc.show_network_eth0_detail` | `show network eth0 detail` | 30s |
| `cuc.utils_diagnose_test` | `utils diagnose test` | 180s |
| `cuc.utils_service_list` | `utils service list` | 120s |
| `cuc.utils_core_active_list` | `utils core active list` | 120s |
| `cuc.show_cluster_status` | `show cuc cluster status` | 30s |

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

CUC first obtains its bounded `show network cluster` listing from the publisher,
then applies its read-only platform catalog to each discovered cluster member.
An unknown SSH host key remains rejected unless the operator explicitly enables
first-use enrollment after out-of-band fingerprint verification.
