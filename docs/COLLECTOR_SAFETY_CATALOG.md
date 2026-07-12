# Collector safety catalog

All collection is read-only and bounded. CUC UCOS commands run only during
diagnostic capture and are defined in `collectors.cuc_platform.CUC_COMMAND_CATALOG`.
Each command has a stable ID, an explicit timeout, diagnostic-only scope, and a
sensitive-output classification. Output is retained as private diagnostic
evidence after configured redaction.

| ID | Command | Timeout |
| --- | --- | --- |
| `cuc.show_status` | `show status` | 30s |
| `cuc.show_version_active` | `show version active` | 30s |
| `cuc.show_version_inactive` | `show version inactive` | 30s |
| `cuc.show_hardware` | `show hardware` | 30s |
| `cuc.show_network_cluster` | `show network cluster` | 30s |
| `cuc.show_network_eth0_detail` | `show network eth0 detail` | 30s |
| `cuc.show_perf_processor_memory` | `show perf query class Processor\|Memory` | 30s |
| `cuc.utils_diagnose_test` | `utils diagnose test` | 180s |
| `cuc.utils_service_list` | `utils service list` | 120s |
| `cuc.utils_core_active_list` | `utils core active list` | 120s |
| `cuc.show_cluster_status` | `show cuc cluster status` | 30s |

An unsupported command must be omitted by selection logic, not executed and
misreported as a health failure. CUC command behavior is fixture-tested; exact
output and runtime require live validation on supported Unity Connection versions.
