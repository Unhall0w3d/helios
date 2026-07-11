"""Backward-compatible AXL body exports."""

from cisco_collab_health.collectors.axl.bodies import (
    DEVICE_DEFAULTS_SQL,
    execute_sql_query_body,
    get_ccm_version_body,
    list_device_pool_body,
    list_phone_body,
    list_process_node_body,
)

__all__ = [
    "DEVICE_DEFAULTS_SQL",
    "execute_sql_query_body",
    "get_ccm_version_body",
    "list_device_pool_body",
    "list_phone_body",
    "list_process_node_body",
]
