"""Backward-compatible AXL body exports."""

from cisco_collab_health.collectors.axl.bodies import (
    get_ccm_version_body,
    get_device_defaults_body,
    list_device_pool_body,
    list_phone_body,
    list_process_node_body,
)

__all__ = [
    "get_ccm_version_body",
    "get_device_defaults_body",
    "list_device_pool_body",
    "list_phone_body",
    "list_process_node_body",
]
