"""Inventory/runtime reconciliation helpers."""

from __future__ import annotations

from dataclasses import dataclass

from cisco_collab_health.models.facts import DeviceInventoryFact, DeviceRegistrationFact


@dataclass(frozen=True)
class InventoryRuntimeReconciliation:
    """Name-based reconciliation between configured inventory and runtime registrations."""

    inventory_count: int
    runtime_count: int
    matched_names: list[str]
    inventory_only: list[DeviceInventoryFact]
    runtime_only: list[DeviceRegistrationFact]


def build_inventory_runtime_reconciliation(
    devices: list[DeviceInventoryFact],
    registrations: list[DeviceRegistrationFact],
) -> InventoryRuntimeReconciliation:
    """Build an initial name-based reconciliation between inventory and runtime facts."""

    registration_names = {_normalize_name(registration.name) for registration in registrations}
    device_names = {_normalize_name(device.name) for device in devices}
    matched_names = sorted(device_names & registration_names)

    return InventoryRuntimeReconciliation(
        inventory_count=len(devices),
        runtime_count=len(registrations),
        matched_names=matched_names,
        inventory_only=[
            device for device in devices if _normalize_name(device.name) not in registration_names
        ],
        runtime_only=[
            registration
            for registration in registrations
            if _normalize_name(registration.name) not in device_names
        ],
    )


def _normalize_name(name: str) -> str:
    return name.strip().lower()
