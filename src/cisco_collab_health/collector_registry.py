"""Collector selection for assessment runs."""

from __future__ import annotations

from cisco_collab_health.collectors.axl import AxlCollector
from cisco_collab_health.collectors.base import Collector
from cisco_collab_health.collectors.diagnostic import DiagnosticCaptureCollector
from cisco_collab_health.collectors.sample import SampleCollector
from cisco_collab_health.collectors.cuc import CucCollector
from cisco_collab_health.interfaces import PreflightResult


def select_collectors(
    preflight: PreflightResult | None,
    *,
    smoke_test: bool = False,
    diagnostic_capture: bool = False,
    product: str = "cucm",
) -> list[Collector]:
    """Select collectors for the current runtime mode and preflight result."""

    if smoke_test:
        return [SampleCollector()]
    if product == "cuc":
        return [CucCollector()]
    if preflight is None:
        return []

    collectors: list[Collector] = []
    if "axl" in preflight.transport_available_interfaces:
        collectors.append(AxlCollector())
    if diagnostic_capture:
        collectors.append(
            DiagnosticCaptureCollector(preflight.transport_available_interfaces)
        )
    return collectors
