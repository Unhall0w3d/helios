"""Collector selection for assessment runs."""

from __future__ import annotations

from cisco_collab_health.collectors.axl import AxlCollector
from cisco_collab_health.collectors.base import Collector
from cisco_collab_health.collectors.sample import SampleCollector
from cisco_collab_health.interfaces import PreflightResult


def select_collectors(
    preflight: PreflightResult | None,
    *,
    smoke_test: bool = False,
) -> list[Collector]:
    """Select collectors for the current runtime mode and preflight result."""

    if smoke_test:
        return [SampleCollector()]
    if preflight is None:
        return []

    collectors: list[Collector] = []
    if "axl" in preflight.available_interfaces:
        collectors.append(AxlCollector())
    return collectors
