"""CUCM collector and rule factories, imported only for CUCM targets."""

from __future__ import annotations

from cisco_collab_health.collectors.base import Collector
from cisco_collab_health.interfaces import PreflightResult
from cisco_collab_health.rules.base import HealthRule


class CucmPlugin:
    key = "cucm"

    def collectors(
        self,
        preflight: PreflightResult | None,
        *,
        smoke_test: bool,
        diagnostic_capture: bool,
    ) -> list[Collector]:
        if smoke_test:
            from cisco_collab_health.collectors.sample import SampleCollector

            return [SampleCollector()]
        if preflight is None:
            return []
        collectors: list[Collector] = []
        if "axl" in preflight.transport_available_interfaces:
            from cisco_collab_health.collectors.axl import AxlCollector

            collectors.append(AxlCollector())
        if diagnostic_capture:
            from cisco_collab_health.collectors.diagnostic import DiagnosticCaptureCollector
            from cisco_collab_health.collectors.cucm_platform import CucmPlatformCollector

            collectors.append(DiagnosticCaptureCollector(preflight.transport_available_interfaces))
            collectors.append(CucmPlatformCollector())
        return collectors

    def rules(self) -> list[HealthRule]:
        from cisco_collab_health.rules.basic import (
            CertificateValidityRule,
            CucmPlatformHealthRule,
            CucmServicePolicyRule,
            CucmTopologyCompletenessRule,
            ConfigurationInventorySummaryRule,
            DeviceInventorySummaryRule,
            DeviceLoadRule,
            DeviceLoadSummaryRule,
            FirmwareDownloadRule,
            RegistrationSummaryRule,
            ServiceRuntimeRule,
            ServiceSummaryRule,
            SipTrunkRuntimeRule,
        )

        return [
            CucmPlatformHealthRule(),
            CucmServicePolicyRule(),
            CertificateValidityRule(),
            DeviceLoadRule(),
            DeviceInventorySummaryRule(),
            RegistrationSummaryRule(),
            SipTrunkRuntimeRule(),
            ServiceSummaryRule(),
            ServiceRuntimeRule(),
            DeviceLoadSummaryRule(),
            FirmwareDownloadRule(),
            ConfigurationInventorySummaryRule(),
            CucmTopologyCompletenessRule(),
        ]


def plugin() -> CucmPlugin:
    return CucmPlugin()
