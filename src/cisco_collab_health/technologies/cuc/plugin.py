"""Unity Connection collector and rule factories, imported only for CUC targets."""

from __future__ import annotations

from cisco_collab_health.collectors.base import Collector
from cisco_collab_health.interfaces import PreflightResult
from cisco_collab_health.rules.base import HealthRule


class CucPlugin:
    key = "cuc"

    def collectors(
        self,
        preflight: PreflightResult | None,
        *,
        smoke_test: bool,
        diagnostic_capture: bool,
    ) -> list[Collector]:
        del preflight
        if smoke_test:
            from cisco_collab_health.collectors.sample import SampleCollector

            return [SampleCollector()]
        from cisco_collab_health.collectors.cuc import CucCollector

        collectors: list[Collector] = [CucCollector(diagnostic_capture=diagnostic_capture)]
        if diagnostic_capture:
            from cisco_collab_health.collectors.cuc_platform import CucPlatformCollector

            collectors.append(CucPlatformCollector())
        return collectors

    def rules(self) -> list[HealthRule]:
        from cisco_collab_health.rules.basic import (
            CucPlatformHealthRule,
            CucPlatformStatusRule,
            CucServicePolicyRule,
            CucSmtpSecurityRule,
        )

        return [
            CucPlatformHealthRule(), CucPlatformStatusRule(), CucServicePolicyRule(),
            CucSmtpSecurityRule(),
        ]


def plugin() -> CucPlugin:
    return CucPlugin()
