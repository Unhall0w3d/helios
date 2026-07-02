"""JSON report builder."""

from __future__ import annotations

import json
from dataclasses import asdict

from cisco_collab_health.models.assessment import AssessmentReport


class JsonReportBuilder:
    """Builds a JSON report from an assessment result."""

    def build(self, report: AssessmentReport) -> str:
        return json.dumps(asdict(report), indent=2, sort_keys=True)
