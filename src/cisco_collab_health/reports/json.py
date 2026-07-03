"""JSON report builder."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from cisco_collab_health.models.assessment import AssessmentReport


class JsonReportBuilder:
    """Builds a JSON report from an assessment result."""

    def build(self, report: AssessmentReport) -> str:
        return json.dumps(_to_jsonable(asdict(report)), indent=2, sort_keys=True)


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, list | tuple | set):
        return [_to_jsonable(item) for item in value]
    return value
