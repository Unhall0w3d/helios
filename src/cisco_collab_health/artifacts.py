"""Assessment artifact storage.

Artifacts are local run evidence for parsers, debugging, and future report
traceability. They should not contain reusable credentials.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ArtifactStore:
    """Writes assessment artifacts into a per-run local directory."""

    root: Path
    run_id: str
    profile_name: str

    @classmethod
    def create(
        cls,
        root_dir: str | Path,
        profile_name: str,
        started_at: datetime | None = None,
    ) -> "ArtifactStore":
        run_time = started_at or datetime.now()
        run_id = run_time.strftime("%Y%m%d-%H%M%S")
        root = Path(root_dir).expanduser() / _safe_name(profile_name) / run_id
        root.mkdir(parents=True, exist_ok=True)
        return cls(root=root, run_id=run_id, profile_name=profile_name)

    def write_manifest(self, metadata: dict[str, Any]) -> Path:
        payload = {
            "run_id": self.run_id,
            "profile_name": self.profile_name,
            **metadata,
        }
        return self.write_json("manifest.json", payload)

    def write_json(self, relative_path: str | Path, payload: Any) -> Path:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(_to_jsonable(payload), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return path

    def write_text(self, relative_path: str | Path, content: str) -> Path:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def write_node_json(self, node: str, category: str, filename: str, payload: Any) -> Path:
        return self.write_json(
            Path("nodes") / _safe_name(node) / _category_path(category) / filename,
            payload,
        )

    def write_node_text(self, node: str, category: str, filename: str, content: str) -> Path:
        return self.write_text(
            Path("nodes") / _safe_name(node) / _category_path(category) / filename,
            content,
        )

    def write_api_exchange(
        self,
        node: str,
        interface: str,
        operation: str,
        *,
        request: str,
        response: str,
    ) -> tuple[Path, Path]:
        category = Path("api") / _safe_name(interface) / _safe_name(operation)
        request_path = self.write_node_text(node, str(category), "request.txt", request)
        response_path = self.write_node_text(node, str(category), "response.txt", response)
        return request_path, response_path

    def write_command_output(self, node: str, command: str, output: str) -> Path:
        filename = f"{_safe_name(command)}.txt"
        content = f"$ {command}\n\n{output.rstrip()}\n"
        return self.write_node_text(node, "cli", filename, content)


@dataclass(frozen=True)
class RunLogStore:
    """Writes troubleshooting logs for one Helios run."""

    root: Path
    run_id: str
    profile_name: str

    @classmethod
    def create(
        cls,
        root_dir: str | Path,
        profile_name: str,
        started_at: datetime | None = None,
    ) -> "RunLogStore":
        run_time = started_at or datetime.now()
        run_id = run_time.strftime("%Y%m%d-%H%M%S")
        root = Path(root_dir).expanduser() / run_id
        root.mkdir(parents=True, exist_ok=True)
        return cls(root=root, run_id=run_id, profile_name=profile_name)

    @property
    def run_log_path(self) -> Path:
        return self.root / "run.log"

    def open_run_log(self):
        self.root.mkdir(parents=True, exist_ok=True)
        return self.run_log_path.open("a", encoding="utf-8")

    def write_manifest(self, metadata: dict[str, Any]) -> Path:
        payload = {
            "run_id": self.run_id,
            "profile_name": self.profile_name,
            **metadata,
        }
        return self.write_json("manifest.json", payload)

    def write_json(self, relative_path: str | Path, payload: Any) -> Path:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(_to_jsonable(payload), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return path

    def write_text(self, relative_path: str | Path, content: str) -> Path:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def copy_file(self, source: Path, relative_path: str | Path) -> Path:
        destination = self.root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        return destination


def write_preflight_artifacts(store: ArtifactStore, publisher: str, preflight: Any) -> Path:
    """Write Publisher preflight evidence for parser/debug review."""

    return store.write_node_json(
        publisher,
        "preflight",
        "publisher_preflight.json",
        preflight,
    )


def write_assessment_artifacts(store: ArtifactStore, report: Any) -> list[Path]:
    """Write normalized assessment outputs for parser/report development."""

    paths = [store.write_json("normalized/assessment_report.json", report)]
    for result in report.collector_results:
        collector_name = getattr(result, "collector_name", "unknown_collector")
        paths.append(
            store.write_json(
                Path("normalized") / "collectors" / f"{_safe_name(collector_name)}.json",
                result,
            )
        )

    for node in report.facts.nodes:
        paths.append(
            store.write_node_json(
                node.address,
                "normalized",
                "node_facts.json",
                node,
            )
        )

    return paths


def write_log_bundle(
    store: RunLogStore,
    *,
    report: Any,
    summary_text: str,
    artifact_store: ArtifactStore | None,
    html_report_path: Path | None,
) -> list[Path]:
    """Write troubleshooting files that are easy to share for analysis."""

    paths = [
        store.write_text("executive_summary.txt", summary_text),
        store.write_json("assessment_report.json", report),
        store.write_json("collector_warnings.json", _collector_warnings(report)),
    ]
    if artifact_store is not None:
        paths.append(
            store.write_text(
                "artifact_index.txt",
                "\n".join(_artifact_index(artifact_store.root)) + "\n",
            )
        )
    if html_report_path is not None and html_report_path.exists():
        paths.append(store.copy_file(html_report_path, "report.html"))
    return paths


def _safe_name(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return sanitized.strip("._") or "unknown"


def _collector_warnings(report: Any) -> list[dict[str, Any]]:
    warnings = []
    for result in getattr(report, "collector_results", []):
        collector_name = getattr(result, "collector_name", "unknown_collector")
        for warning in getattr(result, "warnings", []):
            warnings.append({"collector": collector_name, "warning": warning})
    return warnings


def _artifact_index(root: Path) -> list[str]:
    if not root.exists():
        return []
    return [str(path) for path in sorted(root.rglob("*")) if path.is_file()]


def _category_path(value: str) -> Path:
    parts = Path(value).parts
    return Path(*(_safe_name(part) for part in parts if part not in {"", "."}))


def _to_jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return _to_jsonable(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, list | tuple | set):
        return [_to_jsonable(item) for item in value]
    return value
