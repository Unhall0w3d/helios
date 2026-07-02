"""Terminal status messages for Helios runs."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import TextIO


COLORS = {
    "INFO": "\033[36m",
    "OK": "\033[32m",
    "WARN": "\033[33m",
    "FAIL": "\033[31m",
    "STAGE": "\033[35m",
}
RESET = "\033[0m"


@dataclass(frozen=True)
class StatusPrinter:
    """Prints concise bracketed status messages without leaking raw command output."""

    stream: TextIO = sys.stderr
    use_color: bool | None = None

    def stage(self, message: str) -> None:
        self.emit("STAGE", message)

    def info(self, message: str) -> None:
        self.emit("INFO", message)

    def ok(self, message: str) -> None:
        self.emit("OK", message)

    def warn(self, message: str) -> None:
        self.emit("WARN", message)

    def fail(self, message: str) -> None:
        self.emit("FAIL", message)

    def emit(self, level: str, message: str) -> None:
        label = f"[{level}]"
        if self._should_color():
            label = f"{COLORS.get(level, '')}{label}{RESET}"
        print(f"{label} {message}", file=self.stream, flush=True)

    def _should_color(self) -> bool:
        if self.use_color is not None:
            return self.use_color
        return self.stream.isatty()
