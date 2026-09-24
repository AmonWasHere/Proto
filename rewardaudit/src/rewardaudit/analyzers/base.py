"""Analyzer adapters: a scanner reduced to `scan(root) -> ScanResult`.

A crash and a clean scan are different facts and must not share a return shape,
so adapters raise `AnalyzerError` when the tool fails rather than returning an
empty list.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..schema import ScanResult


class AnalyzerError(RuntimeError):
    """A scanner failed in a way that must not be read as 'no findings'."""


class Analyzer(Protocol):
    name: str

    def version(self) -> str: ...

    def scan(self, root: Path) -> ScanResult: ...

    def available(self) -> bool: ...
