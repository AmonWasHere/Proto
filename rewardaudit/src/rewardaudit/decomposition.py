"""The four-way decomposition: does a verdict *track the fix*, or just match a
construct that was present before and after?

This is the reusable measurement lifted from `sastaudit/artifact/FINDINGS.md`.
Naive "coverage" (the tool flagged the file the commit touched) over-reports by
roughly 9x, because a tool that flags a construct before and after a fix has
detected nothing. The four cells make that visible:

    both        flagged on the vulnerable AND the fixed revision  -> not detection
    vuln_only   flagged only before the fix                        -> a flip (detection)
    fixed_only  flagged only after the fix                         -> noise / regression
    neither     silent on both                                     -> a miss
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum

from .schema import Finding


class Cell(StrEnum):
    BOTH = "both"
    VULN_ONLY = "vuln_only"
    FIXED_ONLY = "fixed_only"
    NEITHER = "neither"


@dataclass(frozen=True, slots=True)
class RevisionPair:
    id: str
    vuln: str
    fixed: str
    category: str = ""
    cwe: str = ""


def classify(flagged_vuln: bool, flagged_fixed: bool) -> Cell:
    if flagged_vuln and flagged_fixed:
        return Cell.BOTH
    if flagged_vuln and not flagged_fixed:
        return Cell.VULN_ONLY
    if not flagged_vuln and flagged_fixed:
        return Cell.FIXED_ONLY
    return Cell.NEITHER


def _flagged(paths: set[str], name: str) -> bool:
    target = name.lstrip("./")
    for path in paths:
        candidate = path.lstrip("./")
        if candidate == target or candidate.endswith("/" + target):
            return True
    return False


@dataclass
class DecompositionReport:
    cells: dict[str, Cell] = field(default_factory=dict)
    categories: dict[str, str] = field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        counter = Counter(self.cells.values())
        return {cell.value: counter.get(cell, 0) for cell in Cell}

    @property
    def total(self) -> int:
        return len(self.cells)

    @property
    def vuln_only(self) -> int:
        return sum(c is Cell.VULN_ONLY for c in self.cells.values())

    @property
    def both(self) -> int:
        return sum(c is Cell.BOTH for c in self.cells.values())

    @property
    def neither(self) -> int:
        return sum(c is Cell.NEITHER for c in self.cells.values())

    @property
    def naive_coverage(self) -> float:
        """"Flagged on the vulnerable revision" — the misleading metric."""
        return (self.vuln_only + self.both) / self.total if self.total else 0.0

    @property
    def flip_rate(self) -> float:
        """Verdict moved with the fix — the strongest observable detection signal."""
        return self.vuln_only / self.total if self.total else 0.0

    @property
    def over_report_factor(self) -> float:
        """How many times naive coverage overstates the flip signal."""
        return self.naive_coverage / self.flip_rate if self.flip_rate else float("inf")


def decompose(pairs: list[RevisionPair], findings: list[Finding]) -> DecompositionReport:
    paths = {f.location.path for f in findings}
    report = DecompositionReport()
    for pair in pairs:
        report.cells[pair.id] = classify(_flagged(paths, pair.vuln), _flagged(paths, pair.fixed))
        report.categories[pair.id] = pair.category
    return report


def by_category(report: DecompositionReport) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for pair_id, cell in report.cells.items():
        cat = report.categories.get(pair_id, "")
        out.setdefault(cat, Counter())
        out[cat][cell.value] += 1
    return {cat: dict(counts) for cat, counts in out.items()}
