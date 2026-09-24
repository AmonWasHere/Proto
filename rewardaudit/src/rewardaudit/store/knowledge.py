"""The hybrid knowledge store: a pinned feed snapshot joined to the active ledger.

- **Public feed** (pinned snapshot): answers "is this dependency affected?".
- **Own findings** (ledger): answers "how has this signal performed?".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..ledger import Ledger, new_run_id
from ..schema import Disposition
from .snapshot import Snapshot


@dataclass(frozen=True, slots=True)
class Dependency:
    package: str
    version: str
    ecosystem: str = "PyPI"


def parse_requirements(text: str, ecosystem: str = "PyPI") -> list[Dependency]:
    """Tiny requirements.txt parser: `name==version` lines only.

    Deliberately minimal — ranged specifiers are not resolved, because doing so
    correctly is a project in itself and the false confidence would be worse than
    the gap.
    """
    deps: list[Dependency] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+]+)", line)
        if match:
            deps.append(Dependency(match.group(1), match.group(2), ecosystem))
    return deps


@dataclass
class SignalStats:
    true_positive: int = 0
    false_positive: int = 0

    @property
    def total(self) -> int:
        return self.true_positive + self.false_positive

    @property
    def precision(self) -> float | None:
        return self.true_positive / self.total if self.total else None


class KnowledgeStore:
    def __init__(self, snapshot: Snapshot | None = None, ledger: Ledger | None = None) -> None:
        self.snapshot = snapshot
        self.ledger = ledger

    # --- public feed side -------------------------------------------------
    def match_dependencies(self, deps: list[Dependency]) -> list[dict]:
        if self.snapshot is None:
            return []
        out = []
        for dep in deps:
            advisories = self.snapshot.match(dep.ecosystem, dep.package, dep.version)
            if advisories:
                out.append({"dependency": dep, "advisories": advisories})
        return out

    @property
    def snapshot_provenance(self) -> dict:
        if self.snapshot is None:
            return {}
        return {
            "path": str(self.snapshot.path),
            "sha256": self.snapshot.sha256,
            "date": self.snapshot.date,
            "advisories": len(self.snapshot),
        }

    # --- own findings side ------------------------------------------------
    def record_outcome(
        self,
        signal: str,
        disposition: Disposition,
        *,
        fingerprint: str = "",
        run_id: str | None = None,
        source: str = "verifier",
    ) -> None:
        if self.ledger is None:
            raise ValueError("record_outcome requires a ledger")
        self.ledger.record(
            run_id or new_run_id(),
            "outcome",
            signal=signal,
            disposition=Disposition(disposition).value,
            fingerprint=fingerprint,
            source=source,
        )

    def signal_stats(self) -> dict[str, SignalStats]:
        stats: dict[str, SignalStats] = {}
        if self.ledger is None:
            return stats
        for record in self.ledger.entries(kind="outcome"):
            signal = record.get("signal", "")
            entry = stats.setdefault(signal, SignalStats())
            if record.get("disposition") == Disposition.TRUE_POSITIVE.value:
                entry.true_positive += 1
            elif record.get("disposition") == Disposition.FALSE_POSITIVE.value:
                entry.false_positive += 1
        return stats

    def precision(self, signal: str) -> float | None:
        return self.signal_stats().get(signal, SignalStats()).precision

    def link(self, finding_fingerprint: str, advisory_id: str, *, run_id: str | None = None) -> None:
        """Record that a finding corresponds to an advisory."""
        if self.ledger is None:
            raise ValueError("link requires a ledger")
        self.ledger.record(
            run_id or new_run_id(),
            "advisory_link",
            fingerprint=finding_fingerprint,
            advisory=advisory_id,
        )

    def advisories_for_finding(self, finding_fingerprint: str) -> list[str]:
        if self.ledger is None:
            return []
        return [
            r.get("advisory", "")
            for r in self.ledger.entries(kind="advisory_link")
            if r.get("fingerprint") == finding_fingerprint
        ]
