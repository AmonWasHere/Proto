"""A pinned, dated snapshot of public advisories (OSV JSON Lines).

Snapshots are immutable: refreshing produces a *new* dated file, so any run can
name the exact snapshot it used and freshness can be measured as a variable
(ADR-0003).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .advisory import Advisory


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class Snapshot:
    path: Path
    advisories: tuple[Advisory, ...]
    sha256: str
    date: str = ""

    @classmethod
    def load(cls, path: str | Path) -> "Snapshot":
        path = Path(path)
        advisories: list[Advisory] = []
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            advisories.append(Advisory.from_osv(json.loads(line)))
        meta_path = path.with_suffix(path.suffix + ".meta.json")
        date = ""
        if meta_path.is_file():
            date = json.loads(meta_path.read_text()).get("date", "")
        return cls(path=path, advisories=tuple(advisories), sha256=_sha256(path), date=date)

    def match(self, ecosystem: str, package: str, version: str) -> list[Advisory]:
        return [a for a in self.advisories if a.affects(ecosystem, package, version)]

    def __len__(self) -> int:
        return len(self.advisories)
