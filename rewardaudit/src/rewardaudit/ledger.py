"""Append-only evidence ledger.

Every finding, verdict, and run manifest is written as one JSON line, so a run is
auditable and reproducible after the fact and a later leak-free evaluation can be
re-derived from disk.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def new_run_id() -> str:
    return uuid.uuid4().hex[:12]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Ledger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def record(self, run_id: str, kind: str, **fields: Any) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"ts": _now(), "run_id": run_id, "kind": kind, **fields})
        with open(self.path, "a") as handle:
            handle.write(line + "\n")

    def entries(self, kind: str | None = None) -> Iterator[dict]:
        if not self.path.is_file():
            return
        with open(self.path) as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if kind is None or record.get("kind") == kind:
                    yield record
