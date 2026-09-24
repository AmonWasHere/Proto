"""Load RewardAudit's own small labelled datasets."""

from __future__ import annotations

import json
from pathlib import Path

from .decomposition import RevisionPair


def load_pairs(manifest_path: str | Path) -> list[RevisionPair]:
    data = json.loads(Path(manifest_path).read_text())
    return [
        RevisionPair(
            id=p["id"],
            vuln=p["vuln"],
            fixed=p["fixed"],
            category=p.get("category", ""),
            cwe=p.get("cwe", ""),
            line=int(p.get("line", 1) or 1),
            message=p.get("message", ""),
        )
        for p in data["pairs"]
    ]


def load_canaries(manifest_path: str | Path) -> list[dict]:
    return json.loads(Path(manifest_path).read_text())["canaries"]


def _hit(paths: set[str], name: str) -> bool:
    target = name.lstrip("./")
    return any(p.lstrip("./") == target or p.lstrip("./").endswith("/" + target) for p in paths)


def canary_report(canaries: list[dict], findings) -> dict:
    paths = {f.location.path for f in findings}
    rows = [
        {"file": c["file"], "reason": c.get("reason", ""), "flagged": _hit(paths, c["file"])}
        for c in canaries
    ]
    return {
        "rows": rows,
        "flagged": sum(r["flagged"] for r in rows),
        "total": len(rows),
    }
