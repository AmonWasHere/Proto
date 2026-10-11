"""Fetch live advisories from the OSV API into a new dated snapshot.

Snapshots are immutable (ADR-0003): refreshing never edits an existing file, it
writes a new `osv-<date>.jsonl` (+ `.meta.json`) in OSV shape so the existing
`Snapshot` loader and matcher consume it unchanged.

Only *declared* dependencies are queried (targeted, fast, no bulk download):
`name==version` lines from a requirements.txt. `--ecosystem` selects PyPI/npm/etc.
"""

from __future__ import annotations

import json
import urllib.request
from datetime import date
from pathlib import Path

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

#: Fields worth keeping (drops huge `details`-only blobs, keeps what we display).
_KEEP = ("id", "aliases", "summary", "details", "affected", "severity",
         "database_specific", "references", "epss", "kev")


def query(ecosystem: str, name: str, version: str, *, timeout: float = 25.0) -> list[dict]:
    """POST one package/version to OSV and return its vulnerabilities."""
    body = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    req = urllib.request.Request(
        OSV_QUERY_URL,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "User-Agent": "rewardaudit/0.0.1 (advisory refresh)"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode())
    return list(data.get("vulns", []) or [])


def _slim(record: dict) -> dict:
    return {key: record[key] for key in _KEEP if key in record}


def refresh(deps, out_path: str | Path, *, query_fn=None) -> dict:
    """Query each dependency and write a new OSV JSONL snapshot. Returns metadata."""
    query_fn = query_fn or query
    seen: dict[str, dict] = {}
    for dep in deps:
        for record in query_fn(dep.ecosystem, dep.package, dep.version):
            rid = record.get("id")
            if rid and rid not in seen:
                seen[rid] = _slim(record)

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as handle:
        for rid in sorted(seen):
            handle.write(json.dumps(seen[rid]) + "\n")

    meta = {
        "date": date.today().isoformat(),
        "source": "osv.dev /v1/query",
        "packages": len(deps),
        "advisories": len(seen),
    }
    out_path.with_suffix(out_path.suffix + ".meta.json").write_text(json.dumps(meta, indent=2))
    return meta
