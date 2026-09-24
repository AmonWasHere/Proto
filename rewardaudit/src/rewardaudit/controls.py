"""Load the prior study's pinned Java control set and score a scan against it.

The control set is 18 hand-checked vulnerable classes and 3 negative controls
(`sastaudit/controls/manifest.json`). Reproducing its numbers through the new
interface is the M0 exit gate.
"""

from __future__ import annotations

import json
from pathlib import Path

from .schema import ControlCase, Finding


def load_controls(controls_dir: Path) -> list[ControlCase]:
    manifest = json.loads((Path(controls_dir) / "manifest.json").read_text())
    return [
        ControlCase(
            file=c["file"],
            expect=c["expect"],
            cwe=c.get("cwe", ""),
            category=c.get("category", ""),
            shape=c.get("shape", ""),
            pairs_with=c.get("pairs_with"),
        )
        for c in manifest["cases"]
    ]


def _hit(case: ControlCase, findings: list[Finding]) -> list[Finding]:
    suffix = case.file.lstrip("./")
    out = []
    for finding in findings:
        path = finding.location.path.lstrip("./")
        if path == suffix or path.endswith("/" + suffix):
            out.append(finding)
    return out


def control_matrix(cases: list[ControlCase], findings: list[Finding]) -> dict:
    """Per-case detection plus the two headline counts."""
    rows = []
    for case in cases:
        hits = _hit(case, findings)
        rows.append(
            {
                "file": case.file,
                "expect": case.expect,
                "cwe": case.cwe,
                "detected": bool(hits),
                "rules": sorted({h.rule for h in hits}),
            }
        )
    vulnerable = [r for r in rows if r["expect"] == "vulnerable"]
    safe = [r for r in rows if r["expect"] == "safe"]
    return {
        "rows": rows,
        "vulnerable_detected": sum(r["detected"] for r in vulnerable),
        "vulnerable_total": len(vulnerable),
        "safe_flagged": sum(r["detected"] for r in safe),
        "safe_total": len(safe),
        "findings_total": len(findings),
    }
