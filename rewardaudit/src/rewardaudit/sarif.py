"""SARIF 2.1.0 -> Finding.

CWE claims are read from the tool's own rule metadata (`properties.tags` using
the CodeQL `external/cwe/cwe-###` convention, or `properties.cwe`) and never
assigned on the tool's behalf.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .schema import Evidence, EvidenceKind, Finding, Location, normalise_cwe

CWE_TAG = "external/cwe/cwe-"


def _finding_id(analyzer: str, rule: str, loc: Location) -> str:
    raw = f"{analyzer}|{rule}|{loc.path}|{loc.start_line}|{loc.start_col}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def _cwes_from_tags(tags: list[str]) -> tuple[str, ...]:
    out: list[str] = []
    for tag in tags or []:
        low = str(tag).lower()
        if CWE_TAG in low:
            norm = normalise_cwe(low.split(CWE_TAG, 1)[1])
        elif low.startswith("cwe-"):
            norm = normalise_cwe(low)
        else:
            norm = None
        if norm and norm not in out:
            out.append(norm)
    return tuple(out)


def _relpath(uri: str, root: Path) -> str | None:
    if uri.startswith("file://"):
        uri = uri[len("file://") :]
    try:
        return Path(uri).resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return Path(uri).as_posix()


def findings_from_sarif(
    sarif: dict, *, root: Path, analyzer: str = "sarif"
) -> list[Finding]:
    """Parse SARIF 2.1.0 into findings."""
    out: list[Finding] = []
    for run in sarif.get("runs", []):
        rules_by_id: dict[str, dict] = {}
        for rule in (run.get("tool", {}).get("driver", {}) or {}).get("rules", []) or []:
            rid = rule.get("id")
            if rid:
                rules_by_id[rid] = rule

        for result in run.get("results", []) or []:
            rule_id = result.get("ruleId") or result.get("rule", {}).get("id") or "?"
            rule = rules_by_id.get(rule_id, {})
            props = rule.get("properties", {}) or {}
            cwes = list(_cwes_from_tags(props.get("tags", []) or []))
            if props.get("cwe"):
                raw = props["cwe"]
                values = [raw] if isinstance(raw, str) else list(raw)
                for value in values:
                    norm = normalise_cwe(str(value))
                    if norm and norm not in cwes:
                        cwes.append(norm)

            message = (
                result.get("message", {}).get("text", "")
                or (result.get("message", {}).get("markdown", "") or "")
            )[:300]

            for loc in result.get("locations", []) or []:
                phys = loc.get("physicalLocation", {}) or {}
                artifact = (phys.get("artifactLocation", {}) or {}).get("uri", "")
                region = phys.get("region", {}) or {}
                path = _relpath(artifact, root)
                if path is None:
                    continue
                location = Location(
                    path=path,
                    start_line=int(region.get("startLine", -1)),
                    end_line=int(region.get("endLine", region.get("startLine", -1))),
                    start_col=int(region.get("startColumn", 0)),
                    end_col=int(region.get("endColumn", 0)),
                )
                out.append(
                    Finding(
                        id=_finding_id(analyzer, rule_id, location),
                        analyzer=analyzer,
                        rule=rule_id,
                        message=message,
                        location=location,
                        cwes=tuple(cwes),
                        evidence=(
                            Evidence(
                                kind=EvidenceKind.TOOL_FINDING,
                                source=analyzer,
                                summary=message or rule_id,
                                ref=location.ref(),
                            ),
                        ),
                    )
                )
    return out


def load_sarif(path: str | Path, *, root: Path, analyzer: str = "sarif") -> list[Finding]:
    return findings_from_sarif(json.loads(Path(path).read_text()), root=root, analyzer=analyzer)
