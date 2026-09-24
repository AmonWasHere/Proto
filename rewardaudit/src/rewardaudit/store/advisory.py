"""Advisory records in OSV shape, with conservative version matching.

Version matching is famously error-prone. This implementation is deliberately
small and conservative; it is documented as such and is not a claim of complete
coverage of semver/ecosystem semantics.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


def parse_version(value: str) -> tuple[int, ...]:
    """Extract the leading numeric-dotted version, ignoring pre-release suffixes.

    "1.2.3rc1" -> (1, 2, 3); "5.4" -> (5, 4); unparseable -> (). Tuples of
    different length compare component-wise, so (5, 4) < (5, 4, 1).
    """
    match = re.match(r"\s*(\d+(?:\.\d+)*)", str(value))
    if not match:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def _in_range(version: str, introduced: str, fixed: str | None, last_affected: str | None) -> bool:
    v = parse_version(version)
    lo = parse_version(introduced) if introduced else ()
    if lo and v < lo:
        return False
    if fixed is not None:
        return v < parse_version(fixed)
    if last_affected is not None:
        return v <= parse_version(last_affected)
    return True


@dataclass(frozen=True, slots=True)
class Advisory:
    id: str
    aliases: tuple[str, ...] = ()
    summary: str = ""
    ecosystem: str = ""
    package: str = ""
    cwe: str = ""
    cvss: str = ""
    kev: bool = False
    epss: float = 0.0
    references: tuple[str, ...] = ()
    affected: tuple[dict, ...] = field(default_factory=tuple)

    @classmethod
    def from_osv(cls, record: dict) -> "Advisory":
        affected = tuple(record.get("affected", []) or [])
        ecosystem = package = ""
        if affected:
            pkg = affected[0].get("package", {}) or {}
            ecosystem = pkg.get("ecosystem", "")
            package = pkg.get("name", "")
        db_specific = record.get("database_specific", {}) or {}
        cwe_ids = db_specific.get("cwe_ids", []) or record.get("cwe_ids", []) or []
        severity = record.get("severity", []) or []
        cvss = ""
        for entry in severity:
            if isinstance(entry, dict) and "score" in entry:
                cvss = str(entry["score"])
                break
        return cls(
            id=record.get("id", ""),
            aliases=tuple(record.get("aliases", []) or []),
            summary=(record.get("summary") or record.get("details") or "")[:300],
            ecosystem=ecosystem,
            package=package,
            cwe=str(cwe_ids[0]) if cwe_ids else "",
            cvss=cvss,
            kev=bool(db_specific.get("kev", record.get("kev", False))),
            epss=float(record.get("epss", 0.0) or 0.0),
            references=tuple(r.get("url", "") for r in record.get("references", []) or [] if isinstance(r, dict)),
            affected=affected,
        )

    def affects(self, ecosystem: str, package: str, version: str) -> bool:
        for entry in self.affected:
            pkg = entry.get("package", {}) or {}
            if package and pkg.get("name") != package:
                continue
            if ecosystem and pkg.get("ecosystem") and pkg.get("ecosystem") != ecosystem:
                continue
            versions = entry.get("versions") or []
            if versions and version in versions:
                return True
            for rng in entry.get("ranges", []) or []:
                introduced, fixed, last_affected = "", None, None
                for event in rng.get("events", []) or []:
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]
                    if "last_affected" in event:
                        last_affected = event["last_affected"]
                if _in_range(version, introduced, fixed, last_affected):
                    return True
        return False
