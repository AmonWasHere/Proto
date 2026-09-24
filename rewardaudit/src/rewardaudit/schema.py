"""The data contracts everything else is written against.

Deliberately small: a finding is a location plus the analyzer's own claims; a
verdict is a disposition plus whatever it cited. Emptiness is preserved rather
than filled in, so downstream counts stay honest (e.g. "the tool claimed no CWE"
is different from "we assigned it one").
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum


class Disposition(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNKNOWN_RISK = "unknown_risk"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceKind(StrEnum):
    TOOL_FINDING = "tool_finding"
    GRAPH_NODE = "graph_node"
    DATAFLOW = "dataflow"
    REACHABILITY = "reachability"
    RETRIEVAL = "retrieval"
    TEST = "test"
    PROVENANCE = "provenance"


def normalise_cwe(text: str) -> str | None:
    """Turn any spelling a tool uses into "CWE-79", or None.

    Accepts "CWE-79", "cwe-79", "79", "external/cwe/cwe-079".
    """
    digits = ""
    for ch in reversed(text):
        if ch.isdigit():
            digits = ch + digits
        elif digits:
            break
    if not digits:
        return None
    return f"CWE-{int(digits)}"


@dataclass(frozen=True, slots=True)
class Location:
    path: str
    start_line: int
    end_line: int = -1
    start_col: int = 0
    end_col: int = 0

    def ref(self) -> str:
        """The canonical, verifiable reference string: `path:line`."""
        return f"{self.path}:{self.start_line}"


@dataclass(frozen=True, slots=True)
class Evidence:
    kind: EvidenceKind
    source: str
    summary: str
    ref: str | None = None
    payload: tuple[tuple[str, str], ...] = ()

    def get(self, key: str, default: str = "") -> str:
        for k, v in self.payload:
            if k == key:
                return v
        return default


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    analyzer: str
    rule: str
    message: str
    location: Location
    cwes: tuple[str, ...] = ()
    severity: Severity | None = None
    evidence: tuple[Evidence, ...] = ()

    def with_evidence(self, *items: Evidence) -> "Finding":
        return replace(self, evidence=self.evidence + tuple(items))


@dataclass(frozen=True, slots=True)
class Verdict:
    finding_id: str
    verifier: str
    disposition: Disposition
    confidence: float
    cwe: str | None = None
    rationale: str = ""
    evidence_refs: tuple[str, ...] = ()
    abstain: bool = False
    cost_usd: float = 0.0

    @property
    def is_abstention(self) -> bool:
        return self.abstain or self.disposition is Disposition.UNKNOWN_RISK


@dataclass
class ControlCase:
    """One labelled case from the prior study's control set."""

    file: str
    expect: str
    cwe: str
    category: str
    shape: str = ""
    pairs_with: str | None = None

    @property
    def is_vulnerable(self) -> bool:
        return self.expect == "vulnerable"


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    returncode: int = 0
    stderr: str = ""
    seconds: float = 0.0
    analyzer: str = ""
    version: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0
