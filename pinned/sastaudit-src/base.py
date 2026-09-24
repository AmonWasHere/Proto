"""A tool-agnostic interface to SAST scanners.

The study's first phase measured one tool. That is the weakest form of the
claim, because every number in it is a fact about Semgrep 1.177.0 with one
pinned ruleset, and a reader is entitled to ask whether the 93x gap between
benchmark and reality belongs to *the tool* or to *this tool*.

Answering that needs the same measurement across tools with independent
lineage. This module is the seam that makes that possible: every scanner is
reduced to `scan(root) -> [RawFinding]`, and everything downstream -- the
four-way decomposition, the line attribution, the control matrix -- is written
once against that.

What is deliberately NOT abstracted
-----------------------------------
The interface is small on purpose. It does not try to normalise *rules* or
*severities* across tools, because those do not mean the same thing across
tools and pretending otherwise would manufacture comparability that does not
exist. A finding is: a file, a line, the tool's own rule id, and whatever CWE
claims the tool makes. That is the entire common ground, and it is enough for
both of the measurements this study performs:

  * on the real corpus, only (file, line) matters -- did the tool's verdict
    change when the vulnerability was fixed;
  * on the OWASP corpus, (case, CWE) matters, because the published metric
    grades an exact CWE match -- and there the tool's *own* CWE claim is used,
    never one we assign on its behalf.

The one place a hand-written mapping is unavoidable is PMD, which reports no
CWE at all; that map is declared explicitly and pinned, never silent. See
tools/pmd.py.
"""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

CWE_TAG = "external/cwe/cwe-"


class ToolError(RuntimeError):
    """A scanner failed in a way that must not be silently read as 'no findings'."""


@dataclass(frozen=True, slots=True)
class RawFinding:
    """One finding, in the smallest vocabulary every scanner shares."""

    path: str
    """File the finding is in, relative to the scanned root, using / separators."""

    line: int
    """1-based start line, or -1 when the tool reported no position."""

    rule: str
    """The tool's own rule/query identifier. Never translated."""

    cwes: tuple[str, ...] = ()
    """CWE ids the tool itself claims, normalised to "CWE-79" form.

    Empty when the tool makes no claim. Emptiness is preserved rather than
    filled in, so a downstream count of "tool-claimed CWEs" stays honest.
    """

    message: str = ""


@dataclass
class ScanOutcome:
    """What one scanner produced, plus whether the run is trustworthy."""

    findings: list[RawFinding] = field(default_factory=list)
    returncode: int = 0
    stderr: str = ""
    seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def normalise_cwe(text: str) -> str | None:
    """Turn any of the spellings tools use into "CWE-79", or None.

    Accepts "CWE-79", "cwe-79", "79", "external/cwe/cwe-079". The zero-padded
    CodeQL tag is the reason this exists: `external/cwe/cwe-089` and `CWE-89`
    are the same claim, and comparing them as strings would silently drop every
    CodeQL finding.
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


def relpath(path: str | Path, root: Path) -> str | None:
    """Path relative to the scanned root, or None if it escapes it.

    Every adapter routes paths through this so the vuln/ vs fixed/ split in the
    real-corpus harness cannot be fooled by a relative/absolute mismatch, and
    so a finding from outside the tree is dropped rather than misfiled.
    """
    try:
        rel = Path(path).resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return None
    return rel.as_posix()


class Tool(ABC):
    """A SAST scanner, reduced to the one operation the study needs."""

    name: str = "tool"
    """Short stable identifier, used in result filenames and tables."""

    @abstractmethod
    def version(self) -> str:
        """The scanner's own version string, recorded in every result file."""

    @abstractmethod
    def scan(self, root: Path) -> ScanOutcome:
        """Analyse every file under `root` and return normalised findings.

        Implementations must raise ToolError rather than return an empty list
        when the scanner failed. A crash and a clean scan are the same shape of
        return value and completely different facts, and conflating them is the
        failure mode this whole study is about.
        """

    def available(self) -> bool:
        """Whether the scanner's binary is present. Checked before a run."""
        return True


def require_binary(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise ToolError(f"{name} is not on PATH")
    return path


def parse_cwe_tags(tags: list[str]) -> tuple[str, ...]:
    """Extract CWE claims from a SARIF-style tag list.

    This is the CodeQL convention: a query tagged `external/cwe/cwe-089` is
    claiming CWE-89. Semgrep instead puts CWEs in `metadata.cwe` and is handled
    in its own adapter; both end up in the same normalised form.
    """
    out: list[str] = []
    for tag in tags:
        low = tag.lower()
        if CWE_TAG in low:
            norm = normalise_cwe(low.split(CWE_TAG, 1)[1])
            if norm and norm not in out:
                out.append(norm)
    return tuple(out)
