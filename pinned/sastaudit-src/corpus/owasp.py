"""Loaders for OWASP Benchmark corpora and published scorecards.

Two file formats matter, both shipped in the upstream repos:

1. `expectedresults-1.2.csv` (BenchmarkJava) — the ground truth.
       # test name, category, real vulnerability, cwe, Benchmark version: 1.2, ...
       BenchmarkTest00001,pathtraver,true,22

2. `Benchmark_v1.2_Scorecard_for_<Tool>.csv` (BenchmarkJava/scorecard) — the
   per-case outcomes BenchmarkUtils produced for a given tool. These are gold:
   they let the scorer be validated end-to-end without running any tool.
       # test name, category, CWE, real vulnerability, identified by tool, pass/fail, ...
       BenchmarkTest00001, crypto, 327, true, false, fail

Note the two files disagree on column order (cwe `<->` real-vulnerability are
swapped) and the scorecard pads values with spaces. Both are parsed by header
position where possible, but the headers themselves are commented out, so we
rely on the known positional layouts and assert on the arity.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .case import Case, parse_case_number


class CorpusFormatError(ValueError):
    """Raised when an upstream file does not match the layout we expect."""


def _rows(path: Path) -> list[list[str]]:
    """Yield stripped, non-comment, non-empty rows from a Benchmark CSV."""
    out: list[list[str]] = []
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.reader(fh):
            if not row or not any(c.strip() for c in row):
                continue
            if row[0].lstrip().startswith("#"):
                continue
            out.append([c.strip() for c in row])
    return out


def load_expected_results(path: str | Path) -> dict[int, Case]:
    """Parse `expectedresults-<version>.csv` into {case_number: Case}.

    Columns: test name, category, real vulnerability, cwe
    """
    path = Path(path)
    cases: dict[int, Case] = {}
    for row in _rows(path):
        if len(row) < 4:
            raise CorpusFormatError(f"{path}: expected >=4 columns, got {len(row)}: {row!r}")
        name, category, real_vuln, cwe = row[0], row[1], row[2], row[3]
        number = parse_case_number(name)
        if number < 0:
            raise CorpusFormatError(f"{path}: unparseable test name {name!r}")
        is_real = real_vuln.lower() == "true"
        try:
            cwe_int = int(cwe)
        except ValueError as exc:
            raise CorpusFormatError(f"{path}: non-integer CWE {cwe!r} for {name}") from exc
        if number in cases:
            raise CorpusFormatError(f"{path}: duplicate case number {number}")
        cases[number] = Case(
            name=name, number=number, category=category,
            is_real_vuln=is_real, cwe=cwe_int,
        )
    if not cases:
        raise CorpusFormatError(f"{path}: no cases parsed")
    return cases


def load_scorecard(path: str | Path) -> dict[int, bool]:
    """Parse a published scorecard CSV into {case_number: passed}.

    Columns: test name, category, CWE, real vulnerability,
             identified by tool, pass/fail

    `passed` is the Benchmark's own per-case verdict — `TestCaseResult.isPassed()`
    — meaning the tool's answer matched the ground-truth label. We deliberately
    read this column rather than recomputing it from "identified by tool" so that
    the aggregator is validated against upstream's own per-case decisions.
    """
    path = Path(path)
    passed: dict[int, bool] = {}
    for row in _rows(path):
        if len(row) < 6:
            raise CorpusFormatError(f"{path}: expected >=6 columns, got {len(row)}: {row!r}")
        name, verdict = row[0], row[5]
        number = parse_case_number(name)
        if number < 0:
            raise CorpusFormatError(f"{path}: unparseable test name {name!r}")
        if verdict not in ("pass", "fail"):
            raise CorpusFormatError(f"{path}: bad verdict {verdict!r} for {name}")
        passed[number] = verdict == "pass"
    if not passed:
        raise CorpusFormatError(f"{path}: no rows parsed")
    return passed


def load_scorecard_with_labels(path: str | Path) -> tuple[dict[int, Case], dict[int, bool]]:
    """Convenience: scorecard rows carry their own labels, so return both.

    Used when validating a scorecard that was generated against a different
    Benchmark version than the expected-results file on disk.
    """
    path = Path(path)
    cases: dict[int, Case] = {}
    passed: dict[int, bool] = {}
    for row in _rows(path):
        if len(row) < 6:
            raise CorpusFormatError(f"{path}: expected >=6 columns, got {len(row)}: {row!r}")
        name, category, cwe, real_vuln, _identified, verdict = row[:6]
        number = parse_case_number(name)
        if number < 0:
            raise CorpusFormatError(f"{path}: unparseable test name {name!r}")
        cases[number] = Case(
            name=name, number=number, category=category,
            is_real_vuln=(real_vuln.lower() == "true"), cwe=int(cwe),
        )
        passed[number] = verdict == "pass"
    if not cases:
        raise CorpusFormatError(f"{path}: no rows parsed")
    return cases, passed
