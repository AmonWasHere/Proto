"""Faithful reimplementation of the OWASP Benchmark scoring algorithm.

This is a deliberate line-by-line port of BenchmarkUtils, pinned at
`beb6ef94ad8828e101598e2e9624374e7219e33c`. It must reproduce upstream numbers
exactly; any deviation is a bug in *this* file, not a finding about upstream.

Source mapping — every function names the Java it mirrors:

  compare()          <- BenchmarkScore.compare            (BenchmarkScore.java:740)
  category_counts()  <- BenchmarkScore.calculateScores    (BenchmarkScore.java:683)
  score_tool()       <- BenchmarkScore.calculateMetrics   (BenchmarkScore.java:606)
                        + CategoryResults ctor             (CategoryResults.java:39)
                        + ToolResults.set{True,False}PositiveRate (ToolResults.java:139,157)

The algorithm, stated plainly:

  1. Per case, `passed` = the tool's verdict matched the ground-truth label,
     where a "verdict" only counts if the reported CWE matches exactly.
  2. Per category, tally TP/FN/TN/FP.
  3. Per category: TPR = TP/(TP+FN), FPR = FP/(FP+TN), precision = TP/(TP+FP),
     score = TPR - FPR  (the Youden index J).
  4. Overall: TPR and FPR are **unweighted means across categories** (macro),
     while precision is **pooled** over all cases (micro). Overall
     score = mean(TPR) - mean(FPR).

Step 4's asymmetry is the load-bearing property: because the mean is unweighted,
a 35-case category contributes as much as a 504-case one. See `corrected.py`.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from ..corpus.case import Case, Finding


@dataclass(slots=True)
class Counts:
    """Mirrors TP_FN_TN_FP_Counts (TP_FN_TN_FP_Counts.java:24)."""

    tp: int = 0
    fn: int = 0
    tn: int = 0
    fp: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fn + self.tn + self.fp


@dataclass(frozen=True, slots=True)
class CategoryResult:
    """Mirrors CategoryResults (CategoryResults.java:20)."""

    category: str
    precision: float
    true_positive_rate: float
    false_positive_rate: float
    fscore: float
    total_test_cases: int
    score: float

    def as_row(self) -> dict[str, object]:
        return {
            "category": self.category,
            "tp_rate": self.true_positive_rate,
            "fp_rate": self.false_positive_rate,
            "precision": self.precision,
            "fscore": self.fscore,
            "total": self.total_test_cases,
            "score": self.score,
        }


@dataclass(frozen=True, slots=True)
class ToolMetrics:
    """Mirrors ToolResults (ToolResults.java:26), including its macro rates."""

    precision: float
    true_positive_rate: float
    false_positive_rate: float
    fscore: float
    score: float
    total_test_cases: int
    tp: int
    fp: int
    fn: int
    tn: int
    categories: dict[str, CategoryResult] = field(default_factory=dict)

    def as_row(self) -> dict[str, object]:
        return {
            "tp_rate": self.true_positive_rate,
            "fp_rate": self.false_positive_rate,
            "precision": self.precision,
            "fscore": self.fscore,
            "score": self.score,
            "total": self.total_test_cases,
        }


# --------------------------------------------------------------------------
# Step 1 — per-case verdict
# --------------------------------------------------------------------------

# Tool-name prefixes that receive the CWE-327/328 leniency.
# BenchmarkScore.java:731 (tool.startsWith("AppScan") || "Vera" || "CodeQL")
_LENIENT_TOOL_PREFIXES = ("AppScan", "Vera", "CodeQL")

# CWE whose cases accept a report of 89 (hibernate SQL injection
# is commonly reported as a generic SQL injection instead of 564).
# BenchmarkScore.java:725
_HIBERNATE_CWE = 564
_HIBERNATE_ACCEPTED = 89

_WEAK_ALGO_EXPECTED = 328
_WEAK_ALGO_ACCEPTED = 327


def compare(case: Case, findings: list[Finding], tool: str) -> bool:
    """Did `tool` correctly classify `case`? Port of BenchmarkScore.compare.

    Semantics, exactly as upstream:

      * No findings for the case  -> passed iff the case is a *fake* vulnerability.
      * Otherwise                 -> passed iff some finding matches the expected
                                     CWE, AND the case is a real vulnerability.

    The second clause is what makes this an exact-CWE-match rule: a tool that
    finds the right *problem* but labels it with a sibling CWE scores zero.
    """
    if not findings:
        # BenchmarkScore.java:743
        return not case.is_real_vuln

    for act in findings:
        actual_cwe = act.cwe
        expected_cwe = case.cwe

        match = actual_cwe == expected_cwe  # BenchmarkScore.java:722

        if not match and expected_cwe == _HIBERNATE_CWE:
            match = actual_cwe == _HIBERNATE_ACCEPTED
        if not match and tool.startswith(_LENIENT_TOOL_PREFIXES):
            if expected_cwe == _WEAK_ALGO_EXPECTED and actual_cwe == _WEAK_ALGO_ACCEPTED:
                match = True

        if match:
            # BenchmarkScore.java:735
            return case.is_real_vuln

    return not case.is_real_vuln  # BenchmarkScore.java:740


# --------------------------------------------------------------------------
# Step 2 — per-category tallies
# --------------------------------------------------------------------------


def category_counts(cases: dict[int, Case], passed: dict[int, bool]) -> dict[str, Counts]:
    """Port of BenchmarkScore.calculateScores (BenchmarkScore.java:683).

    `passed` may be a subset of `cases`; missing entries are treated as
    "no findings", i.e. passed iff the case is a fake vulnerability.
    """
    out: dict[str, Counts] = {}
    for number, case in cases.items():
        c = out.setdefault(case.category, Counts())
        did_pass = passed.get(number, not case.is_real_vuln)

        if case.is_real_vuln and did_pass:
            c.tp += 1
        elif case.is_real_vuln and not did_pass:
            c.fn += 1
        elif not case.is_real_vuln and did_pass:
            c.tn += 1
        else:
            c.fp += 1
    return out


# --------------------------------------------------------------------------
# Step 3 — rates
# --------------------------------------------------------------------------


def _safe_div(num: float, den: float) -> float:
    """Java `(double) num / (double) den` with the NaN -> 0.0 guard upstream applies."""
    if den == 0:
        return 0.0
    return num / den


def _fscore(precision: float, tpr: float) -> float:
    """CategoryResults.java:58 and ToolResults.java:141 — 2PR/(P+R), NaN -> 0.0."""
    if precision + tpr == 0:
        return 0.0
    return 2 * precision * tpr / (precision + tpr)


def category_result(category: str, c: Counts) -> CategoryResult:
    """Port of the CategoryResults constructor (CategoryResults.java:39)."""
    precision = _safe_div(c.tp, c.tp + c.fp)
    tpr = _safe_div(c.tp, c.tp + c.fn)
    fpr = _safe_div(c.fp, c.fp + c.tn)
    return CategoryResult(
        category=category,
        precision=precision,
        true_positive_rate=tpr,
        false_positive_rate=fpr,
        fscore=_fscore(precision, tpr),
        total_test_cases=c.total,
        score=tpr - fpr,  # CategoryResults.java:63 — the Youden index
    )


def score_tool(cases: dict[int, Case], passed: dict[int, bool]) -> ToolMetrics:
    """Port of BenchmarkScore.calculateMetrics (BenchmarkScore.java:606).

    The two lines that matter:

        metrics.setTruePositiveRate(totalTPRate / resultsSize);
        metrics.setFalsePositiveRate(totalFPRate / resultsSize);

    where `totalTPRate`/`totalFPRate` are *sums of per-category rates*. So the
    overall rates are unweighted category means — macro-averaging — even though
    the overall precision on the next line is pooled over all cases.
    """
    counts = category_counts(cases, passed)

    total_fp_rate = 0.0
    total_tp_rate = 0.0
    total = total_tp = total_fp = total_fn = total_tn = 0
    categories: dict[str, CategoryResult] = {}

    for category, c in counts.items():
        precision = _safe_div(c.tp, c.tp + c.fp)
        tpr = _safe_div(c.tp, c.tp + c.fn)
        fpr = _safe_div(c.fp, c.fp + c.tn)

        total_fp_rate += fpr
        total_tp_rate += tpr
        total += c.total
        total_tp += c.tp
        total_fp += c.fp
        total_fn += c.fn
        total_tn += c.tn

        categories[category] = category_result(category, c)

    results_size = len(counts)
    # Pooled (micro) precision, unlike the macro rates below. BenchmarkScore.java:641
    total_precision = _safe_div(total_tp, total_tp + total_fp)

    tpr_overall = total_tp_rate / results_size if results_size else 0.0
    fpr_overall = total_fp_rate / results_size if results_size else 0.0

    return ToolMetrics(
        precision=total_precision,
        true_positive_rate=tpr_overall,
        false_positive_rate=fpr_overall,
        fscore=_fscore(total_precision, tpr_overall),
        score=tpr_overall - fpr_overall,  # ToolResults.java:147
        total_test_cases=total,
        tp=total_tp,
        fp=total_fp,
        fn=total_fn,
        tn=total_tn,
        categories=categories,
    )


def score_from_findings(
    cases: dict[int, Case], run, tool: str | None = None
) -> ToolMetrics:
    """Score a raw ToolRun by applying `compare` per case (full upstream path)."""
    tool_name = tool if tool is not None else run.tool
    by_case = run.by_case()
    passed = {n: compare(c, by_case.get(n, []), tool_name) for n, c in cases.items()}
    return score_tool(cases, passed)
