"""Corrected aggregation for OWASP Benchmark results, and the delta decomposition.

`owasp_original.py` reproduces upstream exactly. This module answers the
research question: what changes if the overall rates are computed over cases
rather than over categories?

The defect, restated precisely. Upstream computes, per category i:

    tpr_i = TP_i / (TP_i + FN_i)        fpr_i = FP_i / (FP_i + TN_i)

and then reports the overall rates as unweighted means:

    TPR_macro = (1/N) * sum_i tpr_i     FPR_macro = (1/N) * sum_i fpr_i

with N = number of categories. Every category therefore contributes 1/N of the
overall rate regardless of how many cases it contains. On Benchmark v1.2 the
categories range from 35 cases (xpathi) to 504 (sqli), so the 35-case category
carries ~14x the weight it would carry under a case-weighted average.

The correction is the standard pooled (micro) rate:

    TPR_micro = sum_i TP_i / sum_i (TP_i + FN_i)
    FPR_micro = sum_i FP_i / sum_i (FP_i + TN_i)

`score = TPR - FPR` in both cases; only the aggregation differs. Note that
micro-averaging is identical to weighting each category by its case count, so
the correction is not a change of metric family, only of weighting.

`decompose()` makes the difference exactly attributable. Since
sum_i w_i = 1 for the micro weights,

    TPR_macro - TPR_micro = sum_i (1/N - w_i) * tpr_i

so each category's contribution can be read off individually. That is what
turns "the score moves" into "these specific categories move it, by this much".
"""

from __future__ import annotations

from dataclasses import dataclass

from ..corpus.case import Case
from .owasp_original import (
    CategoryResult,
    Counts,
    ToolMetrics,
    category_counts,
    category_result,
    _fscore,
)


@dataclass(frozen=True, slots=True)
class CategoryContribution:
    """One category's exact contribution to (macro - micro) for a rate."""

    category: str
    n_cases: int
    macro_weight: float
    micro_weight: float
    weight_ratio: float
    rate: float
    contribution: float

    def as_row(self) -> dict[str, object]:
        return {
            "category": self.category,
            "n": self.n_cases,
            "macro_weight": self.macro_weight,
            "micro_weight": self.micro_weight,
            "weight_ratio": self.weight_ratio,
            "rate": self.rate,
            "contribution": self.contribution,
        }


@dataclass(frozen=True, slots=True)
class DeltaReport:
    """The corrected metrics plus an exact attribution of the difference."""

    tool: str
    original: ToolMetrics
    corrected: ToolMetrics
    tpr_contributions: tuple[CategoryContribution, ...]
    fpr_contributions: tuple[CategoryContribution, ...]
    categories: dict[str, CategoryResult]

    @property
    def score_delta(self) -> float:
        """corrected_score - original_score. Positive means upstream understated."""
        return self.corrected.score - self.original.score

    @property
    def tpr_delta(self) -> float:
        return self.corrected.true_positive_rate - self.original.true_positive_rate

    @property
    def fpr_delta(self) -> float:
        return self.corrected.false_positive_rate - self.original.false_positive_rate

    def as_row(self) -> dict[str, object]:
        return {
            "tool": self.tool,
            "cases": self.corrected.total_test_cases,
            "macro_tpr": self.original.true_positive_rate,
            "micro_tpr": self.corrected.true_positive_rate,
            "macro_fpr": self.original.false_positive_rate,
            "micro_fpr": self.corrected.false_positive_rate,
            "published_score": self.original.score,
            "corrected_score": self.corrected.score,
            "score_delta": self.score_delta,
        }


def counts_for(cases: dict[int, Case], passed: dict[int, bool]) -> dict[str, Counts]:
    """Re-exported for callers that want the raw tallies alongside the metrics."""
    return category_counts(cases, passed)


def _micro_metrics(counts: dict[str, Counts], categories: dict[str, CategoryResult]) -> ToolMetrics:
    """Pooled (case-weighted) overall rates, matching upstream's precision treatment."""
    total_tp = sum(c.tp for c in counts.values())
    total_fp = sum(c.fp for c in counts.values())
    total_fn = sum(c.fn for c in counts.values())
    total_tn = sum(c.tn for c in counts.values())
    total = total_tp + total_fp + total_fn + total_tn

    tpr = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 0.0
    fpr = total_fp / (total_fp + total_tn) if (total_fp + total_tn) else 0.0
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0.0

    return ToolMetrics(
        precision=precision,
        true_positive_rate=tpr,
        false_positive_rate=fpr,
        fscore=_fscore(precision, tpr),
        score=tpr - fpr,
        total_test_cases=total,
        tp=total_tp,
        fp=total_fp,
        fn=total_fn,
        tn=total_tn,
        categories=categories,
    )


def _contributions(
    counts: dict[str, Counts],
    categories: dict[str, CategoryResult],
    *,
    positive_field: str,
) -> tuple[CategoryContribution, ...]:
    """Exact per-category attribution of (macro - micro) for one rate.

    positive_field is "tp" for TPR (denominator TP+FN) and "fp" for FPR
    (denominator FP+TN).
    """
    n_categories = len(counts)
    if n_categories == 0:
        return ()

    # Denominator of the micro rate, i.e. the total number of cases that *could*
    # carry this outcome: vulnerable cases for TPR, fake cases for FPR.
    def denominator(c: Counts) -> int:
        return (c.tp + c.fn) if positive_field == "tp" else (c.fp + c.tn)

    grand_total = sum(denominator(c) for c in counts.values())
    if grand_total == 0:
        return ()

    rows: list[CategoryContribution] = []
    for name, c in counts.items():
        rate = (
            categories[name].true_positive_rate
            if positive_field == "tp"
            else categories[name].false_positive_rate
        )
        macro_weight = 1.0 / n_categories
        micro_weight = denominator(c) / grand_total
        rows.append(
            CategoryContribution(
                category=name,
                n_cases=c.total,
                macro_weight=macro_weight,
                micro_weight=micro_weight,
                weight_ratio=(macro_weight / micro_weight) if micro_weight else float("inf"),
                rate=rate,
                contribution=(macro_weight - micro_weight) * rate,
            )
        )
    # Largest absolute effect first.
    rows.sort(key=lambda r: abs(r.contribution), reverse=True)
    return tuple(rows)


def score_tool_corrected(
    cases: dict[int, Case], passed: dict[int, bool], tool: str = ""
) -> DeltaReport:
    """Score with both aggregations and attribute the difference."""
    from .owasp_original import score_tool as _original

    original = _original(cases, passed)
    counts = category_counts(cases, passed)
    categories = {name: category_result(name, c) for name, c in counts.items()}
    corrected = _micro_metrics(counts, categories)

    return DeltaReport(
        tool=tool,
        original=original,
        corrected=corrected,
        tpr_contributions=_contributions(counts, categories, positive_field="tp"),
        fpr_contributions=_contributions(counts, categories, positive_field="fp"),
        categories=categories,
    )
