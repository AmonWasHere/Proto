"""P5 — calibration, selective risk, FNR, and cost for the verifier.

The four-way decomposition says *whether* a verdict tracked the fix. This says
how much the verdict's own confidence can be trusted, and what it costs.

Points are per (pair, revision) judgements:

    side="vuln"   the revision is vulnerable   -> "correct" means flagged
    side="fixed"  the fix removed the vuln     -> "correct" means NOT flagged

Abstentions are recorded, not scored: they are a coverage loss, not an error. A
verifier that abstains is honest; one that guesses confidently and wrongly is not.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Point:
    confidence: float
    correct: bool
    side: str
    flagged: bool
    disposition: str


def _bins(points: list[Point], bins: int) -> list[dict]:
    out = []
    for index in range(bins):
        lo, hi = index / bins, (index + 1) / bins
        bucket = [
            p for p in points
            if (lo < p.confidence <= hi) or (index == 0 and p.confidence == 0.0)
        ]
        if bucket:
            out.append(
                {
                    "bin": f"{lo:.1f}-{hi:.1f}",
                    "n": len(bucket),
                    "mean_confidence": sum(p.confidence for p in bucket) / len(bucket),
                    "accuracy": sum(p.correct for p in bucket) / len(bucket),
                }
            )
    return out


def expected_calibration_error(points: list[Point], bins: int = 5) -> float:
    if not points:
        return 0.0
    total = len(points)
    ece = 0.0
    for row in _bins(points, bins):
        ece += (row["n"] / total) * abs(row["mean_confidence"] - row["accuracy"])
    return ece


def selective_risk(points: list[Point], thresholds: tuple[float, ...] = (0.0, 0.5, 0.7, 0.9)) -> list[dict]:
    """Risk–coverage: keep only confident points and see what error rate remains."""
    rows = []
    for threshold in thresholds:
        kept = [p for p in points if p.confidence >= threshold]
        rows.append(
            {
                "threshold": threshold,
                "coverage": len(kept) / len(points) if points else 0.0,
                "n": len(kept),
                "accuracy": sum(p.correct for p in kept) / len(kept) if kept else None,
                "risk": 1 - (sum(p.correct for p in kept) / len(kept)) if kept else None,
            }
        )
    return rows


def analyze(points: list[Point], *, abstained: int, bins: int = 5) -> dict:
    scored = [p for p in points if p.disposition != "unknown_risk"]
    vuln = [p for p in points if p.side == "vuln"]
    fixed = [p for p in points if p.side == "fixed"]

    def rate(numerator: int, denominator: int) -> float:
        return numerator / denominator if denominator else 0.0

    return {
        "n_pairs": len(vuln),
        "scored_points": len(scored),
        "abstentions": abstained,
        "abstention_rate": rate(abstained, len(points)),
        "detection_rate": rate(sum(p.flagged for p in vuln), len(vuln)),
        "false_negative_rate": 1 - rate(sum(p.flagged for p in vuln), len(vuln)),
        "fixed_side_fp_rate": rate(sum(p.flagged for p in fixed), len(fixed)),
        "accuracy": rate(sum(p.correct for p in scored), len(scored)),
        "ece": expected_calibration_error(scored, bins),
        "reliability": _bins(scored, bins),
        "selective_risk": selective_risk(scored),
    }
