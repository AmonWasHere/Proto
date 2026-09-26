"""Small statistics used by the evidence runs (E0).

Deliberately dependency-free and explicit. Proportions get Wilson intervals
(better than normal approximation at small n), means get bootstrap intervals, and
paired model comparisons get an exact McNemar test.
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Sequence


def wilson_ci(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion."""
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def bootstrap_ci(
    values: Sequence[float],
    *,
    statistic: Callable[[Sequence[float]], float] | None = None,
    n_resamples: int = 5000,
    z: float = 1.96,
    seed: int = 0,
) -> tuple[float, float]:
    """Percentile bootstrap CI for a statistic of a small sample."""
    values = list(values)
    if not values:
        return (0.0, 0.0)
    if len(values) == 1:
        return (values[0], values[0])
    stat = statistic or (lambda sample: sum(sample) / len(sample))
    rng = random.Random(seed)
    draws = []
    for _ in range(n_resamples):
        sample = [rng.choice(values) for _ in values]
        draws.append(stat(sample))
    draws.sort()
    lo = draws[max(0, int(0.025 * n_resamples))]
    hi = draws[min(n_resamples - 1, int(0.975 * n_resamples) - 1)]
    return (lo, hi)


def mean_ci(values: Sequence[float], seed: int = 0) -> dict:
    values = list(values)
    if not values:
        return {"mean": 0.0, "lo": 0.0, "hi": 0.0, "values": []}
    mean = sum(values) / len(values)
    lo, hi = bootstrap_ci(values, seed=seed)
    return {"mean": mean, "lo": lo, "hi": hi, "values": values}


def mcnemar_exact(b: int, c: int) -> float:
    """Exact two-sided McNemar p-value for discordant counts b and c."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def compare_models(a_flags: dict[str, bool], b_flags: dict[str, bool]) -> dict:
    """Paired comparison of two models over the same pairs (majority flags).

    Returns the 2x2 discordant counts and the exact McNemar p-value.
    """
    shared = set(a_flags) & set(b_flags)
    b_count = sum(1 for pair in shared if a_flags[pair] and not b_flags[pair])  # a only
    c_count = sum(1 for pair in shared if b_flags[pair] and not a_flags[pair])  # b only
    agree = sum(1 for pair in shared if a_flags[pair] == b_flags[pair])
    return {
        "pairs": len(shared),
        "agree": agree,
        "a_only": b_count,
        "b_only": c_count,
        "mcnemar_p": mcnemar_exact(b_count, c_count),
    }
