from rewardaudit.stats import (
    bootstrap_ci,
    compare_models,
    mcnemar_exact,
    mean_ci,
    wilson_ci,
)


def test_wilson_ci_bounds_and_edges():
    lo, hi = wilson_ci(0, 0)
    assert (lo, hi) == (0.0, 1.0)
    lo, hi = wilson_ci(10, 10)
    assert hi == 1.0 and 0.6 < lo < 0.8
    lo, hi = wilson_ci(1, 10)
    assert lo < 0.1 < hi and hi < 0.5


def test_bootstrap_and_mean_ci():
    lo, hi = bootstrap_ci([0.2, 0.4, 0.6], seed=1)
    assert lo <= 0.4 <= hi
    summary = mean_ci([0.2, 0.4, 0.6], seed=1)
    assert abs(summary["mean"] - 0.4) < 1e-9
    assert summary["lo"] <= summary["mean"] <= summary["hi"]


def test_mean_ci_constant_sample():
    summary = mean_ci([1.0, 1.0, 1.0])
    assert summary["mean"] == 1.0 and summary["lo"] == 1.0 and summary["hi"] == 1.0


def test_mcnemar_exact():
    assert mcnemar_exact(0, 0) == 1.0
    assert abs(mcnemar_exact(10, 0) - 2 * (0.5 ** 10)) < 1e-9
    assert mcnemar_exact(5, 0) == mcnemar_exact(0, 5)  # symmetric


def test_compare_models_paired():
    a = {"p1": True, "p2": False, "p3": True}
    b = {"p1": True, "p2": True, "p3": False}
    result = compare_models(a, b)
    assert result["pairs"] == 3
    assert result["a_only"] == 1 and result["b_only"] == 1
    assert result["agree"] == 1
    assert 0.0 <= result["mcnemar_p"] <= 1.0
