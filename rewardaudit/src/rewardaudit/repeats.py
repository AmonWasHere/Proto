"""E0 evidence runs: repeat each configuration k times and aggregate with CIs.

Reasoning models are non-deterministic even at temperature 0, so a single run is
not a measurement. This module runs an experiment k times per model, aggregates
metrics as mean [95% CI] across runs, and compares models pairwise with an exact
McNemar test on the same pairs.
"""

from __future__ import annotations

import os
from pathlib import Path

from . import config
from .analyzers.opengrep import Opengrep
from .calibration import analyze
from .cpg import Cpg
from .datasets import load_pairs
from .decomposition import Cell
from .e1 import collect_calibration, four_way_hybrid, four_way_llm, four_way_tool
from .llm import build_backend
from .stats import compare_models, mean_ci
from .verifiers.base import VerificationContext
from .verifiers.llm_judge import LLMJudge

METRICS = {
    "e1": ["flip_rate", "naive_coverage", "vuln_only", "both", "neither"],
    "calibrate": ["detection_rate", "false_negative_rate", "fixed_side_fp_rate", "accuracy", "ece", "abstention_rate"],
}


def _context(root: Path, model: str, no_thinking: bool):
    os.environ["REWARDAUDIT_LLM_MODEL"] = model
    backend = build_backend("cloud", no_thinking=no_thinking)
    return backend, VerificationContext(root.resolve(), Cpg(root), backend)


def _tool_findings(root: Path, pairs) -> list:
    """Deterministic analyzer findings over a revision-pair directory."""
    is_java = any(p.vuln.endswith(".java") for p in pairs)
    rules = config.JAVA_RULES if is_java else config.PYTHON_RULES
    return Opengrep(config.OPENGREP_BIN, rules).scan(root).findings


def run_experiment(
    name: str,
    root: Path,
    model: str,
    *,
    k: int,
    no_thinking: bool = False,
    verifier: str = "llm",
    gate: bool = True,
) -> dict:
    """Run `name` k times for one model and one verifier arm; return per-run metrics.

    `verifier` selects the arm: `llm` (V1g, evidence-gated), `ungated` (V1,
    gate disabled), `hybrid` (V5, LLM AND tool), or `tool` (V2, deterministic).
    """
    root = Path(root)
    pairs = load_pairs(root / "manifest.json")
    runs: list[dict] = []
    for _ in range(k):
        _, ctx = _context(root, model, no_thinking)
        judge = LLMJudge(gate_evidence=gate)
        if name == "e1":
            if verifier == "tool":
                report = four_way_tool(pairs, _tool_findings(root, pairs))
            elif verifier == "hybrid":
                report = four_way_hybrid(pairs, ctx, _tool_findings(root, pairs), judge).report
            else:  # "llm" (gated) or "ungated"
                report = four_way_llm(pairs, ctx, judge).report
            runs.append(
                {
                    "flip_rate": report.flip_rate,
                    "naive_coverage": report.naive_coverage,
                    "vuln_only": float(report.vuln_only),
                    "both": float(report.both),
                    "neither": float(report.neither),
                    "n": report.total,
                    "per_pair": {pid: (cell is Cell.VULN_ONLY) for pid, cell in report.cells.items()},
                }
            )
        elif name == "calibrate":
            points, abstained = collect_calibration(pairs, ctx, judge)
            m = analyze(points, abstained=abstained)
            runs.append(
                {
                    "detection_rate": m["detection_rate"],
                    "false_negative_rate": m["false_negative_rate"],
                    "fixed_side_fp_rate": m["fixed_side_fp_rate"],
                    "accuracy": m["accuracy"],
                    "ece": m["ece"],
                    "abstention_rate": m["abstention_rate"],
                    "n": m["n_pairs"],
                }
            )
        else:
            raise ValueError(f"unknown experiment: {name}")
    return {"model": model, "experiment": name, "k": k, "runs": runs}


def _majority(runs: list[dict], pair: str) -> bool | None:
    votes = [r["per_pair"][pair] for r in runs if "per_pair" in r and pair in r["per_pair"]]
    if not votes:
        return None
    return sum(votes) > len(votes) / 2


def aggregate(results: list[dict], experiment: str) -> dict:
    """Mean [CI] per metric per model, plus pairwise McNemar for e1."""
    out: dict = {"experiment": experiment, "models": {}}
    per_metrics = {r["model"]: r["runs"] for r in results if r["experiment"] == experiment}
    for model, runs in per_metrics.items():
        metrics = METRICS[experiment]
        summary = {}
        for metric in metrics:
            summary[metric] = mean_ci([float(run[metric]) for run in runs])
        out["models"][model] = {"k": len(runs), "n": runs[0].get("n"), "metrics": summary}

    if experiment == "e1" and len(per_metrics) >= 2:
        models = list(per_metrics)
        flags = {}
        for model in models:
            pair_ids = set().union(*[set(r["per_pair"]) for r in per_metrics[model]])
            flags[model] = {p: bool(_majority(per_metrics[model], p)) for p in pair_ids}
        a, b = models[0], models[1]
        out["comparison"] = {"a": a, "b": b, **compare_models(flags[a], flags[b])}
    return out
