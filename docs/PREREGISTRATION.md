# Pre-registration — E0 (repeatability and confidence intervals)

**Committed before the runs.** Thresholds and decision rules below are fixed now;
any later analysis is labelled exploratory.

**Date:** 2026-09-26 · **Scope:** E0 only (existing corpora; no new data).

## Data and configuration

- Corpora: JavaVFC security subset (21 pairs), Python pairs (5 pairs) + 3 canaries.
- Models available at run time: `deepseek-flash`, `deepseek-v4-pro`.
- Repeats: **k = 3** per model per experiment.
- Verifier: LLM, evidence-gated (V1g); calibration uses default judgement mode.
- Temperature 0; provider thinking mode **on** unless a run is explicitly labelled
  `no_thinking`.

## Pre-registered exclusion rule

A judgement whose API response has an empty `content` with
`finish_reason=length` (reasoning tokens consumed the budget) is a **configuration
failure, not a verdict**. If it occurs, the run is logged, the count of affected
judgements is recorded, and the run is re-executed after raising `max_tokens`.
Runs are not silently dropped.

## Hypotheses and thresholds

| ID | Hypothesis | Supported if |
|---|---|---|
| **H1** | Verdicts are verifier-dependent | the 95% CIs of `flip_rate` for two models are **disjoint** |
| **H2** | Abstention is a substantial share of judgements | mean `abstention_rate` ≥ **0.30** |
| **H3** | Adversarial evasion is predominantly abstention, not false positive | `evaded_unknown_risk` > `evaded_false_positive` in aggregate |
| **H4** | Evidence gating improves precision at no recall cost | gated `flip_rate` ≥ ungated − **0.05**, and `both` not larger than ungated |

## Statistical treatment

- Proportions: mean over k runs with **bootstrap 95% CIs**; per-run proportions
  additionally reported with **Wilson intervals**.
- Cross-model comparison: **exact McNemar** on the same pairs, using each pair's
  majority flag across the k runs. Reported significant at **p < 0.05** only when
  the discordant count ≥ **5** (otherwise reported as underpowered).
- Two models ⇒ one comparison; no multiplicity correction, stated as such.

## What this cannot establish

E0 does not fix the small sample (n=21 / n=5), the noisy labels, the single
language at scale, or contamination. It establishes only whether the reported
effects are **stable across repeated runs** and whether model differences survive a
paired test. Scale is E2/E3.
