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

## Amendments

**Amendment 1 (2026-09-26, before analysis).** The original E0 specified k=3 and
two models (`deepseek-flash`, `deepseek-v4-pro`). Two facts forced a change:
`deepseek-v4-pro` did not complete a single 42-call run in ~50 minutes (latency,
not budget), and the API balance is finite. E0 is therefore run as:

- **single model:** `deepseek-flash`, **k = 5** (more repeats instead of a second
  model).
- **H1 (verifier-dependence) is deferred to E1**, which requires a second model
  provider (a different API key or a local server). H1 cannot be tested on one
  family.
- H2 (abstention ≥ 0.30), H3 (evasion mainly abstention) and H4 (gating helps at
  no recall cost) remain as pre-registered, now with wider intervals from k=5.

This amendment was written **before** the amended runs completed, so it is a
pre-analysis change, not a post-hoc one. Cost of E0 is expected to be ~$1.

## What this cannot establish

E0 does not fix the small sample (n=21 / n=5), the noisy labels, the single
language at scale, or contamination. It establishes only whether the reported
effects are **stable across repeated runs** and whether model differences survive a
paired test. Scale is E2/E3.
