# Evidence plan

After the honest review, evidence is the only lever that moves the paper. This is
the ladder, cheapest first, with a gate between rungs. Plan C (full scale-up) is
`docs/archive/` context; this is the executable order.

| Step | What | Cost | Status |
|---|---|---|---|
| **E0** | k=3 repeats + 95% CIs + paired McNemar on existing data | ~$2–10 | **in progress** |
| **E1** | Run ≥3 families on the JavaVFC-21 set | ~$5–20 | blocked on API keys |
| **E2** | Scale corpus to n≥100 clean-label fixes (CVEfilter) | 1–2 weeks, ~$20–60 | pending gate |
| **E3** | Blinded human audit (~50–100 items) for FNR | human hours | pending gate |
| **E4** | Contamination holdout (temporal/private) | ~1 day | pending |
| **E5** | Evaluate the whole-codebase graph, or cut Section III-F | 2–3 days | pending |

## E0 — repeatability and CIs

**Why first:** it needs no new data, costs a few dollars, and removes the single
largest reviewer objection (single numbers, no intervals) even though a real
variance was already observed (detection 38.1% vs 28.6% for one configuration).

**Command**

```bash
cd rewardaudit
set -a; . ~/.config/rewardaudit/env; set +a
export REWARDAUDIT_LLM_BASE_URL=https://api.deepseek.com/v1
PYTHONPATH=src python3 -m rewardaudit.harness repeats \
    --dir datasets/javavfc_pairs \
    --experiments e1,calibrate \
    --models deepseek-flash,deepseek-v4-pro \
    --k 3 --json runs/e0.json
```

**Outputs:** per-run metrics, mean [95% CI] per metric per model, and an exact
McNemar comparison between the two models. `runs/e0.json` keeps the raw runs and
the aggregation. Thresholds are fixed in `docs/PREREGISTRATION.md`.

**Exit gate:** if H1 holds (disjoint CIs) and H3 holds (evasion is mainly
abstention), proceed to E2/E3. If the CIs overlap entirely, the honest outcome is a
**methods / negative-result** paper and E2 is not worth the corpus cost.

## E1 — multi-family at scale

Blocked only on API access: today only DeepSeek models are reachable. Add
Groq/Alibaba/frontier keys (or a local 7–8B server) and run the same `repeats`
command with `--models` covering ≥3 families. This removes the internal
contradiction ("verifier-dependent" asserted from one family on the scaled set).

## E2/E3 — scale and audit

Only after E0/E1 pass the gate. E2 replaces JavaVFC's noisy screening labels with
CVE-named fixes; E3 anchors the false-negative estimate with a blinded sample.
Their cost is dominated by **human audit hours**, not compute.

## E5 — whole-codebase graph

Section III-F of the paper currently describes a graph with no results. Either
evaluate it (path-level candidates on multi-file revisions) or remove the section
before submission; an unevaluated section is a liability.
