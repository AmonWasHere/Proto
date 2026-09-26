# Cost & Optimizations (measured)

All prices: DeepSeek, fetched 2026-09-26, USD per 1M tokens (off-peak).
`deepseek-flash`: input cache-miss $0.15, output $0.60 (peak = 2×).

## Unit cost (measured, P5)

Per verifier judgement: **1,043 input + ~2,600 output** tokens.
Output is **~91% of cost** (output price is 4× input, volume 2.5×). Optimise output.

## Measured: thinking mode OFF

21 JavaVFC security pairs = 42 judgements, `deepseek-flash`, same code and prompts.

| | thinking ON | thinking OFF | delta |
|---|---|---|---|
| output tokens | 121,596 | **5,271** | **23× fewer** |
| input tokens | 43,817 | 42,767 | ~same |
| **cost (42 judgements)** | **$0.0795** | **$0.0096** | **~8.3× cheaper** |
| cost / judgement | $0.00189 | $0.00023 | |
| abstention rate | 50.0% | 35.7% | answers more |
| detection rate | 28.6% | 23.8% | worse |
| **fixed-side FP rate** | **0.0%** | **9.5%** | **worse (new FPs)** |
| accuracy (scored) | 66.7% | 59.3% | worse |
| ECE | 0.153 | 0.207 | worse calibration |

**The trade is real:** ~8× cheaper, but the verifier starts committing to false
positives (0% → 9.5% on the fixed side) and its confidence becomes less
trustworthy. Cost per true positive still falls (~7×), but the precision loss is
the kind this project exists to measure — so a deployment must decide the
precision floor before taking it.

*Caveat:* single run per arm; the thinking-ON baseline itself varies run-to-run
(detection was 38.1% in the P5 run, 28.6% here). The FP introduction and ECE
degradation are the more reliable signals.

## Measured: verdict cache

A repeat of the *same* run returned **in=0, out=0 tokens (100% saved)** with
identical results. Cache file: `runs/llm_cache.jsonl` (84 entries, 48 KB).

## How the verdict cache works

A wrapper (`llm/cache.py`) around any backend, keyed on a SHA-256 of:

```
inner backend name · model · extra_body · system prompt · user prompt
· temperature · json_mode · max_tokens
```

- **Hit** → replay the stored response, `tokens = 0`. **Miss** → call the
  provider, append `{key, text, model, tokens_in, tokens_out}` to an append-only
  JSONL (loaded into memory at start; `O_APPEND` for concurrent writers).
- **Invalidation is automatic:** any change to the code slice, the question, the
  system prompt, the model, or the provider settings changes the key. There is no
  stale-verdict path, because the key *is* the question.
- **Why it is the best saving:** a CI scan that changes 2% of files re-verifies 2%
  of candidates; the other 98% are free. The cache is on by default for
  cloud/local backends (`REWARDAUDIT_LLM_CACHE=off` to disable).
- **What it does not do:** help the first scan of new code. That is the
  thinking-mode / funnel territory.

## Optimization ranking (measured vs estimated)

| Lever | Saving | Status |
|---|---|---|
| Verdict cache (repeated scans) | **100% on repeats** | **measured, on by default** |
| Disable thinking | **~8×** | **measured** (accuracy cost above) |
| Off-peak scheduling | 2× | price arithmetic, not yet scheduled |
| Tool → candidate funnel | up to ~7× at 5% candidates; break-even 36% | not implemented |
| Prefix caching | ≤9% (input-bound) | not implemented |
| Trim output schema | ~5–15% | not implemented |

## Bottom line

- **Cheap, measured, safe-ish:** cache (free on rescans) and off-peak (2×).
- **Big but costly:** disable thinking → **8× cheaper**, at a measurable precision
  and calibration cost. Use per-tier (only for easy/clear candidates) if the
  precision floor matters.
- **Structural, unbuilt:** the candidate funnel is what would let the tools pay
  for themselves; today the pipeline verifies everything it is given.
