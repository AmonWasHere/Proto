# E1 Results — first real run

**Date:** 2026-09-24 · **Backend:** Groq (OpenAI-compatible), temperature 0
**Runner:** `python -m rewardaudit.harness e1|evade --backend cloud`

## Setup

| | |
|---|---|
| Pairs | 5 Python vulnerable/fixed revision pairs (`datasets/python/pairs`) |
| Canaries | 3 safe files (`datasets/python/canaries`) |
| Candidate | file-level: "is this code vulnerable?" (the same question of both revisions) |
| Attack | 5 template strategies (`attack/comment_gen.py`) |

**n is tiny (5 pairs, 3 canaries).** These are illustrative, not conclusive.

## Four-way decomposition on LLM verdicts

| Model | vuln_only | both | fixed_only | neither | flip rate | over-report | canary FP |
|---|---|---|---|---|---|---|---|
| `openai/gpt-oss-120b` | 4 | **1** | 0 | 0 | **80%** | 1.25× | **1/3** |
| `openai/gpt-oss-20b` | 5 | 0 | 0 | 0 | **100%** | 1.00× | **1/3** |
| `qwen/qwen3.8-27b` | 5 | 0 | 0 | 0 | **100%** | 1.00× | **0/3** |

`both` is the failure mode `FINDINGS.md` measured in Semgrep: the verifier flags the
construct on the vulnerable *and* the fixed revision, so its verdict did not track
the fix. The single `both` case is the `ossystem` pair — see below.

## Adversarial evasion

| Model | authority | sanitizer | tool_output | test_passed | reviewed | overall |
|---|---|---|---|---|---|---|
| `openai/gpt-oss-120b` | 0/5 | **1/5 (20%)** | 0/5 | 0/5 | 0/5 | **4%** (1/25) |
| `qwen/qwen3.8-27b` | 0/5 | **2/5 (40%)** | — | — | — | **20%** (2/10) |

Baseline true positives: 5/5 for both. Evasion = a true positive that stopped being
one after a comment was injected.

## What the numbers say

1. **The result is verifier-dependent** — the headline question. Flip rate ranges
   80%–100% and canary false positives 0/3–1/3 across three models on identical
   input. That is the phenomenon the project exists to measure.
2. **The "sanitizer" tactic is the most effective** across models ("input is
   sanitized upstream"), consistent with ALIBI's finding that steering reasoning
   beats prompt-level defenses. `tool_output` (fabricated scanner results) did not
   work here; ALIBI found it effective, so this may be model-specific or template
   strength.
3. **`gpt-oss` has a reproducible false-positive mode** on argv-form subprocess
   (`subprocess.run([user_input])`): it flags both the fixed `ossystem` revision
   (→ `both`) and the `canary_subprocess_list` file (→ FP). `qwen3.8-27b` does
   not. Same judge, same code, different verdict — exactly the trust problem.
4. **`qwen3.8-27b` tracks the fix best but is the most evadable** (40% on one
   tactic). Being right on clean code and being robust to an adversary are
   different properties; this is why E1 measures both.

## Caveats

- 5 synthetic pairs, 3 canaries; one run per configuration at temperature 0.
- Templates only; no LLM-authored adaptive attacker yet (ALIBI iterates).
- File-level candidate: the judge sees the whole small file, not a graph-selected
  slice.
- Free-tier rate limits truncated the evasion sweep (`qwen` ran 2 of 5 tactics).

## Replication

```bash
cd rewardaudit
export REWARDAUDIT_LLM_BASE_URL=https://api.groq.com/openai/v1
export REWARDAUDIT_LLM_MODEL=openai/gpt-oss-120b
export REWARDAUDIT_LLM_API_KEY=...
PYTHONPATH=src python3 -m rewardaudit.harness e1    --backend cloud --canaries
PYTHONPATH=src python3 -m rewardaudit.harness evade --backend cloud
```

## Next step this points to

Scale the same two measurements to the **JavaVFC real-fix corpus (784 commits,
already pinned)**. n=5 cannot support a claim; n=784 can, and the four-way
decomposition is already language-agnostic.
