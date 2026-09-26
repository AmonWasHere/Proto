# RewardAudit — Findings Report (draft)

**Working title:** *Measuring LLM Security Verdicts* (working subtitle: evidence
gating and adversarial comments).

**Status:** draft for P6. All numbers are from runs recorded in
`docs/e1-results.md`; none are projected.

---

## Abstract

We build an instrument that asks of a code-review model what the prior
`sastaudit` study asked of static analyzers: **does the verdict track the fix?**
The instrument is the four-way decomposition (flagged on both revisions / on the
vulnerable revision only / on the fixed revision only / on neither), applied to
LLM verdicts on vulnerable/fixed revision pairs. Three additional measurements
follow: adversarial comment injection (templates and an adaptive attacker),
verifier composition, and calibration.

Across five model families and a real-fix corpus (JavaVFC), four results stand out:

1. An evidence-grounded LLM **tracks the fix ~4× more often than a pattern
   matcher** (19–24% vs 4.8%) and does not over-report (1.0–1.25× vs the tool's
   6.0×).
2. **Adversarial comments evade 26% (templates) to 50% (adaptive), and nearly
   every evasion is an abstention, not a false positive.**
3. **Composition relocates trust**: requiring evidence to resolve helps for free;
   requiring agreement with a weaker analyzer *loses recall and gains nothing*.
4. The verifier is **calibrated and precise but silent**: ECE 0.025, 0% fixed-side
   false positives, but **50% abstention and 62% false-negative rate**. Attacks
   amplify an existing weakness rather than create a new one.

---

## 1. Question

Prior work (`pinned/sastaudit-src/artifact/FINDINGS.md`) showed benchmark scores
can be reproduced, internally consistent, and still not measure detection. This
project asks the same of **LLM verifiers**: when an LLM says a finding is real, is
its verdict *grounded* — does it move with the vulnerability — or does it merely
match a construct present before and after? And can an adversary move it?

## 2. Instrument

- **Four-way decomposition** (`decomposition.py`): per revision pair, classify the
  verdict into `both` / `vuln_only` / `fixed_only` / `neither`. `vuln_only` (a
  flip) is the stringent signal; `both` means the verdict could not have been
  about the vulnerability.
- **Bounded verdict request** (`e1.py`, `verifiers/llm_judge.py`): the model sees
  a candidate, a graph-selected code slice, and the commit message — never a
  repository. Every cited reference must resolve to a real tree-sitter node or
  the verdict is rejected (evidence gating).
- **Adversary**: five template strategies (`attack/comment_gen.py`) and an
  adaptive LLM attacker that refines against the judge (`attack/adaptive.py`).
- **Calibration** (`calibration.py`): reliability, selective risk, FNR, cost.

## 3. Data

| Corpus | Role |
|---|---|
| Python pairs (5) + canaries (3) | method development, cross-family check |
| **JavaVFC** (784 commits; 327 usable single-file; **207 materialised offline**; **21-pair security subset**) | the scaled measurement |
| OWASP Benchmark / Java controls | regression control (`sastaudit`) |

## 4. Results

### 4.1 Verifier dependence (rounds 1–3)

Identical input, different models — flip rate 80–100% (n=5) and different failure
modes: `gpt-oss` false-*positives* on argv-form subprocess; `deepseek-v4-pro`
*abstains*; `qwen`/`deepseek-flash` clean. On JavaVFC, `deepseek-flash` flips
19.0% (abstention allowed) / 23.8% (`--require-decision`).

### 4.2 LLM vs pattern matcher (round 4)

| Verifier | flip rate | over-report |
|---|---|---|
| tool (opengrep, pinned Java) | 4.8% | **6.0×** |
| LLM ungated | 19.0% | 1.25× |
| LLM evidence-gated | 19.0% | 1.00× |
| hybrid (LLM ∧ tool) | 14.3% | 1.00× |

The tool flags a construct on both revisions in 5/21 pairs; the LLM notices the
change.

### 4.3 Adversarial comments (rounds 2–3)

| Attack | evasion | via FP | via abstention |
|---|---|---|---|
| templates (best: authority) | 43% (3/7) | 0 | 3 |
| templates (overall) | 26% | 1 | 8 |
| adaptive attacker | **50% (3/6)** | **0** | **3** |

No model family was immune; "input is sanitized" was the strongest single tactic
across families.

### 4.4 Composition (round 4)

Evidence gating removed the one `both` case at **no recall cost**. Requiring tool
agreement lost one flip and gained nothing. **Trust comes from grounding, not from
consensus with a weaker verifier.**

### 4.5 Calibration and silence (round 5)

ECE 0.025; 0% fixed-side false positives; but 50% abstention and 62% FNR. At
confidence ≥0.9, coverage 43% and risk 0.11. The verifier is trustworthy when it
commits; its problem is silence.

## 5. Contributions

1. **The four-way decomposition applied to LLM verifiers** — a reusable instrument
   for asking whether a verdict is grounded, not just plausible.
2. **Abstention as the dominant defeat surface** — measured separately from false
   positives; most adversarial wins are abstentions.
3. **Composition relocates trust** — evidence gating is a free improvement; adding
   a weaker verifier by consensus is not.
4. **A calibrated-but-silent characterization** of the current verifier, with a
   concrete bottleneck (coverage, not correctness).
5. **A methodological warning**: a reasoning-model verifier silently degrades to
   "always abstain" under a small `max_tokens` cap — invisible without the
   decomposition.

## 6. Limitations

- **n=21** for the scaled measurement (cached JavaVFC security subset). Directional.
- **Screening labels**: ~18% of JavaVFC is not a genuine security fix, so recall is
  a floor against a cleaner label set.
- **Single runs**; reasoning-model non-determinism at temperature 0 (baseline TPs
  varied 4–7/21).
- **Isolated files**; the commit message is supplied as candidate context.
- One model family (`deepseek-flash`) for the scaled rounds; cross-family evidence
  is at n=5.

## 7. Relation to prior work

- Extends `FINDINGS.md` (benchmark ≠ detection; four-way decomposition) from static
  tools to LLM verifiers.
- Reproduces ALIBI's core result (comments defeat detectors) in a *reward/verifier*
  setting, and adds the abstention split and an adaptive attacker.
- `VulAgentRL` uses exact graph verification as a training reward; we measure the
  trust a graph-grounded verdict actually earns, and find it is precision without
  coverage.

## 8. Reproduction

```bash
cd rewardaudit
PYTHONPATH=src python3 -m pytest                                    # 74 tests
PYTHONPATH=src python3 -m rewardaudit.harness controls              # 12/18, 1/3
PYTHONPATH=src python3 -m rewardaudit.harness javavfc --offline --limit 327
# with an OpenAI-compatible endpoint in ~/.config/rewardaudit/env:
./scripts/with_env.sh python3 -m rewardaudit.harness e1       --dir datasets/javavfc_pairs --verifier llm
./scripts/with_env.sh python3 -m rewardaudit.harness e1       --dir datasets/javavfc_pairs --verifier tool
./scripts/with_env.sh python3 -m rewardaudit.harness e1       --dir datasets/javavfc_pairs --verifier hybrid
./scripts/with_env.sh python3 -m rewardaudit.harness evade    --dir datasets/javavfc_pairs --backend cloud
./scripts/with_env.sh python3 -m rewardaudit.harness adaptive --dir datasets/javavfc_pairs --backend cloud
./scripts/with_env.sh python3 -m rewardaudit.harness calibrate --dir datasets/javavfc_pairs --backend cloud
```

All assets pinned in `pinned/` (`pins.json`); the tool result is reproducible with
no network.

## 9. Next

1. Raise **n** by materialising the 186 uncached JavaVFC commits (network) → a
   security stratum of ~30–40.
2. Reproduce rounds 1–5 with a second judge family for the scaled corpus.
3. A **coverage-oriented** verifier: the data says the bottleneck is silence, so
   the next experiment should measure whether richer context (callers/callees,
   project files) raises recall without losing calibration.
