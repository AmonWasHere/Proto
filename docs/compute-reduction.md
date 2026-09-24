# Reducing Compute Without Losing Accuracy

Answers: *can we keep model quality while cutting training/inference hours?*

**Short answer:** up to **~2–4× is free** (identical math, faster kernels/better
batching). Beyond that you are on a **compute↔quality Pareto curve** — every extra
hour saved costs some capability. But most of our savings come from **structural
choices** (what we train, and whether we train at all) rather than from squeezing
the same job. Those are 10–100×, and they cost little if chosen correctly.

> The single most important sentence: **for RewardAudit, the cheapest way to
> "maintain accuracy" is to not train a policy at all.** E1 is inference-only,
> and E1b approximates reward hacking without RL. Training is the fallback, not
> the default.

---

## 1. Free efficiency (same result, fewer hours)

These do not change the objective or the model — only how fast the same math runs.

| Lever | Typical saving | Accuracy impact | Notes |
|---|---|---|---|
| BF16 instead of FP32 | ~2× | none | standard |
| FlashAttention-2 / SDPA | 1.5–3× on attention | none (exact) | needs Ampere+ (not T4) |
| Sequence packing + packing-aware attn | 20–50% fewer tokens | none | kill padding waste |
| Fused/8-bit optimizer (AdamW-8bit, Lion) | 20–40% step time | negligible | |
| Gradient checkpointing | enables larger batch | none | ~20% compute overhead, net throughput up |
| Continuous batching / vLLM / SGLang | 2–5× rollout throughput | none | essential for RL |
| Prefix/KV caching | 2–4× effective input | none | agent contexts repeat prefixes |
| Larger effective batch + warmup LR | 1.2–1.8× | none if tuned | better GPU utilization |
| Async / off-policy rollouts | 20–50% wall-clock | small | overlap gen + train |
| Early stopping on eval plateau | 10–40% of steps | none (or better) | avoids overtraining |
| Better GPU (H200 vs A100) | ~1.8–2.5× | none | pure infra |

Stacked, these give roughly **3–5× fewer hours for the same model**.

---

## 2. Structural savings (10–100×, the real levers)

### 2.1 Don't train at all — test-time compute
- **Best-of-N + verifier selection**: sample N candidates, pick the one the
  verifier likes. Can match a trained policy at **0 training hours**, with cost
  moved to inference. This is our E1b strategy.

### 2.2 Distill instead of RL
- Use a **frontier API teacher** to generate high-quality investigations, then
  **SFT a small student** on them. One-time inference cost, no rollouts, no
  policy gradient. Student usually lands close to teacher, far above base.
- Cost: a few hundred $, vs $2–3k for RL.

### 2.3 Offline preference methods instead of online RL
| Method | Rollouts? | Cost vs GRPO | Quality |
|---|---|---|---|
| **DPO / ORPO / KTO** | no | **5–20× cheaper** | comparable on preference-style tasks; can lag on exploration-heavy reasoning |
| **RFT / STaR** (sample, keep verified-correct, SFT) | offline sampling only | 3–10× cheaper | strong, simple, very effective with a good verifier |
| **GRPO / PPO** | yes, online | 1× (most expensive) | best when exploration is needed |

For our task, where a **verifier already exists**, RFT/DPO typically captures most
of the benefit at a fraction of the compute. Reserve online GRPO for the specific
question "does online optimization learn to hack the reward?".

### 2.4 Train less of the model
- **LoRA/QLoRA**: adapters only. ~10× cheaper than full FT, usually within 1–2%
  on a narrow adaptation task.
- **Frozen base + adapter merge**: many small runs instead of one big one.
- **Distill 7B → 3B** (Antares-style) for deployment: same behavior, ~1/4 the
  inference cost.

### 2.5 Make the environment do the work
- Move intelligence into **tools, retrieval, and verifiers** rather than weights.
- **Cache tool outputs** and dedupe episodes — often the biggest RL saving after
  removing rollouts.
- **Curriculum**: easy→hard ordering converges in fewer steps.

---

## 3. Where accuracy actually gets sacrificed (be honest)

| Technique | Risk |
|---|---|
| 4-bit **training** (QLoRA vs bf16 LoRA) | small but real quality drop; measure it |
| Shorter context | loses multi-file reasoning — central to vuln work |
| Smaller GRPO group size | noisier reward, slower/less stable learning |
| Fewer epochs | underfitting |
| 3B instead of 7B | capability ceiling, especially on logic flaws |
| Aggressive inference quantization | small quality loss; verify task metrics |
| Cutting verifier/ablation count | hurts *scientific* validity, not model accuracy |

Rule: every "saving" in §1 is safe; every item in §3 must be **A/B tested**.

---

## 4. Recommended stack for this project

If we ever train (post-E1, with budget):

1. **Start at zero training**: E1 + E1b (best-of-N + verifier). This is the accuracy-preserving
   optimum.
2. If a policy is needed: **teacher distillation → SFT** (LoRA, bf16, packing,
   FA2). ~10–25 H200-hr.
3. If preference data exists: **DPO/RFT**, not GRPO. ~20–70 H200-hr.
4. Only for the explicit online-reward-hacking question: **GRPO**, but with
   LoRA, G=4–8, curriculum, warm start, cached tools — target the *low* end of the
   earlier estimate (Tier A, ~60 H200-hr) rather than Tier B.
5. Deploy a **distilled 3B** with best-of-N.

Realistic effect: the "serious RL" Tier B (~500–700 H200-hr) can be reframed as
**~60–150 H200-hr** by replacing online RL with distillation + RFT, at a quality
cost that is small *for the questions we are actually asking*.

---

## 5. How to prove accuracy was maintained

Non-negotiable: **measure against a fixed baseline**.

- Hold out a **frozen eval set** (E1 dataset + canary repos).
- Report **the same metrics** (verifier evasion ASR, precision, FNR, cost-per-TP)
  for every configuration.
- Run the **reward-hack regression suite** and a blinded human audit on a sample.
- Pre-register an acceptable quality delta (e.g., "within 2 points on ASR") before
  optimizing for speed, so you don't rationalize a regression after the fact.

---

## 6. Bottom line

- **Yes, for ~2–4× with no accuracy loss** via kernels, packing, batching, and
  infrastructure.
- **Yes, for 10–100×** by *changing the method*: no training → best-of-N; or
  distillation → SFT; or DPO/RFT instead of online RL.
- **No**, you cannot get arbitrarily cheap at the same quality — the tail of the
  quality curve is expensive, and quantizing/truncating the model is a real
  tradeoff that must be measured.
- For RewardAudit specifically, the highest-accuracy-per-dollar configuration is
  **inference-only (E1) + best-of-N (E1b)**, which is exactly what ADR-0002
  already commits to.
