# Cost breakdown of approaches

What each way of building the verifier actually costs, and where each one breaks
down. Figures are USD. **[M]** = measured in this project; **[E]** = estimate from
the archived planning docs (`docs/COST.md`, `docs/archive/compute-and-model-strategy.md`,
`docs/archive/gcp-rl-cost-estimate.md`). Hardware baseline: one RTX 3070 Ti (8 GB)
workstation; the cloud ceiling observed on the capped key was ~$7.

## Price anchors

| Resource | Rate | Source |
|---|---|---|
| DeepSeek `deepseek-flash` in / out | $0.15 / $0.60 per 1M (off-peak) | [M] |
| Frontier API (planning) | ~$3 in / ~$15 out per 1M | [E] |
| A100 40 GB (GCP spot / standard) | $2.20 / $3.67 per GPU-hr | [E] |
| RTX PRO 6000, GCP DWS Flex | $2.25 per GPU-hr (no preemption) | [E] |
| Third-party H200 SXM | ~$4.30 per GPU-hr | [E] |
| CPU (vCPU) | $0.02–0.04 per hr | [E] |
| Owned RTX 3070 Ti (amortised + power) | ~$0 marginal; ~$30–60/mo power for 7–8B on-prem | [E] |

---

## A. Static analysis only (no LLM)

Pinned analyzers (opengrep/Semgrep + rules). No model.

| | |
|---|---|
| One-time | $0 (open-source tooling) |
| Marginal | $0 — CPU only |
| Wall-clock | seconds–minutes per repo (OWASP Benchmark: 102 s) |
| Measured | recall **0.905**, precision **0.734**, FPR **0.349** (2,740 labelled cases) |

**Shortcomings:** a third of flags are false; no reasoning about context, sanitizers,
or intent; rules must be written per class and rot; silent on unmodelled languages.

---

## B. Cloud LLM inference (API verifier) — the current default

Send a bounded request per candidate to a hosted model.

| | |
|---|---|
| One-time | $0 |
| Marginal | **[M]** $0.00189 / judgement (thinking on), **$0.00023** (thinking off, ~8×) |
| Measured run | **[M]** E0 (21 pairs × k=5, e1+calibrate) ≈ **$0.79** |
| Repeat scans | **[M]** verdict cache = **100% saved** (replays, 0 tokens) |
| Wall-clock | ~19 s/call (reasoning model) |

**Shortcomings:** recurring cost scales with *new* code; data leaves the machine
(only the bounded slice); rate limits and model deprecation; the model may be
stronger or weaker than you think (verifier-dependent). Caching removes repeat cost
but not first-scan cost.

---

## C. Local open-weights inference (owned GPU, e.g. LM Studio)

Run an open model (Qwen2.5-Coder-7B) on the workstation.

| | |
|---|---|
| One-time | $0 (hardware already owned; a new 8 GB GPU ≈ $300–400) |
| Marginal | **$0** API cost; ~$30–60/mo electricity for a 7–8B on-prem [E] |
| Latency | **[M]** ~2–20 s/call (7B Q4); **too slow at scale** on 8 GB |
| Model quality | **[M]** weak: on OWASP Benchmark it **rejected 0/15** false positives |

**Shortcomings:** capability gap — the 7B rubber-stamps (see `docs/VALIDATION.md`);
8 GB caps model size and throughput (7B Q4 ≈ 20–40 tok/s [E]); reasoning models can
loop/return empty `content`; one model fits at a time; no redundancy.

---

## D. Own model, fine-tuned (LoRA/QLoRA) — the realistic "locally developed model"

Adapt an existing open base to the security-review task.

| Run | Compute | Cost | Wall-clock |
|---|---|---|---|
| 7B QLoRA SFT (30–100M tok) | 10–40 A100-hr | **$15–60** | <1 day |
| 7B QLoRA SFT + DPO | 50–200 GPU-hr | **$100–300** | 2–4 days |
| 32B QLoRA SFT + DPO | 250–800 GPU-hr | **$375–1,200** | ~1 week |
| 70B QLoRA SFT + DPO | 800–2,600 GPU-hr | **$1,200–3,900** | 1–2 weeks |
| 7B **full** fine-tune | 50–250 GPU-hr | **$300–1,500** | 1–3 days (4–8 GPU) |

All **[E]**. **Not possible on the 8 GB laptop** — smoke tests only.

**Shortcomings:** needs **labelled trajectories** (data is the real cost, more than
compute); QLoRA adapts style/schema far more than it adds reasoning; quality is
bounded by the base model and the labels; you now own evaluation, drift, and
serving; a fine-tuned 7B is unlikely to beat a frontier API on judgement quality.

---

## E. Own model, pretrained from scratch — infeasible

Train a language model from random weights.

| | |
|---|---|
| Compute | ~**70,000–100,000 GPU-hr** for a 7B-class model [E] |
| Cost | ~**$300k–$450k** at H200/A100 rates |
| Wall-clock | ~**8–11 years** on one GPU; weeks only on a large cluster |
| Data | trillions of tokens; collection/cleaning dwarfs compute |

**Shortcomings:** out of scope by orders of magnitude; no research question here
needs it; would not beat existing open weights at this budget. Listed only to rule
it out.

---

## F. Reinforcement learning from verifiable rewards (GRPO/RLOO)

Optimise a policy against analyzer/verifier rewards.

| Tier | Scope | Spot | G4 Flex | Wall-clock |
|---|---|---|---|---|
| A — sanity | 3B, 1 verifier, 20k episodes | **~$0.45k** | ~$0.4–0.56k | 1–2 days |
| B — serious | 3–8B, 3 verifiers, ~1,200 GPU-hr | **~$3.7k** | **~$3.6–5.0k** | 2–4 weeks |
| C — ablations | 8B, ~3,500 GPU-hr | **~$11k** | ~$9.8–12.8k | 4–10 weeks |

All **[E]**. Environment/tool CPU is **25–40% of the bill** and is the commonly
forgotten line item.

**Shortcomings:** 10–50× the cost of fine-tuning; needs a **credit-assignment
signal** and a non-gameable reward (the whole point of this project is that LLM
verifiers *are* gameable); reward hacking; long, fragile training loops; the result
is a policy you must still serve and evaluate. The project's own gate: **do not
start RL unless a prompted/DPO policy plateaus**.

---

## G. Rented GPU, self-hosted large model (e.g. 32B/70B)

Self-host a stronger open model instead of paying per token.

| | |
|---|---|
| 32B Q4 serving | 1×A100 80 GB ≈ **~$1,100/mo** [E] |
| 70B Q4 serving | 2×A100 ≈ **~$2,200/mo** [E] |
| Batch scanning | spot cuts GPU 40–70% |

**Shortcomings:** always-on cost even when idle; ops burden (serving, quantization,
upgrades); still weaker than frontier APIs on hard judgement; no data-egress win
unless on-prem (capex $8k–50k [E]).

---

## H. Human expert audit (ground truth)

Pay reviewers to label a sample (for measuring precision/recall or building data).

| | |
|---|---|
| Rate | ~$50–150/hr expert [E] |
| 100 items × ~8 min | ~13 hr → **~$700–2,000** per sample |
| 500 items | **~$3.5k–10k** |

**Shortcomings:** the only source of true labels, but expensive and slow; inter-rater
disagreement; does not scale; a one-off measurement, not a detector.

---

## I. Hybrid: tools + LLM verifier + measurement (this project)

Analyzer finds candidates → bounded LLM verifier with evidence gating → four-way
decomposition and calibration measure trust.

| | |
|---|---|
| One-time | ~$0 software; engineering time |
| Marginal | **[M]** ~$0.0017/verdict (cloud) or **$0** (local) + cache on repeats |
| Measured run | **[M]** E0 ≈ **$0.79** total |

**Shortcomings:** effectiveness is **model- and corpus-dependent** — on OWASP
Benchmark the verifier did **not** improve on the analyzer (see
`docs/VALIDATION.md`); the free local model is too weak to be a reliable filter; the
cloud model abstains heavily; the whole approach is a **measurement**, not a new
detector.

---

## J. Hybrid: local deterministic pipeline + DeepSeek API verifier

The configuration the E0 study actually ran: cheap, deterministic work stays local;
only the **judgement** is sent to the **DeepSeek API**, and only for the bounded slice.

| Stage | Where | Cost |
|---|---|---|
| Analyzer + rules (opengrep) | local CPU | $0 |
| Code property graph + evidence gating | local CPU | $0 |
| Bounded verdict request (per candidate) | **DeepSeek API** | **$0.00189** (thinking on) / **$0.00023** (off) |
| Repeat scan of unchanged code | local verdict cache | **$0** (100% saved) |
| Codebase graph / coverage / metrics | local CPU | $0 |

**Measured:** the 21-pair, k=5 E0 run (e1 + calibrate = 420 judgements) cost
**$0.79** on `deepseek-flash` ($0.15 in / $0.60 out per 1M, off-peak); a single real
repo scan (sqlmap, 9 candidates) cost **< $0.01**.

**Cascade variant (local funnel → DeepSeek escalation).** Use the free local 7B to
pre-screen candidates and call DeepSeek only on those the local model marks
`unknown_risk` or low-confidence. At the observed 32–43% abstention rate this cuts
DeepSeek calls ~2–3× — with the caveat below.

| | |
|---|---|
| One-time | $0 |
| Marginal | **$0.0002–0.0019 / verdict**, funnel-reduced ~2–3× by cache + cascade |
| Data boundary | only the bounded code slice leaves the machine |

**Shortcomings:**
- **Data egress** — even bounded slices go to a third party; a local-only
  requirement rules this out.
- **Vendor dependence** — one provider, its prices, rate limits, and model
  deprecations; `deepseek-flash` is a moving alias, not a stable contract.
- **Cascade risk** — the local funnel deciding what to escalate is the *same* weak
  model that rubber-stamped false positives in `docs/VALIDATION.md`. A bad funnel
  either escalates everything (no saving) or escalates nothing (lost findings).
  Measure the funnel's precision before trusting it.
- **Non-determinism** — a cached verdict is reproducible; a fresh reasoning-model
  verdict is not.
- **Not a capability win** — this buys judgement, it does not build one; the model
  can still be wrong (see the OWASP Benchmark result).

---

## Summary

| Approach | One-time | Per run / month | Hardware | Verdict |
|---|---|---|---|---|
| A. Static only | $0 | $0 | CPU | high recall, 35% FPR |
| B. Cloud API | $0 | **[M]** $0.0002–0.002 / verdict | any | cheap, effective, data egress |
| C. Local inference | $0 | ~$30–60/mo power | 8 GB GPU | free but weak |
| D. Fine-tune (LoRA) | **[E]** $100–1,200 | serving | rented GPU | data-bound, modest gain |
| E. Pretrain from scratch | **[E]** ~$0.3–0.45M | — | cluster | infeasible |
| F. RL (GRPO) | **[E]** $3.6k–12.8k | — | 4–8×A100/G4 | 10–50× cost, gameable |
| G. Self-host large | $0 | $1.1k–2.2k/mo | A100 | ops burden |
| H. Human audit | **[E]** $0.7k–10k | — | people | ground truth, slow |
| I. Hybrid (this) | $0 | **$0–0.0017 / verdict** | CPU + optional GPU/API | honest measurement |
| J. Hybrid: local + **DeepSeek API** | $0 | **[M]** $0.0002–0.0019 / verdict | CPU | data egress; vendor-coupled |

## Recommendation under the current constraints (≤$1k, 8 GB GPU)

1. **Use the cloud API for measurement runs** (B/I): the whole E0 study cost under
   $1, and the cache makes rescans free. This is the only approach where the
   modeling quality is adequate at this budget.
2. **Use the local 7B only for private/offline smoke tests** (C), accepting it is
   too weak to certify findings.
3. **Do not pretrain (E).** **Do not start RL (F)** unless a prompted/DPO policy
   demonstrably plateaus — it is 10–50× the cost and the reward is the exact thing
   this project shows is unreliable.
4. **If a "own model" is a hard requirement (D),** do a **7B QLoRA SFT** first
   (~$15–60) on labelled trajectories and check whether it beats the prompted
   baseline; spend the $100–300 SFT+DPO only if it does.
5. **Spend on human labels before compute (H)** — the binding constraint is ground
   truth, not FLOPs.
