# Google Cloud RL Cost Estimate (contingency)

Answers: *if we ever run the RL experiment (E2/C4), what does it cost on GCP?*
Companion to `docs/compute-and-model-strategy.md` §6.

> **Status:** contingency only. The project is currently **inference-only, $0–$1k**
> (ADR-0002). This document prices the deferred RL path.
>
> **Pricing caveat:** TPU figures below are as-fetched from
> `cloud.google.com/tpu/pricing` (2026-09-24). GPU figures are **approximate**
> us-central1 on-demand list prices for planning — verify in the
> [GCP pricing calculator](https://cloud.google.com/products/calculator) before
> committing. Regions, quotas, and DWS availability change the numbers.

---

## 1. GCP accelerators relevant here

| Machine series | Example type | Accelerator | Approx. on-demand (USD/hr) |
|---|---|---|---|
| A2 (Ampere) | `a2-ultragpu-1g` | 1× A100 80 GB | ~$5.07 |
| A2 (Ampere) | `a2-ultragpu-8g` | 8× A100 80 GB | ~$40.6 |
| A2 (Ampere) | `a2-highgpu-1g` | 1× A100 40 GB | ~$3.67 |
| A3 (Hopper) | `a3-highgpu-8g` | 8× H100 80 GB | ~$88.3 |
| A3 Ultra | `a3-ultragpu-8g` | 8× H200 | ~$110+ |
| G2 (Ada) | `g2-standard-4` | 1× L4 24 GB | ~$0.71 |
| G2 (Ada) | `g2-standard-24` | 2× L4 24 GB | ~$1.7 |
| N1 + T4 | `n1-standard-4` + T4 | 1× T4 16 GB | ~$0.55–0.70 |

**Discounts**
- **Spot:** up to ~91% off; GPU spot typically **60–70% off**. Preemptible →
  checkpoint aggressively. Prices change up to monthly.
- **CUD:** 1-year **37% off**, 3-year **55% off** (resource-based). Cannot combine
  with Spot.
- **DWS Flex-start:** fixed-duration accelerator reservations at a large discount
  (see TPU table — Flex is ~50% of on-demand). Useful for a bounded RL run.
- **SUD:** automatic up to 30% for non-committed, >25%-of-month usage.

**Confirmed TPU prices (chromebooks fixed, per chip-hour, on-demand → Flex → 1yr CUD)**

| TPU | On-demand | Flex-start | 1yr CUD |
|---|---|---|---|
| v5e | $1.20 | $0.60 | $0.84 |
| v5p | $4.20 | $2.10 | $2.94 |
| Trillium (v6e) | $2.70 | $1.35 | $1.89 |
| Ironwood (v7) | $12.00 | $6.00 | $8.40 |
| v4 | $3.22 | N/A | $2.03 |

> **TPU fit caveat:** the RL loop here is rollout-dominated and CUDA-centric
> (vLLM for the policy, HF/TRL or verl for GRPO). TPU training is cheapest per
> FLOP but the tool/sandbox environment is CPU-bound anyway, so **GPU is the
> pragmatic default**. TPU is worth revisiting only if we adopt a JAX stack.

---

## 2. RL workload sizing (recap from the compute doc)

| Quantity | Value |
|---|---|
| Policy | 3–8B, LoRA adapter (frozen base, ADR-0001) |
| Episodes / epoch | ~80,000 (Tier B) |
| Raw tokens / epoch | 19.2B in / 1.28B out |
| GPU per epoch (gen + prefill, cached) | 200–600 GPU-hr |
| Policy updates | +20–40% |
| **Environment/tool CPU** | **16k–160k vCPU-hr / epoch** |
| Full serious run | 1,000–4,000 GPU-hr |

The **environment CPU** line is the sleeper cost: every episode runs real
analyzers/sandboxes. On GCP it is priced separately and is 25–40% of the bill.

---

## 3. Cost estimates by tier (GCP, us-central1)

Assumes 8× A100 80 GB (`a2-ultragpu-8g`, ~$40.6/hr/node) unless noted; env CPU at
~$0.025/vCPU-hr on-demand; storage/egress minor.

### Tier A — Minimal RL sanity run (prove the loop)
3B policy, 1 verifier, ~20k episodes.

| Line item | Qty | On-demand | Spot (~65% off) |
|---|---|---|---|
| GPU (1×A100 80GB) | 120–160 GPU-hr | $610–$810 | $210–$290 |
| Environment CPU | 10k vCPU-hr | $250 | $90 |
| Storage/egress | — | ~$50 | ~$50 |
| **Total** | | **~$0.9k–$1.1k** | **~$0.35k–$0.45k** |

### Tier B — Serious single-policy RL (paper-grade)
3–8B, 3 verifiers, 3 epochs, ~1,200 GPU-hr.

| Line item | Qty | On-demand | Spot (~65% off) | 1yr CUD (37% off) |
|---|---|---|---|---|
| GPU (8×A100, ~150 node-hr) | 1,200 GPU-hr | $6,085 | $2,130 | $3,830 |
| Environment CPU | 120k vCPU-hr | $3,000 | $1,050 | $3,000 |
| Storage/egress | — | ~$150 | ~$150 | ~$150 |
| **Total** | | **~$9.2k** | **~$3.3k** | **~$5.0k** |

*H100 node (`a3-highgpu-8g`) alternative: ~$13.2k on-demand — overkill for a
3–8B policy; only justifies itself if rollouts are batch-1 latency-bound.*

### Tier C — Frontier RL (full verifier ablations, 8B)
~3,500 GPU-hr.

| Line item | Qty | On-demand | Spot |
|---|---|---|---|
| GPU (8×A100, ~440 node-hr) | 3,500 GPU-hr | $17,850 | $6,250 |
| Environment CPU | 300k vCPU-hr | $7,500 | $2,600 |
| Storage/egress | — | ~$300 | ~$300 |
| **Total** | | **~$25.6k** | **~$9.2k** |

---

## 4. Why GCP spot beats GCP on-demand by ~2.5–3×

| Tier | On-demand | Spot | CUD 1yr | Cheapest viable |
|---|---|---|---|---|
| A (sanity) | ~$1.0k | **~$0.4k** | ~$0.7k | Spot |
| B (serious) | ~$9.2k | **~$3.3k** | ~$5.0k | Spot |
| C (frontier) | ~$25.6k | **~$9.2k** | ~$14k | Spot |

**But spot has a cost:** A100/H100 spot frequently preempts. You must checkpoint
LoRA adapters + rollout buffers every few minutes, and use a resume-capable
trainer. Add ~10–15% wallclock overhead. DWS Flex-start (fixed-duration, no
preemption) is the middle ground if a discount is offered for the accelerator.

---

## 5. Cost-optimization checklist

1. **Use A100 80GB, not H100,** for 3–8B policies — ~2× cheaper, same result.
2. **Spot + checkpointing** for rollouts; keep the small trainer on-demand if
   preemption hurts. Mixed procurement.
3. **Environment CPU on Spot/`e2`/`n2`**, not the GPU node.
4. **Cap context** (KV cache) — the dominant rollout cost.
5. **Batch and cache** tool outputs; dedupe episodes; replay buffers.
6. **DWS Flex-start** for a fixed 1–2 week RL window instead of continuous CUD.
7. **Region arbitrage:** us-central1 cheapest; avoid premium regions.
8. **Vertex AI tuning** (managed SFT/DPO) is an alternative for the *offline*
   stages (no rollout control), charged per token — cheaper for SFT, unsuitable
   for GRPO.

---

## 6. Credits that could fund RL

- **$300 free credits** for new GCP accounts.
- **Google for Startups Cloud Program** — up to hundreds of thousands in credits.
- **Google Research Credits / academic grants** — relevant if affiliated.
- **GCP research grants** for papers with public artifacts.

If any apply, Tier B on GCP moves from "out of budget" to "free."

---

## 7. Verdict vs current budget

Current decision: **inference-only, $0–$1k** (ADR-0002).

- **Tier A on spot (~$0.4k)** is the only RL that fits the current budget — a
  single-verifier sanity run, not a study. It would not support C4's
  verifier-comparison claims.
- **Tier B (~$3.3k spot)** is the minimum for a publishable RL result and
  requires either a budget increase or GCP credits.
- **Recommendation:** stay inference-only; keep Tier A as a documented
  "if credits appear" path. Revisit only after E1 shows verifier-dependent
  evasion (the trigger defined in the proposal).

---

## 8. Non-GCP note

Specialist GPU clouds (RunPod/Vast/Lambda/Modal) are typically **40–60% cheaper
than GCP spot** for equivalent A100/H100, but lack GCP's credits, managed
networking, and compliance. If the RL is pure research with no data-residency
constraint, price both before committing.
