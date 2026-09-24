# Google Cloud RL Cost Estimate (contingency)

Answers: *if we run the RL experiment (E2/C4), what does it cost on GCP?*
Companion to `docs/compute-and-model-strategy.md` §6.

> **Status:** contingency. The project is currently **inference-only, $0–$1k**
> (ADR-0002). This prices the deferred RL path.
>
> **Sources (fetched 2026-09-24):**
> - GPU/VM prices: [gcloud-compute.com](https://gcloud-compute.com/) (data last
>   updated **2026-09-21**, derived from GCP list prices), us-central1.
> - TPU prices: [cloud.google.com/tpu/pricing](https://cloud.google.com/tpu/pricing) (official).
> - Environment CPU prices are **estimates** (see §2), not fetched.
>
> GPU monthly ÷ 730 = per-hour used for CUD rows.

---

## 1. Actual GCP accelerator prices (us-central1, USD/hour)

| Machine type | Accelerator | Standard | Spot | 1-yr CUD | 3-yr CUD |
|---|---|---|---|---|---|
| `a2-highgpu-1g` | 1× A100 40 GB | **3.6734** | **2.2040** | 2.3134 | 1.2857 |
| `a2-ultragpu-1g` | 1× A100 80 GB | **5.0688** | **3.0412** | n/a* | n/a* |
| `a2-highgpu-8g` | 8× A100 40 GB | **29.3871** | **17.6321** | 18.5137 | 10.2857 |
| `a3-highgpu-8g` | 8× H100 80 GB | **88.4900** | **52.9623** | 61.3837 | 38.8644 |
| `g2-standard-4` | 1× L4 24 GB | **0.7068** | **0.4241** | 0.4453 | 0.3181 |
| `g2-standard-24` | 2× L4 24 GB | **2.0008** | **1.2003** | 1.2605 | 0.9004 |

\* `a2-ultragpu-1g` shows no CUD discount in the source data — verify before
relying on a commitment for A100 80 GB.

Other regions cost 15–38% more; `us-central1` (Iowa) is at or near cheapest.
A3/H100 spot is volatile (us-central1 ~$52.96, but Finland ~$9.14 when capacity
is idle).

**Official TPU prices** (per chip-hour, on-demand / DWS Flex / 1-yr CUD):

| TPU | On-demand | Flex-start | 1-yr CUD |
|---|---|---|---|
| v5e | $1.20 | $0.60 | $0.84 |
| v5p | $4.20 | $2.10 | $2.94 |
| Trillium (v6e) | $2.70 | $1.35 | $1.89 |
| Ironwood (v7) | $12.00 | $6.00 | $8.40 |
| v4 | $3.22 | — | $2.03 |

> **TPU fit caveat:** the RL loop is rollout-dominated and CUDA-centric (vLLM +
> HF/TRL or verl). The environment is CPU-bound anyway. **GPU is the default**;
> TPU only if we move to a JAX stack.

---

## 2. Assumptions

| Quantity | Value | Source |
|---|---|---|
| Policy | 3–8B LoRA (frozen base) | ADR-0001 |
| Episodes/epoch | ~80,000 | compute doc |
| GPU/epoch | 200–600 GPU-hr | compute doc |
| Full serious run | 1,200 GPU-hr | compute doc |
| Environment CPU | 0.5 vCPU-hr/episode → 120k vCPU-hr for 240k episodes | estimate |
| Env CPU price | **$0.035 / vCPU-hr** on-demand, **$0.012** spot | *estimate* (n2/e2 class) |
| Storage/egress | ~$50–300 | estimate |

Note: the 8×A100 node includes **96 vCPU / 680 GB RAM**, so part of the
environment compute runs "free" on the GPU node. Net external CPU is reduced by
~96 × node-hours in each tier (already subtracted below).

> **Verify both caveats before budgeting:** (1) env-CPU price, (2) A100 80GB CUD.

---

## 3. RL cost estimates (us-central1)

### Tier A — Minimal sanity run (3B, 1 verifier, ~20k episodes)

| Line item | Qty | Standard | Spot |
|---|---|---|---|
| GPU `a2-highgpu-1g` (1×A100 40GB) | 120–160 GPU-hr | $441–$588 | $264–$353 |
| Environment CPU | 10k vCPU-hr | $350 | $120 |
| Storage/egress | — | ~$50 | ~$50 |
| **Total** | | **~$840–$990** | **~$430–$520** |

Cheaper pilot variant: `g2-standard-24` (2×L4) at $2.00/hr ($1.20 spot) — lower
throughput, but roughly half the GPU cost for a 3B model.

### Tier B — Serious single-policy RL (3–8B, 3 verifiers, 3 epochs, ~1,200 GPU-hr)

On `a2-highgpu-8g` (8×A100 40GB), 150 node-hours:

| Line item | Qty | Standard | Spot | 1-yr CUD GPU + spot CPU |
|---|---|---|---|---|
| GPU node | 150 node-hr | $4,408 | $2,645 | $2,777 |
| Environment CPU (net) | ~77k vCPU-hr | $2,700 | $900 | $900 |
| Storage/egress | — | ~$150 | ~$150 | ~$150 |
| **Total** | | **~$7.3k** | **~$3.7k** | **~$3.8k** |
| 3-yr CUD GPU + spot CPU | | | | ~$2.6k |

H100 alternative (`a3-highgpu-8g`): **$13.3k standard / $7.9k spot** — ~3× the
A100 cost for no benefit at 3–8B. Only use if latency-bound.

### Tier C — Frontier RL (full verifier ablations, 8B, ~3,500 GPU-hr)

On `a2-highgpu-8g`, ~438 node-hours:

| Line item | Qty | Standard | Spot | 1-yr CUD GPU + spot CPU |
|---|---|---|---|---|
| GPU node | ~438 node-hr | $12,857 | $7,714 | $8,100 |
| Environment CPU (net) | ~258k vCPU-hr | $9,030 | $3,000 | $3,000 |
| Storage/egress | — | ~$300 | ~$300 | ~$300 |
| **Total** | | **~$22.2k** | **~$11.0k** | **~$11.4k** |

---

## 4. Summary

| Tier | Scope | Standard | **Spot** | 1-yr CUD |
|---|---|---|---|---|
| A | 3B, 1 verifier, 20k episodes | ~$0.9k | **~$0.45k** | ~$0.6k |
| B | 3–8B, 3 verifiers, 3 epochs | ~$7.3k | **~$3.7k** | ~$3.8k |
| C | ablations, 8B, ~3,500 GPU-hr | ~$22.2k | **~$11.0k** | ~$11.4k |

**Spot vs standard: ~2× cheaper** (less than the 60–70% off on GPU alone,
because environment CPU doesn't discount as much). **3-yr CUD** on tier B would
reach ~$2.6k, but a multi-year commitment is unrealistic for a research pilot.

**Environment CPU is 25–40% of the SPOT bill and up to 40% of standard** — the
most commonly forgotten line item.

---

## 5. Cost-optimization checklist

1. **Use A100 40GB (`a2-highgpu-8g`), not H100** — ~3× cheaper, sufficient for
   3–8B LoRA.
2. **Spot + aggressive checkpointing** (LoRA + rollout buffer every few minutes).
   Budget +10–15% wallclock for preemption/restart.
3. **Run env CPU on Spot/`e2`/`n2`**, co-locating part on the GPU node's 96 vCPU.
4. **Cap context** (KV cache dominates rollout cost).
5. **DWS Flex-start** for a fixed 1–2 week window instead of continuous CUD.
6. **Region:** us-central1 (cheapest, `us-east5`/`us-west1` same).
7. **L4 (`g2-*`)** for 3B pilots — cheapest per hour, lower throughput.
8. **Offline stages (SFT/DPO)** can use Vertex AI tuning instead of self-host.

---

## 6. Credits that could fund it

- **$300** GCP new-account credits.
- **Google for Startups Cloud Program** — large credits.
- **Google Research Credits / academic grants** — for public-artifact papers.

If any apply, Tier B moves from "out of budget" to free.

---

## 7. Verdict

- **Tier A spot (~$0.45k) fits the current $1k budget** — but it is a
  single-verifier sanity run, not enough for C4's verifier-comparison claims.
- **Tier B spot (~$3.7k) is the real minimum** for a publishable RL result and
  requires a budget increase or credits.
- **Stay inference-only.** Keep Tier A documented as the "if credits appear"
  path; trigger RL only after **E1 shows verifier-dependent evasion**.

---

## 8. Non-GCP comparison

Specialist clouds (RunPod/Vast/Lambda/Modal) are typically **40–60% cheaper than
GCP spot** for equivalent A100 (roughly $0.6–$1.2/hr/GPU vs GCP's ~$2.2/hr on
`a2-highgpu-1g`). GCP's advantages are credits, compliance, and managed
networking — not raw price. Price both before committing.

---

### Revision note

Supersedes the earlier placeholder estimate in this file (which used unverified
list prices). Corrections: Tier A confirmed ~$0.4k; Tier B ~$3.3k → **~$3.7k**;
Tier C ~$9.2k → **~$11k** (environment CPU priced explicitly). H100 penalty
quantified at ~3×.
