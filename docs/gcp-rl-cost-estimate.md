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
  requires a budget increase or credits. **G4 DWS Flex-start (~$3.6–5.0k,
  non-preemptible) is the recommended procurement.**
- **Stay inference-only.** Keep Tier A documented as the "if credits appear"
  path; trigger RL only after **E1 shows verifier-dependent evasion**.

---

## 8. Non-GCP comparison

Specialist clouds (RunPod/Vast/Lambda/Modal) are typically **40–60% cheaper than
GCP spot** for equivalent A100 (roughly $0.6–$1.2/hr/GPU vs GCP's ~$2.2/hr on
`a2-highgpu-1g`). GCP's advantages are credits, compliance, and managed
networking — not raw price. Price both before committing.

---

## 9. G4 alternative — 4× RTX PRO 6000 (the likely best fit)

**Confirmed: your `$9.00/hr` is the DWS Flex-start price.** GCP's G4 Flex-start
table (user-supplied, matches Google's DWS pricing):

| Machine type | GPUs | vCPU / RAM | DWS Flex-start | ~per GPU-hr |
|---|---|---|---|---|
| `g4-standard-6` | 1/8 | 6 / 22 GiB | $0.32344 | $2.5875 |
| `g4-standard-12` | 1/4 | 12 / 45 GiB | $0.64688 | $2.5875 |
| `g4-standard-24` | 1/2 | 24 / 90 GiB | $1.29376 | $2.5875 |
| `g4-standard-48` | 1 | 48 / 180 GiB | $2.2500 | $2.2500 |
| `g4-standard-96` | 2 | 96 / 360 GiB | $4.5000 | $2.2500 |
| `g4-standard-192` | 4 | 192 / 720 GiB | **$9.0000** | $2.2500 |
| `g4-standard-384` | 8 | 384 / 1440 GiB | $18.0000 | $2.2500 |

**Price ladder for `g4-standard-192`** (us-central1):

| Procurement | $/hr | ~$/GPU-hr | Preemptible? |
|---|---|---|---|
| Spot | 7.0866 | 1.77 | Yes |
| **DWS Flex-start** | **9.0000** | **2.25** | **No — fixed duration** |
| 1-yr CUD | ~12.42 | ~3.10 | No |
| Standard on-demand | 17.9997 | 4.50 | No |
| 3-yr CUD | ~7.92 | ~1.98 | No |

Flex is ~50% off standard and only ~27% above spot — **without preemption**.
Fractional shapes cost more per GPU ($2.59); whole-GPU shapes are $2.25. Flex-start
requires a requested duration and capacity is not guaranteed at a given time.

**Per-GPU-hour comparison**

| Option | Std/GPU-hr | Spot/GPU-hr | Flex/GPU-hr | VRAM/GPU | Interconnect |
|---|---|---|---|---|---|
| G4 (RTX PRO 6000) | $4.50 | $1.77 | **$2.25** | **96 GB** | PCIe (no NVLink) |
| A2 (A100 40GB) | $3.67 | $2.20 | — | 40 GB | NVLink |
| A3 (H100 80GB) | $11.06 | $6.62 | — | 80 GB | NVLink |

**G4 Flex-start is the best-value option for this workload:** $2.25/GPU-hr with
**no preemption** is essentially A100-spot pricing ($2.20/GPU-hr, but
preemptible) with **2.4× the VRAM** and 192 vCPU attached. It beats A100 spot on
memory and reliability at the same price.

### Is 4× RTX PRO 6000 enough for the training?

**Yes — comfortably, for the whole in-scope RL workload.**

| Training target | Need | 4× RTX PRO 6000 (384 GB) |
|---|---|---|
| 7–8B LoRA / QLoRA SFT | 12–24 GB | ✅ trivially |
| 7–8B **full** fine-tune (FSDP) | ~130 GB | ✅ |
| 32B QLoRA / LoRA | 24–90 GB | ✅ (fits one card) |
| 32B full fine-tune | ~512 GB | ❌ |
| 70B QLoRA | 40–90 GB | ✅ (1–2 cards) |
| GRPO 3–8B (SFT+rollouts) | rollout-heavy | ✅ 4 replicas or TP=2×2 |
| Frontier full FT / pretraining | TB-scale | ❌ (out of scope) |

**Caveats that matter more than capacity**

1. **No NVLink (PCIe only).** Avoid tensor parallelism >2. Run **4 independent
   vLLM replicas** (data-parallel) for rollouts and DDP/FSDP (or single-GPU LoRA)
   for training. This suits our workload, which is rollout-bound, not
   tensor-bound.
2. **Blackwell software support.** RTX PRO 6000 is a Blackwell part; verify
   CUDA/`torch`/`vLLM`/`flash-attn` wheels support it before starting. This is
   the most likely blocker.
3. **Environment CPU may become the critical path.** 192 vCPU over a 300-node-hr
   GPU run = 57.6k vCPU-hr, but the run needs ~120k vCPU-hr of tool/sandbox
   compute. So the **env outlasts the GPU** (~625 wall-clock hr vs 300) — rent an
   additional CPU pool, or cut per-episode tool cost, or the GPU idles waiting.
4. **Quota and availability.** G4 requires quota; use DWS to reserve capacity.
5. **Spot preemption** → checkpoint LoRA + rollout buffer frequently.

### G4 tier costs (incl. env CPU)

| Tier | Shape | GPU-hours → node-hours | Flex ($9) | Spot ($7.09) | Standard ($18) |
|---|---|---|---|---|---|
| A (sanity) | `g4-standard-96` (2 GPU) | 120–160 → 60–80 | **~$0.40–0.56k** | ~$0.32–0.44k | ~$1.2–1.5k |
| B (serious) | `g4-standard-192` (4 GPU) | 1,200 → 300 | **~$3.6–5.0k** | ~$3.0–4.5k | ~$7.7k |
| C (ablations) | `g4-standard-192` (4 GPU) | 3,500 → 875 | **~$9.8–12.8k** | ~$8.1–11.0k | ~$20.7k |

Line items (Tier B): GPU $2,700 (Flex) + env CPU $750 (spot) to $2,184
(on-demand) + storage $150. Tier A uses the 2-GPU shape for better vCPU
coverage; Tier C: GPU $7,875 + env $1,580–$4,620 + $300.

**Verdict on G4:** with the confirmed **$9.00/hr DWS Flex-start** rate,
`g4-standard-192` is the **best-value option for the RL contingency** — enough
VRAM for everything in scope (96 GB/GPU, 384 GB total), plenty of vCPU for the
tool environment, **no preemption**, and Tier B at **~$3.6–5.0k** — equal to or
better than A100 spot (~$3.7k) while being more reliable and more capable. Its
only real risks are Blackwell wheel support and PCIe-only scaling, neither of
which our data-parallel, rollout-heavy loop cares much about. For the current
inference-only phase it is overkill; for the Tier A sanity run, the 2-GPU
`g4-standard-96` shape is the right size.

## 10. Wall-clock training time

GPU-hours ÷ accelerators = wall-clock. Assumes 7B-class QLoRA/LoRA, ~3–6k
tok/s effective per GPU.

| Stage | GPU-hours | G4 `g4-standard-192` (4 GPU) | A100×8 (`a2-highgpu-8g`) | H100×8 (`a3-highgpu-8g`) |
|---|---|---|---|---|
| SFT warm start | 10–40 | 3–10 h (sharded) / 10–40 h (1 GPU) | 1.5–5 h | 1–4 h |
| DPO | 40–150 | 10–38 h | 5–19 h | 3–12 h |
| GRPO — Tier A (sanity) | 120–160 | **30–40 h** | 15–20 h | 10–13 h |
| GRPO — Tier B (serious) | ~1,200 | **~300 h ≈ 12.5 days** | ~150 h ≈ 6.3 days | ~90 h ≈ 3.8 days |
| GRPO — Tier C (ablations) | ~3,500 | **~875 h ≈ 36.5 days** | ~438 h ≈ 18.3 days | ~260 h ≈ 11 days |

**Tier B pipeline (one policy, 3 verifiers):** SFT ~0.5 day + DPO ~1 day +
GRPO ~12.5 days ≈ **~14 days GPU-bound** on G4; **~8 days** on 8×A100.
With **DWS Flex-start there is no preemption overhead**; on spot add **+10–15%**
for restart/checkpoint recovery.

**Environment CPU can extend wall-clock.** Tier B needs ~120k vCPU-hr; the G4
node's 192 vCPU only supply ~58k over a 300-h GPU run, so env work outlasts the
GPU (~625 h if unparallelized). Attach a separate 192-vCPU pool to keep the
critical path on the GPU.

**Realistic calendar time for the full study (Tier C, ~4 verifiers with
ablations):** **4–10 weeks** including debugging, failed runs, and re-runs —
not a single clean run. Tier B is **2–4 weeks**.

> Reminder: this is the **deferred RL** path. The headline experiment E1
> (verifier evasion) needs **0 training hours** — it is inference-only.

## 11. T4 (Turing) — works for smoke tests, not for the RL training

NVIDIA T4: Turing, **16 GB GDDR6**, ~320 GB/s, ~65 TFLOPS FP16 / 260 TOPS INT8.
Introduced 2018; available on GCP as an N1-attached GPU (~$0.35/GPU-hr + CPU),
and free on Colab/Kaggle.

**Capability assessment**

| Use case | T4 verdict |
|---|---|
| Static analysis / tooling | N/A — CPU work |
| E1 inference (≤3B Q4) | ✅ workable, slow |
| E1 inference (7B Q4) | ⚠️ fits, ~15–30 tok/s |
| SFT — 1–3B LoRA/QLoRA | ✅ fine |
| SFT — 7B QLoRA | ⚠️ possible, very slow |
| DPO — 7B | ⚠️ slow |
| **GRPO — 3–8B (our RL)** | ❌ **impractical** |
| 32B / 70B anything | ❌ (16 GB) |
| Long-context agent (16–32k) | ❌ no FlashAttention-2, bandwidth-bound |

**Why it fails for our RL, specifically**

1. **No BF16** (Turing predates it) → FP16 + loss scaling or 4-bit only.
2. **No FlashAttention-2** (needs Ampere+). Our agent runs long contexts
   (accumulated code + tool output); without FA2, attention memory and time
   explode.
3. **320 GB/s bandwidth** → ~5× slower rollout throughput than A100, so the
   rollout-dominated GRPO loop takes weeks-to-months instead of days.
4. **PCIe only**, no NVLink — same scaling limit as G4, but without the compute
   or memory to compensate.
5. **Poor cost-per-token.** Even at ~$0.35/hr, T4 delivers a small fraction of an
   A100 spot's throughput, so it is usually *more* expensive per useful token.

**Where T4 is genuinely useful here**

- **Pipeline smoke tests** on 1–3B models to validate SFT/QoRA/GRPO code paths
  before renting real hardware (Colab/Kaggle are free).
- **Cheap local inference** for small models if no GPU is otherwise available.
- **CPU-bound tooling** — but that needs no GPU at all.

> **Note:** the local **RTX 3070 Ti is architecturally better than a T4** for this
> work (Ampere sm86 → BF16 + FlashAttention-2 + 608 GB/s), despite 8 GB vs 16 GB.
> T4's only advantage is VRAM. It is not an upgrade path.

**Verdict:** do not provision T4 for training. Use it only for free smoke tests;
run the actual RL on A100/G4, and run the current inference-only phase on an API
or a small rented L4/A100.

---

### Revision note

Supersedes the earlier placeholder estimate in this file (which used unverified
list prices). Corrections: Tier A confirmed ~$0.4k; Tier B ~$3.3k → **~$3.7k**;
Tier C ~$9.2k → **~$11k** (environment CPU priced explicitly). H100 penalty
quantified at ~3×.

**Addendum (G4):** `g4-standard-192` fetched at **$18.00 standard / $7.09 spot**;
the user-supplied table confirms **$9.00/hr is DWS Flex-start** (= 50% of list,
$2.25/GPU-hr, non-preemptible). G4 is VRAM-rich (4×96 GB) and vCPU-rich
(192/720 GB), making it the **best-value RL option**; Tier B ~$3.6–5.0k, Tier C
~$9.8–12.8k. Main risks: Blackwell wheel support, PCIe-only scaling, and
environment CPU becoming the critical path. **T4 is not viable for training**
(§11) — smoke tests only.
