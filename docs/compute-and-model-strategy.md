# Compute Requirements & Model Strategy

Companion to `docs/rl-vulnerability-analysis-plan.md`. Addresses backlog items
**B7** (no compute budget), **C1** (8 GB VRAM cannot support the plan), and **D3**
(RL premise unaffordable).

> All figures are order-of-magnitude planning estimates with stated assumptions,
> not vendor quotes. Re-baseline after Phase 1/2 measurements.

---

## 1. Assumptions

**Agent episode profile** (the unit that drives everything):

| Quantity | Assumption |
|---|---|
| LLM calls per episode | ~40 |
| Raw input tokens per call | ~6k (retrieved snippets + tool output) |
| Raw input per episode | ~240k tokens |
| Effective billed input (prefix caching) | ~60–100k tokens |
| Output tokens per episode | ~16k |
| Tool/CPU work per episode | 0.2–2 vCPU-hours (sandbox, tests, fuzz) |

**Scale points**

- Evaluation set: 300 repos × 8 episodes = **2,400 episodes per eval pass**
  → 576M raw input / 38.4M output tokens.
- RL rollout epoch: 10k prompts × 8 group samples = **80,000 episodes**
  → 19.2B raw input / 1.28B output tokens.

**Prices used** (USD, 2026 planning anchors — verify current)

| Resource | Rate |
|---|---|
| Frontier API | ~$3 / M in, ~$15 / M out (cached input ~$0.3–0.75 / M) |
| Mid-tier API | ~$0.75 / M in, ~$3 / M out |
| A100 80GB / H100 | ~$1.5 / hr · ~$3 / hr |
| RTX 4090 24GB / L40S / A6000 | ~$0.4 / hr · ~$0.8–1.2 / hr |
| CPU vCPU | ~$0.02–0.04 / hr |
| Storage | ~$0.02 / GB-month |

---

## 2. Compute by phase

### Phase 0–1 — Tool ensemble baseline (no ML)
Static analysis (Semgrep/CodeQL/linters/dep audit) over 300 repos.

| Item | Estimate |
|---|---|
| CPU | 2,000–10,000 vCPU-hours |
| RAM peaks | 32–128 GB (CodeQL on monorepos) |
| Storage | 0.5–2 TB (repos + SARIF + caches) |
| GPU | 0 |
| Cost | **$100–$500** |

*Local laptop:* viable but slow; run batched overnight. CodeQL RAM is the main ceiling (15 GB total on this machine).

### Phase 2 — Prompted agent, no RL

| Item | Estimate |
|---|---|
| Eval pass (2,400 episodes) | 576M in / 38.4M out |
| — frontier API | **$1.7k–$2.3k / pass** |
| — mid API | **$0.4k–$0.6k / pass** |
| — self-host 7B on A100 | 12–20 GPU-hr → **$20–$40 / pass** |
| Dev iterations (≈20 passes) | **$5k–$46k** (API) or **~300 GPU-hr** (self-host) |
| Tool/CPU | 2,000–8,000 vCPU-hours |

Self-hosting a 7B for eval is ~50–100× cheaper than frontier API but needs a
rented GPU. On the laptop, 7B Q4 inference at ~20–40 tok/s makes a full eval pass
take ~10–20 days of continuous generation — impractical.

### Phase 3 — SFT / LoRA

| Item | Estimate |
|---|---|
| Training tokens | 30–120M (5k–20k trajectories × ~6k tokens) |
| QLoRA 7B on A100 | 10–25 GPU-hr |
| QLoRA 7B on RTX 4090 | 60–150 GPU-hr |
| QLoRA 7B on laptop 3070 Ti (8 GB) | **not viable at scale**; smoke test only (seq ≤1024, batch 1) |
| Full fine-tune 7B | 2–8× A100 80GB (80–100 GB optimizer+weights) |
| Cost | **$30–$200** |

SFT is cheap relative to data collection and rollouts.

### Phase 4 — Preference optimization (DPO/ORPO/KTO)

| Item | Estimate |
|---|---|
| Cost vs SFT | ~2–3× (reference model + preference pairs) |
| GPU | 20–60 A100-hr |
| Cost | **$50–$400** |

**Offline methods need no live rollouts** — they reuse logged trajectories. This
is the recommended first "learning" step.

### Phase 5 — Online RL (GRPO/RLOO), per epoch

| Item | Estimate |
|---|---|
| Rollout episodes | 80,000 |
| Raw tokens | 19.2B in / 1.28B out |
| Generation + prefill on 8×A100 (prefix-cached) | 200–600 GPU-hr |
| Policy updates | +20–40% |
| **Environment/tool CPU** | **16,000–160,000 vCPU-hr** ← often dominates |
| GPU cost / epoch | **$300–$1,800** |
| CPU/tool cost / epoch | **$500–$6,000** |
| Typical run (3 epochs) | **1,000–4,000 GPU-hr + 50k–500k vCPU-hr** |
| Cost / run | **$2k–$18k** |
| Or with API rollouts | **$30k–$60k / epoch** (not recommended) |

Online RL is the single most expensive workstream and the one the ablation gate
may cancel.

### Phase 6 — Dynamic verification & fuzzing

| Item | Estimate |
|---|---|
| Fuzz campaigns | 100–1,000 CPU-hr each |
| Targets | 50–200 |
| Total | **10,000–200,000 vCPU-hours** |
| Cost | **$300–$8,000** |

Fuzzing often dominates total project CPU. Budget it explicitly and cap per
target.

---

## 3. Scenario totals

| Scenario | Scope | Compute | Wallclock | Cost |
|---|---|---|---|---|
| **Pilot** | 10 CVEs + canary repo, prompted agent only, no training | API + 500–2k vCPU-hr | 1–2 weeks | **$1k–$4k** |
| **Serious** | 300 repos, SFT + DPO + full eval, no online RL | 50–200 GPU-hr + 10k–40k vCPU-hr | 2–3 months | **$3k–$15k** |
| **Frontier** | Online RL + dynamic track, 300+ repos | 1k–4k GPU-hr + 100k–500k vCPU-hr | 3–6 months | **$15k–$75k** |

Storage across scenarios: 0.5–5 TB (**$10–$100/mo**).

---

## 4. What this machine can and cannot do

| Capability | On RTX 3070 Ti 8 GB / 15 GB RAM |
|---|---|
| 7B Q4 inference | ✅ (slow, ~20–40 tok/s; dev/smoke only) |
| 14B Q4 inference | ⚠️ partial offload, very slow |
| 32B+ / 70B inference | ❌ (rent) |
| QLoRA SFT 7B | ⚠️ smoke test only; real training = rent |
| DPO / GRPO | ❌ (rent; RL needs multi-GPU + 100s of GB RAM) |
| Static tooling | ✅ CPU-bound, slow for CodeQL |
| Sandbox/microVM host | ❌ use isolated remote worker; do not run hostile code here (C7) |

**Verdict:** the laptop is a *development and orchestration* machine. Every
training and large-scale evaluation workload must be rented. This does not kill
the project; it changes the architecture to **API-or-rented policy + local
tooling**.

---

## 5. Addressing the model

### 5.1 Model options

| Tier | Examples (families) | Params | Local 8 GB? | Role |
|---|---|---|---|---|
| Local small | Qwen2.5-Coder-7B, Llama-3.1-8B, GLM-4-9B | 7–9B | ✅ Q4 | router, triage, offline privacy |
| Local medium | DeepSeek-Coder-V2-Lite (MoE) | 16B | ⚠️ offload | private deployment |
| Rented open | Qwen2.5-Coder-32B, Codestral-22B | 22–32B | ❌ | self-hosted policy |
| Rented large | 70B-class open | 70B | ❌ | strongest open policy |
| API frontier | Claude / GPT / Gemini class | — | ✅ (network) | best capability, data-egress risk |

Choose per **B1** (deployment/privacy). Default: frontier API for data
generation + evaluation, local 7B for private deployment and cheap routing.

### 5.2 Training ladder (cheapest → most expensive)

| Step | Method | Rollouts needed | Compute | When |
|---|---|---|---|---|
| 0 | Prompting + tools + test-time scaling (best-of-N, verifier selection) | none | inference only | **always start here** |
| 1 | Trajectory distillation → SFT (LoRA/QLoRA) | none (logged) | ≤25 A100-hr | after G1 beats G0 |
| 2 | Offline preference optimization (DPO/ORPO/KTO/SimPO) | none (logged pairs) | 20–60 A100-hr | before any RL |
| 3 | Process reward model (1–7B classifier) | none | small | when step credit needed |
| 4 | Online RL (GRPO/RLOO/PPO) | 80k/episode-epoch | 1k–4k GPU-hr | **only if DPO plateaus** |
| 5 | Distill back to small policy | inference | small | deployment |

### 5.3 Methods to cope with limited compute

**Architecture-level (biggest levers)**
- **Push intelligence into tools and verifiers; keep the policy small.** A
  tool-heavy / model-light design needs far less training and generalizes better.
- **RAG + episodic memory over weight updates.** New patterns become retrievals,
  not gradient steps.
- **Train only the router/prioritizer**, not the whole analyzer. The router can
  be a ≤1B classifier — trainable on a laptop.
- **Hybrid policy:** cheap local model for routine steps, frontier API only for
  hard reasoning (cascaded/budgeted).

**Test-time methods (often beat RL per dollar)**
- Best-of-N sampling + verifier-based selection.
- Tree search / MCTS guided by tool feedback and the verifier.
- Reflection / self-critique loops with re-verification.
- More sampling on high-uncertainty findings, less on confident ones.

**Inference efficiency**
- 4-bit quantization; vLLM / llama.cpp / SGLang.
- Prefix/KV caching across agent steps (cuts effective input 3–4×).
- Speculative decoding; batched rollouts; continuous batching.
- Cap context growth via summarization + retrieval.

**Training efficiency**
- LoRA/QLoRA only; frozen base; swappable adapters (100 MB each).
- Gradient checkpointing, sequence packing, short-horizon curriculum.
- Async rollout workers; replay buffers; environment caching/dedup.
- Offline RL / DPO from logged trajectories — no live environment cost.
- Distill frontier → small local model for deployment.

**Infrastructure paths**
- Single rented GPU (4090/L40S/A6000/A100) for SFT+DPO trials.
- 8×A100/H100 (spot) for GRPO.
- Serverless GPU (Modal/RunPod/Vast/Lambda) for bursty rollouts.
- Free/credit tiers (Colab T4, Kaggle, HF, cloud research credits, TRC).
- VPC/on-prem when code cannot leave the perimeter.

### 5.4 Recommended path

1. **Weeks 1–3:** Phase 0–2 on the laptop + API. Build tool ensemble and prompted
   agent. Establish G0/G1 baselines and cost-per-TP. No training.
2. **Weeks 4–6:** Rent **one 24–48 GB GPU for ~1 week (~$100–$300)** for SFT +
   DPO on logged trajectories. Check the G2 gate.
3. **Weeks 7+:** **Only if DPO clearly beats the prompted baseline**, rent
   **8×A100 for 2–4 weeks** for a GRPO pilot against the reward-hack suite.
4. **Deploy** a distilled 7B Q4 locally; keep the frontier API as an optional
   escalation path for hard cases.

**Kill criteria:** if the prompted agent (step 1) does not beat the tool
ensemble on cost-per-TP, or DPO does not beat prompting, stop before spending on
online RL. Shipping the tool-orchestrated assistant is a valid outcome.

---

## 6. Training & fine-tuning compute (detailed)

Memory is driven by method. LoRA/QLoRA scale well; full fine-tuning does not.

**Memory footprint by method** (mixed precision, gradient checkpointing on):

| Model | Full FT (ZeRO-3) | LoRA (bf16 base) | QLoRA (4-bit) |
|---|---|---|---|
| 1B | 1×24 GB | 1×16 GB | 1×8 GB |
| 7–8B | 4–8×A100 80 GB | 1×24 GB | 1×12–16 GB |
| 14B | 8×A100 80 GB | 1×48 GB | 1×24 GB |
| 32B | 16×A100 80 GB | 2×48 GB | 1×48 GB |
| 70B | 32–64×A100 80 GB | 8×48 GB | 2×80 GB |

Full FT ≈ 16 bytes/param + activations (weights + grads + Adam + master weights).
LoRA stores optimizer state only for adapters, so it is ~10× cheaper.

**Effective throughput** (tokens/s, seq 4k, packing on — planning anchors):

| Method | RTX 4090 24 GB | A100 80 GB | 8×A100 |
|---|---|---|---|
| 7B QLoRA | 1,000–2,000 | 3,000–6,000 | 20k+ |
| 7B LoRA bf16 | 700–1,500 | 2,500–5,000 | 18k+ |
| 7B full FT | — | — | 10k–20k |
| 32B QLoRA | offload only | 800–1,500 | 6k–12k |
| 70B QLoRA | — | 300–600 | 2k–5k |

**Run estimates**

| Run | Data | GPU-hours | Wallclock | Cost (@$1.5/A100-hr) |
|---|---|---|---|---|
| 7B QLoRA SFT | 30–100M effective tokens | 10–40 | <1 day (1 GPU) | **$15–$60** |
| 7B QLoRA DPO | 50k–200k pairs | 40–150 | 1–2 days | **$60–$225** |
| 7B LoRA SFT+DPO (4090) | 30–100M | 100–300 | 3–7 days | **$40–$150** |
| 32B QLoRA SFT | 100–300M | 60–200 | 2–4 days | **$90–$300** |
| 32B QLoRA SFT+DPO | 100–300M | 250–800 | ~1 week | **$375–$1,200** |
| 70B QLoRA SFT+DPO | 100–300M | 800–2,600 | 1–2 weeks | **$1,200–$3,900** |
| 7B full FT | 100–300M | 50–250 | 1–3 days (4–8 GPU) | **$300–$1,500** |
| Reward model (1–7B) | 1–5M labels | 20–80 | 1 day | **$30–$120** |
| **Online RL (GRPO)** | 3 epochs | **1,000–4,000** | **2–6 weeks (8 GPU)** | **$1,500–$6,000** |
| Big-lab RL (70B) | large | 10,000–40,000 | 1–3 months | **$15k–$60k** |

**Scenario totals for training only**

| Scope | GPU-hours | Cost | Wallclock |
|---|---|---|---|
| **Minimum viable** (7B QLoRA SFT + DPO) | 50–200 | **$100–$300** | 2–4 days |
| **Serious** (7–32B SFT + DPO + reward model) | 300–1,000 | **$500–$2,000** | 1–2 weeks |
| **Frontier** (+ online RL) | 1,300–5,000 | **$2,000–$8,000** | 3–6 weeks |
| **Big-lab** (70B full RL) | 10k–40k | **$15k–$60k** | 1–3 months |

Takeaways:
- **QLoRA/LoRA make fine-tuning nearly free.** A pilot SFT+DPO on a 7–8B model is a
  few hundred dollars on one rented GPU.
- **Online RL is 10–50× the training cost** and is where budgets explode.
- **Data collection and evaluation usually cost more than training.** Budget
  them together.
- The free tier (Colab T4 16 GB / Kaggle 2×T4) can run a 7B QLoRA smoke test but
  not a production run.

---

## 7. Live deployment compute

Live serving cost is driven by **context length × concurrency**, not model size
alone. Agent workloads carry large contexts (accumulated code + tool output), so
KV cache dominates.

**KV cache per sequence** (fp16, GQA):

| Model | MB/token | 8k ctx | 32k ctx | 128k ctx |
|---|---|---|---|---|
| 7–8B (8 KV heads) | ~0.125 | 1 GB | 4 GB | 16 GB |
| 32B (8 KV heads) | ~0.25 | 2 GB | 8 GB | 32 GB |
| 70B (8 KV heads) | ~0.31 | 2.5 GB | 10 GB | 40 GB |

Weights: 8B = 16 GB fp16 / 5 GB 4-bit · 32B = 64 GB / 18 GB · 70B = 140 GB / 40 GB.

**Serving tiers**

| Tier | Model / precision | Context | Concurrency | GPU | VRAM | Aggregate output | Cost |
|---|---|---|---|---|---|---|---|
| Dev / single user | 7B 4-bit | 8k | 1 | local 3070 Ti 8 GB | ~6 GB | 20–40 tok/s | $0 (owned) |
| Team / small prod | 8B fp16 | 16k | 10–20 | 1×L40S 48 GB | ~40 GB | 1.5–2.5k tok/s | **~$700/mo** |
| Small prod+ | 8B fp16 | 32k | 15 | 1×A100 80 GB | ~76 GB | 2–3k tok/s | **~$1,100/mo** |
| Medium | 8B fp16 (TP=2) | 32k | 40–60 | 2×A100 / 1×H100 | ~150 GB | 5–8k tok/s | **$2,200–$3,300/mo** |
| Medium+ | 32B 4-bit | 32k | 20–30 | 1×A100 80 GB | ~70 GB | 1.5–3k tok/s | **~$1,100/mo** |
| Large | 32B fp16 (TP=4) | 32k | 40 | 4×A100 80 GB | ~320 GB | 3–5k tok/s | **~$4,300/mo** |
| Enterprise | 70B 4-bit (TP=2) | 32k | 20–40 | 2×A100 80 GB | ~110 GB | 2–4k tok/s | **~$2,200/mo** |
| Enterprise+ | 70B fp16 (TP=8) | 32k | 40+ | 8×H100 | ~640 GB | 10–20k tok/s | **~$17,000/mo** |

Spot instances cut GPU cost 40–70% for **batch scanning**; interactive latency
requires on-demand or always-on.

**Full system deployment (not just the LLM)** — small production:

| Component | Spec | Cost |
|---|---|---|
| LLM inference | 1×L40S or A100 node | $700–$1,100/mo |
| Orchestrator + index + static tools | 16–32 vCPU, 64–128 GB RAM | $200–$500/mo |
| Sandbox worker pool | 4–16 ephemeral 4-vCPU pods | $100–$600/mo |
| Vector DB + storage (0.5–5 TB) | managed or self-hosted | $50–$300/mo |
| **Total** | | **~$1,100–$2,500/mo** |

Medium production: **~$5k–$8k/mo**. Enterprise: **~$20k–$40k/mo**.

**On-prem / privacy deployment (no data egress):**

| Scope | Hardware | Capex | Power/mo |
|---|---|---|---|
| 7–8B | 1×RTX 6000 Ada 48 GB / 2×4090 | $8k–$15k | ~$30–$60 |
| 32B | 1×A100 80 GB | $15k–$25k | ~$100 |
| 70B (4-bit) | 2×A100 80 GB | $30k–$50k | ~$200 |

**Deployment cost levers**

- **Cap and summarize context** — the single biggest serving cost driver
  (KV cache scales linearly with context).
- **Multi-LoRA serving** (vLLM/SGLang): one base model + many small adapters =
  cheap per-tenant customization instead of separate models.
- **Cascade routing:** small local model for routine steps, frontier API or
  large model only for hard cases. Typical 3–10× cost reduction.
- **Quantization** (AWQ/GPTQ 4-bit): ~4× less weight VRAM, minor quality loss.
- **Prefix caching:** reuse shared system/repo prefixes across agent steps.
- **Batch vs interactive separation:** batch scans → spot + throughput mode;
  interactive → latency mode with smaller context.
- **Autoscale to zero** for bursty workloads (serverless GPU).
- **Distill to a 3B-class policy** for deployment; keep the big model for
  training/data generation only.

**Key operational insight:** in this workload **tool latency usually dominates
end-to-end time**, so GPU over-provisioning is the wrong lever. Provision one
modest GPU node, cap context, and scale the *tool/sandbox* pool instead.

---

## 8. Open items this doc does not resolve

- B1: local-only vs external API still determines the model tier and legal posture.
- B6: model-based verifiers remain gameable; compute estimates assume cheap
  deterministic verifiers dominate.
- C3/C7: sandbox/microVM hosting is unpriced here beyond CPU hours; a dedicated
  isolated worker host is assumed.
