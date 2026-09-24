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

## 6. Open items this doc does not resolve

- B1: local-only vs external API still determines the model tier and legal posture.
- B6: model-based verifiers remain gameable; compute estimates assume cheap
  deterministic verifiers dominate.
- C3/C7: sandbox/microVM hosting is unpriced here beyond CPU hours; a dedicated
  isolated worker host is assumed.
