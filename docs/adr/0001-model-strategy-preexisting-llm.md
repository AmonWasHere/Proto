# ADR-0001 — Use a pre-existing LLM; do not pretrain a base model from scratch

- **Status:** Accepted
- **Date:** 2026-09-24
- **Deciders:** TBD (project owner)
- **Related:** `docs/archive/rl-vulnerability-analysis-plan.md` §2.3, §2.7;
  `docs/archive/compute-and-model-strategy.md` §5, §6; issues B7, C1, D3.

## Context

The plan refers to "training" and "SFT → RL" of the decision layer. It was not
explicit whether the base language model is:

1. a pre-existing model (open-weights or API) that we adapt, or
2. a model pretrained from scratch on code/security corpora.

This distinction determines budget by 3–5 orders of magnitude, so it must be
fixed before any implementation.

## Decision

**Use a pre-existing LLM as the base and adapt it. Never pretrain a base LM from
scratch.**

- **Base model:** frontier API model and/or open-weights 7–32B
  (Qwen-Coder / Llama / GLM / DeepSeek-Coder class), selected per ADR on
  deployment/privacy (B1).
- **Adaptation only:** frozen base + LoRA/QLoRA adapters via
  SFT → DPO → (optional) GRPO. The "policy" we train is the orchestration /
  decision behavior, not language or code understanding.
- **Small components may be trained from scratch** because they are cheap and
  produce no language ability on their own:
  - tool router / prioritizer classifier (0.1–1B),
  - process reward model (1–7B),
  - CWE / severity classifier,
  - optional dedup/similarity model fine-tuned from an existing code encoder.
- **Optional continued pretraining** (domain adaptation) may be considered later
  as a bounded experiment (1–10B security/CPG tokens, ~$100–$1,000), but it is
  **not** on the critical path and must beat the adapter-only baseline to ship.

## Rationale

1. **Cost.** Pretraining is 3–5 orders of magnitude more expensive than
   adaptation (see table below).
2. **Quality.** A from-scratch model trained on our budget would be far weaker
   than existing open 7–8B models that saw trillions of tokens.
3. **Data.** Competitive pretraining requires a 1–10T-token curated corpus and
   pipeline; that pipeline alone typically costs more than the GPU bill.
4. **Value location.** The project's contribution is tool orchestration,
   verification, and reward design — not language modeling. Adapting a strong
   base isolates the novelty and keeps experiments affordable.
5. **Hardware.** 8 GB VRAM / 15 GB RAM cannot pretrain anything; adaptation is
   already at the edge of this machine.

## Cost comparison

| Approach | GPU-hours | Approx. cost | Wallclock | Feasible here? |
|---|---|---|---|---|
| **LoRA/QLoRA adaptation (chosen)** | 10–800 | **$15–$1,200** | days | Yes (rent 1 GPU) |
| 7B pretrain from scratch (Llama-2-class) | ~184,000 A100-hr | **$275k–$370k** | weeks–months | No |
| 13B pretrain from scratch | ~369,000 A100-hr | **$550k–$740k** | months | No |
| 70B pretrain from scratch | ~1,720,000 A100-hr | **$2.6M–$3.4M** | months | No |
| Modern 8B (15T tokens) | ~1.3–2M H100-hr | **$4M–$8M** | months | No |
| Frontier (100B+) | 10M+ H100-hr | **$30M–$100M+** | many months | No |
| Continued pretraining (optional) | 20–200 | $30–$1,000 | days | Yes (rent) |

Pretraining figures are published-class estimates; data curation, evaluation,
alignment, and safety costs are additional and often comparable.

## Consequences

- We depend on the chosen base model's license, availability, and context window.
- Privacy posture is set by whether the base is API-hosted or self-hosted (B1).
- Adapters keep checkpoints tiny (~100 MB) and swappable, enabling multi-LoRA
  serving and cheap per-tenant customization.
- If adapters cannot express a needed capability, the fallback is **tooling or
  retrieval**, not pretraining.
- Any "from scratch" proposal must return to this ADR with evidence that
  adaptation cannot work.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Pretrain base LM from scratch | Economically infeasible; worse quality than existing open models; outside project's contribution. |
| Continued pretraining as the primary path | Unproven marginal benefit over adapters; delays the ablation gate; keeps as bounded optional experiment. |
| API-only, no training at all | Viable **baseline** (Phase 2) and must be beaten first; rejected as the *end state* because it blocks local/private deployment and per-tenant tuning. |
| Train a small 1–3B code model from scratch | Possible but unnecessary; fine-tuning an existing small code model is cheaper and better. |
