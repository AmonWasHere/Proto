# Research

Research and design work for an RL-based vulnerability analysis agent — a
tool-using policy that categorizes and analyzes security vulnerabilities and
code problems across arbitrary codebases.

## Documents

- [`docs/rl-vulnerability-analysis-plan.md`](docs/rl-vulnerability-analysis-plan.md) —
  draft v2 plan: architecture, tool suite, reward design, evaluation, a
  cross-validation of shortcomings/limitations, the developed v2 roadmap, and a
  risk register.
- [`docs/issues.md`](docs/issues.md) — tracked backlog (IDs A1–D6) with severity,
  owner, state, and resolution criteria.
- [`docs/compute-and-model-strategy.md`](docs/compute-and-model-strategy.md) —
  compute estimates by phase/scenario and the model-selection plus
  training-ladder strategy under the hardware constraint.
- [`docs/gcp-rl-cost-estimate.md`](docs/gcp-rl-cost-estimate.md) — contingency
  GCP pricing if the deferred RL experiment is ever run.
- [`docs/compute-reduction.md`](docs/compute-reduction.md) — how to lower
  training/inference compute while preserving model quality.
- [`docs/adr/`](docs/adr/) — architecture decision records.
  - [ADR-0001](docs/adr/0001-model-strategy-preexisting-llm.md) — use a
    pre-existing LLM; adapt with LoRA/QLoRA; never pretrain from scratch.
- [`docs/novelty-and-related-work.md`](docs/novelty-and-related-work.md) —
  2026 prior-art map, direct duplications, candidate novelty axes, and
  recommended repositioning.
- [`docs/research-proposal.md`](docs/research-proposal.md) — draft proposal for
  **RewardAudit**: whether security-agent rewards can be trusted.
- [`docs/adr/0002-reposition-measurement-first.md`](docs/adr/0002-reposition-measurement-first.md)
  — recommended repositioning to a measurement-first study.

## Status

Planning / design. No implementation yet.
