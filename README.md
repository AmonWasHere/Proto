# Research

Research and design work for an **evidence-first security adjudicator** and the
**RewardAudit** benchmark: measuring when deterministic verifiers make an LLM's
security verdict trustworthy.

## Start here

- **[`docs/PLAN.md`](docs/PLAN.md)** — the canonical north star. Read this first.

## Everything else (background)

- [`docs/rl-vulnerability-analysis-plan.md`](docs/rl-vulnerability-analysis-plan.md) —
  original broad plan (superseded as a spine; kept for context).
- [`docs/research-proposal.md`](docs/research-proposal.md) — RewardAudit proposal.
- [`docs/novelty-and-related-work.md`](docs/novelty-and-related-work.md) — prior art.
- [`docs/compute-and-model-strategy.md`](docs/compute-and-model-strategy.md),
  [`docs/gcp-rl-cost-estimate.md`](docs/gcp-rl-cost-estimate.md),
  [`docs/compute-reduction.md`](docs/compute-reduction.md) — cost/efficiency.
- [`docs/architecture-lastline.md`](docs/architecture-lastline.md) — rejected
  alternative, with critique.
- [`docs/issues.md`](docs/issues.md) — tracked backlog.
- [`docs/adr/`](docs/adr/) — decisions.
  - [ADR-0001](docs/adr/0001-model-strategy-preexisting-llm.md) — adapt a
    pre-existing LLM; never pretrain from scratch.
  - [ADR-0002](docs/adr/0002-reposition-measurement-first.md) — measurement-first,
    inference-only.

## Status

Design + planning. Next action: **M0** (finding schema, one scanner, two
verifiers, ten CVEs, a canary repo) → **M2 (E1)**.
