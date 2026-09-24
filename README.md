# Research

Research and design work for an **evidence-first security adjudicator** and the
**RewardAudit** benchmark: measuring when deterministic verifiers make an LLM's
security verdict trustworthy.

## Start here

- **[`docs/PLAN.md`](docs/PLAN.md)** — the canonical north star. Read this first.
  - [`docs/tools.md`](docs/tools.md) — language coverage and analyzer inventory.
- **[`rewardaudit/`](rewardaudit/)** — M0 working code (harness, adapters, CPG
  evidence layer, local/cloud LLM backends, V1/V2 verifiers).

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

**M0 + M1 complete.** `rewardaudit/` reproduces the pinned opengrep Java control
result (12/18 vulnerable, 1/3 safe flagged); supports Java + Python; implements
the **four-way decomposition** and an evidence ledger; canary set shows 0 false
positives. 40 tests green. Next: **M2 (E1)** — adversarial comment generator and
the four-way decomposition applied to LLM verdicts.

## Status (design)

Design + planning. Next action: **M0** (finding schema, one scanner, two
verifiers, ten CVEs, a canary repo) → **M2 (E1)**.
