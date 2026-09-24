# ADR-0003 — Hybrid knowledge store: pinned public feed + active own findings

- **Status:** Accepted
- **Date:** 2026-09-24
- **Deciders:** project owner
- **Related:** `docs/issues.md` F4, `docs/architecture-lastline.md` §10,
  `pinned/sastaudit-src/artifact/FINDINGS.md`

## Context

The project needs vulnerability knowledge, and there are two tempting extremes:

1. **Build and maintain a live threat database** (NVD/OSV/GHSA/KEV/EPSS feeds,
  continuously synced). This is a permanent operational cost, a commodity that
  OSV/Trivy/Grype already provide, and — decisively — a *reproducibility hazard*:
  if the feed mutates between runs, the measurement changes for reasons unrelated
  to the verifier.
2. **Use only pristine pinned corpora**, ignoring that real analysis must map a
  codebase's dependencies to advisories.

## Decision

**Maintain a hybrid store with a hard boundary:**

- **Public threat feed → consume as pinned, dated snapshots.** No live mutable
  service in the experiment path. A `refresh` step may pull OSV and emit a
  **new dated snapshot with its hash recorded**; snapshots are never edited in
  place. This keeps runs reproducible *and* lets freshness be measured as a
  variable rather than assumed.
- **Own findings → active ledger.** Verdicts, dispositions, and outcomes are
  appended (the existing `Ledger`) and are the source of empirical priors
  (precision per rule/signal). This is the part that learns.
- **Join them by dependency:** a dependency's advisory (feed) is linked to the
  findings a scanner raised for that dependency (ledger).

## Consequences

- Reproducibility is preserved: every experiment names the snapshot hash it used.
- The "active" property lives in our data, not in a feed pipeline — no maintenance
  treadmill, no wrapper trap.
- Freshness sensitivity becomes a measurable experiment (old vs new snapshot).
- We do **not** reimplement feed integrations; we consume OSV-format data and can
  layer Trivy/Grype later.
- Auto-rule synthesis from advisories remains **out of scope** (a research
  question under a precision gate, not infrastructure).

## Alternatives considered

| Alternative | Why not |
|---|---|
| Live mutable threat DB | Ops treadmill; breaks reproducibility; no differentiation |
| Own-findings ledger only | Cannot answer dependency-CVE questions |
| Public feeds only | Ignores the model-performance feedback loop the project is about |
| Auto-rule synthesis now | Unproven generalization; belongs behind an experimental gate |
