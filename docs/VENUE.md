# Venue plan — IEEE, ~2-week submission

**Goal:** a peer-reviewed IEEE publication from the RewardAudit work.
**Date:** 2026-10-01.

## Reality check

No IEEE venue *publishes* within two weeks. Two weeks buys a **submission-ready
manuscript**; publication follows acceptance. The plan below gets the paper to
submission quality and out the door inside the window.

## Candidate IEEE venues (as of 2026-10-01)

| Venue | Type | Deadline | Fit | Notes |
|---|---|---|---|---|
| **LRLS @ IEEE BigData 2026** | workshop | **2026-10-30** | medium | up to 10 pp, IEEE 2-col; proceedings in IEEE Xplore; topics list LLMs and Software Engineering; workshop theme is learning with limited/weak labels |
| IEEE BigDataSecurity 2026 | conference | ~Oct/Nov (TBA) | good | AI security & robustness; 6–12 pp; EasyChair link on CFP is stale — verify |
| IEEE SaTML 2027 | conference | 2026-09-29 (**closed**) | excellent | missed by 2 days; best topical fit |
| IEEE BigData 2026 (main) | conference | 2026-08-21 (closed) | low | closed |
| IEEE Access | journal | rolling | good | APC ~US$1,950; fast but not free |
| IEEE Euro S&P 2027 | conference | 2026-12-02 | good | full-paper bar; 4+ weeks |

## Recommendation

**LRLS @ IEEE BigData 2026, deadline 2026-10-30.** It is the only *confirmed open*
near-term IEEE deadline with IEEE Xplore proceedings; the 10-page limit fits the
material; and the paper can be framed honestly as an evaluation of LLM verifiers
**under weak / limited labels** (JavaVFC's screening labels, low coverage,
abstention), which matches the workshop theme. Backup: **IEEE BigDataSecurity
2026** (better topical fit, deadline must be confirmed).

## The submission asset

Only one submittable artifact exists at this scale: the **measurement study**
(`paper/main.tex`). The certificate-veto / proof-carrying idea is not implemented
and has no data; it would need 3–4 weeks and a new experiment, and I have argued
it is thin. So the 2-week paper is the measurement study, retargeted.

## Critical fix list (current draft)

1. **Numbers are inconsistent.** The arms table reports a *single run*
   (gated flip 19.0%), while the abstract and calibration table report the
   **E0 k=5** result (gated flip 30.5% [22.9, 37.1]; detection 31.4%). The two
   runs disagree and are presented as if from one measurement. Fix: make E0 the
   headline and either (a) re-run the four arms with k=5, or (b) relabel the
   arms table as a single illustrative run and add a sentence saying E0 supersedes
   its point estimates.
2. **"Five model families"** is true only for the cross-language check at n=5;
   the scaled result is one model. State the split precisely everywhere.
3. **Weak-label caveat** should be promoted (it is the honest framing and the
   venue hook): JavaVFC labels are screening labels (~18% genuine).
4. **Add design implications** (abstention is the failure mode; grounding beats
   consensus) — this is the actionable contribution reviewers will want.
5. Title / abstract re-cut for the target venue.

## Two-week schedule

| Days | Work |
|---|---|
| 1–3 | Reconcile numbers (extend `repeats` to the four arms; run k=5 if budget allows); fix abstract, tables, claims |
| 4–7 | Expand related work, method, threats; add design-implications subsection |
| 8–11 | Venue formatting, page budget, references, figure/table polish |
| 12–14 | Internal review, build PDF, submit |

## Open decision

Whether to spend ~US$2–3 of the capped DeepSeek balance on a k=5 re-run of the
verifier arms, or reconcile by relabelling the existing single run. The re-run is
the stronger fix; the relabel is free.
