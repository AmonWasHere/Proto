# Security Policy

## Scope

RewardAudit analyses untrusted code. It is itself security-relevant software, so
the following are in scope for disclosure:

- vulnerabilities in `rewardaudit/` (the harness, adapters, verifiers, CPG layer);
- prompt-injection bypasses of the LLM verifier's evidence checks;
- sandbox/execution concerns (note: M0 executes no scanned code, but later
  milestones may);
- dependency and supply-chain issues in pinned tools.

Out of scope: findings produced by the third-party analyzers it wraps (report
those upstream), and the contents of corpora it consumes.

## Reporting

Open a private security advisory on the repository, or email the maintainer
listed in `README.md`/git history. Do not file public issues for exploitable
bugs.

## Handling

- Acknowledgement within 5 working days.
- A fix or documented mitigation for confirmed issues.
- Credit on request.

## Design posture

- Scanned code, comments, and tool output are treated as **untrusted data**, never
  as instructions.
- Every LLM claim must resolve to a real CPG node or be rejected
  (`verifiers/llm_judge.py`).
- Analyzers are pinned by version and hash (`sastaudit/artifact/pins.json`).
