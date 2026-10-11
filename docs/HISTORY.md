# Project history — RewardAudit / VERITAS

A single narrative record of how this project came to be, what was measured, what
was built, what was rejected, and where it stands. Canonical facts live in the
docs it links to; this file is the through-line.

**One line:** an *evidence-first security adjudicator* — pinned analyzers find
candidates, a bounded LLM verifier adjudicates them, and a measurement (the
*four-way decomposition*) asks whether the verdict actually tracks the fix. It is a
**measurement harness with a usable front end**, not a new detector.

---

## At a glance (as of 2026-10-11)

| | |
|---|---|
| Harness | `rewardaudit/` — analyzers, code graph, verifier arms, calibration, stats, advisory store, CLI, local web app |
| Tests | **144 passing** |
| Languages | Java (690 rules) · Python (5) · **JavaScript/TypeScript (13)** — covered; C grammar-only; others reported *unchecked* |
| LLM backends | cloud (DeepSeek `deepseek-flash`), local (LM Studio, auto-recognized), scripted/mock (offline) |
| Key result | verifier flip rate **30.5% [22.9, 37.1]** vs tool **4.8%**; abstention **49%**; FNR **69%**; fixed-side FP **0%**; ECE **0.206** |
| Negative result | on OWASP Benchmark (2,740 labelled cases) the verifier **does not improve** analyzer precision |
| Cost | E0 run **$0.79**; **~$0.0019/verdict**; cache = **100%** on repeats |
| Paper | `paper/main.pdf` — 7 pages, 31 refs, 5 figures |
| Name | umbrella code name **RewardAudit**; framework name **VERITAS** |

---

## 1. Origin (September 2026)

The project did not start greenfield. A frozen prior project (`~/Projects/Patch`,
`sastaudit`) had already established that a static analyzer's **benchmark score does
not predict real detection**, and introduced the **four-way decomposition** (a
verifier's verdict over a vulnerable/fixed pair: *both / vuln-only / fixed-only /
neither*). It also supplied the **JavaVFC** corpus (784 commits; 327 usable; 207
materialised) and a pinned analyzer binary + rule set.

The new question: **an LLM now sits in the verifier role — can its verdict be
trusted?** The project would extend `sastaudit` from static tools to LLM verifiers.

Three decisions were fixed early (ADRs):
- **ADR-0001** — use a pre-existing LLM; never pretrain from scratch.
- **ADR-0002** — measurement-first, inference-only; no RL, no GPU training.
- **ADR-0003** — hybrid knowledge store: a pinned OSV snapshot + an own-findings
  ledger; snapshots are immutable and dated.

---

## 2. Timeline

### 2026-09-24 — foundations and first live runs
- **M0/M1/M2**: harness reproduces the pinned analyzer control matrix (12/18
  vulnerable, 1/3 safe); Python support, pairs, canaries; adversarial comment
  generator and the four-way decomposition; evidence ledger; hybrid threat store.
- **First real E1 run** (Groq, 3 model families, n=5) — *verifier-dependence
  confirmed*: flip rate 80–100%, differing failure modes, different canary FPs.
- **Adaptive attacker** (ALIBI-style): adaptive evasion 40% vs 12% for templates;
  **abstention emerges as a distinct evasion path**.
- **JavaVFC scale-up (P1–P3)**: security subset n=21; flip 19–24% vs Semgrep
  0.83%; template evasion 26% (8/9 via abstention); adaptive 50% (all abstention).
  Fixed a reasoning-model bug: a too-small token cap silently produced "always
  abstain".

### 2026-09-26 — composition, calibration, cost, front end
- **P4 composition**: tool over-reports **6×**; evidence gating improves trust at
  no recall cost; requiring tool agreement *loses* recall — *trust relocates*.
- **P5 calibration**: ECE 0.025, 0% fixed-side FP, **50% abstention**, 62% FNR —
  "trustworthy but silent".
- **P6 report** consolidating rounds 1–5.
- **Cost optimizations**: thinking-off ~8× cheaper at a precision cost; verdict
  cache 100% on repeats.
- **Local web app** (Review / Measure / Setup), then the Whole-Codebase Graph MVP
  (coverage registry, route→handler→sink paths, dependency boundaries), frontend
  rework, repo cleanup.
- **Draft IEEE paper** written on the measured results.
- **E0 complete** (k=5, `deepseek-flash`): flip **30.5% [22.9, 37.1]** (runs
  19.0–42.9%); ECE **0.206 [0.128, 0.293]** (runs 0.073–0.349) — the earlier 0.025
  was a lucky single run; fixed-side FP **0.0% in every run**. Cost **$0.79**.
  Fixed a settings-save bug that blanked the cloud endpoint.

### 2026-10-01/02 — paper, toolchain, arms
- Venue analysis; paper corrected to the E0 numbers; removed the unevaluated
  whole-codebase section.
- Installed a real LaTeX toolchain (**tectonic**) so `main.tex` compiles to a true
  IEEEtran two-column PDF; `make paper` works.
- Extended `repeats` to re-run every verifier arm (gated/ungated/hybrid/tool).
- Paper expanded and made internally consistent; figures added.

### 2026-10-06 — naming and presentation
- Keywords, alternate titles, and a framework name. The project settled on
  **VERITAS** (Verifier Evaluation via Revision-Informed Trust, Abstention, and
  Suppression).

### 2026-10-10 — real-world validation (and a negative result)
- Ran the pipeline on real repositories: commons-lang (Java), requests (Python),
  NodeGoat (JS), sqlmap (Python+C/C++), WebGoat (Java+JS).
- Ran the **OWASP Benchmark** (2,740 labelled cases): analyzer recall **0.905**,
  precision **0.734**, FPR **0.349**.
- **Verifier ablation** on a matched sample (15 TP + 15 FP): neither local 7B nor
  cloud improved precision (FP rejected 0/15 and 2/15); blinding the scanner hint
  did **not** help — it raised abstention and cut recall. The negative result is
  now in the paper.
- Local models: **Bonsai-27B failed** (reasoning-only output, empty `content`);
  **Qwen2.5-Coder-7B worked**; built **auto-recognition** of the served model.
- Fixed the **folder picker** (it had been confined to the server's browse root).

### 2026-10-11 — hardening and breadth
- Cloned a set of deliberately-vulnerable repos into `vuln-repos/` (git-ignored).
- **Code-only review**: CI/config matches (`.github/*.yml`) are no longer given
  verdicts — they're reported as *skipped*, not checked.
- **View the flagged snippet** in review; **selective function audit** (pick
  functions → send to the LLM, cloud).
- **JavaScript/TypeScript support**: grammar (auditable) then a **13-rule JS/TS
  ruleset** (eval, `new Function`, `child_process.exec`, DOM HTML sinks, SQL
  strings, weak hashes, `unserialize`, SSRF, path traversal, open redirect,
  string-eval timers, NoSQL injection, hardcoded secrets) — NodeGoat now produces
  JS candidates end-to-end.
- **Richer audit context** (file imports + sibling functions): the `safe.py`
  false positive disappeared.
- **Live OSV refresh**: `harness threat-refresh` queries `api.osv.dev` per declared
  dependency into a new dated snapshot (demo: 8 real advisories for `flask==2.2.0`
  and `pyyaml==5.3`).
- Folded the OWASP results, coverage, audit and OSV refresh into the paper.

---

## 3. What was measured

| Finding | Value | Corpus |
|---|---|---|
| Verifier flip rate (gated LLM) | **30.5% [22.9, 37.1]** | JavaVFC-21, k=5 |
| Pattern-matcher flip rate | 4.8% (over-reports **6.0×**) | JavaVFC-21 |
| Abstention | **49.0% [44.3, 53.8]** | JavaVFC-21, k=5 |
| False-negative rate | 68.6% [64.8, 72.4] | JavaVFC-21, k=5 |
| Fixed-side false positives | **0.0%** (every run) | JavaVFC-21, k=5 |
| ECE | **0.206** [0.128, 0.293] (runs 0.073–0.349) | JavaVFC-21, k=5 |
| Adversarial evasion | 26% templates → **50% adaptive**, almost all **abstention** | JavaVFC-21 |
| Analyzer on labelled benchmark | recall **0.905**, precision **0.734**, FPR **0.349** | OWASP Benchmark, 2,740 |
| LLM verifier on labelled benchmark | **no precision gain** (FP rejected 0–2 of 15); blinding only raises abstention | 15 TP + 15 FP |
| Cost | **$0.79** (E0); **$0.0019/verdict**; cache 100% on repeats | DeepSeek |

Interpretation: the verifier is **precise when it commits**, but its bottleneck is
**coverage** (silence), and adversarial comments exploit exactly that. On a labelled
benchmark, verification does **not** improve on the analyzer. This is a
measurement/characterization result with a negative core.

---

## 4. What was built

- **Harness** (`rewardaudit/`): analyzer adapter (opengrep), tree-sitter CPG with
  function extraction, verifier arms V1/V1g/V2/V5, evidence gating, four-way
  decomposition, calibration/selective risk, statistics (Wilson/bootstrap/McNemar),
  content-addressed verdict cache, hybrid advisory store, run ledger.
- **CLI**: `controls`, `pairs`, `canaries`, `e1`, `evade`, `adaptive`, `calibrate`,
  `repeats`, `javavfc`, `review`, `audit`, `threat`, `threat-refresh`.
- **Local web app**: Review / Measure / Setup, background jobs, folder picker
  (whole filesystem by default), status pills, snippet viewing, selective audit.
- **LLM backends**: cloud (OpenAI-compatible), local (LM Studio/ollama) with
  **auto-recognition**, scripted/mock for offline runs; a `blind` judge mode.
- **Whole-function audit**: sends functions (or a chosen subset) to the LLM for
  mistakes beyond rules; file context curbs over-flagging.
- **Coverage discipline**: unsupported languages are reported *unchecked*, never
  silently clean.
- **Demo**: `./demo.sh` (offline, six steps, < 1 min); `docs/DEMO.md` talk track.

---

## 5. What was rejected (and why)

- **Reinforcement learning (GRPO/RLOO)** — 10–50× the cost of fine-tuning
  (Tier B ≈ $3.7k–5k, weeks), and the reward is the very thing shown unreliable.
- **Pretraining a model from scratch** — ~$0.3–0.45M and GPU-years; infeasible.
- **RL/architecture narratives** (LastLine cascade, whole-codebase-graph as a
  paper) — unnecessary for the measurement question, or unevaluated.
- **A pure position/protocol paper** and **an ensemble-theory paper** — either
  taken by prior art or not supported by the evidence.
- **Shipping the measurement as a "detector" claim** — the evidence says it does
  not beat the analyzer.

Costs for every approach (API, local, fine-tune, RL, human audit) are broken down
in `docs/COST-BREAKDOWN.md`.

---

## 6. Lessons learned

1. **Score the fix, not the sample.** A verdict that moves with a code change is
   the only strong signal; construct-matching (`both`) detects nothing.
2. **Abstention is a first-class outcome.** Half the judgements are silent, and
   silence — not error — is both the bottleneck and the dominant adversarial target.
3. **Single runs are noise.** The same configuration's ECE was 0.025 once and 0.206
   over k=5; report intervals *and* observed range.
4. **Verification does not automatically help.** On labelled ground truth it does
   not improve precision; grounding beats consensus, but neither fixes coverage.
5. **Unchecked is not clean.** Reporting unsupported languages is a feature, not a
   gap to hide.
6. **Reasoning models can silently fail** (token budget consumed → empty content →
   always abstain), and 1-bit/reasoning local models can loop without emitting a
   verdict.

---

## 7. Artifacts map

| Path | What |
|---|---|
| `rewardaudit/` | the harness, verifiers, graph, store, CLI, web app |
| `paper/main.pdf` (+ `main.tex`, `references.bib`) | 7-page IEEE-format manuscript |
| `docs/PLAN.md` | north star and phases |
| `docs/e1-results.md` | every measured result, by round |
| `docs/REPORT.md` | findings report |
| `docs/COST.md`, `docs/COST-BREAKDOWN.md` | measured cost; per-approach costs |
| `docs/VALIDATION.md` | real-repo + OWASP Benchmark evidence |
| `docs/VENUE.md` | venue analysis |
| `docs/DEMO.md`, `demo.sh` | demonstration |
| `docs/adr/` | ADR-0001…0003 |
| `docs/archive/` | superseded plans and costing (kept for the record) |
| `vuln-repos/` (git-ignored) | cloned vulnerable repos for validation |

---

## 8. Open threads

- **Scale the labelled evaluation** (n≥100) and add a human-audited sample for true
  precision/recall.
- **Richer context** for the verifier (not just the audit) to attack the FP problem
  where the hint/blind ablations failed.
- **More language rules** (JS/TS is now covered; Go/Rust/PHP remain unchecked).
- **Dynamic analysis** for runtime classes — deferred, and it re-introduces the
  infrastructure cost the project deliberately avoided.
- **Finalize the paper**: author block and a target venue.
