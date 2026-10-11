# Architecture

**VERITAS / RewardAudit** — an evidence-first security adjudicator. Deterministic
analyzers *find* candidates; a bounded LLM verifier *adjudicates* them; and a
measurement (the four-way decomposition) asks whether the verdict actually tracks
the fix. It is a **measurement harness with a usable front end**, not a detector.

This document is the structural companion to `docs/HISTORY.md`.

---

## 1. Design principles

1. **Evidence-first.** A finding is only as good as the evidence behind it. A
   verdict must cite resolvable code locations; unverifiable positives are
   downgraded, not trusted (`verifiers/llm_judge.py`, `cpg.py`).
2. **Bounded requests.** The verifier never sees a repository — only a candidate
   plus a graph-selected slice. Whole-codebase breadth is delegated to the
   analyzer, not the prompt.
3. **Coverage honesty.** Every language is labelled `covered` / `find_only` /
   `ground_only` / `unsupported`. Unsupported code is reported *unchecked*, never
   silently clean (`languages.py`).
4. **Deterministic core.** Analyzers are pinned by hash; the verdict cache is
   content-addressed; offline backends make the whole pipeline reproducible with
   no network (`config.py`, `llm/cache.py`, `llm/scripted.py`).
5. **Immutable snapshots.** Advisory data is dated and never edited in place;
   refreshing writes a new file (ADR-0003).
6. **Honest failure.** Abstention (`unknown_risk`) is a first-class outcome, not an
   error.

---

## 2. System context

```
                    +-------------------------------------------------+
   repo folder ---> |  analyzers (opengrep + pinned rule sets)        |
                    |  java / python / javascript-typescript          |
                    +--------------------------+----------------------+
                                               | Finding[]
   requirements --> deps scan -----------------+--> Advisory store
                                               |    (OSV snapshot, dated)
                                               v
                    +-------------------------------------------------+
                    |  code graph (tree-sitter CPG)                    |
                    |  functions, spans, entry->sink path candidates   |
                    +--------------------------+----------------------+
                                               | bounded verdict request
   comments ------> adversary ---------------> |
                                               v
                    +-------------------------------------------------+
                    |  LLM verifier  (cloud | local | scripted)        |
                    |  evidence gate: cited refs must resolve          |
                    +--------------------------+----------------------+
                                               | Verdict (TP / FP / unknown)
                                               v
                    +-------------------------------------------------+
                    |  four-way decomposition over (vulnerable,fixed)  |
                    |  flip rate · over-report · calibration · cost    |
                    +-------------------------------------------------+
```

---

## 3. Component map

| Module | Responsibility |
|---|---|
| `schema.py` | domain types: `Disposition`, `Severity`, `Location`, `Evidence`, `Finding`, `Verdict`, `ScanResult` |
| `config.py` | pinned asset resolution (opengrep binary, Java/Python/JS rule sets, corpora, advisory snapshot) |
| `analyzers/` | analyzer adapters; `opengrep.py` (Semgrep-compatible engine), `base.py` (`Analyzer`, `AnalyzerError`) |
| `languages.py` | language registry and explicit **coverage** (`registry`, `detect`, `rules_for`, `coverage_report`) |
| `cpg.py` | tree-sitter evidence layer: `spans`, `verify_ref`, `context_slice`, `functions()` → `FunctionUnit` |
| `graph.py` | lightweight whole-codebase graph: functions, calls, routes, env reads, dependency edges, `path_candidates` |
| `decomposition.py` | the instrument: `Cell` (both/vuln_only/fixed_only/neither), `RevisionPair`, `classify`, `decompose` |
| `e1.py` | four-way decomposition over LLM/tool/hybrid verdicts; evasion; calibration collection |
| `verifiers/llm_judge.py` | **V1/V1g** — the LLM judge, its prompts, JSON parsing, evidence gating, `blind` mode |
| `verifiers/tool_verdict.py` | **V2** — the deterministic analyzer's verdict wrapper |
| `llm/` | backends (`openai_compat`, `local`, `mock`, `scripted`), content-addressed `cache`, `build_backend` factory |
| `audit.py` | whole-function LLM audit for mistakes beyond rules (with file context) |
| `review.py` | the end-to-end `review` flow (scan → graph → verdicts), code/non-code partition |
| `calibration.py` | ECE, reliability, selective risk, FNR |
| `stats.py` | Wilson/bootstrap CIs, exact McNemar |
| `repeats.py` | E0: run an experiment k times, aggregate, compare |
| `store/` | advisory store: `advisory.py` (OSV record + version matching), `snapshot.py` (load/match), `knowledge.py` (deps + ledger join) |
| `osv.py` | live OSV refresh (`query`, `refresh`) → new dated snapshot |
| `deps.py` | manifest parsing (requirements/package.json/Cargo/go.mod/pom) |
| `ledger.py` | append-only run/outcome ledger |
| `sarif.py`, `controls.py`, `datasets.py`, `javavfc.py` | SARIF ingestion, control matrix, dataset/corpus loaders |
| `harness.py` | the CLI (`controls`, `e1`, `review`, `audit`, `threat`, `threat-refresh`, …) |
| `web/` | stdlib HTTP server + SPA (Review / Measure / Setup) |

---

## 4. Data model

- **`Finding`** — a candidate: `id, analyzer, rule, message, location, cwes`.
- **`Verdict`** — an adjudication: `disposition, confidence, cwe, rationale,
  evidence_refs, abstain`.
- **`Disposition`** — `true_positive` · `false_positive` · `unknown_risk` (abstain).
- **`Cell`** — the four-way outcome for a revision pair: `both` · `vuln_only`
  (a *flip*, detection) · `fixed_only` · `neither`.
- **`Advisory`** — an OSV record with conservative version matching
  (`from_osv`, `affects`).

---

## 5. The review pipeline

`review.run_review(path, backend_kind, verifier, limit, rules)`:

1. **Coverage** — `languages.coverage_report(root)` labels every file's language.
2. **Scan** — `Opengrep.scan(root)` with the rule set(s) for the languages present.
3. **Partition** — `partition_code_findings` keeps only files with a grammar;
   analyzer matches in CI/config (`.github/*.yml`) are **skipped**, not judged.
4. **Graph** — `graph.path_candidates` attaches an entry→sink traversal and a
   per-path coverage label to each finding.
5. **Verify** — `LLMJudge.verify` per finding: a bounded request, then evidence
   gating; the enclosing function is captured as a **snippet**.
6. **Report** — rows `{path, line, rule, cwe, language, disposition, confidence,
   rationale, evidence, entry, hops, reachable, coverage, snippet}` + a summary
   (candidates, TP/FP/abstain, reachable, skipped, tokens).

---

## 6. Measurement: the four-way decomposition

For a vulnerable/fixed pair, a verdict is classified by `classify(flagged_vuln,
flagged_fixed)`. Only `vuln_only` is detection; `both` means the verifier flagged a
construct present in *both* revisions and therefore detected nothing.

Reported metrics: **flip rate** (vuln_only fraction), **naive coverage**,
**over-report factor**, plus calibration (ECE, selective risk), FNR, and cost.
Verifier arms compared on identical input:

| Arm | What |
|---|---|
| **V1** | LLM verdict, ungated |
| **V1g** | LLM verdict + **evidence gating** (default) |
| **V2** | the deterministic analyzer's verdict |
| **V5** | hybrid: gated LLM **and** tool agree |

---

## 7. Evidence gating

`LLMJudge._request` sends the candidate, a code slice, and the commit message; the
model must return strict JSON with `path:line` evidence. `Cpg.verify_ref` resolves
each reference against the real tree; a positive verdict whose references do not
resolve is **downgraded to `unknown_risk`**. A `blind` mode hides the rule name,
message and CWE hint (used to test scanner-confirmation bias).

---

## 8. LLM layer

`build_backend(kind)` returns a backend, wrapped in a content-addressed
`CachedBackend` unless disabled:

- **`cloud`** — any OpenAI-compatible endpoint (`openai_compat.py`); `list_models()`,
  retry/backoff, provider `extra_body`.
- **`local`** — LM Studio / ollama (`local.py`): base URL normalized to `/v1`,
  **auto-recognizes** the served model (prefers a loaded, non-embedding LLM),
  falls back to the generic `/v1/models`; JSON mode off by default for servers
  that reject `json_object`.
- **`scripted` / `mock`** — offline, deterministic (tests, demo).
- **cache** — keyed on backend·model·prompts·temperature·json-mode·max_tokens; a
  hit replays the response with `tokens = 0`.

Configuration lives out-of-repo in `~/.config/rewardaudit/env`; keys are never
returned to the browser.

---

## 9. Whole-function audit

`audit.audit_codebase(root, backend, ...)` enumerates functions with `Cpg.functions`
and sends each a bounded request asking for mistakes (security, logic, resources,
concurrency, API misuse). Each call also receives the file's **imports and sibling
function names** for context. Findings are parsed, evidence-gated, and returned per
function with the **function snippet**. `selections` restricts the audit to chosen
`(path, start_line)` functions — this backs the GUI's *Selective function audit*.

---

## 10. Coverage & languages

`LanguageSpec` combines two capabilities: **rules** (can *find*) and **grammar**
(can *ground*).

| Status | Meaning |
|---|---|
| `covered` | rules + grammar (Java, Python, JavaScript/TypeScript) |
| `find_only` | rules, no grammar (cannot ground) |
| `ground_only` | grammar, no rules (auditable, not rule-findable; C) |
| `unsupported` | neither → reported **unchecked** |

Adding a language = add a tree-sitter grammar (`cpg._load_language`) and a rule set
(`rules/*.yaml`), then register it.

---

## 11. Advisory store & OSV refresh

`store.Snapshot` loads a dated OSV JSONL and matches `(ecosystem, package,
version)`. `osv.refresh(deps, out)` queries `api.osv.dev/v1/query` per declared
dependency and writes a **new** dated snapshot (+ `.meta.json`) in OSV shape, so the
loader is unchanged. `harness threat-refresh` / `scripts/refresh_osv.sh` drive it.

---

## 12. Web application

`web/server.py` is a stdlib `ThreadingHTTPServer` (bound to `127.0.0.1`) plus a
static SPA (`web/static/`). Endpoints:

| Route | Purpose |
|---|---|
| `GET /`, `/static/*` | the app |
| `GET/POST /api/settings` | backend / base URL / model / key (key never returned) |
| `GET /api/backends`, `GET /api/local/models` | available backends; auto-recognized local models |
| `GET /api/browse`, `GET /api/inspect` | folder picker; coverage preview |
| `GET /api/functions` | list functions (for selective audit) |
| `POST /api/jobs`, `GET /api/jobs/{id}` | background jobs: `review`, `audit`, `measure` |
| `POST /api/test` | one-call backend connectivity check |

Jobs run on threads; the UI polls progress.

---

## 13. CLI surface

`python -m rewardaudit.harness <cmd>`:

`controls` · `pairs` · `canaries` · `judge` · `e1` · `evade` · `adaptive` ·
`calibrate` · `repeats` · `javavfc` · `review` · `audit` · `threat` ·
`threat-refresh`.

---

## 14. Extension points

- **New rule** — append to `rules/<lang>-minimal.yaml`; no code change.
- **New language** — add a grammar in `cpg._load_language` + a rule set, register in
  `languages.registry`; status becomes `covered`/`ground_only`.
- **New backend** — implement `LLMBackend` (one `complete()`), register in
  `build_backend`.
- **New evidence layer** — extend `Cpg` (sound dataflow, call graph) without touching
  the verifiers.

---

## 15. Determinism & reproducibility

Pinned analyzer + rules by hash (`pins.json`); offline backends and corpora; a
content-addressed verdict cache; `repeats` for k-run aggregation with CIs. The
control reproduction (12/18, 1/3) and the Python-pair run work fully offline; a
single `./demo.sh` exercises the pipeline end to end.

---

## 16. Non-goals / boundaries

- **Not a detector** — detection is delegated to pinned analyzers.
- **No dynamic analysis / no sandbox** — runtime classes are out of scope.
- **No training** — ADR-0001/0002 (inference only).
- **Sound dataflow is not claimed** — the CPG confirms a cited location exists, not
  that taint flows.
- **Whole-repo reasoning is limited** — the verifier sees bounded slices; the audit
  is per-function.

---

## 17. Testing

`rewardaudit/tests/` — **144 tests** covering schema, analyzers/controls, CPG and
JS/TS grammars, languages/coverage, decomposition, verifier arms and gating,
calibration/stats, cache, advisory store and OSV refresh, review/audit, the web
server, and the CLI.

---

## 18. Known limitations (architectural)

- Coverage is bounded by rule sets and grammars; Go/Rust/PHP are unchecked.
- The verifier's bounded slice can miss the deciding evidence (sanitizers); on a
  labelled benchmark this yielded **no precision gain** (`docs/VALIDATION.md`).
- Abstention is high (≈49%), the dominant failure mode and adversarial target.
