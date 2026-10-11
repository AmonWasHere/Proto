# Validation on real repositories

Goal: confirm the pipeline (analyzer → coverage → candidates → LLM verdicts) behaves
as intended on real, larger third-party codebases — not just the hand-built example.

## Method

- `git clone --depth 1` of public repositories into `/tmp/opencode/repos/`.
- Coverage preview via the web API (`/api/inspect`).
- Scans in two modes:
  - `--backend scripted` — analyzer + graph only (offline stub verdicts), for counts;
  - `--backend local` — the real **LLM** verifier (LM Studio,
    `qwen2.5-coder-7b-instruct-gtap-v3`), `REWARDAUDIT_LLM_CACHE=off`.

## Repositories

| Repo | Files | Languages | Coverage | Candidates | LLM verdicts (sampled) |
|---|---|---|---|---|---|
| `apache/commons-lang` | 639 | Java | 98% (629 covered) | 3 | **1 TP**, 2 abstain |
| `psf/requests` | 62 | Python | 60% (37 covered) | 0 | — |
| `OWASP/NodeGoat` | 61 | JavaScript | **0%** (46 unsupported) | **refused** | — |
| `sqlmapproject/sqlmap` | 777 | Python + C/C++ | 89% (688 covered) | 9 | **7 TP**, 2 abstain |
| `WebGoat/WebGoat` | 1076 | Java + JavaScript | 43% (468 covered) | 68 | — |
| `WebGoat/src/main/java` | 314 | Java | 100% | 10 (limit) | **7 TP**, 3 abstain |

## What this confirms

- **Coverage / "unchecked is not clean" works.** NodeGoat reports `javascript`
  *unsupported* at 0% checked; sqlmap reports `cpp` unchecked; WebGoat reports
  `javascript` unchecked. Unsupported languages are surfaced, never silently clean.
- **Refusal beats a false clean.** NodeGoat (JS-only) is refused with
  `no ruleset for any language present; unchecked languages: javascript, unknown`.
- **Real verdicts on real findings.** WebGoat's deliberately vulnerable lessons are
  judged true positives with high confidence — e.g. `tainted-sql-string` (conf 1.0),
  `formatted-sql-string` (1.0), `weak-random` (0.9), `unrestricted-request-mapping`
  (1.0). sqlmap: 7 TP, 2 abstain. commons-lang: 1 TP
  (`SerializationUtils.java:201`), 2 abstain.
- **Abstention works.** Ambiguous candidates (conf 0.5–0.8) and non-code files the
  judge cannot ground are returned as `unknown_risk`, not guessed.
- **Performance is workable.** Analyzer+graph scans: 5 s (requests) to 47 s
  (WebGoat, 1076 files). LLM verification: ≈14–20 s per finding on the local 7B.

## Detection effectiveness — OWASP Benchmark (ground truth)

`OWASP-Benchmark/BenchmarkJava`: **2,740 labelled Java test cases** (1,415
vulnerable, 1,325 safe), scored with the pinned 690-rule Java ruleset.

### Analyzer alone

| Metric | Value |
|---|---|
| true positives | 1,280 |
| false positives | 463 |
| false negatives | 135 |
| true negatives | 862 |
| **recall (TPR)** | **0.905** |
| **precision** | **0.734** |
| false-positive rate | 0.349 |
| Youden J | 0.555 |

Per category: `crypto`, `weakrand`, `securecookie` reach recall 1.00 with FPR 0.00;
`ldapi` recall 1.00 but **FPR 0.84**; `pathtraver` recall 0.94 / FPR 0.74; `cmdi`
0.92 / 0.62; `sqli` 0.89 / 0.54; `xss` 0.86 / 0.48; `hash` 0.69 / 0.00.

**So the analyzer detects most real vulnerabilities but over-reports heavily** — the
classic static-analyzer profile, and exactly the "benchmark ≠ detection" gap.

### Does the LLM verifier help? (matched sample: 15 analyzer TPs + 15 analyzer FPs)

`blind` mode hides the scanner's rule name, message, and CWE hint — testing whether
the verifier is just echoing the scanner (confirmation bias).

| Verifier | TP kept | FP rejected | abstained | precision (decided) | end-to-end recall |
|---|---|---|---|---|---|
| local `qwen2.5-coder-7b`, hinted | 14/15 | 0/15 | 1/30 | 0.48 | ≈0.84 |
| local `qwen2.5-coder-7b`, **blind** | 7/15 | 0/15 | 15/30 | 0.47 | ≈0.42 |
| cloud `deepseek-flash`, hinted | 10/15 | 2/15 | 13/30 | 0.67 | ≈0.60 |
| cloud `deepseek-flash`, **blind** | 5/15 | 0/15 | 22/30 | 0.62 | ≈0.30 |

- **No configuration rejects false positives.** Both models, hinted or blind, call
  the ground-truth-safe files `true_positive` (or abstain): FP rejection is 0/15 in
  three of four settings and 2/15 in the best.
- **Blinding does not help — it hurts.** Removing the scanner hint did not raise FP
  rejection; it drove abstention up (50–73%) and recall down. The confirmation-bias
  hypothesis is **not supported** on this corpus.
- **The analyzer's precision (0.73) is not improved by the verifier.** As a
  false-positive filter on OWASP Benchmark, this verifier does not work.

Why: Benchmark safe cases are near-misses — vulnerable and safe variants differ by
taint propagation/sanitization — so separating them needs whole-program taint
reasoning beyond the bounded slice, and the models tend to confirm.

## Observations / caveats

- The pinned Java ruleset also carries **CI/meta rules** (GitHub Actions,
  dependabot), so a Java scan surfaces `.github/*.yml` candidates with
  `coverage=unknown`; the LLM abstains on them. Noisy but honest — a language filter
  would remove them.
- `requests` produced **zero** candidates — the minimal Python ruleset is
  conservative, which is expected (few false positives, low coverage).
- Reachable entry→sink paths were found where the graph can trace one (sqlmap 9,
  WebGoat 19, commons-lang 0).
