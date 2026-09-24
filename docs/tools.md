# Tools & Language Coverage

Answers: *can the harness cover Java and Python?* and *which static analyzers
does RewardAudit wrap?*

**Principle (from the Patch postmortem):** we **wrap** existing analyzers and
**implement only the interfaces** — adapter, evidence extraction, exact-match
verifier, adversarial generator. We do not reimplement Semgrep/CodeQL; that is
the incumbent's moat.

---

## 1. Language coverage — yes, Java + Python + C/C++

| Language | Corpus (on disk) | Deterministic engines |
|---|---|---|
| **Java** | OWASP Benchmark v1.2 (2,740 cases), JavaVFC (784 commits) | opengrep, CodeQL (build), PMD 7.27 |
| **Python** | 5 cloned repos (sqlite-web, records, pyodbc, pgcli, mycli) + 179k commit pairs | opengrep (no build), CodeQL Python (no build), Bandit (install) |
| **C/C++** | 10 cloned repos (curl, openssl, tcpdump, redis, ImageMagick, exiv2, libredwg, openjpeg, jasper, libarchive) | opengrep (no build), CodeQL C/C++ (build), clang-tidy (installed), cppcheck (install) |

**Start with Java + Python**, then add C/C++.

Why not all three at once:
- **opengrep/Semgrep is build-free for all three** — it is the one engine that
  gives uniform multi-language coverage cheaply.
- **CodeQL needs a build for Java and C/C++** (compiled languages) and is heavy;
  CodeQL **Python needs no build**. So Python is a free CodeQL comparison; Java
  uses the OWASP build; C/C++ CodeQL comes last.
- Corpus/label normalization differs per language — do it incrementally.

The **four-way decomposition is language-agnostic** (it operates on
verdict-before/verdict-after pairs), so the *measurement* is uniform even while
tool coverage is layered.

---

## 2. Tool inventory (what we wrap)

### Already available
| Tool | Status | Role |
|---|---|---|
| **opengrep 1.30.0** | bundled (`sastaudit/tools/bin/opengrep`) | Semgrep-compatible SAST, Java/Python/C/C++, build-free |
| **CodeQL 2.27.0** | bundled (`sastaudit/tools/bin/codeql`) | deep taint/dataflow; Python build-free, Java/C++ need build |
| **PMD 7.27.0** | bundled | Java rules |
| **clang-tidy 22** | on PATH | C/C++ |
| **tree-sitter** (c, java, python) | installed | CPG / node IDs for evidence verification (V2) |

### To add (cheap, high value)
| Tool | Languages | Role | Cost |
|---|---|---|---|
| **Bandit** | Python | language-specific SAST | `pip` |
| **cppcheck** | C/C++ | language-specific SAST | `dnf` |
| **SpotBugs + FindSecBugs** | Java | deeper Java patterns | jar |
| **gitleaks / detect-secrets** | all | secrets | binary |
| **OSV-Scanner / Trivy + Syft** | all | dependency CVE + SBOM | binary |
| **Joern** | multi | CPG queries (optional; heavier) | JVM |

### Later (dynamic, not core)
clang sanitizers · pytest/regression runner · AFL++/libFuzzer · KLEE/angr.

---

## 3. Mapping tools → the plan

| Tier / role | Tool | When |
|---|---|---|
| **Discovery** (candidates) | opengrep (universal), Bandit, PMD, clang-tidy | M1 |
| **Deterministic verifier V2** | opengrep rule verdict; later CodeQL taint | M0–M1 |
| **Evidence / CPG** | tree-sitter (c/java/python) for node IDs | M0 |
| **Composition comparison** | CodeQL (Python first, then Java) | M3 |
| **Commodity coverage** | gitleaks, OSV-Scanner | M3 |
| **Adversarial generator** | *ours* | M2 |
| **Exact-match verifier** | *ours* (tree-sitter) | M1 |
| **Dynamic confirmation** | sanitizers/tests | post-M5 |

---

## 4. What we implement vs wrap

**Wrap** (extend `sastaudit/tools/base.py` + `semgrep.py` + `codeql.py` +
`sarif.py`):

- A uniform `Analyzer` adapter: `run(repo, rules) -> SARIF/Findings`, with pinned
  versions, timeouts, and process-group cleanup (the prior harness already
  regression-tests orphan reaping).

**Implement ourselves:**

1. `LLMBackend` (mock / local / cloud) and the verifier interface.
2. **Exact-match verifier (V2)**: every LLM claim must resolve to a real
   tree-sitter node / `file:line`.
3. **Adversarial comment generator** (ALIBI-style).
4. **Four-way decomposition** applied to LLM verdicts (lift from `sastaudit`).
5. **Calibration / FNR / cost-per-TP** reporting.
6. **Canary repos**.

---

## 5. Recommended build ladder

| Milestone | Tools | Corpus |
|---|---|---|
| **M0** | opengrep adapter + tree-sitter CPG + mock LLM | one `sastaudit` control case |
| **M1** | opengrep across **Java + Python** | OWASP + JavaVFC + 5 Python repos |
| **M2 (E1)** | + adversarial generator; four-way decomposition on LLM verdicts | same |
| **M3** | + CodeQL (Python build-free, then Java) | same |
| **M4** | + Bandit, gitleaks, OSV | expand |
| **M5** | + C/C++ (opengrep, clang-tidy; CodeQL later) | 10 C/C++ repos |

---

## 6. Host constraints (measured)

- No `semgrep`/`bandit`/`joern`/`gitleaks` on PATH — but **opengrep, CodeQL, PMD
  are bundled** in `sastaudit/tools/bin`, and `clang-tidy 22` + tree-sitter
  (c/java/python) are present.
- Python is **3.14.7**; install Bandit/Semgrep into a pinned 3.11 venv (issue C2).
- Java present (needed for CodeQL/PMD/Joern).
- No Go/Rust toolchains — irrelevant to the chosen scope.
