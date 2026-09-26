# Design: Whole-Codebase Graph (WCG)

**Problem with today's shape.** Analysis is *repository*-scoped and *file*-scoped.
Tools see one language at a time; the verifier sees one function; the four-way
decomposition is per file. Real systems are not repositories — they are
**services, libraries, config, and boundaries**, often spanning several repos. The
interesting vulnerabilities live at the seams.

**Reframe:** make the unit of analysis a single, language-agnostic,
evidence-backed graph of the *system*, and make the LLM adjudicate **paths**
through it, not files.

---

## The four ideas

### 1. Interface edges: connect per-language subgraphs, don't unify grammars
We do **not** need one parser for all languages. We need per-language CPGs plus a
thin layer of **interface (boundary) edges** that stitches them:

| Boundary | Producer side | Consumer side |
|---|---|---|
| HTTP | client call / fetch / RestTemplate | route handler (Flask/FastAPI/Spring/Express) |
| RPC/gRPC | stub invocation | service method |
| FFI | Python `ctypes`/C extension call | native export |
| IPC/queues | publish / enqueue | subscribe / consume |
| DB | query string / ORM call | schema, stored proc |
| Env/config | `os.environ[...]`, `@Value` | deployment manifest / `.env` / IaC |
| Shell-out | `subprocess`, `ProcessBuilder` | external tool |

Each boundary is a **node with a producer and a consumer**, so a taint path can
traverse languages without a unified AST. This is the innovation that makes
"whole codebase" tractable: analyse each language with its own tools, then connect.

### 2. Reachability-first slicing: candidates are *paths*, not files
Define **entrypoints** (public routes, CLI, message consumers, exported APIs).
From them, compute the **reachable subgraph** and emit **path objects**:

```
PathFinding(
  id,
  entry: NodeId,
  hops: [NodeId, Edge, NodeId, ...],   # each hop verifiable in the graph
  sink: NodeId,
  cwe_hint,
  coverage: {checked, unchecked, unsupported}   # per hop
)
```

The deterministic analyzers (opengrep/CodeQL/Joern) remain the **detectors**; the
graph turns their per-file hits into path candidates. The LLM verifier is
unchanged — it still adjudicates a bounded candidate, except the candidate is a
**path with a verifiable hop list** rather than a function.

### 3. Coverage propagation: honest uncertainty over the graph
Every node and edge carries a **coverage label**:

- `checked` — a ruleset and a grammar exist for its language;
- `unchecked` — no ruleset (silently skipped today — the bug we are fixing);
- `unsupported` — no grammar, so no evidence grounding;
- `unparsed` — parse failure.

Coverage **propagates along paths**: a path through an `unsupported` hop is
reported as *partially checked*, never as clean. This makes the polyglot
limitation a first-class, visible property instead of a silent omission.

### 4. System-level deltas: measure the fix, not the file
Extend the four-way decomposition from files to **paths**. A fix is applied to a
system state (code + config + deps + IaC). The question becomes:

> Does the verdict on this **path** move when the fix is applied?

`vuln_only` (a flipped path) is now "the dangerous path was cut", which is a far
stronger signal than "the file stopped matching a pattern." The instrument itself
is unchanged — only the candidate's granularity.

---

## Architecture

```
 sources                      builder (deterministic)                graph
 ───────                      ───────────────────────                ─────
 code (multi-lang)  ──▶  per-language CPG (tree-sitter now, Joern) ─┐
 manifests/SBOM     ──▶  dependency + version graph                │
 IaC / env / k8s    ──▶  config graph                              ├─▶ WCG
 routes / handlers  ──▶  entrypoint extraction                     │   (nodes,
 imports / FFI      ──▶  interface-edge resolution                 │    edges,
 git history        ──▶  ownership / fix-commit index              ┘    coverage)
 advisories (OSV)   ──▶  advisory ↔ package ↔ symbol links

        WCG ──▶ reachability (from entrypoints) ──▶ path candidates
                                                        │
                        deterministic detectors ────────┘
                                                        ▼
                     verifier (unchanged, evidence-gated over path hops)
                                                        ▼
                     four-way decomposition (path-level) + calibration + coverage
```

- **Deterministic builders** do everything structural. The LLM is only the
  verifier, and its evidence references are **hops** — each checked to exist in
  the graph, exactly as today's `path:line` refs are.
- **No LLM for discovery**, no LLM for routing. Same discipline as now.

## Why this is better (not just bigger)

| Gain | Mechanism |
|---|---|
| **Real coverage** | interface edges + per-language subgraphs, instead of one ruleset per repo |
| **Higher precision / fewer FPs** | candidates are reachable paths, not pattern hits |
| **Lower cost** | reachability is the **candidate funnel** that makes the tool pay for itself (LLM verifies paths that matter, not every file) |
| **Honest reporting** | coverage labels propagate; polyglot gaps are visible |
| **Stronger measurement** | path-level four-way decomposition ("was the path cut") |
| **Cross-language reach** | boundary traversal without a unified parser |

## What's easy, what's hard (honest)

**Easy / now:** entrypoint extraction for common frameworks; route↔client binding
by literal URL; env/config binding; SBOM ↔ OSV; reachability within one language;
coverage labels; path-level decomposition.

**Hard / later:** precise FFI taint; dynamic dispatch / reflection / metaprogramming
(Spring, Python decorators, JS prototypes); queues and async hops; build-dependent
languages (C/C++, Java) needing compilation for deep analysis; monorepo build graphs.

**Do not fake:** where a boundary cannot be resolved, emit an **opaque boundary
node** and mark paths through it `unchecked`. That is the same abstention principle
the verifier already follows.

## MVP (graph-lite) — buildable on what exists

**Status:** steps 1–4 done (`languages.py`, `graph.py`, multi-ruleset scan,
interface edges for HTTP and env/config, path candidates in the Review tab).
Remaining: dependency edges via SBOM, path-level E1 re-run.

1. **Graph schema + builder** reusing the current CPG for functions/calls and the
   SBOM/store for dependencies. ✅
2. **Boundary types:** HTTP routes ✅ and env/config ✅; dependency usage ⬜.
3. **Reachability** from route handlers and untrusted-config sources ✅.
4. **Path candidates** in `e1.py` / the Review tab; the evidence gate verifies hops ✅.
5. **Coverage report** in the app: `checked / unchecked / unsupported` ✅.
6. **Re-run E1** at path granularity ⬜.

Everything downstream — verifier, four-way decomposition, calibration, ledger,
cache, cost model, web app — is reused unchanged. That is the point: the WCG is a
**front-end to the existing instrument**, not a new system.
