# pinned/

Assets copied from the frozen prior study `~/Projects/Patch/sastaudit`.
Copied, **not moved**, so that project's published record stays intact.

## Committed (small, source-like)

| Path | What |
|---|---|
| `rules/p-java-best.yaml` | the prior study's pinned 690-rule Java ruleset |
| `controls/` | the prior study's Java control set (21 files + manifest) |
| `sastaudit-src/corpus/` | the corpus loader we import (`javavfc.py`), plus the corpus modules it belongs to |
| `sastaudit-src/artifact/` | provenance: `pins.json`, `FINDINGS.md`, `REVISIONS.md` |

Reference-only duplicates of the prior study's `tools/`, `eval/`, and `scoring/`
were removed — the live project is at `~/Projects/Patch/sastaudit` if needed.

## Gitignored (local, regenerable)

| Path | What | Size |
|---|---|---|
| `bin/opengrep` | opengrep 1.30.0 binary | 45 MB |
| `corpus/javavfc/` | JavaVFC corpus (784 commits) + fetched-file cache | 37 MB |

The larger C/C++ repos and the 179k-record `commit_pairs.jsonl` remain in
`~/Projects/Patch/data/` and are referenced by path via `rewardaudit.config`.
Materialised revision pairs live under `rewardaudit/datasets/javavfc_pairs/` and
are regenerable (`harness javavfc --offline`).

## Provenance

Everything pinned is recorded in `sastaudit-src/artifact/pins.json`. Do not edit
vendored files; add new work under `rewardaudit/`.

## Restoring

If `pinned/` is lost, re-copy from `~/Projects/Patch/sastaudit`:

```bash
mkdir -p pinned/{bin,rules,controls,corpus,sastaudit-src}
cp ~/Projects/Patch/sastaudit/tools/bin/opengrep pinned/bin/
cp ~/Projects/Patch/sastaudit/rules/*.yaml pinned/rules/
cp -r ~/Projects/Patch/sastaudit/controls/. pinned/controls/
cp -r ~/Projects/Patch/sastaudit/data/javavfc pinned/corpus/javavfc
cp -r ~/Projects/Patch/sastaudit/{corpus,artifact} pinned/sastaudit-src/
```
