# pinned/

Pinned assets copied from the frozen prior study `~/Projects/Patch/sastaudit`.
Copied, **not moved**, so that project's published record stays intact.

## Committed (small, source-like)

| Path | What |
|---|---|
| `bin/` (gitignored) | `opengrep` 1.30.0 binary — 45 MB, not committed |
| `rules/p-java-best.yaml` | the prior study's pinned 690-rule Java ruleset |
| `controls/` | the prior study's Java control set (21 files + manifest) |
| `sastaudit-src/` | reference source: `tools/*.py`, `eval/`, `scoring/`, `corpus/`, `artifact/` (pins + FINDINGS.md) |

## Gitignored (bulk data)

| Path | What | Size |
|---|---|---|
| `corpus/javavfc/` | JavaVFC vulnerability-fixing commit corpus | 35 MB |
| `data/repos-python/` | small Python repos (pgcli, pyodbc, sqlite-web, records) | ~6 MB |
| `data/splits/` | commit-pair splits | ~249 MB |

The larger C/C++ repos and the 179k-record `commit_pairs.jsonl` remain in
`~/Projects/Patch/data/` and are referenced by path via `rewardaudit.config`.

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
cp ~/Projects/Patch/sastaudit/tools/*.py pinned/sastaudit-src/
cp -r ~/Projects/Patch/sastaudit/{eval,scoring,corpus,artifact} pinned/sastaudit-src/
```
