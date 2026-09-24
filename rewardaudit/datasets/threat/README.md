# threat/

`osv_snapshot.jsonl` is a **synthetic fixture** in OSV JSON Lines shape, used to
exercise the knowledge store offline. It is **not real advisory data** (ids are
prefixed `RA-FIXTURE-`).

Real snapshots are produced by `scripts/refresh_osv.sh` into dated files
(`osv-YYYY-MM-DD.jsonl`) with a sidecar `.meta.json`; never edit a snapshot in
place (ADR-0003).
