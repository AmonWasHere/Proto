"""Materialise JavaVFC revision pairs for E1.

We reuse the pinned, stdlib-only corpus module from the prior study
(`pinned/sastaudit-src/corpus/javavfc.py`) rather than reimplementing patch
reversal: it fetches the fixed file (cached, offline after first fetch) and
reverse-applies the patch to reconstruct the vulnerable revision.

Each selected commit becomes one pair of files:

    <sha12>_vuln.java   <sha12>_fixed.java   + manifest.json

Selection is restricted to **single-file** commits, matching the prior study's
`raw`/`security` strata: with several changed files, "did the verdict track the
fix?" is ambiguous at file granularity.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from . import config


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location("pinned_javavfc", path)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise RuntimeError(f"cannot load corpus module: {path}")
    module = importlib.util.module_from_spec(spec)
    # Register before exec: dataclasses resolve annotations via
    # sys.modules[cls.__module__] on import, and a None lookup crashes on 3.14.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _usable(commits):
    return [c for c in commits if c.is_usable and len(c.reconstructible_java_files) == 1]


def cached_count(commits, cache_dir: Path) -> int:
    module = _load_module(config.JAVAVFC_MODULE)
    total = 0
    for commit in _usable(commits):
        path = commit.reconstructible_java_files[0].path
        if (module._cache_path(cache_dir, commit.repo, commit.sha, path)).exists():
            total += 1
    return total


def build_pairs(
    out_dir: Path,
    *,
    limit: int = 100,
    stride: int = 1,
    allow_network: bool = True,
) -> dict:
    """Materialise pairs into `out_dir`; returns a small summary."""
    module = _load_module(config.JAVAVFC_MODULE)
    commits = module.load(config.JAVAVFC_JSONL)
    pool = _usable(commits)
    if stride > 1:
        pool = pool[::stride]
    if limit:
        pool = pool[:limit]

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pairs: list[dict] = []
    skipped: list[dict] = []
    for commit in pool:
        changed = commit.reconstructible_java_files[0]
        try:
            vuln, fixed = module.materialize(
                commit,
                changed.path,
                changed.patch,
                cache_dir=config.JAVAVFC_CACHE,
                allow_network=allow_network,
            )
        except Exception as exc:  # noqa: BLE001 - uncached/network/reverse-apply
            skipped.append({"sha": commit.sha, "reason": f"{type(exc).__name__}: {exc}"[:160]})
            continue
        name = commit.sha[:12]
        (out_dir / f"{name}_vuln.java").write_text(vuln, encoding="utf-8")
        (out_dir / f"{name}_fixed.java").write_text(fixed, encoding="utf-8")
        # The line the fix removed, in the vulnerable revision: point the
        # candidate at the change, not at line 1 (which shows only imports).
        removed = sorted(module.removed_lines(changed.patch))
        line = removed[0] if removed else 1
        message = (commit.message or "").splitlines()
        pairs.append(
            {
                "id": name,
                "category": "",
                "cwe": "",
                "vuln": f"{name}_vuln.java",
                "fixed": f"{name}_fixed.java",
                "line": line,
                "repo": commit.repo,
                "message": (message[0] if message else "")[:120],
            }
        )

    (out_dir / "manifest.json").write_text(json.dumps({"pairs": pairs}, indent=2))
    return {
        "corpus_total": len(commits),
        "usable_single_file": len(_usable(commits)),
        "selected": len(pool),
        "materialised": len(pairs),
        "skipped": len(skipped),
        "skip_reasons": skipped[:10],
        "out_dir": str(out_dir),
    }


def _main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="rewardaudit.datasets.javavfc")
    parser.add_argument("--out", default=str(config.JAVAVFC_PAIRS))
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--stride", type=int, default=1)
    parser.add_argument("--offline", action="store_true", help="use only the cache")
    args = parser.parse_args(argv)
    summary = build_pairs(
        Path(args.out), limit=args.limit, stride=args.stride, allow_network=not args.offline
    )
    for key, value in summary.items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
