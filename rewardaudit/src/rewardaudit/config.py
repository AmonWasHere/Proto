"""Filesystem locations of pinned assets.

Resolution order for each asset:
  1. explicit environment variable,
  2. the pinned copy inside this repository (`pinned/`),
  3. the frozen prior project `~/Projects/Patch` (read-only fallback).

Large corpora and binaries live in `pinned/` but are gitignored; see
`pinned/README.md`.
"""

from __future__ import annotations

import os
from pathlib import Path

_RESEARCH_ROOT = Path(__file__).resolve().parents[3]
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
ASSETS = Path(os.environ.get("REWARDAUDIT_ASSETS", str(_RESEARCH_ROOT / "pinned")))
_PATCH = Path(os.environ.get("REWARDAUDIT_PATCH", "~/Projects/Patch")).expanduser()


def _first(*candidates: Path, env: str | None = None) -> Path:
    if env and os.environ.get(env):
        return Path(os.environ[env]).expanduser()
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[-1]


PATCH_ROOT = _PATCH

#: Pinned opengrep binary (Semgrep-compatible engine).
OPENGREP_BIN = _first(
    ASSETS / "bin/opengrep",
    _PATCH / "sastaudit/tools/bin/opengrep",
    env="REWARDAUDIT_OPENGREP",
)

#: Pinned 690-rule Java ruleset from the prior study.
JAVA_RULES = _first(
    ASSETS / "rules/p-java-best.yaml",
    _PATCH / "sastaudit/rules/p-java-best.yaml",
    env="REWARDAUDIT_JAVA_RULES",
)

#: RewardAudit's own minimal, pinned Python ruleset (for harness validation).
PYTHON_RULES = _first(
    _PROJECT_ROOT / "rules/python-minimal.yaml",
    env="REWARDAUDIT_PYTHON_RULES",
)

#: Pinned Java control set (18 vulnerable / 3 safe).
CONTROLS_DIR = _first(
    ASSETS / "controls",
    _PATCH / "sastaudit/controls",
    env="REWARDAUDIT_CONTROLS",
)

#: JavaVFC corpus (vulnerability-fixing commits, Java).
JAVAVFC_DIR = _first(
    ASSETS / "corpus/javavfc",
    _PATCH / "sastaudit/data/javavfc",
    env="REWARDAUDIT_JAVAVFC",
)

#: Vendored small Python repositories.
PYTHON_REPOS = _first(
    ASSETS / "data/repos-python",
    _PATCH / "data/repos",
    env="REWARDAUDIT_PY_REPOS",
)

#: RewardAudit's own labelled datasets.
DATASETS = Path(os.environ.get("REWARDAUDIT_DATASETS", str(_PROJECT_ROOT / "datasets")))
PYTHON_PAIRS = DATASETS / "python/pairs"
PYTHON_CANARIES = DATASETS / "python/canaries"
