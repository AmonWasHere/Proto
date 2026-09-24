"""Filesystem locations of the pinned, prior-study assets.

Everything is overridable by environment variable so the package never hard-codes
a machine. Defaults point at the frozen `~/Projects/Patch` study, which we
consume **read-only** (see docs/issues.md F2).
"""

from __future__ import annotations

import os
from pathlib import Path

PATCH_ROOT = Path(os.environ.get("REWARDAUDIT_PATCH", "~/Projects/Patch")).expanduser()

OPENGREP_BIN = Path(
    os.environ.get("REWARDAUDIT_OPENGREP", str(PATCH_ROOT / "sastaudit/tools/bin/opengrep"))
)
JAVA_RULES = Path(
    os.environ.get("REWARDAUDIT_JAVA_RULES", str(PATCH_ROOT / "sastaudit/rules/p-java-best.yaml"))
)
CONTROLS_DIR = Path(
    os.environ.get("REWARDAUDIT_CONTROLS", str(PATCH_ROOT / "sastaudit/controls"))
)
