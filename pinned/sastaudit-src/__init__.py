"""Scanner adapters, behind one interface.

Adding a scanner should be a matter of writing a `scan(root)` that returns
RawFinding, and registering it here. Everything downstream -- the control
matrix, the four-way decomposition, the comparison table -- is written against
that interface and needs no change.

Binary resolution
-----------------
The scanners do not share an installation root: semgrep lives in the project
virtualenv, while codeql and opengrep are unpacked into tools/bin because
neither has a package on PyPI. Rather than making every caller aware of that,
importing this package puts both locations on PATH. It is done here, once, so a
scanner can never be silently missing simply because the harness was launched
with the system interpreter instead of the venv.
"""

from __future__ import annotations

import inspect
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SASTAUDIT = _HERE.parent
BIN = _HERE / "bin"

for _candidate in (BIN, BIN / "codeql", Path(sys.executable).parent):
    if _candidate.is_dir():
        _existing = os.environ.get("PATH", "")
        if str(_candidate) not in _existing.split(os.pathsep):
            os.environ["PATH"] = f"{_candidate}{os.pathsep}{_existing}"

from .base import RawFinding, ScanOutcome, Tool, ToolError  # noqa: E402
from .codeql import DEFAULT_SUITE, CodeQL  # noqa: E402
from .semgrep import Opengrep, Semgrep  # noqa: E402

#: Registration order is also report order: cheapest first, so a partial run
#: still contains the tools that finish quickly.
REGISTRY: dict[str, type[Tool]] = {
    "semgrep": Semgrep,
    "opengrep": Opengrep,
    "codeql": CodeQL,
}

#: Tools deliberately excluded, with the reason. Kept in code rather than in a
#: commit message because the question "why isn't SpotBugs here" is one a
#: reviewer will ask, and the answer is a property of the study design.
EXCLUDED: dict[str, str] = {
    "pmd": (
        "PMD's category/java/security.xml contains exactly two rules "
        "(HardCodedCryptoKey, InsecureCryptoIv) and includes no SQL injection, "
        "XSS, or path traversal rule. It is a linter, not a taint analyser, so "
        "scoring it on the OWASP Benchmark would measure its purpose rather "
        "than its quality -- the precise error this study criticises."
    ),
    "spotbugs": (
        "FindSecBugs analyses compiled bytecode, which the real-world corpus "
        "cannot supply: reconstructing a buildable project from one changed "
        "file is not possible. Its inclusion would also force a build on the "
        "OWASP side, making the two halves of the study use different "
        "measurement conditions."
    ),
    "infer": (
        "Same bytecode requirement as SpotBugs, plus a compilation database "
        "per commit that the reconstruction method cannot produce."
    ),
}


def build_tool(name: str, **kwargs) -> Tool:
    """Construct a registered scanner by name.

    Keyword arguments a scanner does not accept are dropped rather than raising,
    so a caller can pass one uniform set of tuning options (heap, thread count)
    without knowing which analyzers have such knobs. Filtering happens against
    the signature instead of by catching TypeError from the call, which would
    also swallow a genuine TypeError raised inside a constructor.
    """
    if name in EXCLUDED:
        raise ToolError(f"{name} is excluded from this study: {EXCLUDED[name]}")
    try:
        cls = REGISTRY[name]
    except KeyError:
        raise ToolError(
            f"unknown tool {name!r}; known: {sorted(REGISTRY)}"
        ) from None
    accepted = inspect.signature(cls.__init__).parameters
    return cls(**{k: v for k, v in kwargs.items() if k in accepted})


def available_tools() -> dict[str, bool]:
    """Which registered scanners are actually runnable right now."""
    out: dict[str, bool] = {}
    for name in REGISTRY:
        try:
            out[name] = build_tool(name).available()
        except Exception:  # noqa: BLE001 - availability probing must not raise
            out[name] = False
    return out


__all__ = [
    "BIN",
    "DEFAULT_SUITE",
    "EXCLUDED",
    "REGISTRY",
    "CodeQL",
    "Opengrep",
    "RawFinding",
    "ScanOutcome",
    "Semgrep",
    "Tool",
    "ToolError",
    "available_tools",
    "build_tool",
]
