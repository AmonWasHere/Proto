"""Semgrep and its fork opengrep, which share an output schema.

Why both are here
-----------------
Opengrep is a fork of Semgrep taken after Semgrep's licence change, maintained
by a separate team with its own engine work. Running both is the cheapest
available test of a specific worry: if the real-world miss rate were an artefact
of one project's rule-writing or one engine's pattern matcher, a fork that
started from the same code but has diverged would not reproduce it. Agreement
between them is *not* independent confirmation -- they share ancestry and, in
this study, the same input rules -- so the result is reported as "the same
family", never as two independent tools. CodeQL and PMD carry the independence
in this study, and neither shares lineage with Semgrep.

Rule provenance
---------------
Both are driven by the SAME pinned ruleset file (rules/p-java-best.yaml, the
690-rule union of the three large Java rulesets). That is deliberate: it holds
the rules constant and varies the engine, which is the comparison that isolates
"is the miss a rule gap or an engine gap". Feeding opengrep the Semgrep
registry's own rule files would instead confound the two.

Semgrep's native JSON is used rather than its SARIF, because the first phase of
the study was validated against that schema; re-routing it through SARIF would
change an already-measured number for no gain.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from .base import RawFinding, ScanOutcome, Tool, ToolError, normalise_cwe, relpath

#: The union ruleset. Both engines read this exact file.
RULES = Path(__file__).resolve().parents[1] / "rules" / "p-java-best.yaml"


def _cwes(finding: dict) -> tuple[str, ...]:
    """CWE claims from a Semgrep finding's metadata, normalised."""
    meta = finding.get("extra", {}).get("metadata", {}) or {}
    raw = meta.get("cwe")
    if raw is None:
        return ()
    values = [raw] if isinstance(raw, str) else list(raw)
    out: list[str] = []
    for value in values:
        norm = normalise_cwe(str(value))
        if norm and norm not in out:
            out.append(norm)
    return tuple(out)


class SemgrepFamily(Tool):
    """Shared implementation for the `semgrep` and `opengrep` CLIs."""

    binary = "semgrep"
    name = "semgrep"

    #: Both engines accept these; the fork has drifted from its parent on a few
    #: flags and the divergence is handled in `_engine_flags` rather than by
    #: maintaining two command builders that could silently drift apart.
    def __init__(self, rules: Path = RULES, jobs: int = 4) -> None:
        self.rules = rules
        self.jobs = jobs

    def _engine_flags(self) -> list[str]:
        """Flags this engine accepts. Overridden where the fork has diverged."""
        return ["--metrics=off"]

    def _cmd(self, root: Path) -> list[str]:
        cmd = [
            self.binary,
            "scan",  # accepted by both; semgrep treats it as the default verb
            "--config", str(self.rules),
            "--json",
            "--quiet",
            "--disable-version-check",
            "--no-git-ignore",
            "--timeout", "60",
            "--max-target-bytes", "4000000",
            # Pinned rather than defaulted: opengrep defaults to 16 parallel
            # jobs, which is enough to make the engine abort under memory
            # pressure on this machine and turn a scan into a false "clean".
            "--jobs", str(self.jobs),
            *self._engine_flags(),
            str(root),
        ]
        return cmd

    def version(self) -> str:
        try:
            proc = subprocess.run(
                [self.binary, "--version"], capture_output=True, text=True, timeout=120
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ToolError(f"{self.binary} --version failed: {exc}") from exc
        return proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else "unknown"

    def scan(self, root: Path) -> ScanOutcome:
        root = Path(root).resolve()
        # semgrep-core returns rc=2 and dies when several instances run at once
        # on a memory-tight machine. It is contention, not the input: the same
        # commit scans cleanly on its own. Retry rather than drop, because a
        # silently dropped scan biases coverage downward and that bias would
        # land on the tool, which is the opposite of the study's interest.
        started = time.monotonic()
        last = ""
        for attempt in range(3):
            try:
                proc = subprocess.run(
                    self._cmd(root), capture_output=True, text=True, timeout=1800
                )
            except subprocess.TimeoutExpired as exc:
                last = f"timeout after 1800s: {exc}"
                continue
            # rc 1 means "findings present" for semgrep-family tools.
            if proc.returncode in (0, 1):
                return ScanOutcome(
                    findings=self._parse(proc.stdout, root),
                    returncode=0,
                    stderr=proc.stderr[:2000],
                    seconds=time.monotonic() - started,
                )
            last = (proc.stderr.strip() or proc.stdout.strip())[:400]
            time.sleep(2 * (attempt + 1))
        raise ToolError(f"{self.binary} failed after 3 attempts: {last}")

    def _parse(self, stdout: str, root: Path) -> list[RawFinding]:
        if not stdout.strip():
            return []
        raw = json.loads(stdout).get("results", [])
        findings: list[RawFinding] = []
        for f in raw:
            path = relpath(f.get("path", ""), root)
            if path is None:
                continue
            findings.append(
                RawFinding(
                    path=path,
                    line=int(f.get("start", {}).get("line", -1)),
                    rule=f.get("check_id", "?"),
                    cwes=_cwes(f),
                    message=(f.get("extra", {}) or {}).get("message", "")[:300],
                )
            )
        return findings


class Semgrep(SemgrepFamily):
    name = "semgrep"
    binary = "semgrep"


class Opengrep(SemgrepFamily):
    name = "opengrep"
    binary = "opengrep"

    def _engine_flags(self) -> list[str]:
        # The fork removed telemetry, so it has no --metrics flag and rejects
        # the parent's spelling outright rather than ignoring it.
        return []
