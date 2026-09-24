"""opengrep adapter (Semgrep-compatible), using its native JSON output.

Why native JSON rather than SARIF: the prior study validated its control numbers
against this schema, so re-routing through SARIF would change an already-measured
number for no gain. CodeQL will use SARIF (see `sarif.py`).

Robustness learned from the prior study's postmortem:
  * a timeout must kill the whole **process group**, or the JVM/extractor child
    survives and starves later runs;
  * a crash must raise, never return an empty list — a silent "clean" is the
    failure mode this whole project is about.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path

from ..schema import Evidence, EvidenceKind, Finding, Location, ScanResult, normalise_cwe
from .base import AnalyzerError

CWE_KEY = "cwe"


def _run(cmd: list[str], timeout: float) -> tuple[int, str, str]:
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.communicate()
        raise AnalyzerError(f"timeout after {timeout}s; process group killed") from exc
    return proc.returncode, out, err


def _cwes(extra: dict) -> tuple[str, ...]:
    raw = (extra.get("metadata", {}) or {}).get(CWE_KEY)
    if raw is None:
        return ()
    values = [raw] if isinstance(raw, str) else list(raw)
    out: list[str] = []
    for value in values:
        norm = normalise_cwe(str(value))
        if norm and norm not in out:
            out.append(norm)
    return tuple(out)


class Opengrep:
    """Runs a pinned opengrep binary against a pinned ruleset."""

    name = "opengrep"

    def __init__(
        self,
        binary: Path,
        rules: Path,
        *,
        jobs: int = 4,
        scan_timeout: float = 1800.0,
        per_rule_timeout: float = 60.0,
        max_target_bytes: int = 4_000_000,
    ) -> None:
        self.binary = Path(binary)
        self.rules = Path(rules)
        self.jobs = jobs
        self.scan_timeout = scan_timeout
        self.per_rule_timeout = per_rule_timeout
        self.max_target_bytes = max_target_bytes

    def available(self) -> bool:
        return self.binary.is_file() and os.access(self.binary, os.X_OK)

    def version(self) -> str:
        code, out, err = _run([str(self.binary), "--version"], timeout=120)
        if code != 0:
            raise AnalyzerError(f"opengrep --version failed: {err.strip()[:200]}")
        return out.strip().splitlines()[0] if out.strip() else "unknown"

    def _cmd(self, root: Path) -> list[str]:
        return [
            str(self.binary),
            "scan",
            "--config",
            str(self.rules),
            "--json",
            "--quiet",
            "--disable-version-check",
            "--no-git-ignore",
            "--timeout",
            str(int(self.per_rule_timeout)),
            "--max-target-bytes",
            str(self.max_target_bytes),
            "--jobs",
            str(self.jobs),
            str(root),
        ]

    def scan(self, root: Path) -> ScanResult:
        if not self.available():
            raise AnalyzerError(f"opengrep binary not found: {self.binary}")
        if not self.rules.is_file():
            raise AnalyzerError(f"ruleset not found: {self.rules}")
        root = Path(root).resolve()
        started = time.monotonic()
        last = ""
        for attempt in range(3):
            code, out, err = _run(self._cmd(root), timeout=self.scan_timeout)
            # opengrep returns 1 when findings are present.
            if code in (0, 1):
                return ScanResult(
                    findings=self._parse(out, root),
                    returncode=0,
                    stderr=err[:2000],
                    seconds=time.monotonic() - started,
                    analyzer=self.name,
                    version=self.version(),
                )
            last = (err.strip() or out.strip())[:400]
            time.sleep(2 * (attempt + 1))
        raise AnalyzerError(f"opengrep failed after 3 attempts: {last}")

    def _parse(self, stdout: str, root: Path) -> list[Finding]:
        if not stdout.strip():
            return []
        raw = json.loads(stdout).get("results", [])
        findings: list[Finding] = []
        for item in raw:
            path = item.get("path", "")
            try:
                rel = Path(path).resolve().relative_to(root).as_posix()
            except (ValueError, OSError):
                continue
            start = item.get("start", {}) or {}
            end = item.get("end", {}) or {}
            location = Location(
                path=rel,
                start_line=int(start.get("line", -1)),
                end_line=int(end.get("line", start.get("line", -1))),
                start_col=int(start.get("col", 0)),
                end_col=int(end.get("col", 0)),
            )
            rule = item.get("check_id", "?")
            message = (item.get("extra", {}) or {}).get("message", "")[:300]
            findings.append(
                Finding(
                    id=f"opengrep|{rule}|{rel}|{location.start_line}",
                    analyzer=self.name,
                    rule=rule,
                    message=message,
                    location=location,
                    cwes=_cwes(item.get("extra", {}) or {}),
                    evidence=(
                        Evidence(
                            kind=EvidenceKind.TOOL_FINDING,
                            source=self.name,
                            summary=message or rule,
                            ref=location.ref(),
                        ),
                    ),
                )
            )
        return findings
