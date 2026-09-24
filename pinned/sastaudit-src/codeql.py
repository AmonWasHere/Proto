"""CodeQL, driven through the CLI in no-build mode.

Why CodeQL is the tool this study most needs
--------------------------------------------
Two reasons, and only the second is about accuracy.

1. **Independent lineage.** Semgrep and opengrep are parent and fork, running
   the same rule file; agreement between them is close to vacuous. PMD's entire
   `category/java/security.xml` is two rules (`HardCodedCryptoKey`,
   `InsecureCryptoIv`) with no SQL-injection or XSS rule at all, so it is a
   linter rather than a taint analyser and cannot serve as a comparator. CodeQL
   is a semantic, database-backed taint tracker sharing no code or rules with
   either, built by a different organisation. It is the only tool available here
   whose results would be genuinely independent evidence.

2. **It is the tool the benchmark's own scorer treats specially.** The ported
   BenchmarkUtils grants CodeQL a hardcoded CWE-327-for-328 leniency that no
   other tool receives. A study about how the benchmark grades tools should
   include the tool the benchmark bends its rules for.

The no-build question
---------------------
CodeQL's Java extractor historically required a build, which would have been
fatal for the real-world corpus: reconstructing a compiled state for 263
repositories is not possible from a single changed file. `--build-mode=none`
removes that requirement by indexing source directly.

It is not free. GitHub's own documentation rates no-build accuracy "Good"
rather than "Best", and generated code is not analysed. That caveat is recorded
here and in the result files rather than being quietly absorbed, because a tool
given a weaker mode and then reported as having missed something is exactly the
kind of unearned comparison this study exists to criticise. The no-build mode is
used only where a build is genuinely impossible; on the OWASP Benchmark, which
is a real Maven project, CodeQL gets a normal built database instead.

Cost
----
A database is built per scan, which is the expensive part -- seconds for a
handful of files, minutes for a repository. Each database is deleted as soon as
its findings are extracted, because 120 of them would otherwise fill the disk.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from .base import RawFinding, ScanOutcome, Tool, ToolError, require_binary
from .sarif import parse as parse_sarif

#: The standard CodeQL Java security suite. `extended` is the broadest of the
#: three shipped variants (security, security-extended, security-and-quality);
#: the study's whole argument on the real corpus is "the tool was given every
#: rule available", so the broadest suite is the only defensible choice. The
#: dependency-consistency suites that make up the rest of `andon` are excluded
#: because they answer a different question (known-CVE dependencies), not
#: "is this source code vulnerable".
DEFAULT_SUITE = "codeql/java-queries:codeql-suites/java-security-extended.qls"

BUILD_MODES = ("none", "autobuild")


class CodeQL(Tool):
    name = "codeql"

    def __init__(
        self,
        *,
        suite: str = DEFAULT_SUITE,
        build_mode: str = "none",
        binary: str = "codeql",
        ram_mb: int = 4096,
        threads: int = 4,
        download: bool = True,
    ) -> None:
        if build_mode not in BUILD_MODES:
            raise ValueError(f"build_mode must be one of {BUILD_MODES}")
        self.suite = suite
        self.build_mode = build_mode
        self.binary = binary
        self.ram_mb = ram_mb
        self.threads = threads
        self.download = download

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def version(self) -> str:
        proc = self._run([self.binary, "version", "--format=terse"], timeout=300)
        out = (proc.stdout or proc.stderr).strip().splitlines()
        return out[0] if out else "unknown"

    #: "Recording pack reference codeql/java-queries at <path>/<version>."
    _PACK_REF = re.compile(
        r"Recording pack reference (\S+) at (.+?)/?\.?$", re.M
    )

    def resolved_suite(self) -> dict:
        """Resolve the suite to concrete pack versions.

        Recorded in every result file, because "the latest
        java-security-extended" is not a reproducible description: query packs
        gain and lose queries between releases, so a score without the pack
        version is a number nobody can re-derive. `resolve queries` prints one
        `Recording pack reference` line per pack; the version is the last path
        segment of the reported location.
        """
        proc = self._run(
            [self.binary, "resolve", "queries", self.suite], timeout=600
        )
        if proc.returncode != 0:
            raise ToolError(f"could not resolve {self.suite}: {proc.stderr[:300]}")
        packs: dict[str, str] = {}
        for name, location in self._PACK_REF.findall(proc.stdout):
            packs[name] = Path(location.rstrip("/.")).name
        return {"suite": self.suite, "packs": packs}

    def _run(self, cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
        """Run a CodeQL subcommand, reclaiming the WHOLE process tree on timeout.

        `subprocess.run(..., timeout=)` kills only the direct child. For CodeQL
        that child is the `/bin/sh` launcher script, and the java extractor it
        forked survives as an orphan -- still holding the pipes it inherited,
        and still resident.

        This was measured rather than reasoned about, because the obvious
        hypothesis turned out to be wrong twice. `subprocess.run`'s timeout is
        NOT defeated by a process tree: it raises on schedule. What it fails to
        do is reclaim one. A 2-second timeout on `database create` raises
        `ToolError` at exactly 2.0s and leaves 2 java processes behind.

        That leak is what starved a 120-commit run rather than any hang. One
        extractor tree is ~2.2 GB against ~3.6 GB available; a few timeouts and
        every later commit crawls. The failure presents as a run that has hung,
        when it is in fact running at a fraction of its speed -- the same
        "silence indistinguishable from working" shape this study documents in
        its subject. Freeing the leaked trees mid-run restored ~10x throughput
        immediately.

        `start_new_session=True` makes the child a session and process-group
        leader, so the group can be killed as a unit. The group id equals the
        child's pid, so the kill is race-free even though grandchildren are
        reparented as soon as the child dies.
        """
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
            leaked = self._reclaim(proc)
            raise ToolError(
                f"timed out after {timeout}s: {' '.join(cmd[:3])} "
                f"(killed process group; {leaked} surviving process(es)"
                f"{'' if not leaked else ' -- see _reclaim'})"
            ) from exc
        return subprocess.CompletedProcess(cmd, proc.returncode, out, err)

    @staticmethod
    def _reclaim(proc: subprocess.Popen) -> int:
        """SIGKILL the child's whole process group, drain it, and reap it.

        Returns the number of processes still alive in the group afterwards.
        A nonzero return is a real finding, not a formality: it would mean the
        group was not fully killed, and the caller says so in the error rather
        than reporting a clean timeout. Expected to be 0.
        """
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            # The group is already gone, or the child was reaped under us.
            try:
                proc.kill()
            except OSError:
                pass
        # Draining is safe now that the group is dead: no surviving process
        # holds a write end, so this returns instead of blocking forever.
        try:
            proc.communicate(timeout=60)
        except (subprocess.TimeoutExpired, ValueError):
            proc.kill()
            proc.wait()
        try:
            os.killpg(proc.pid, 0)
        except OSError:
            return 0  # ESRCH: no process left in the group.
        return 1

    def scan(self, root: Path) -> ScanOutcome:
        root = Path(root).resolve()
        if not root.is_dir():
            raise ToolError(f"not a directory: {root}")

        started = time.monotonic()
        # The database is scratch, not an artefact of the study: it is deleted
        # in the finally block regardless of outcome. 120 built databases would
        # be tens of gigabytes.
        workdir = Path(tempfile.mkdtemp(prefix="codeql-db-"))
        db = workdir / "db"
        sarif = workdir / "out.sarif"
        try:
            create = self._run(
                [
                    self.binary, "database", "create", str(db),
                    "--language=java",
                    f"--build-mode={self.build_mode}",
                    f"--source-root={root}",
                    "--overwrite",
                ],
                # Reconstruction corpora are small; a full repository build is
                # not, and a hung extractor must not stall a 120-commit run.
                timeout=3600,
            )
            if create.returncode != 0:
                raise ToolError(
                    "database create failed: "
                    + (create.stderr.strip() or create.stdout.strip())[-600:]
                )

            cmd = [
                self.binary, "database", "analyze", str(db), self.suite,
                "--format=sarif-latest",
                f"--output={sarif}",
                f"--ram={self.ram_mb}",
                f"--threads={self.threads}",
            ]
            if self.download:
                cmd.append("--download")
            analyze = self._run(cmd, timeout=7200)
            # OBSERVED, not assumed: when a query in the suite runs out of heap,
            # the evaluator dies, CodeQL exits NONZERO and no SARIF is written,
            # so the whole commit is lost rather than one query's results being
            # omitted. This comment previously claimed the opposite -- that
            # CodeQL "exits 0 even when individual queries fail: it logs the
            # failure and simply omits those results from the SARIF". That was
            # written from expectation and is wrong for this failure mode; it
            # was caught by the run recording `database analyze failed` for a
            # commit whose stderr was an OverlyLargeRange.ql OOM.
            #
            # The distinction matters because the two failure modes are not
            # equally dangerous. Losing a query is silent and looks exactly like
            # "that query ran and matched nothing". Losing a commit is loud: it
            # lands in `scan_failures`, the run is marked incomplete, and
            # --resume retries it. The expensive failure is the recoverable one.
            #
            # Whether some *other* query failure is non-fatal and does exit 0
            # with a partial SARIF is NOT established. `failed_queries()` in
            # real_corpus parses stderr for that case; if this OOM behaviour is
            # the only one, that parser never fires.
            if analyze.returncode != 0 or not sarif.exists():
                raise ToolError(
                    "database analyze failed: "
                    + (analyze.stderr.strip() or analyze.stdout.strip())[-600:]
                )

            findings = parse_sarif(sarif.read_text(encoding="utf-8"), root)
            return ScanOutcome(
                findings=findings,
                returncode=0,
                stderr=analyze.stderr[-4000:],
                seconds=time.monotonic() - started,
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


def preflight(binary: str = "codeql") -> str:
    """Confirm the CLI is present and usable before a long run starts."""
    path = require_binary(binary)
    proc = subprocess.run(
        [binary, "version", "--format=terse"], capture_output=True, text=True, timeout=300
    )
    if proc.returncode != 0:
        raise ToolError(f"codeql present at {path} but not runnable")
    return (proc.stdout or "").strip().splitlines()[0]
