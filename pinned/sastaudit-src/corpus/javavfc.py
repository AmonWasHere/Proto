"""JavaVFC: real, human-verified Java vulnerability-fixing commits.

Source: Zenodo record 13731781 (784 records, sha256 pinned in artifact/pins.json).
Each record is a commit whose message matched a vulnerability-fixing regex
(see data/javavfc/regex.txt). JavaVFC reports its own labeling precision as
0.7, which is why it is a *screening* corpus here and Vul4J's execution-verified
entries remain the high-confidence tier.

Why this module exists in this study
------------------------------------
The OWASP Benchmark is synthetic: 2,740 servlet test cases, frozen since 2016,
each written to be flaggable. Any claim of the form "tool X scores 0.85" is a
claim about that corpus, not about code. The open question is what happens when
the same tool meets a vulnerability that a human actually had to fix.

Reconstruction without cloning
------------------------------
`diff_raw` is verbatim `git show` output, so it carries a complete per-file
patch. That is enough to rebuild *both* sides of every changed file:

    fixed      = fetch the file at the fix commit (raw.githubusercontent)
    vulnerable = git apply -R the patch to the fixed file

This needs no repository clone and no GitHub API call (raw.githubusercontent is
a CDN with its own, far looser limits than the 60/hr REST API), so the whole
corpus is reachable from a laptop.

Statuses: only `modified` files are reconstructible. A file *added* by the fix
had no vulnerable predecessor; a file *deleted* by the fix is gone at the fix
commit; a rename moves the path out from under the fetch. All three are
excluded rather than approximated.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

DIFF_HEADER = re.compile(r"^diff --git a/(\S+) b/(\S+)$", re.M)
COMMIT_LINK = re.compile(r"https://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]+)")

STATUS_MODIFIED = "modified"
STATUS_NEW = "new"
STATUS_DELETED = "deleted"
STATUS_RENAMED = "rename"


@dataclass(frozen=True, slots=True)
class ChangedFile:
    """One file's entry within a commit, with its patch text."""

    path: str
    patch: str
    status: str

    @property
    def is_reconstructible(self) -> bool:
        """True only for plain modifications, where a pre-image exists."""
        return self.status == STATUS_MODIFIED


@dataclass(frozen=True, slots=True)
class JavaVFCCommit:
    """One vulnerability-fixing commit."""

    index: int
    repo: str
    sha: str
    date: int
    message: str
    commit_link: str
    files: tuple[ChangedFile, ...]

    @property
    def java_files(self) -> tuple[ChangedFile, ...]:
        return tuple(f for f in self.files if f.path.endswith(".java"))

    @property
    def reconstructible_java_files(self) -> tuple[ChangedFile, ...]:
        return tuple(f for f in self.java_files if f.is_reconstructible)

    @property
    def is_usable(self) -> bool:
        """A commit this study can actually evaluate."""
        return bool(self.reconstructible_java_files)

    def url_for(self, path: str) -> str:
        return f"https://raw.githubusercontent.com/{self.repo}/{self.sha}/{path}"


def split_patch(diff_raw: str) -> dict[str, str]:
    """Split a `git show` body into {post-image path: patch text}.

    Keyed on the b/ path, i.e. the file's name *after* the fix, because that is
    the path the fetch needs. Renames are keyed on the new path and are excluded
    downstream anyway.
    """
    out: dict[str, str] = {}
    for chunk in re.split(r"(?m)^(?=diff --git )", diff_raw):
        m = DIFF_HEADER.match(chunk)
        if not m:
            continue
        body = chunk if chunk.endswith("\n") else chunk + "\n"
        out[m.group(2)] = body
    return out


def _classify(patch: str) -> str:
    if re.search(r"(?m)^new file mode", patch):
        return STATUS_NEW
    if re.search(r"(?m)^deleted file mode", patch):
        return STATUS_DELETED
    if re.search(r"(?m)^rename from", patch):
        return STATUS_RENAMED
    return STATUS_MODIFIED


HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def removed_lines(patch: str) -> set[int]:
    """Line numbers in the *vulnerable* (pre-image) file that the fix deleted.

    This is what makes the coverage figure mean something. Flagging a file is
    weak evidence -- the tool may be reporting a pattern that was there before
    and after. Flagging a line the fix actually removed is the tool pointing at
    the vulnerability itself.

    Line numbers are 1-based into the pre-image, which is exactly the coordinate
    system of a finding produced by scanning the reconstructed vulnerable file.
    """
    out: set[int] = set()
    cursor: int | None = None
    for line in patch.splitlines():
        if line.startswith("diff --git ") or line.startswith("index "):
            cursor = None
            continue
        m = HUNK_HEADER.match(line)
        if m:
            cursor = int(m.group(1))
            continue
        # Only the "before any hunk" state distinguishes a `---`/`+++` file
        # header from a hunk body line. Matching on the prefix instead would
        # misread a deleted Java line `--x;` (which appears as `---x;`) as a
        # header and drop it, undercounting deletions -- and an undercounted
        # deletion is exactly what makes a fix look purely additive.
        if cursor is None:
            continue
        if line.startswith("-"):
            out.add(cursor)
            cursor += 1
        elif line.startswith("+"):
            pass  # added line: occupies no pre-image position
        elif line.startswith("\\"):
            pass  # "\ No newline at end of file"
        else:
            cursor += 1  # context line (including a bare empty line)
    return out


def load(path: str | os.PathLike[str]) -> list[JavaVFCCommit]:
    """Read the JSONL and return one entry per commit, in file order."""
    commits: list[JavaVFCCommit] = []
    with open(path, "r", encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            rec = json.loads(line)
            m = COMMIT_LINK.match(rec.get("commit_link", ""))
            repo, sha = (m.group(1), m.group(2)) if m else ("", "")
            patches = split_patch(rec.get("diff_raw") or "")
            commits.append(
                JavaVFCCommit(
                    index=i,
                    repo=repo,
                    sha=sha,
                    date=rec["date"],
                    message=(rec.get("message") or "").strip(),
                    commit_link=rec.get("commit_link", ""),
                    files=tuple(
                        ChangedFile(path=p, patch=t, status=_classify(t))
                        for p, t in patches.items()
                    ),
                )
            )
    return commits


# ---------------------------------------------------------------------------
# Materialisation: fetch the fixed file, reverse the patch for the vulnerable one
# ---------------------------------------------------------------------------


class FetchError(RuntimeError):
    pass


def _fetch(url: str, *, retries: int = 3, timeout: int = 60) -> str:
    last: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sastaudit/0.1"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            # 404 is terminal: the path genuinely is not at that revision.
            if exc.code == 404:
                raise FetchError(f"404 {url}") from exc
            last = exc
        except Exception as exc:  # noqa: BLE001 - network is untrusted here
            last = exc
    raise FetchError(f"{url}: {last}")


def _cache_path(cache_dir: Path, repo: str, sha: str, path: str) -> Path:
    owner, _, name = repo.partition("/")
    return cache_dir / owner / name / sha / path


def materialize(
    commit: JavaVFCCommit,
    path: str,
    patch: str,
    *,
    cache_dir: Path,
    allow_network: bool = True,
) -> tuple[str, str]:
    """Return (vulnerable_text, fixed_text) for one modified Java file.

    Cached under cache_dir so a re-run is offline and byte-identical. The cache
    stores the *fetched* (fixed) text only; the vulnerable side is always
    re-derived by patch application, so the two sides can never drift apart.
    """
    cached = _cache_path(cache_dir, commit.repo, commit.sha, path)
    if cached.exists():
        fixed = cached.read_text(encoding="utf-8")
    else:
        if not allow_network:
            raise FetchError(f"not cached and network disabled: {path}")
        fixed = _fetch(commit.url_for(path))
        cached.parent.mkdir(parents=True, exist_ok=True)
        # Published atomically. Two processes fetching the same file is not
        # hypothetical -- every tool run over a stratum shares this cache -- and
        # a plain write_text lets them interleave into a truncated entry that
        # every later run reads back and trusts. The failure would surface only
        # as a reverse-apply error, i.e. as a silently skipped commit.
        tmp = cached.parent / f"{cached.name}.tmp{os.getpid()}"
        tmp.write_text(fixed, encoding="utf-8")
        os.replace(tmp, cached)

    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(fixed, encoding="utf-8")
        patch_file = Path(td) / "__p.patch"
        patch_file.write_text(patch.rstrip("\n") + "\n", encoding="utf-8")
        proc = subprocess.run(
            ["git", "apply", "-R", str(patch_file)],
            cwd=td,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise FetchError(f"reverse-apply failed for {path}: {proc.stderr.strip()[:200]}")
        vulnerable = target.read_text(encoding="utf-8")

    return vulnerable, fixed
