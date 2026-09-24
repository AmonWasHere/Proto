"""SARIF 2.1.0 -> RawFinding.

SARIF is the one output format CodeQL and PMD both speak, so parsing it once
means adding a scanner is a matter of command line and metadata, not of writing
another parser. Semgrep keeps its native JSON path (tools/semgrep.py) because
that is the output the first phase of the study was validated against, and
re-parsing it through SARIF would be a silent change to an already-published
number.

Two things SARIF makes easy to get wrong, both handled here:

* **Paths.** `artifactLocation.uri` may be a relative path, an absolute path, or
  a `file://` URI, and CodeQL emits the third. All three are reduced to a path
  relative to the scan root; anything that resolves outside the root is dropped
  rather than guessed at, because a misfiled finding would land in the wrong
  arm of the vuln/fixed split.
* **CWE claims.** CodeQL puts them in rule tags as `external/cwe/cwe-089`; PMD
  does not report them at all. Rather than synthesise a CWE for a tool that
  never claimed one, the parser takes an optional per-tool lookup that is
  applied only when the tool itself said nothing.
"""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path

from .base import RawFinding, parse_cwe_tags, relpath


class SarifParseError(RuntimeError):
    """A SARIF log that could not be interpreted, as opposed to an empty one."""

#: Rules whose metadata carries a CWE under a plain `cwe` property rather than a
#: tag. CodeQL's older query packs used this spelling.
_CWE_KEYS = ("cwe", "cweId", "cwe_id")


def _rule_metadata(run: dict) -> dict[str, tuple[str, ...]]:
    """Map rule id -> the CWEs that rule claims, from the driver's rule table."""
    out: dict[str, tuple[str, ...]] = {}
    rules = run.get("tool", {}).get("driver", {}).get("rules", []) or []
    for rule in rules:
        rid = rule.get("id")
        if not rid:
            continue
        props = rule.get("properties", {}) or {}
        cwes: list[str] = list(parse_cwe_tags(props.get("tags", []) or []))
        for key in _CWE_KEYS:
            value = props.get(key)
            if isinstance(value, str) and value not in cwes:
                cwes.append(value)
        if cwes:
            out[rid] = tuple(cwes)
    return out


def parse_uri(uri: str, root: Path) -> str | None:
    """Reduce a SARIF artifactLocation URI to a root-relative path.

    The subtlety that matters: a SARIF uri may be absolute, or relative to a
    base named by `uriBaseId`. CodeQL uses the latter, emitting bare filenames
    with `uriBaseId = %SRCROOT%`, where SRCROOT is the analysis source root --
    which is precisely the directory being scanned. Resolving such a URI
    against the process working directory instead (the intuitive reading of a
    relative path) makes every single finding resolve outside the scan root and
    vanish, turning a tool that found 19 things into a tool that found nothing,
    with no error anywhere. That is the exact failure mode this study is about,
    so the relative case is handled explicitly rather than incidentally.
    """
    if uri.startswith("file://"):
        uri = urllib.parse.unquote(urllib.parse.urlparse(uri).path)
    # Windows-style separators appear even in some Linux tool outputs.
    uri = uri.replace("\\", "/")
    candidate = Path(uri)
    if not candidate.is_absolute():
        candidate = root / candidate
    return relpath(candidate, root)


def parse(
    text: str,
    root: Path,
    *,
    cwe_lookup: dict[str, tuple[str, ...]] | None = None,
) -> list[RawFinding]:
    """Parse a SARIF log into findings relative to `root`.

    `cwe_lookup` is consulted only for rules that made no CWE claim of their
    own, so a tool that reports CWEs is never overridden by our table.

    Raises SarifParseError if the log contains results but not one of them could
    be placed. A parser that silently drops everything reports the same thing as
    a scanner that found nothing, and the two are not the same fact -- so the
    ambiguous case is refused rather than returned.
    """
    if not text.strip():
        return []
    log = json.loads(text)
    findings: list[RawFinding] = []
    seen = dropped = 0

    for run in log.get("runs", []) or []:
        claimed = _rule_metadata(run)
        for result in run.get("results", []) or []:
            seen += 1
            rid = result.get("ruleId") or result.get("rule", {}).get("id") or "?"
            cwes = claimed.get(rid, ())
            if not cwes and cwe_lookup:
                cwes = cwe_lookup.get(rid, ())

            locations = result.get("locations", []) or []
            if not locations:
                dropped += 1
                continue
            phys = locations[0].get("physicalLocation", {}) or {}
            uri = (phys.get("artifactLocation", {}) or {}).get("uri", "")
            path = parse_uri(uri, root) if uri else None
            if path is None:
                dropped += 1
                continue
            line = (phys.get("region", {}) or {}).get("startLine", -1)
            findings.append(
                RawFinding(
                    path=path,
                    line=int(line) if line is not None else -1,
                    rule=rid,
                    cwes=tuple(cwes),
                    message=(result.get("message", {}) or {}).get("text", "")[:300],
                )
            )

    if seen and not findings:
        sample = _first_uri(log)
        raise SarifParseError(
            f"{seen} results in the log but none could be located under {root}; "
            f"first uri was {sample!r}. This is a parser failure, not a clean scan."
        )
    return findings


def _first_uri(log: dict) -> str:
    for run in log.get("runs", []) or []:
        for result in run.get("results", []) or []:
            for loc in result.get("locations", []) or []:
                uri = (loc.get("physicalLocation", {}) or {}).get(
                    "artifactLocation", {}
                ).get("uri")
                if uri:
                    return uri
    return "<none>"
