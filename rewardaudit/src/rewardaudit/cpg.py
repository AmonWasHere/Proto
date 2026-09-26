"""Minimal tree-sitter evidence layer.

Its job is *verification*, not analysis: it answers "does this cited location
resolve to a real node in the real file?" — which is what stops an LLM from
asserting a line that does not exist. It also extracts a bounded code slice
(the enclosing function) for the LLM's verdict request.

tree-sitter is optional at import time so the rest of the package works without
it; using the CPG raises a clear error if it is missing.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

try:  # optional dependency
    import tree_sitter as _ts

    _HAVE_TS = True
except Exception:  # pragma: no cover - exercised when tree-sitter absent
    _ts = None  # type: ignore[assignment]
    _HAVE_TS = False


EXT_LANG = {
    ".java": "java",
    ".py": "python",
    ".c": "c",
    ".h": "c",
}

#: Node types that denote a function-like scope, per language.
FUNCTION_TYPES = {
    "method_declaration",
    "constructor_declaration",
    "function_definition",
    "function_declaration",
    "function_declarator",
}


@dataclass(frozen=True, slots=True)
class NodeHit:
    type: str
    start_line: int
    end_line: int
    start_col: int
    end_col: int
    text: str

    def ref(self, path: str) -> str:
        return f"{path}:{self.start_line}"


@dataclass(frozen=True, slots=True)
class RefCheck:
    ref: str
    ok: bool
    reason: str
    node_type: str | None = None


def _load_language(lang: str):
    if not _HAVE_TS:
        raise RuntimeError("tree-sitter is not installed; install the 'cpg' extra")
    if lang == "java":
        import tree_sitter_java as mod
    elif lang == "python":
        import tree_sitter_python as mod
    elif lang == "c":
        import tree_sitter_c as mod
    else:  # pragma: no cover - guarded by caller
        raise ValueError(f"unsupported language: {lang}")
    return _ts.Language(mod.language())


@lru_cache(maxsize=8)
def _parser(lang: str):
    return _ts.Parser(_load_language(lang))


class Cpg:
    """Read-only tree-sitter view over a repository root."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()
        self._trees: dict[str, object] = {}

    def available(self) -> bool:
        return _HAVE_TS

    def language_for(self, path: str) -> str | None:
        return EXT_LANG.get(Path(path).suffix.lower())

    def _tree(self, path: str):
        if path in self._trees:
            return self._trees[path]
        lang = self.language_for(path)
        if lang is None:
            raise ValueError(f"unsupported file type: {path}")
        full = self.root / path
        if not full.is_file():
            raise FileNotFoundError(path)
        source = full.read_bytes()
        tree = _parser(lang).parse(source)
        self._trees[path] = tree
        return tree

    def _source(self, path: str) -> bytes:
        return (self.root / path).read_bytes()

    def tree(self, path: str):
        """The parsed tree for `path` (public accessor for the graph builder)."""
        return self._tree(path)

    def source(self, path: str) -> bytes:
        return self._source(path)

    def spans(self, path: str, line: int) -> list[NodeHit]:
        """Nodes whose extent covers `line`, smallest first."""
        tree = self._tree(path)
        src = self._source(path)
        hits: list[NodeHit] = []

        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            sl = node.start_point[0] + 1
            el = node.end_point[0] + 1
            if sl <= line <= el:
                hits.append(
                    NodeHit(
                        type=node.type,
                        start_line=sl,
                        end_line=el,
                        start_col=node.start_point[1],
                        end_col=node.end_point[1],
                        text=src[node.start_byte : node.end_byte].decode("utf-8", "replace"),
                    )
                )
                stack.extend(node.children)
        hits.sort(key=lambda h: (h.end_line - h.start_line, h.end_col - h.start_col))
        return hits

    def verify_ref(self, ref: str) -> RefCheck:
        """Check a `path:line` reference resolves to a real node."""
        path, _, line_s = ref.rpartition(":")
        if not path or not line_s.isdigit():
            return RefCheck(ref, False, "malformed ref (expected path:line)")
        try:
            hits = self.spans(path, int(line_s))
        except FileNotFoundError:
            return RefCheck(ref, False, "file not found")
        except ValueError as exc:
            return RefCheck(ref, False, str(exc))
        if not hits:
            return RefCheck(ref, False, "no node spans this line")
        return RefCheck(ref, True, "resolved", hits[0].type)

    def context_slice(self, path: str, line: int, *, max_chars: int = 6000) -> str:
        """The enclosing function's source, or a bounded window fallback."""
        hits = self.spans(path, line)
        for hit in reversed(hits):  # reversed => largest first
            if hit.type in FUNCTION_TYPES:
                return hit.text[:max_chars]
        if hits:
            return hits[-1].text[:max_chars]
        return ""
