"""Whole-codebase graph — graph-lite MVP.

The unit of analysis becomes a *system* graph, not a file: functions, the calls
between them, HTTP entrypoints, package dependencies, and the findings attached to
them. From it we compute **reachability from entrypoints** and turn each finding
into a **path candidate** (entry -> ... -> sink), which is what the verifier
adjudicates.

Heuristics, stated plainly (an MVP, not a sound call graph):
* call edges are matched **by simple name**, attributed to the enclosing function
  (over-approximate on name collisions, blind to dynamic dispatch);
* routes are recognised by common decorators/annotations and bound to the next
  function declaration;
* package edges are top-level imports only.

Every node carries the coverage status of its language; a path is only as covered
as its least-covered hop.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import languages
from .cpg import FUNCTION_TYPES, Cpg
from .schema import Finding

CALL_TYPES = {"call", "method_invocation", "call_expression"}

PY_ROUTE = re.compile(r"@\w+\.(?:route|get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]", re.I)
PY_DEF = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)")
JAVA_ROUTE = re.compile(
    r"@(?:Get|Post|Put|Delete|Request)Mapping\(\s*(?:value\s*=\s*)?['\"]([^'\"]+)", re.I
)
JAVA_METHOD = re.compile(r"^\s*(?:public|protected|private|static|final|\s)+[\w<>\[\],\s]+\s+(\w+)\s*\(")
PY_IMPORT = re.compile(r"^\s*(?:from\s+([\w.]+)|import\s+([\w.]+))")
JAVA_IMPORT = re.compile(r"^\s*import\s+([\w.]+);?")

_STATUS_RANK = {"covered": 0, "ground_only": 1, "find_only": 2, "unsupported": 3, "unknown": 4}


@dataclass(frozen=True, slots=True)
class Node:
    id: str
    kind: str  # file | function | route | package | finding
    name: str
    path: str = ""
    line: int = 0
    language: str = ""
    coverage: str = "unknown"


@dataclass(frozen=True, slots=True)
class Edge:
    src: str
    dst: str
    kind: str  # contains | calls | imports | localizes


@dataclass
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    handlers: list[str] = field(default_factory=list)

    def add(self, node: Node) -> None:
        self.nodes[node.id] = node

    def link(self, src: str, dst: str, kind: str) -> None:
        self.edges.append(Edge(src, dst, kind))

    def calls_map(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for edge in self.edges:
            if edge.kind == "calls":
                out.setdefault(edge.src, set()).add(edge.dst)
        return out


# --------------------------------------------------------------------------- #
# tree helpers
# --------------------------------------------------------------------------- #
def _first_identifier(node, source: bytes) -> str:
    queue = [node]
    while queue:
        current = queue.pop(0)
        if current.type == "identifier":
            return source[current.start_byte:current.end_byte].decode("utf-8", "replace")
        queue.extend(current.children)
    return ""


def _function_nodes(tree) -> list:
    found = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in FUNCTION_TYPES:
            found.append(node)
        stack.extend(node.children)
    return found


def _functions(tree, source: bytes) -> list[tuple[str, int, int, int]]:
    """(name, line, start_byte, end_byte) for every function-like node."""
    out = []
    for node in _function_nodes(tree):
        name = _first_identifier(node, source)
        if name:
            out.append((name, node.start_point[0] + 1, node.start_byte, node.end_byte))
    return out


def _calls_with_enclosing(tree, source: bytes) -> list[tuple[str, str]]:
    """(enclosing_function_name, callee_name) pairs."""
    functions = _functions(tree, source)
    pairs: list[tuple[str, str]] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in CALL_TYPES:
            callee = _first_identifier(node, source)
            if callee:
                enclosing = ""
                best_span = None
                for name, _line, start, end in functions:
                    if start <= node.start_byte and node.end_byte <= end:
                        span = end - start
                        if best_span is None or span < best_span:
                            best_span, enclosing = span, name
                if enclosing:
                    pairs.append((enclosing, callee))
        stack.extend(node.children)
    return pairs


def _routes(source_lines: list[str], language: str) -> list[tuple[str, str]]:
    routes: list[tuple[str, str]] = []
    pattern = PY_ROUTE if language == "python" else JAVA_ROUTE
    def_pattern = PY_DEF if language == "python" else JAVA_METHOD
    for index, line in enumerate(source_lines):
        match = pattern.search(line)
        if not match:
            continue
        for follow in source_lines[index + 1: index + 4]:
            handler = def_pattern.match(follow)
            if handler:
                routes.append((match.group(1), handler.group(1)))
                break
    return routes


def _imports(source_lines: list[str], language: str) -> list[str]:
    pattern = PY_IMPORT if language == "python" else JAVA_IMPORT
    packages: list[str] = []
    for line in source_lines:
        match = pattern.match(line)
        if match:
            raw = next((g for g in match.groups() if g), "")
            top = raw.split(".")[0]
            if top and top not in packages:
                packages.append(top)
    return packages


# --------------------------------------------------------------------------- #
# build
# --------------------------------------------------------------------------- #
def build(root: Path, findings: list[Finding] | None = None) -> Graph:
    root = Path(root)
    cpg = Cpg(root)
    graph = Graph()
    specs = languages.registry()
    by_name: dict[str, list[str]] = {}

    for language, files in languages.detect(root).items():
        spec = specs[language]
        for file_path in files:
            rel = file_path.relative_to(root).as_posix()
            file_id = f"file|{rel}"
            graph.add(Node(file_id, "file", rel, rel, 0, language, spec.status))
            source = file_path.read_text(encoding="utf-8", errors="replace")
            lines = source.splitlines()

            for package in _imports(lines, language):
                pkg_id = f"package|{package}"
                graph.add(Node(pkg_id, "package", package, "", 0, "", "unknown"))
                graph.link(file_id, pkg_id, "imports")

            if spec.grammar:
                tree = cpg.tree(rel)
                raw = cpg.source(rel)
                for name, line, _start, _end in _functions(tree, raw):
                    fn_id = f"function|{rel}|{name}|{line}"
                    graph.add(Node(fn_id, "function", name, rel, line, language, spec.status))
                    graph.link(file_id, fn_id, "contains")
                    by_name.setdefault(name, []).append(fn_id)
                for enclosing, callee in set(_calls_with_enclosing(tree, raw)):
                    for target in by_name.get(callee, []):
                        src = next(
                            (fid for fid in by_name.get(enclosing, []) if graph.nodes[fid].path == rel),
                            None,
                        )
                        if src and target != src:
                            graph.link(src, target, "calls")

            for route, handler in _routes(lines, language):
                route_id = f"route|{language}|{route}"
                graph.add(Node(route_id, "route", f"{route} -> {handler}", rel, 0, language, spec.status))
                for fn_id in by_name.get(handler, []):
                    if graph.nodes[fn_id].path == rel:
                        graph.link(route_id, fn_id, "calls")
                        graph.handlers.append(fn_id)

    # Second pass for calls whose target name was defined later in the walk.
    for language, files in languages.detect(root).items():
        spec = specs[language]
        if not spec.grammar:
            continue
        for file_path in files:
            rel = file_path.relative_to(root).as_posix()
            tree = cpg.tree(rel)
            raw = cpg.source(rel)
            for enclosing, callee in set(_calls_with_enclosing(tree, raw)):
                for src in by_name.get(enclosing, []):
                    if graph.nodes[src].path != rel:
                        continue
                    for target in by_name.get(callee, []):
                        if target != src:
                            graph.link(src, target, "calls")

    if findings:
        for finding in findings:
            fid = f"finding|{finding.id}"
            graph.add(
                Node(fid, "finding", finding.rule, finding.location.path,
                     finding.location.start_line,
                     languages.language_of(finding.location.path) or "", "")
            )
            fn_id = enclosing_function(graph, finding.location.path, finding.location.start_line)
            if fn_id:
                graph.link(fn_id, fid, "localizes")
    return graph


def enclosing_function(graph: Graph, path: str, line: int) -> str | None:
    best: Node | None = None
    for node in graph.nodes.values():
        if node.kind == "function" and node.path == path and node.line <= line:
            if best is None or node.line > best.line:
                best = node
    return best.id if best else None


def reachable(graph: Graph) -> set[str]:
    adjacency = graph.calls_map()
    seen: set[str] = set()
    queue = list(graph.handlers)
    while queue:
        current = queue.pop()
        if current in seen:
            continue
        seen.add(current)
        queue.extend(adjacency.get(current, ()))
    return seen


def path_to_entry(graph: Graph, target: str | None) -> list[str] | None:
    if target is None:
        return None
    adjacency = graph.calls_map()
    predecessors: dict[str, str] = {}
    queue = list(graph.handlers)
    seen = set(queue)
    while queue:
        current = queue.pop(0)
        if current == target:
            path = [current]
            while path[-1] in predecessors:
                path.append(predecessors[path[-1]])
            return list(reversed(path))
        for nxt in adjacency.get(current, ()):
            if nxt not in seen:
                seen.add(nxt)
                predecessors[nxt] = current
                queue.append(nxt)
    return None


def _worst_status(graph: Graph, ids: list[str]) -> str:
    statuses = [graph.nodes[i].coverage for i in ids if i in graph.nodes]
    if not statuses:
        return "unknown"
    return max(statuses, key=lambda s: _STATUS_RANK.get(s, 9))


def _entry_route(graph: Graph, handler_id: str) -> str | None:
    for edge in graph.edges:
        if edge.kind == "calls" and edge.dst == handler_id:
            node = graph.nodes.get(edge.src)
            if node is not None and node.kind == "route":
                return node.name
    return None


def path_candidates(root: Path, findings: list[Finding]) -> list[dict]:
    """Findings -> path candidates (entry -> ... -> enclosing function) + coverage."""
    graph = build(root, findings)
    rows = []
    for finding in findings:
        fn_id = enclosing_function(graph, finding.location.path, finding.location.start_line)
        hops = path_to_entry(graph, fn_id)
        hop_ids = hops or ([fn_id] if fn_id else [])
        entry = None
        if hops:
            entry = _entry_route(graph, hops[0]) or graph.nodes[hops[0]].name
        rows.append(
            {
                "finding": finding.id,
                "language": languages.language_of(finding.location.path),
                "entry": entry,
                "hops": [graph.nodes[i].name for i in hop_ids],
                "reachable": bool(hops),
                "coverage": _worst_status(graph, hop_ids),
            }
        )
    return rows
