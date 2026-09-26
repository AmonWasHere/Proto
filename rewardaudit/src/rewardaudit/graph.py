"""Whole-codebase graph — graph-lite with interface edges.

Beyond files and functions, this connects the *seams* of a system:

* **HTTP**: a client call in one function is bound to the route handler it reaches
  (by URL path), giving a cross-file/cross-service edge;
* **config/env**: reads of environment/config keys become untrusted **sources**,
  bound to where the value is defined (`.env`, Dockerfile, compose), so
  `os.environ[...] -> sink` is itself an entry -> sink path.

Heuristics, stated plainly (an MVP, not a sound call graph):
* call edges are matched **by simple name**, attributed to the enclosing function;
* routes are recognised by common decorators/annotations;
* HTTP binding matches URL **paths** (equality or suffix), so dynamic URLs are
  missed; FFI / RPC / queues are not modelled yet.

Every node carries the coverage status of its language; a path is only as covered
as its least-covered hop.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from . import config, deps, languages
from .cpg import FUNCTION_TYPES, Cpg
from .schema import Finding
from .store import KnowledgeStore, Snapshot

_SNAPSHOT: Snapshot | bool | None = None


def _snapshot() -> Snapshot | None:
    """The pinned advisory snapshot, loaded once (None if absent)."""
    global _SNAPSHOT
    if _SNAPSHOT is None:
        path = config.THREAT_SNAPSHOT
        try:
            _SNAPSHOT = Snapshot.load(path) if path.is_file() else False
        except Exception:  # noqa: BLE001
            _SNAPSHOT = False
    return _SNAPSHOT if isinstance(_SNAPSHOT, Snapshot) else None

CALL_TYPES = {"call", "method_invocation", "call_expression"}

PY_ROUTE = re.compile(r"@\w+\.(?:route|get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]", re.I)
PY_DEF = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)")
JAVA_ROUTE = re.compile(
    r"@(?:Get|Post|Put|Delete|Request)Mapping\(\s*(?:value\s*=\s*)?['\"]([^'\"]+)", re.I
)
JAVA_METHOD = re.compile(r"^\s*(?:public|protected|private|static|final|\s)+[\w<>\[\],\s]+\s+(\w+)\s*\(")
PY_IMPORT = re.compile(r"^\s*(?:from\s+([\w.]+)|import\s+([\w.]+))")
JAVA_IMPORT = re.compile(r"^\s*import\s+([\w.]+);?")

PY_ENV = re.compile(
    r"os\.environ(?:\.get)?\s*[\(\[]\s*['\"]([\w]+)['\"]|os\.getenv\s*\(\s*['\"]([\w]+)['\"]"
)
JAVA_ENV = re.compile(r"System\.getenv\s*\(\s*['\"]([\w]+)['\"]|@Value\s*\(\s*['\"]\$\{([\w.]+)\}")

URL = re.compile(r"['\"](https?://[^'\"\s]+|/[^'\"\s]*)['\"]")
CLIENT_HINTS = (
    "requests.", "httpx.", "urlopen", "aiohttp", "session.", "resttemplate",
    "webclient", "httpclient", "okhttp", "url(", "fetch(",
)

CONFIG_FILES = {".env", "docker-compose.yml", "docker-compose.yaml", "dockerfile"}
ENV_LINE = re.compile(r"^\s*(?:ENV\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*(.+)$")

_STATUS_RANK = {"covered": 0, "ground_only": 1, "find_only": 2, "unsupported": 3, "unknown": 4}


@dataclass(frozen=True, slots=True)
class Node:
    id: str
    kind: str  # file | function | route | package | config | finding
    name: str
    path: str = ""
    line: int = 0
    language: str = ""
    coverage: str = "unknown"


@dataclass(frozen=True, slots=True)
class Edge:
    src: str
    dst: str
    kind: str  # contains | calls | http_call | imports | reads_config | defines_config | localizes


@dataclass
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    handlers: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    source_labels: dict[str, str] = field(default_factory=dict)
    boundaries_unresolved: int = 0

    def add(self, node: Node) -> None:
        self.nodes[node.id] = node

    def link(self, src: str, dst: str, kind: str) -> None:
        self.edges.append(Edge(src, dst, kind))

    def calls_map(self) -> dict[str, set[str]]:
        """Traversal edges for reachability: intra-proc calls and HTTP hops."""
        out: dict[str, set[str]] = {}
        for edge in self.edges:
            if edge.kind in ("calls", "http_call"):
                out.setdefault(edge.src, set()).add(edge.dst)
        return out

    def entries(self) -> list[str]:
        seen: list[str] = []
        for item in self.handlers + self.sources:
            if item not in seen:
                seen.append(item)
        return seen


# --------------------------------------------------------------------------- #
# helpers
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
    out = []
    for node in _function_nodes(tree):
        name = _first_identifier(node, source)
        if name:
            out.append((name, node.start_point[0] + 1, node.start_byte, node.end_byte))
    return out


def _enclosing(functions: list[tuple[str, int, int, int]], offset: int) -> str:
    best, best_span = "", None
    for name, _line, start, end in functions:
        if start <= offset < end:
            span = end - start
            if best_span is None or span < best_span:
                best_span, best = span, name
    return best


def _calls_with_enclosing(tree, source: bytes) -> list[tuple[str, str]]:
    functions = _functions(tree, source)
    pairs: list[tuple[str, str]] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in CALL_TYPES:
            callee = _first_identifier(node, source)
            enclosing = _enclosing(functions, node.start_byte)
            if callee and enclosing:
                pairs.append((enclosing, callee))
        stack.extend(node.children)
    return pairs


def _arguments_with_enclosing(tree, source: bytes, pattern: re.Pattern) -> list[tuple[str, str]]:
    """(enclosing function, match) for a regex over each call node's text."""
    functions = _functions(tree, source)
    out: list[tuple[str, str]] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in CALL_TYPES:
            text = source[node.start_byte:node.end_byte].decode("utf-8", "replace")
            match = pattern.search(text)
            enclosing = _enclosing(functions, node.start_byte)
            if match and enclosing:
                out.append((enclosing, match.group(1)))
        stack.extend(node.children)
    return out


def _env_reads_with_enclosing(source_text: str, functions, pattern: re.Pattern) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for match in pattern.finditer(source_text):
        var = next((g for g in match.groups() if g), "")
        offset = len(source_text[: match.start()].encode("utf-8"))
        enclosing = _enclosing(functions, offset)
        if var and enclosing:
            out.append((enclosing, var))
    return out


def _http_calls_with_enclosing(tree, source: bytes) -> list[tuple[str, str]]:
    functions = _functions(tree, source)
    out: list[tuple[str, str]] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in CALL_TYPES:
            text = source[node.start_byte:node.end_byte].decode("utf-8", "replace")
            if any(hint in text.lower() for hint in CLIENT_HINTS):
                match = URL.search(text)
                enclosing = _enclosing(functions, node.start_byte)
                if match and enclosing:
                    out.append((enclosing, match.group(1)))
        stack.extend(node.children)
    return out


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


def _norm_path(value: str) -> str:
    if value.startswith("http://") or value.startswith("https://"):
        value = urlparse(value).path or "/"
    value = value.split("?")[0]
    return value.rstrip("/") or "/"


def _route_matches(client_path: str, route_path: str) -> bool:
    a, b = _norm_path(client_path), _norm_path(route_path)
    if a == b:
        return True
    if len(b) > 1 and a.endswith(b):
        return True
    if len(a) > 1 and b.endswith(a):
        return True
    return False


def _config_definitions(root: Path) -> dict[str, str]:
    """env var name -> file that defines it (`.env`, Dockerfile, compose)."""
    defined: dict[str, str] = {}
    for path in root.rglob("*"):
        if not path.is_file() or any(part in languages.SKIP_DIRS for part in path.parts):
            continue
        if path.name.lower() not in CONFIG_FILES:
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = ENV_LINE.match(line)
            if match:
                defined.setdefault(match.group(1), path.relative_to(root).as_posix())
    return defined


# --------------------------------------------------------------------------- #
# build
# --------------------------------------------------------------------------- #
def build(root: Path, findings: list[Finding] | None = None) -> Graph:
    root = Path(root)
    cpg = Cpg(root)
    graph = Graph()
    specs = languages.registry()
    by_name: dict[str, list[str]] = {}
    route_index: list[tuple[str, str]] = []  # (route_path, handler_fn_id)

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
                functions = _functions(tree, raw)
                for name, line, _s, _e in functions:
                    fn_id = f"function|{rel}|{name}|{line}"
                    graph.add(Node(fn_id, "function", name, rel, line, language, spec.status))
                    graph.link(file_id, fn_id, "contains")
                    by_name.setdefault(name, []).append(fn_id)

                for route, handler in _routes(lines, language):
                    route_id = f"route|{language}|{route}"
                    graph.add(Node(route_id, "route", f"{route} -> {handler}", rel, 0, language, spec.status))
                    for fn_id in by_name.get(handler, []):
                        if graph.nodes[fn_id].path == rel:
                            graph.link(route_id, fn_id, "calls")
                            graph.handlers.append(fn_id)
                            route_index.append((route, fn_id))

                for enclosing, var in _env_reads_with_enclosing(source, functions, PY_ENV if language == "python" else JAVA_ENV):
                    for fn_id in by_name.get(enclosing, []):
                        if graph.nodes[fn_id].path == rel:
                            config_id = f"config|{var}"
                            graph.add(Node(config_id, "config", var, "", 0, "", "unknown"))
                            graph.link(fn_id, config_id, "reads_config")
                            if fn_id not in graph.sources:
                                graph.sources.append(fn_id)
                                graph.source_labels[fn_id] = f"env:{var}"

    # intra-procedural calls (second pass so all function names are known)
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

    # interface edge: HTTP client -> route handler
    for language, files in languages.detect(root).items():
        spec = specs[language]
        if not spec.grammar:
            continue
        for file_path in files:
            rel = file_path.relative_to(root).as_posix()
            tree = cpg.tree(rel)
            raw = cpg.source(rel)
            for enclosing, url in _http_calls_with_enclosing(tree, raw):
                matched = False
                for src in by_name.get(enclosing, []):
                    if graph.nodes[src].path != rel:
                        continue
                    for route_path, handler_id in route_index:
                        if _route_matches(url, route_path) and handler_id != src:
                            graph.link(src, handler_id, "http_call")
                            matched = True
                    if not matched:
                        # Unresolved outbound boundary: make it visible instead of
                        # silently truncating the path (design: opaque boundary).
                        boundary_id = f"external|{_norm_path(url)}"
                        graph.add(Node(boundary_id, "external", _norm_path(url), rel, 0, language, "unknown"))
                        graph.link(src, boundary_id, "unresolved")
                        graph.boundaries_unresolved += 1

    # config definitions (`.env`, Dockerfile, compose)
    for var, defining_file in _config_definitions(root).items():
        config_id = f"config|{var}"
        graph.add(Node(config_id, "config", var, "", 0, "", "unknown"))
        file_id = f"file|{defining_file}"
        if file_id not in graph.nodes:
            graph.add(Node(file_id, "file", defining_file, defining_file, 0, "", "unknown"))
        graph.link(file_id, config_id, "defines_config")

    # dependency edges (manifests) -> advisory links (pinned store)
    declared = deps.scan(root)
    if declared:
        repo_id = "repo|."
        graph.add(Node(repo_id, "repo", root.name or ".", "", 0, "", "unknown"))
        for dep in declared:
            dep_id = f"dependency|{dep.ecosystem}|{dep.package}|{dep.version}"
            graph.add(Node(dep_id, "dependency", f"{dep.package}@{dep.version}", "", 0, "", "unknown"))
            graph.link(repo_id, dep_id, "depends_on")
        # link imported package nodes to declared dependencies (via alias map)
        for node in graph.nodes.values():
            if node.kind != "package":
                continue
            resolved = deps.distribution_name(node.name)
            for dep in declared:
                if dep.package in (node.name, resolved):
                    graph.link(node.id, f"dependency|{dep.ecosystem}|{dep.package}|{dep.version}", "resolves_to")
        snapshot = _snapshot()
        if snapshot is not None:
            for match in KnowledgeStore(snapshot).match_dependencies(declared):
                dep = match["dependency"]
                dep_id = f"dependency|{dep.ecosystem}|{dep.package}|{dep.version}"
                for advisory in match["advisories"]:
                    adv_id = f"advisory|{advisory.id}"
                    graph.add(Node(adv_id, "advisory", advisory.id, "", 0, "", "unknown"))
                    graph.link(dep_id, adv_id, "vulnerable_to")

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
    queue: list[str] = []
    for entry in graph.entries():
        queue.append(entry)
        for edge in graph.edges:
            if edge.kind == "calls" and edge.dst == entry and graph.nodes.get(edge.src, Node("", "")).kind == "route":
                queue.append(entry)
                break
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
    entries = graph.entries()
    queue = list(entries)
    seen = set(entries)
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


def _entry_label(graph: Graph, first: str) -> str:
    for edge in graph.edges:
        if edge.kind == "calls" and edge.dst == first:
            node = graph.nodes.get(edge.src)
            if node is not None and node.kind == "route":
                return node.name
    if first in graph.source_labels:
        return graph.source_labels[first]
    return graph.nodes[first].name if first in graph.nodes else first


def _worst_status(graph: Graph, ids: list[str]) -> str:
    statuses = [graph.nodes[i].coverage for i in ids if i in graph.nodes]
    if not statuses:
        return "unknown"
    return max(statuses, key=lambda s: _STATUS_RANK.get(s, 9))


def path_candidates(root: Path, findings: list[Finding]) -> list[dict]:
    """Findings -> path candidates (entry -> ... -> enclosing function) + coverage."""
    graph = build(root, findings)
    rows = []
    for finding in findings:
        fn_id = enclosing_function(graph, finding.location.path, finding.location.start_line)
        hops = path_to_entry(graph, fn_id)
        hop_ids = hops or ([fn_id] if fn_id else [])
        rows.append(
            {
                "finding": finding.id,
                "language": languages.language_of(finding.location.path),
                "entry": _entry_label(graph, hops[0]) if hops else None,
                "hops": [graph.nodes[i].name for i in hop_ids],
                "reachable": bool(hops),
                "coverage": _worst_status(graph, hop_ids),
            }
        )
    return rows
