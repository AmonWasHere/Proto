"""Language registry and coverage.

Fixes the silent-skip problem: a file whose language has no ruleset must be
reported as `unchecked`, never treated as clean.

A language's status is the combination of two capabilities:

* **rules**    — a pinned ruleset exists, so candidates can be *found*;
* **grammar**  — a tree-sitter grammar exists, so claims can be *grounded*.

    covered       rules + grammar
    find_only     rules, no grammar   (findings cannot be evidence-grounded)
    ground_only   grammar, no rules   (can verify manually-supplied candidates)
    unsupported   neither
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import config

#: Directories that are never part of "the codebase".
SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build",
    "target", "bin", "obj", ".idea", ".vscode", "site-packages", "pinned", "runs",
    ".mypy_cache", ".pytest_cache", ".tox",
}

#: Non-source files that must not be counted as "unchecked code".
NONCODE_EXT = {
    ".md", ".rst", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".lock", ".env", ".xml", ".html", ".htm", ".svg", ".png", ".jpg", ".jpeg", ".gif",
    ".pdf", ".csv", ".log", ".bak", ".orig", ".patch", ".diff", ".sum",
}
NONCODE_NAMES = {
    ".env", ".gitignore", ".gitattributes", "license", "licence", "notice",
    "readme", "makefile", "dockerfile", "changelog",
}


def _is_noncode(path: Path) -> bool:
    return path.suffix.lower() in NONCODE_EXT or path.name.lower() in NONCODE_NAMES


@dataclass(frozen=True, slots=True)
class LanguageSpec:
    name: str
    extensions: tuple[str, ...]
    rules: tuple[Path, ...]
    grammar: bool

    @property
    def status(self) -> str:
        if self.rules and self.grammar:
            return "covered"
        if self.rules:
            return "find_only"
        if self.grammar:
            return "ground_only"
        return "unsupported"


def registry() -> dict[str, LanguageSpec]:
    """The languages this build knows about, with what it can actually do."""
    return {
        "java": LanguageSpec("java", (".java",), (config.JAVA_RULES,), True),
        "python": LanguageSpec("python", (".py",), (config.PYTHON_RULES,), True),
        "c": LanguageSpec("c", (".c", ".h"), (), True),
        "cpp": LanguageSpec("cpp", (".cc", ".cpp", ".cxx", ".hpp", ".hh"), (), False),
        "javascript": LanguageSpec("javascript", (".js", ".jsx", ".mjs", ".cjs"), (), False),
        "typescript": LanguageSpec("typescript", (".ts", ".tsx"), (), False),
        "go": LanguageSpec("go", (".go",), (), False),
        "rust": LanguageSpec("rust", (".rs",), (), False),
        "ruby": LanguageSpec("ruby", (".rb",), (), False),
        "php": LanguageSpec("php", (".php",), (), False),
        "csharp": LanguageSpec("csharp", (".cs",), (), False),
    }


_EXT_INDEX: dict[str, str] | None = None


def language_of(path: str | Path) -> str | None:
    global _EXT_INDEX
    if _EXT_INDEX is None:
        _EXT_INDEX = {
            ext: spec.name for spec in registry().values() for ext in spec.extensions
        }
    return _EXT_INDEX.get(Path(path).suffix.lower())


def _walk(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def detect(root: Path) -> dict[str, list[Path]]:
    """Map language name -> files present, for supported languages only."""
    root = Path(root)
    out: dict[str, list[Path]] = {}
    for path in _walk(root):
        lang = language_of(path)
        if lang:
            out.setdefault(lang, []).append(path)
    return out


def rules_for(root: Path) -> list[Path]:
    """Every available ruleset for the languages present (dedup, existing only)."""
    found = detect(root)
    rules: list[Path] = []
    for spec in registry().values():
        if spec.name in found:
            for rule in spec.rules:
                if rule.is_file() and rule not in rules:
                    rules.append(rule)
    return rules


def coverage_report(root: Path) -> dict:
    """Explicit coverage: what was checked, what was not, and why."""
    root = Path(root)
    counts: dict[str, int] = {}
    files: dict[str, int] = {}
    for path in _walk(root):
        if _is_noncode(path):
            continue
        lang = language_of(path) or "unknown"
        files[lang] = files.get(lang, 0) + 1
        if lang == "unknown":
            counts["unknown"] = counts.get("unknown", 0) + 1
        else:
            counts[registry()[lang].status] = counts.get(registry()[lang].status, 0) + 1

    languages = []
    for name, spec in registry().items():
        n = len(detect(root).get(name, []))
        if n:
            languages.append({"language": name, "files": n, "status": spec.status,
                              "rules": [r.name for r in spec.rules if r.is_file()]})

    unchecked_languages = sorted(
        {name for name, n in files.items() if n and (name == "unknown" or registry().get(name, LanguageSpec(name, (), (), False)).status == "unsupported")}
    )
    total = sum(files.values())
    covered = sum(v for k, v in counts.items() if k in ("covered", "ground_only"))
    return {
        "root": str(root),
        "files_total": total,
        "by_status": counts,
        "by_language": languages,
        "unchecked_languages": unchecked_languages,
        "checked_fraction": (covered / total) if total else 0.0,
    }
