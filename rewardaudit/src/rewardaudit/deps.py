"""Dependency extraction: the second interface type.

Parses the common manifests so the codebase graph can carry **what a project
depends on**, then joins that to the advisory store (`store/`). A code path can
then reach an *advisory*, not just a sink:

    file --imports--> package --resolves_to--> dependency --vulnerable_to--> advisory

Parsers are deliberately minimal and documented as incomplete (ranges, lockfiles,
and transitive resolution are not modelled).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .store import Dependency, parse_requirements

MANIFESTS = {
    "requirements.txt",
    "package.json",
    "cargo.toml",
    "go.mod",
    "pom.xml",
}

_CARGO = re.compile(r"^\s*([A-Za-z0-9_\-]+)\s*=\s*\"([^\"]+)\"", re.M)
_GO = re.compile(r"^\s*([\w./\-]+)\s+v([\w.\-]+)", re.M)
_POM_DEP = re.compile(
    r"<dependency>.*?<groupId>\s*([^<\s]+)\s*</groupId>.*?"
    r"<artifactId>\s*([^<\s]+)\s*</artifactId>.*?"
    r"<version>\s*([^<\s]+)\s*</version>.*?</dependency>",
    re.S,
)


def _parse_requirements(path: Path) -> list[Dependency]:
    return parse_requirements(path.read_text(encoding="utf-8", errors="replace"))


def _parse_package_json(path: Path) -> list[Dependency]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    out: list[Dependency] = []
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            cleaned = str(version).lstrip("^~>=<v ").strip()
            out.append(Dependency(name, cleaned, "npm"))
    return out


def _parse_cargo(path: Path) -> list[Dependency]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return [Dependency(name, version.lstrip("^~="), "crates.io") for name, version in _CARGO.findall(text)]


def _parse_go_mod(path: Path) -> list[Dependency]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return [Dependency(name, version, "Go") for name, version in _GO.findall(text)]


def _parse_pom(path: Path) -> list[Dependency]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return [Dependency(f"{g}:{a}", v, "Maven") for g, a, v in _POM_DEP.findall(text)]


_PARSERS = {
    "requirements.txt": _parse_requirements,
    "package.json": _parse_package_json,
    "cargo.toml": _parse_cargo,
    "go.mod": _parse_go_mod,
    "pom.xml": _parse_pom,
}

#: import name -> distribution name. Partial by nature: the import-name to
#: package-name mapping is a known hard problem (needs a registry mapping), so this
#: covers common cases only and everything else falls through unchanged.
IMPORT_ALIASES = {
    "yaml": "pyyaml",
    "PIL": "pillow",
    "bs4": "beautifulsoup4",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "dotenv": "python-dotenv",
    "OpenSSL": "pyopenssl",
    "dateutil": "python-dateutil",
    "jwt": "pyjwt",
    "serial": "pyserial",
    "Crypto": "pycryptodome",
    "attr": "attrs",
    "pkg_resources": "setuptools",
}


def distribution_name(import_name: str) -> str:
    return IMPORT_ALIASES.get(import_name, import_name)



def scan(root: Path) -> list[Dependency]:
    """All declared dependencies found at or below `root`."""
    root = Path(root)
    out: list[Dependency] = []
    seen: set[tuple[str, str, str]] = set()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        parser = _PARSERS.get(path.name.lower())
        if parser is None:
            continue
        try:
            for dep in parser(path):
                key = (dep.ecosystem, dep.package, dep.version)
                if key not in seen:
                    seen.add(key)
                    out.append(dep)
        except OSError:
            continue
    return out
