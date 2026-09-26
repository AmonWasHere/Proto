import json

import pytest

from rewardaudit import deps, graph
from rewardaudit.cpg import Cpg


def test_requirements_parsing(tmp_path):
    (tmp_path / "requirements.txt").write_text("pyyaml==5.3\n# comment\nflask==3.0\n")
    found = {(d.package, d.version, d.ecosystem) for d in deps.scan(tmp_path)}
    assert ("pyyaml", "5.3", "PyPI") in found
    assert ("flask", "3.0", "PyPI") in found


def test_package_json_parsing(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"left-pad": "^1.2.3"}}))
    found = {(d.package, d.version, d.ecosystem) for d in deps.scan(tmp_path)}
    assert ("left-pad", "1.2.3", "npm") in found


def test_cargo_and_go_parsing(tmp_path):
    (tmp_path / "Cargo.toml").write_text("[dependencies]\nserde = \"1.0.1\"\n")
    (tmp_path / "go.mod").write_text("require (\n\tgithub.com/x/y v1.2.3\n)\n")
    found = {(d.package, d.version, d.ecosystem) for d in deps.scan(tmp_path)}
    assert ("serde", "1.0.1", "crates.io") in found
    assert ("github.com/x/y", "1.2.3", "Go") in found


def test_dependency_and_advisory_edges(tmp_path):
    if not Cpg(tmp_path).available():
        pytest.skip("tree-sitter not installed")
    if not graph._snapshot():
        pytest.skip("advisory snapshot missing")
    (tmp_path / "requirements.txt").write_text("pyyaml==5.3\n")
    (tmp_path / "app.py").write_text("import yaml\n\n\ndef load(data):\n    return yaml.load(data)\n")

    g = graph.build(tmp_path)
    dep_nodes = [n for n in g.nodes.values() if n.kind == "dependency"]
    assert any(n.name == "pyyaml@5.3" for n in dep_nodes)
    # import package resolves to the declared dependency
    assert any(e.kind == "resolves_to" for e in g.edges)
    # and the affected version reaches an advisory
    advisories = [n for n in g.nodes.values() if n.kind == "advisory"]
    assert advisories, "pyyaml 5.3 should map to a fixture advisory"
    assert any(e.kind == "vulnerable_to" for e in g.edges)


def test_unresolved_http_boundary_is_visible(tmp_path):
    if not Cpg(tmp_path).available():
        pytest.skip("tree-sitter not installed")
    (tmp_path / "client.py").write_text(
        "import requests\n\n\ndef go():\n    return requests.get('http://nowhere.invalid/xyz')\n"
    )
    g = graph.build(tmp_path)
    assert g.boundaries_unresolved >= 1
    assert any(n.kind == "external" for n in g.nodes.values())
