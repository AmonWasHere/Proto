import pytest

from rewardaudit import graph
from rewardaudit.cpg import Cpg
from rewardaudit.schema import Finding, Location

FLASK_APP = '''import os
from flask import Flask

app = Flask(__name__)


@app.route("/run")
def handler():
    return run(os.environ["CMD"])


def run(cmd):
    return os.system(cmd)
'''


def _require_cpg(root):
    if not Cpg(root).available():
        pytest.skip("tree-sitter not installed")


def test_route_to_sink_path(tmp_path):
    (tmp_path / "app.py").write_text(FLASK_APP)
    _require_cpg(tmp_path)
    finding = Finding(id="f1", analyzer="t", rule="cmdi", message="",
                      location=Location("app.py", 12))  # the os.system line
    rows = graph.path_candidates(tmp_path, [finding])
    row = rows[0]
    assert row["language"] == "python"
    assert row["reachable"] is True
    assert row["entry"].startswith("/run")
    assert "handler" in row["hops"] and "run" in row["hops"]
    assert row["coverage"] == "covered"


def test_unreachable_finding_has_no_entry(tmp_path):
    (tmp_path / "lib.py").write_text("import os\n\n\ndef helper(x):\n    return os.system(x)\n")
    _require_cpg(tmp_path)
    finding = Finding(id="f2", analyzer="t", rule="cmdi", message="",
                      location=Location("lib.py", 5))
    rows = graph.path_candidates(tmp_path, [finding])
    assert rows[0]["reachable"] is False
    assert rows[0]["entry"] is None


def test_graph_has_packages_and_files(tmp_path):
    (tmp_path / "app.py").write_text(FLASK_APP)
    _require_cpg(tmp_path)
    g = graph.build(tmp_path)
    kinds = {n.kind for n in g.nodes.values()}
    assert {"file", "function", "route", "package"} <= kinds


def test_coverage_propagates_to_unverified_language(tmp_path):
    (tmp_path / "app.py").write_text(FLASK_APP)
    _require_cpg(tmp_path)
    g = graph.build(tmp_path)
    fn = next(n for n in g.nodes.values() if n.kind == "function")
    assert fn.coverage == "covered"
