"""Interface edges: HTTP client->route binding and env/config sources."""

import pytest

from rewardaudit import graph
from rewardaudit.cpg import Cpg
from rewardaudit.schema import Finding, Location

CLIENT = '''import requests
from flask import Flask

app = Flask(__name__)


@app.route("/trigger")
def trigger():
    return requests.get("http://svc/run")
'''

SERVER = '''import os
from flask import Flask

app = Flask(__name__)


@app.route("/run")
def handler():
    return run(os.environ["CMD"])


def run(cmd):
    return os.system(cmd)
'''

CLI = '''import os


def main():
    os.system(os.environ["CMD"])
'''


def _require(tmp_path):
    if not Cpg(tmp_path).available():
        pytest.skip("tree-sitter not installed")


def test_http_client_binds_to_route_handler(tmp_path):
    (tmp_path / "client.py").write_text(CLIENT)
    (tmp_path / "server.py").write_text(SERVER)
    _require(tmp_path)

    g = graph.build(tmp_path)
    http = [e for e in g.edges if e.kind == "http_call"]
    assert http, "expected an http_call edge binding /run to its handler"
    src = g.nodes[http[0].src].name
    dst = g.nodes[http[0].dst].name
    assert src == "trigger" and dst == "handler"


def test_sink_reachable_and_path_from_entry(tmp_path):
    (tmp_path / "client.py").write_text(CLIENT)
    (tmp_path / "server.py").write_text(SERVER)
    _require(tmp_path)

    finding = Finding(id="s1", analyzer="t", rule="cmdi", message="",
                      location=Location("server.py", 12))  # os.system line
    row = graph.path_candidates(tmp_path, [finding])[0]
    assert row["reachable"] is True
    assert "handler" in row["hops"] and "run" in row["hops"]


def test_env_read_is_an_entry_source(tmp_path):
    (tmp_path / "cli.py").write_text(CLI)
    _require(tmp_path)

    g = graph.build(tmp_path)
    assert g.sources, "a function reading os.environ should be an entry source"
    assert any(label.startswith("env:") for label in g.source_labels.values())

    finding = Finding(id="e1", analyzer="t", rule="cmdi", message="",
                      location=Location("cli.py", 5))
    row = graph.path_candidates(tmp_path, [finding])[0]
    assert row["reachable"] is True
    assert row["entry"] == "env:CMD"


def test_config_definition_edge(tmp_path):
    (tmp_path / "cli.py").write_text(CLI)
    (tmp_path / ".env").write_text("CMD=ls\nOTHER=1\n")
    _require(tmp_path)

    g = graph.build(tmp_path)
    config_nodes = [n for n in g.nodes.values() if n.kind == "config" and n.name == "CMD"]
    assert config_nodes
    assert any(e.kind == "defines_config" and e.dst == config_nodes[0].id for e in g.edges)


def test_route_path_matching_is_suffix_aware():
    assert graph._route_matches("http://svc/api/run", "/api/run")
    assert graph._route_matches("/run", "/run")
    assert not graph._route_matches("/other", "/run")
