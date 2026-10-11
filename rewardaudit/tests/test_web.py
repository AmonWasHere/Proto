import json
import threading
import urllib.request

import pytest

from rewardaudit import config
from rewardaudit.web import server as web


@pytest.fixture(scope="module")
def base(tmp_path_factory):
    env_file = tmp_path_factory.mktemp("cfg") / "env"
    web.ENV_FILE = env_file  # keep tests away from real credentials
    httpd = web.serve("127.0.0.1", 0)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def _get(url):
    with urllib.request.urlopen(url, timeout=20) as resp:
        return resp.status, resp.read().decode()


def _getj(url):
    status, body = _get(url)
    return status, json.loads(body)


def _post(url, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.status, json.loads(resp.read().decode())


def test_index_served(base):
    status, body = _get(base + "/")
    assert status == 200
    assert "RewardAudit" in body


def test_static_assets_served(base):
    status, body = _get(base + "/static/app.js")
    assert status == 200
    assert "api(" in body


def test_settings_roundtrip(base):
    status, payload = _getj(base + "/api/settings")
    assert status == 200
    assert payload["backend"] in web.BACKENDS
    assert "api_key_set" in payload

    status, saved = _post(
        base + "/api/settings",
        {"backend": "scripted", "model": "m", "base_url": "http://x/v1", "cache": False, "no_thinking": True},
    )
    assert status == 200
    assert saved["backend"] == "scripted"
    assert saved["model"] == "m"
    assert saved["no_thinking"] is True
    assert saved["cache"] is False


def test_api_key_is_never_returned(base):
    _post(base + "/api/settings", {"backend": "cloud", "api_key": "secret-value"})
    status, payload = _getj(base + "/api/settings")
    assert "secret-value" not in json.dumps(payload)
    assert payload["api_key_set"] is True


def test_browse_lists_directories(base, tmp_path, monkeypatch):
    monkeypatch.setattr(web, "BROWSE_ROOT", tmp_path)
    (tmp_path / "project").mkdir()
    (tmp_path / "project" / "src").mkdir()
    status, data = _getj(base + f"/api/browse?path={tmp_path}")
    assert status == 200
    assert data["path"] == str(tmp_path)
    assert any(e["name"] == "project" for e in data["entries"])


def test_browse_is_confined_to_root(base, tmp_path, monkeypatch):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir(); outside.mkdir()
    monkeypatch.setattr(web, "BROWSE_ROOT", root)
    _, data = _getj(base + f"/api/browse?path={outside}")
    assert data["path"] == str(root)  # escaped path is rejected


def test_inspect_reports_coverage(base, tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.go").write_text("package main\n")
    status, data = _getj(base + f"/api/inspect?path={tmp_path}")
    assert status == 200
    assert data["files_total"] == 2
    assert "go" in data["unchecked_languages"]


def test_inspect_missing_path(base):
    status, data = _getj(base + "/api/inspect?path=/no/such/dir")
    assert "error" in data


def test_test_connection_with_scripted_backend(base):
    _post(base + "/api/settings", {"backend": "scripted", "cache": False})
    status, data = _post(base + "/api/test", {})
    assert status == 200
    assert data["ok"] is True


def test_measure_controls_job(base):
    if not config.OPENGREP_BIN.is_file():
        pytest.skip("opengrep not available")
    _post(base + "/api/settings", {"backend": "scripted", "cache": False})
    status, job = _post(base + "/api/jobs", {"kind": "measure", "params": {"dataset": "controls"}})
    assert status == 200
    for _ in range(60):
        _, state = _getj(base + f"/api/jobs/{job['id']}")
        if state["status"] == "done":
            assert state["result"]["matrix"]["vulnerable_detected"] == 12
            return
        if state["status"] == "error":
            pytest.fail(state["error"])
        import time

        time.sleep(0.5)
    pytest.fail("job did not finish")


def test_review_job_on_python_file(base, tmp_path):
    if not config.OPENGREP_BIN.is_file():
        pytest.skip("opengrep not available")
    target = tmp_path / "repo"
    target.mkdir()
    (target / "vuln.py").write_text("import os\n\n\ndef run(x):\n    os.system(x)\n")
    _post(base + "/api/settings", {"backend": "scripted", "cache": False})
    _, job = _post(base + "/api/jobs", {"kind": "review", "params": {"path": str(target), "verifier": "llm"}})
    for _ in range(60):
        _, state = _getj(base + f"/api/jobs/{job['id']}")
        if state["status"] == "done":
            assert state["result"]["summary"]["candidates"] >= 1
            assert any(r["disposition"] == "true_positive" for r in state["result"]["rows"])
            return
        if state["status"] == "error":
            pytest.fail(state["error"])
        import time

        time.sleep(0.5)
    pytest.fail("job did not finish")
