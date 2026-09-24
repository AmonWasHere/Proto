import json

from rewardaudit.datasets import canary_report, load_canaries, load_pairs
from rewardaudit.schema import Finding, Location


def test_load_pairs_from_manifest(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"pairs": [{"id": "p", "vuln": "a.py", "fixed": "b.py", "category": "c", "cwe": "CWE-1"}]})
    )
    pairs = load_pairs(manifest)
    assert len(pairs) == 1
    assert pairs[0].vuln == "a.py" and pairs[0].cwe == "CWE-1"


def test_canary_report_flags():
    canaries = [{"file": "safe.py", "reason": "safe"}, {"file": "bad.py", "reason": "flagged"}]
    findings = [Finding(id="1", analyzer="a", rule="r", message="", location=Location("bad.py", 1))]
    report = canary_report(canaries, findings)
    assert report["total"] == 2
    assert report["flagged"] == 1
    assert report["rows"][0]["flagged"] is False
    assert report["rows"][1]["flagged"] is True


def test_load_canaries_real_manifest(request):
    from rewardaudit import config

    if not (config.PYTHON_CANARIES / "manifest.json").is_file():
        return
    canaries = load_canaries(config.PYTHON_CANARIES / "manifest.json")
    assert len(canaries) == 3
