from rewardaudit.ledger import Ledger, new_run_id


def test_ledger_append_and_read(tmp_path):
    ledger = Ledger(tmp_path / "run.jsonl")
    run_id = new_run_id()
    ledger.record(run_id, "manifest", analyzer="opengrep", version="1.30.0")
    ledger.record(run_id, "finding", id="f1", rule="r", path="a.py", line=3)

    entries = list(ledger.entries())
    assert len(entries) == 2
    assert entries[0]["kind"] == "manifest"
    assert entries[0]["analyzer"] == "opengrep"
    assert entries[0]["run_id"] == run_id

    findings = list(ledger.entries(kind="finding"))
    assert len(findings) == 1
    assert findings[0]["path"] == "a.py"


def test_ledger_missing_file_is_empty(tmp_path):
    assert list(Ledger(tmp_path / "nope.jsonl").entries()) == []


def test_run_ids_are_unique():
    assert new_run_id() != new_run_id()
