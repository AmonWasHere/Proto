"""The `review` flow end-to-end on the bundled example app."""

from pathlib import Path

import pytest

from rewardaudit import config
from rewardaudit.review import run_review

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "vulnerable-app"


def _require():
    if not config.OPENGREP_BIN.is_file():
        pytest.skip("opengrep not available")
    if not EXAMPLE.is_dir():
        pytest.skip("example app not present")


def test_review_finds_the_sink_and_reports_unchecked_language():
    _require()
    result = run_review(EXAMPLE, backend_kind="scripted")
    summary = result["summary"]

    assert summary["candidates"] == 1
    assert summary["true_positive"] == 1
    assert summary["reachable"] == 1
    assert "javascript" in summary["coverage"]["unchecked_languages"]

    row = result["rows"][0]
    assert row["path"] == "core.py"
    assert row["language"] == "python"
    assert row["rule"].endswith("ra-python-os-system")
    assert row["entry"].startswith("/run")
    assert "run_command" in row["hops"]


def test_review_covers_only_source_files():
    _require()
    result = run_review(EXAMPLE, backend_kind="scripted")
    # app.py, core.py, safe.py are covered; requirements.txt and .env are not code
    assert result["summary"]["coverage"]["by_status"].get("covered") == 3
    assert "unknown" not in result["summary"]["coverage"]["by_status"]
