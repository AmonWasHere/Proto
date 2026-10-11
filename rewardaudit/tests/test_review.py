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


def test_review_finds_the_sink_and_reports_coverage():
    _require()
    result = run_review(EXAMPLE, backend_kind="scripted")
    summary = result["summary"]

    assert summary["candidates"] >= 1
    langs = {row["language"]: row["status"] for row in summary["coverage"]["by_language"]}
    assert langs.get("javascript") == "covered"

    core = [r for r in result["rows"] if r["path"] == "core.py"]
    assert core, "expected the python sink finding"
    row = core[0]
    assert row["language"] == "python"
    assert row["rule"].endswith("ra-python-os-system")
    assert row["entry"].startswith("/run")
    assert "run_command" in row["hops"]


def test_review_covers_only_source_files():
    _require()
    result = run_review(EXAMPLE, backend_kind="scripted")
    cov = result["summary"]["coverage"]
    # python (3 files) + javascript (1 file) are code; requirements.txt and .env are not
    assert cov["by_status"].get("covered", 0) >= 3
    assert "unknown" not in cov["by_status"]
