"""JavaScript / TypeScript are grammar-only: auditable, not yet rule-findable."""

from rewardaudit import languages
from rewardaudit.cpg import Cpg


def test_js_functions_are_extracted(tmp_path):
    (tmp_path / "a.js").write_text(
        "function add(x, y) { return x + y; }\n"
        "const inc = (z) => z + 1;\n"
        "class C { method() { return 1; } }\n"
    )
    names = [f.name for f in Cpg(tmp_path).functions("a.js")]
    assert "add" in names
    assert "method" in names


def test_ts_functions_are_extracted(tmp_path):
    (tmp_path / "a.ts").write_text("function greet(n: string): string { return 'hi ' + n; }\n")
    names = [f.name for f in Cpg(tmp_path).functions("a.ts")]
    assert "greet" in names


def test_js_ts_are_covered():
    reg = languages.registry()
    assert reg["javascript"].grammar and reg["javascript"].rules
    assert reg["javascript"].status == "covered"
    assert reg["typescript"].status == "covered"


def test_js_no_longer_unchecked(tmp_path):
    (tmp_path / "a.js").write_text("function f() { return 1; }\n")
    rep = languages.coverage_report(tmp_path)
    assert "javascript" not in rep["unchecked_languages"]
    assert rep["by_status"].get("covered", 0) == 1
