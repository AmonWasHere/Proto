"""Review must only adjudicate real code — not CI/config files.

The pinned analyzer rulesets also match YAML (dependabot, GitHub Actions), but
those files have no grammar, so the verifier's slice is empty and any verdict is
meaningless. They are reported as skipped, not checked.
"""

from rewardaudit.review import is_groundable, partition_code_findings
from rewardaudit.schema import Finding, Location


def mk(path: str) -> Finding:
    return Finding(id=f"x|{path}", analyzer="a", rule="r", message="m", location=Location(path, 1))


def test_is_groundable_only_for_code_with_grammar():
    assert is_groundable("a.py")
    assert is_groundable("B.java")
    assert is_groundable("m.c")
    assert is_groundable("app.js")   # JS/TS now have grammars (ground-only)
    assert is_groundable("app.ts")
    assert not is_groundable(".github/dependabot.yml")
    assert not is_groundable(".github/workflows/build.yml")
    assert not is_groundable("README.md")
    assert not is_groundable("main.go")  # no grammar in this build


def test_partition_splits_code_from_noncode():
    findings = [
        mk("a.py"),
        mk(".github/workflows/build.yml"),
        mk("B.java"),
        mk("app.js"),
        mk("main.go"),
    ]
    kept, skipped = partition_code_findings(findings)
    assert [f.location.path for f in kept] == ["a.py", "B.java", "app.js"]
    assert [f.location.path for f in skipped] == [".github/workflows/build.yml", "main.go"]
