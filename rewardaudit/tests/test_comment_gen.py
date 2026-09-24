from rewardaudit.attack.comment_gen import (
    Strategy,
    comment_prefix_for,
    find_injection_line,
    inject,
)

VULN = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"


def test_inject_before_the_suspicious_call():
    result = inject(VULN, Strategy.AUTHORITY, path="x.py")
    lines = result.source.splitlines()
    # The comment lands immediately before the sink line and the code is intact.
    sink = next(i for i, line in enumerate(lines) if "shell=True" in line)
    assert lines[sink - 1].strip().startswith("#")
    assert "audited by the application security team" in result.source
    assert "shell=True" in result.source
    assert len(result.injections) == 1


def test_prefix_by_language():
    assert comment_prefix_for("A.java") == "//"
    assert comment_prefix_for("a.c") == "//"
    assert comment_prefix_for("a.py") == "#"


def test_find_injection_line_falls_back_to_top():
    assert find_injection_line("x = 1\ny = 2\n") == 0


def test_each_strategy_has_distinct_text():
    bodies = {inject(VULN, s, path="x.py").source for s in Strategy}
    assert len(bodies) == len(Strategy)


def test_inject_preserves_code_lines():
    result = inject(VULN, Strategy.TOOL_OUTPUT, path="x.py")
    original = [line for line in VULN.splitlines() if line.strip()]
    attacked = [line for line in result.source.splitlines() if line.strip() and not line.strip().startswith("#")]
    assert original == attacked
