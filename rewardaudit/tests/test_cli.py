"""Guard the CLI: parser construction must not fail (e.g. a bad help string).

argparse expands `%` in help text, so an unescaped percent raises at build time.
These tests build the parser without performing any work.
"""

import pytest

from rewardaudit import harness


def test_cli_parser_builds_and_help_exits_clean(capsys):
    with pytest.raises(SystemExit) as excinfo:
        harness.main(["--help"])
    assert excinfo.value.code == 0
    assert "repeats" in capsys.readouterr().out


def test_cli_subcommand_help_all_build(capsys):
    for command in [
        "controls", "pairs", "canaries", "e1", "evade", "adaptive",
        "threat", "javavfc", "calibrate", "repeats", "review",
    ]:
        with pytest.raises(SystemExit) as excinfo:
            harness.main([command, "--help"])
        assert excinfo.value.code == 0
