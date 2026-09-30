from rewardaudit import languages


def test_language_of():
    assert languages.language_of("a.py") == "python"
    assert languages.language_of("A.java") == "java"
    assert languages.language_of("x.js") == "javascript"
    assert languages.language_of("README.md") is None


def test_detect_skips_junk_dirs(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "B.java").write_text("class B {}\n")
    (tmp_path / "c.js").write_text("const x = 1;\n")
    junk = tmp_path / "node_modules"
    junk.mkdir()
    (junk / "d.js").write_text("const y = 1;\n")

    detected = languages.detect(tmp_path)
    assert set(detected) == {"python", "java", "javascript"}
    assert len(detected["javascript"]) == 1


def test_coverage_report_marks_unchecked_languages(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "B.java").write_text("class B {}\n")
    (tmp_path / "c.js").write_text("const x = 1;\n")

    report = languages.coverage_report(tmp_path)
    assert report["files_total"] == 3
    # java + python are covered; javascript has no ruleset and no grammar
    assert "javascript" in report["unchecked_languages"]
    assert report["checked_fraction"] == 2 / 3
    statuses = {row["language"]: row["status"] for row in report["by_language"]}
    assert statuses["java"] == "covered"
    assert statuses["python"] == "covered"
    assert statuses["javascript"] == "unsupported"


def test_coverage_ignores_non_code_files(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "requirements.txt").write_text("flask==2.2.0\n")
    (tmp_path / ".env").write_text("CMD=ls\n")
    (tmp_path / "README.md").write_text("# hi\n")
    report = languages.coverage_report(tmp_path)
    assert report["files_total"] == 1
    assert "unknown" not in report["by_status"]


def test_rules_for_collects_present_languages(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "B.java").write_text("class B {}\n")
    names = {p.name for p in languages.rules_for(tmp_path)}
    assert "python-minimal.yaml" in names
    assert "p-java-best.yaml" in names
