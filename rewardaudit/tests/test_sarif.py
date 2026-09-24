from pathlib import Path

from rewardaudit.sarif import findings_from_sarif

SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "codeql",
                    "rules": [
                        {
                            "id": "java/sql-injection",
                            "properties": {"tags": ["security", "external/cwe/cwe-089"]},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "java/sql-injection",
                    "message": {"text": "SQL injection"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/App.java"},
                                "region": {"startLine": 42, "endLine": 44},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


def test_parse_sarif_extracts_rule_location_and_cwe(tmp_path: Path):
    findings = findings_from_sarif(SARIF, root=tmp_path, analyzer="codeql")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "java/sql-injection"
    assert f.location.path == "src/App.java"
    assert f.location.start_line == 42
    assert f.location.end_line == 44
    assert f.cwes == ("CWE-89",)
    assert f.evidence[0].ref == "src/App.java:42"


def test_parse_sarif_empty():
    assert findings_from_sarif({"runs": []}, root=Path(".")) == []
