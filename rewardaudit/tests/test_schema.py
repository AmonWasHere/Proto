from rewardaudit.schema import (
    Disposition,
    Evidence,
    EvidenceKind,
    Finding,
    Location,
    Verdict,
    normalise_cwe,
)


def test_normalise_cwe_variants():
    assert normalise_cwe("CWE-79") == "CWE-79"
    assert normalise_cwe("cwe-79") == "CWE-79"
    assert normalise_cwe("79") == "CWE-79"
    assert normalise_cwe("external/cwe/cwe-089") == "CWE-89"
    assert normalise_cwe("no digits here") is None


def test_location_ref():
    assert Location("src/a.java", 12).ref() == "src/a.java:12"


def test_finding_with_evidence_is_immutable_copy():
    f = Finding(id="1", analyzer="x", rule="r", message="m", location=Location("a.java", 1))
    g = f.with_evidence(Evidence(kind=EvidenceKind.TOOL_FINDING, source="x", summary="s"))
    assert f.evidence == ()
    assert len(g.evidence) == 1


def test_verdict_abstention_flag():
    v = Verdict(
        finding_id="1",
        verifier="v",
        disposition=Disposition.UNKNOWN_RISK,
        confidence=0.0,
    )
    assert v.is_abstention
