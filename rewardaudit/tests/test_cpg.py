import pytest

from rewardaudit.cpg import Cpg

JAVA = (
    "class A {\n"
    "    void f(String u) {\n"
    "        Runtime.getRuntime().exec(u);\n"
    "    }\n"
    "}\n"
)


@pytest.fixture
def root(tmp_path):
    (tmp_path / "A.java").write_text(JAVA)
    return tmp_path


def test_available():
    if not Cpg(".").available():
        pytest.skip("tree-sitter not installed")


def test_spans_and_verify(root):
    cpg = Cpg(root)
    if not cpg.available():
        pytest.skip("tree-sitter not installed")

    hits = cpg.spans("A.java", 3)
    assert hits, "expected nodes covering line 3"
    assert any(h.type == "method_invocation" for h in hits)

    good = cpg.verify_ref("A.java:3")
    assert good.ok and good.node_type

    missing = cpg.verify_ref("A.java:999")
    assert not missing.ok


def test_verify_ref_malformed(root):
    cpg = Cpg(root)
    if not cpg.available():
        pytest.skip("tree-sitter not installed")
    assert not cpg.verify_ref("not-a-ref").ok
    assert not cpg.verify_ref("A.java:abc").ok
    assert not cpg.verify_ref("nope.java:1").ok


def test_context_slice_returns_enclosing_function(root):
    cpg = Cpg(root)
    if not cpg.available():
        pytest.skip("tree-sitter not installed")
    text = cpg.context_slice("A.java", 3)
    assert "exec" in text
    assert "void f" in text
