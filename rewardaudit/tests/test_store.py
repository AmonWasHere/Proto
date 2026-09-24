from rewardaudit import config
from rewardaudit.ledger import Ledger
from rewardaudit.schema import Disposition
from rewardaudit.store import (
    Advisory,
    Dependency,
    KnowledgeStore,
    Snapshot,
    parse_requirements,
    parse_version,
)


def test_parse_version():
    assert parse_version("5.4") == (5, 4)
    assert parse_version("1.2.3rc1") == (1, 2, 3)
    assert parse_version("2.11.3") > parse_version("2.11")
    assert parse_version("nope") == ()


def test_advisory_from_osv_and_range_match():
    record = {
        "id": "X-1",
        "aliases": ["CVE-2020-1"],
        "summary": "s",
        "affected": [
            {"package": {"ecosystem": "PyPI", "name": "pyyaml"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}
        ],
        "database_specific": {"cwe_ids": ["CWE-502"]},
    }
    advisory = Advisory.from_osv(record)
    assert advisory.cwe == "CWE-502"
    assert advisory.affects("PyPI", "pyyaml", "5.3.1")
    assert not advisory.affects("PyPI", "pyyaml", "5.4")
    assert not advisory.affects("PyPI", "pyyaml", "6.0")
    assert not advisory.affects("PyPI", "other", "5.3.1")


def test_advisory_exact_versions_list():
    advisory = Advisory.from_osv(
        {"id": "Y", "affected": [{"package": {"ecosystem": "PyPI", "name": "p"}, "versions": ["1.0", "1.1"]}]}
    )
    assert advisory.affects("PyPI", "p", "1.1")
    assert not advisory.affects("PyPI", "p", "1.2")


def test_snapshot_load_and_provenance():
    if not config.THREAT_SNAPSHOT.is_file():
        import pytest

        pytest.skip("snapshot fixture missing")
    snapshot = Snapshot.load(config.THREAT_SNAPSHOT)
    assert len(snapshot) >= 4
    assert len(snapshot.sha256) == 64
    hits = snapshot.match("PyPI", "pyyaml", "5.3")
    assert hits and hits[0].id.startswith("RA-FIXTURE")


def test_parse_requirements():
    deps = parse_requirements("pyyaml==5.3\n# comment\nrequests>=2\n-r other.txt\nflask==2.2.0\n")
    names = {d.package: d.version for d in deps}
    assert names == {"pyyaml": "5.3", "flask": "2.2.0"}


def test_knowledge_store_matching_and_precision(tmp_path):
    snapshot = Snapshot.load(config.THREAT_SNAPSHOT)
    ledger = Ledger(tmp_path / "ledger.jsonl")
    store = KnowledgeStore(snapshot, ledger)

    deps = [Dependency("pyyaml", "5.3"), Dependency("flask", "3.0")]
    matches = store.match_dependencies(deps)
    assert len(matches) == 1
    assert matches[0]["dependency"].package == "pyyaml"

    store.record_outcome("opengrep", Disposition.TRUE_POSITIVE, fingerprint="f1")
    store.record_outcome("opengrep", Disposition.TRUE_POSITIVE, fingerprint="f2")
    store.record_outcome("opengrep", Disposition.FALSE_POSITIVE, fingerprint="f3")
    assert store.precision("opengrep") == 2 / 3
    assert store.signal_stats()["opengrep"].total == 3

    store.link("f1", "RA-FIXTURE-PYYAML-01")
    assert store.advisories_for_finding("f1") == ["RA-FIXTURE-PYYAML-01"]
