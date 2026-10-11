"""OSV refresh: fetch advisories for declared deps into a compatible snapshot."""

from rewardaudit.osv import refresh
from rewardaudit.store import Dependency, Snapshot, parse_requirements

CANNED = [
    {
        "id": "GHSA-xxxx-yyyy",
        "aliases": ["CVE-2020-14343"],
        "summary": "PyYAML arbitrary code execution via yaml.load",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pyyaml"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}],
            }
        ],
        "database_specific": {"cwe_ids": ["CWE-502"]},
        "references": [{"url": "https://osv.dev/GHSA-xxxx-yyyy"}],
    }
]


def fake_query(ecosystem, name, version):
    return CANNED if name == "pyyaml" else []


def test_refresh_writes_compatible_snapshot(tmp_path):
    out = tmp_path / "osv-2026-10-11.jsonl"
    deps = [
        Dependency("pyyaml", "5.3", "PyPI"),
        Dependency("flask", "2.2.0", "PyPI"),
    ]
    meta = refresh(deps, out, query_fn=fake_query)
    assert meta["advisories"] == 1 and meta["packages"] == 2
    assert out.is_file()
    assert out.with_suffix(out.suffix + ".meta.json").is_file()

    snap = Snapshot.load(out)
    assert len(snap) == 1
    hits = snap.match("PyPI", "pyyaml", "5.3")
    assert hits and hits[0].cwe == "CWE-502"
    assert snap.match("PyPI", "pyyaml", "5.4") == []  # fixed version is clean


def test_parse_requirements_ignores_noise():
    deps = parse_requirements("flask==2.2.0\n# comment\npyyaml==5.3\n-r other.txt\n")
    assert [(d.package, d.version) for d in deps] == [("flask", "2.2.0"), ("pyyaml", "5.3")]
