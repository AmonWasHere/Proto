"""Run harness: execute an analyzer over a target and emit a reproducible report.

`python -m rewardaudit.harness --controls` reproduces the pinned opengrep control
result (12/18 vulnerable, 1/3 safe flagged) and writes a run manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .analyzers.base import Analyzer, AnalyzerError
from .analyzers.opengrep import Opengrep
from .attack.comment_gen import Strategy
from .attack.adaptive import adaptive_evasion
from .controls import control_matrix, load_controls
from .cpg import Cpg
from .datasets import canary_report, load_canaries, load_pairs
from .decomposition import by_category, decompose
from .e1 import DEFAULT_STRATEGIES, evasion, four_way_llm, judge_canaries
from .ledger import Ledger, new_run_id
from .llm import build_backend
from .llm.openai_compat import OpenAICompatibleBackend
from .schema import Finding
from .verifiers.base import VerificationContext
from .verifiers.llm_judge import LLMJudge
from .verifiers.tool_verdict import ToolVerdict


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(analyzer: Analyzer, target: Path, rules: Path | None) -> dict:
    return {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "analyzer": analyzer.name,
        "analyzer_version": analyzer.version(),
        "target": str(Path(target).resolve()),
        "rules": str(rules.resolve()) if rules else None,
        "rules_sha256": sha256_file(rules) if rules and rules.is_file() else None,
        "python": sys.version.split()[0],
    }


def run_scan(target: Path, rules: Path) -> tuple[Analyzer, list[Finding]]:
    analyzer = Opengrep(config.OPENGREP_BIN, rules)
    if not analyzer.available():
        raise AnalyzerError(f"opengrep not available at {config.OPENGREP_BIN}")
    result = analyzer.scan(target)
    return analyzer, result.findings


def run_opengrep_over(target: Path) -> tuple[Analyzer, list[Finding]]:
    return run_scan(target, config.JAVA_RULES)


def cmd_controls(args: argparse.Namespace) -> int:
    controls_dir = Path(args.controls)
    analyzer, findings = run_opengrep_over(controls_dir)
    cases = load_controls(controls_dir)
    matrix = control_matrix(cases, findings)
    manifest = build_manifest(analyzer, controls_dir, config.JAVA_RULES)

    print(f"analyzer: {manifest['analyzer']} {manifest['analyzer_version']}")
    print(f"rules:    {config.JAVA_RULES.name} sha256={str(manifest['rules_sha256'])[:12]}")
    print(f"target:   {controls_dir}")
    print()
    for row in matrix["rows"]:
        mark = "HIT " if row["detected"] else "miss"
        print(f"  {mark} {row['expect'][:4]:4} {row['file']}")
    print()
    print(
        f"VULNERABLE DETECTED: {matrix['vulnerable_detected']}/{matrix['vulnerable_total']}"
    )
    print(f"SAFE FLAGGED:        {matrix['safe_flagged']}/{matrix['safe_total']}")

    if args.json:
        payload = {"manifest": manifest, "matrix": matrix}
        Path(args.json).write_text(json.dumps(payload, indent=2))
        print(f"\nwrote {args.json}")
    return 0


def cmd_judge(args: argparse.Namespace) -> int:
    """Scan `--root`, then run V1 (LLM) and V2 (tool) on the first N findings."""
    root = Path(args.root)
    analyzer, findings = run_opengrep_over(root)
    backend = build_backend(args.backend)
    ctx = VerificationContext(repo_root=root.resolve(), cpg=Cpg(root), llm=backend)
    judge = LLMJudge()
    tool = ToolVerdict(findings, source=analyzer.name)

    for finding in findings[: args.limit]:
        v1 = judge.verify(finding, ctx)
        v2 = tool.verify(finding, ctx)
        print(f"{finding.location.ref()}")
        print(f"  V1 llm_judge : {v1.disposition.value:14} conf={v1.confidence:.2f} {v1.rationale[:80]}")
        print(f"  V2 tool      : {v2.disposition.value:14} {v2.rationale[:80]}")
    return 0


def cmd_pairs(args: argparse.Namespace) -> int:
    """Four-way decomposition over vulnerable/fixed revision pairs."""
    pairs_dir = Path(args.dir)
    rules = Path(args.rules)
    pairs = load_pairs(pairs_dir / "manifest.json")
    analyzer, findings = run_scan(pairs_dir, rules)
    report = decompose(pairs, findings)
    counts = report.counts()

    print(f"analyzer: {analyzer.name} {analyzer.version()}")
    print(f"rules:    {rules}")
    print(f"pairs:    {report.total}   findings: {len(findings)}")
    print()
    for pair in pairs:
        cell = report.cells[pair.id]
        print(f"  {cell.value:10} {pair.id}")
    print()
    print(f"counts:        {counts}")
    print(f"naive coverage: {report.naive_coverage:.2%}  (flagged on the vulnerable revision)")
    print(f"flip rate:      {report.flip_rate:.2%}  (verdict moved with the fix)")
    print(f"over-report:    {report.over_report_factor:.2f}x")
    print(f"by category:    {by_category(report)}")

    if args.ledger:
        ledger = Ledger(args.ledger)
        run_id = new_run_id()
        ledger.record(
            run_id, "manifest", analyzer=analyzer.name, version=analyzer.version(),
            rules=str(rules), target=str(pairs_dir),
        )
        for finding in findings:
            ledger.record(
                run_id, "finding", id=finding.id, rule=finding.rule,
                path=finding.location.path, line=finding.location.start_line,
            )
        ledger.record(run_id, "decomposition", counts=counts, flip_rate=report.flip_rate)
        print(f"\nledger appended: {args.ledger} (run_id={run_id})")

    if args.json:
        payload = {
            "cells": {k: v.value for k, v in report.cells.items()},
            "counts": counts,
            "naive_coverage": report.naive_coverage,
            "flip_rate": report.flip_rate,
        }
        Path(args.json).write_text(json.dumps(payload, indent=2))
        print(f"wrote {args.json}")
    return 0


def cmd_canaries(args: argparse.Namespace) -> int:
    """Scan the canary set: correct behaviour is zero findings (no false positives)."""
    canary_dir = Path(args.dir)
    rules = Path(args.rules)
    analyzer, findings = run_scan(canary_dir, rules)
    report = canary_report(load_canaries(canary_dir / "manifest.json"), findings)

    print(f"analyzer: {analyzer.name} {analyzer.version()}")
    print(f"canaries: {report['total']}   flagged: {report['flagged']}")
    print()
    for row in report["rows"]:
        mark = "FP " if row["flagged"] else "ok "
        print(f"  {mark} {row['file']}  ({row['reason']})")
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2))
    return 0


def cmd_e1(args: argparse.Namespace) -> int:
    """Four-way decomposition applied to LLM verdicts (does the verdict track the fix?)."""
    root = Path(args.dir)
    pairs = load_pairs(root / "manifest.json")
    backend = build_backend(args.backend)
    ctx = VerificationContext(root.resolve(), Cpg(root), backend)
    result = four_way_llm(pairs, ctx)
    report = result.report

    print(f"backend:  {backend.name} {getattr(backend, 'model', '')}".rstrip())
    print(f"pairs:    {report.total}")
    print()
    for pair in pairs:
        cell = report.cells[pair.id]
        vuln, fixed = result.verdicts[pair.id]
        print(
            f"  {cell.value:10} {pair.id:16} "
            f"vuln={vuln.disposition.value:14} fixed={fixed.disposition.value}"
        )
    print()
    print(f"counts:         {report.counts()}")
    print(f"naive coverage: {report.naive_coverage:.2%}")
    print(f"flip rate:      {report.flip_rate:.2%}   (verdict moved with the fix)")
    print(f"over-report:    {report.over_report_factor:.2f}x")

    if args.canaries:
        canary_dir = Path(args.canaries_dir)
        canaries = load_canaries(canary_dir / "manifest.json")
        canary_ctx = VerificationContext(canary_dir.resolve(), Cpg(canary_dir), backend)
        report_c = judge_canaries(canaries, canary_ctx)
        print(
            f"\ncanaries: {report_c['total']}  false positives: {report_c['false_positives']}"
        )
        for row in report_c["rows"]:
            mark = "FP " if row["false_positive"] else "ok "
            print(f"  {mark} {row['file']}  ({row['disposition']})")

    if args.json:
        payload = {
            "backend": backend.name,
            "counts": report.counts(),
            "naive_coverage": report.naive_coverage,
            "flip_rate": report.flip_rate,
            "cells": {k: v.value for k, v in report.cells.items()},
        }
        Path(args.json).write_text(json.dumps(payload, indent=2))
        print(f"\nwrote {args.json}")
    return 0


def cmd_evade(args: argparse.Namespace) -> int:
    """Adversarial comment injection against the LLM verifier (E1 evasion)."""
    root = Path(args.dir)
    pairs = load_pairs(root / "manifest.json")
    backend = build_backend(args.backend)
    strategies = (
        tuple(Strategy(s) for s in args.strategies) if args.strategies else DEFAULT_STRATEGIES
    )
    report = evasion(pairs, root, backend, strategies=strategies)

    print(f"backend:   {backend.name} {getattr(backend, 'model', '')}".rstrip())
    print(f"baseline true positives: {report.baseline_true_positives}/{len(pairs)}")
    print()
    for name, row in report.per_strategy.items():
        print(f"  {name:14} evaded {row['evaded']}/{row['attempted']}  ({row['rate']:.0%})")
    print(f"\noverall evasion: {report.overall:.0%}")

    if args.json:
        Path(args.json).write_text(json.dumps(report.per_strategy, indent=2))
        print(f"wrote {args.json}")
    return 0


def cmd_adaptive(args: argparse.Namespace) -> int:
    """LLM-authored, iterative adversarial comments (ALIBI-style)."""
    root = Path(args.dir)
    pairs = load_pairs(root / "manifest.json")
    judge_backend = build_backend(args.backend)
    attacker_backend = judge_backend
    attacker_name = f"{getattr(judge_backend, 'name', '?')} {getattr(judge_backend, 'model', '')}".strip()
    if args.attacker_model and isinstance(judge_backend, OpenAICompatibleBackend):
        attacker_backend = OpenAICompatibleBackend(
            base_url=judge_backend.base_url,
            model=args.attacker_model,
            api_key=judge_backend.api_key,
            name="attacker",
        )
        attacker_name = f"attacker:{args.attacker_model}"

    outcomes = adaptive_evasion(
        pairs,
        root,
        judge_llm=judge_backend,
        attacker_llm=attacker_backend,
        rounds=args.rounds,
    )
    evaded = sum(o.evaded for o in outcomes)

    print(f"judge:    {getattr(judge_backend, 'name', '?')} {getattr(judge_backend, 'model', '')}".rstrip())
    print(f"attacker: {attacker_name}")
    print(f"rounds:   {args.rounds}")
    print(f"baseline true positives: {len(outcomes)}/{len(pairs)}")
    print()
    for outcome in outcomes:
        mark = "EVADED" if outcome.evaded else "held  "
        winner = next((a.comment for a in outcome.attempts if a.worked), "")
        print(f"  {mark} {outcome.pair_id:16} rounds={outcome.rounds_used}  {winner[:64]!r}")
    rate = evaded / len(outcomes) if outcomes else 0.0
    print(f"\nadaptive evasion: {rate:.0%} ({evaded}/{len(outcomes)})")

    if args.json:
        payload = {
            o.pair_id: [{"round": a.round, "comment": a.comment, "disposition": a.disposition} for a in o.attempts]
            for o in outcomes
        }
        Path(args.json).write_text(json.dumps(payload, indent=2))
        print(f"wrote {args.json}")
    return 0


def cmd_threat(args: argparse.Namespace) -> int:
    """Show the pinned advisory snapshot and match a requirements file against it."""
    from .store import KnowledgeStore, Snapshot, parse_requirements

    snapshot = Snapshot.load(args.snapshot)
    store = KnowledgeStore(snapshot)
    provenance = store.snapshot_provenance
    print(f"snapshot:   {provenance['path']}")
    print(f"sha256:     {provenance['sha256'][:16]}")
    print(f"date:       {provenance['date'] or 'unknown'}")
    print(f"advisories: {provenance['advisories']}")
    if args.requirements:
        text = Path(args.requirements).read_text()
        deps = parse_requirements(text)
        matches = store.match_dependencies(deps)
        print(f"\ndependencies: {len(deps)}   with advisories: {len(matches)}")
        for match in matches:
            dep = match["dependency"]
            ids = ", ".join(a.id for a in match["advisories"])
            print(f"  {dep.package}=={dep.version}: {ids}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rewardaudit.harness")
    sub = parser.add_subparsers(dest="command", required=True)

    p_controls = sub.add_parser("controls", help="reproduce the pinned control matrix")
    p_controls.add_argument("--controls", default=str(config.CONTROLS_DIR))
    p_controls.add_argument("--json", default="")
    p_controls.set_defaults(func=cmd_controls)

    p_judge = sub.add_parser("judge", help="run V1/V2 verifiers over a scan")
    p_judge.add_argument("--root", required=True)
    p_judge.add_argument("--backend", default="mock", choices=["mock", "scripted", "local", "cloud"])
    p_judge.add_argument("--limit", type=int, default=5)
    p_judge.set_defaults(func=cmd_judge)

    p_pairs = sub.add_parser("pairs", help="four-way decomposition over revision pairs")
    p_pairs.add_argument("--dir", default=str(config.PYTHON_PAIRS))
    p_pairs.add_argument("--rules", default=str(config.PYTHON_RULES))
    p_pairs.add_argument("--json", default="")
    p_pairs.add_argument("--ledger", default="")
    p_pairs.set_defaults(func=cmd_pairs)

    p_can = sub.add_parser("canaries", help="scan the canary set (false-positive check)")
    p_can.add_argument("--dir", default=str(config.PYTHON_CANARIES))
    p_can.add_argument("--rules", default=str(config.PYTHON_RULES))
    p_can.add_argument("--json", default="")
    p_can.set_defaults(func=cmd_canaries)

    p_e1 = sub.add_parser("e1", help="four-way decomposition on LLM verdicts")
    p_e1.add_argument("--dir", default=str(config.PYTHON_PAIRS))
    p_e1.add_argument("--backend", default="mock", choices=["mock", "scripted", "local", "cloud"])
    p_e1.add_argument("--canaries", action="store_true")
    p_e1.add_argument("--canaries-dir", default=str(config.PYTHON_CANARIES))
    p_e1.add_argument("--json", default="")
    p_e1.set_defaults(func=cmd_e1)

    p_ev = sub.add_parser("evade", help="adversarial comment injection against the LLM verifier")
    p_ev.add_argument("--dir", default=str(config.PYTHON_PAIRS))
    p_ev.add_argument("--backend", default="mock", choices=["mock", "scripted", "local", "cloud"])
    p_ev.add_argument("--strategies", nargs="*", default=None)
    p_ev.add_argument("--json", default="")
    p_ev.set_defaults(func=cmd_evade)

    p_threat = sub.add_parser("threat", help="show the pinned advisory snapshot / match deps")
    p_threat.add_argument("--snapshot", default=str(config.THREAT_SNAPSHOT))
    p_threat.add_argument("--requirements", default="")
    p_threat.set_defaults(func=cmd_threat)

    p_ad = sub.add_parser("adaptive", help="LLM-authored iterative adversarial comments")
    p_ad.add_argument("--dir", default=str(config.PYTHON_PAIRS))
    p_ad.add_argument("--backend", default="mock", choices=["mock", "scripted", "local", "cloud"])
    p_ad.add_argument("--attacker-model", default="")
    p_ad.add_argument("--rounds", type=int, default=3)
    p_ad.add_argument("--json", default="")
    p_ad.set_defaults(func=cmd_adaptive)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
