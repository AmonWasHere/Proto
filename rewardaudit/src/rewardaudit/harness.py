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
from .controls import control_matrix, load_controls
from .cpg import Cpg
from .llm import build_backend
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


def run_opengrep_over(target: Path) -> tuple[Analyzer, list[Finding]]:
    analyzer = Opengrep(config.OPENGREP_BIN, config.JAVA_RULES)
    if not analyzer.available():
        raise AnalyzerError(f"opengrep not available at {config.OPENGREP_BIN}")
    result = analyzer.scan(target)
    return analyzer, result.findings


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rewardaudit.harness")
    sub = parser.add_subparsers(dest="command", required=True)

    p_controls = sub.add_parser("controls", help="reproduce the pinned control matrix")
    p_controls.add_argument("--controls", default=str(config.CONTROLS_DIR))
    p_controls.add_argument("--json", default="")
    p_controls.set_defaults(func=cmd_controls)

    p_judge = sub.add_parser("judge", help="run V1/V2 verifiers over a scan")
    p_judge.add_argument("--root", required=True)
    p_judge.add_argument("--backend", default="mock", choices=["mock", "local", "cloud"])
    p_judge.add_argument("--limit", type=int, default=5)
    p_judge.set_defaults(func=cmd_judge)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
