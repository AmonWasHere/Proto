"""Verifier interface: a finding goes in, a verdict comes out.

A verifier is anything that turns a candidate into a disposition with evidence:
a deterministic tool verdict (V2), an LLM judge (V1), or a composition. The
`VerificationContext` carries the repo, the CPG, and (optionally) an LLM.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..cpg import Cpg
from ..llm.base import LLMBackend
from ..schema import Finding, Verdict


@dataclass
class VerificationContext:
    repo_root: Path
    cpg: Cpg
    llm: LLMBackend | None = None


class Verifier(Protocol):
    name: str

    def verify(self, finding: Finding, ctx: VerificationContext) -> Verdict: ...
