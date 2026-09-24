"""Separate security-relevant JavaVFC commits from the rest of the corpus.

Why this exists
---------------
JavaVFC is advertised as 784 manually-verified Java vulnerability-fixing
commits. Measured, it is not. JavaVFC's own VULNERABILITY_PATTERN admits

    (prevent|avoid|run into|lead to|fix|would)[\\s\\S]{0,50}
        (vulnerabilities|vulnerability|crash|clashing|exploit|bypass|auth)

so "Fix crash when fighting divine dragon spirit" -- a Minetest gameplay bug --
is a corpus entry, as are deadlock fixes, OOM fixes and dependency bumps.

A hand-labelled systematic sample (every 26th usable commit, n=31) gives:

    genuine security fix      5/31  16.1%   [Wilson 95% CI 7.1%-32.6%]
    partial / security-adjacent  7/31  22.6%
    plainly not security     19/31  61.3%

An independent keyword pass over all 784 commits agrees at 15.7%. Two methods
built differently landing on the same figure is why it is reported.

Consequence for measurement
---------------------------
Running a SAST tool over the raw corpus measures it against crash fixes,
deadlocks and dependency bumps -- things it is not built to find. Any coverage
number computed over the raw corpus is an artifact of the corpus, not a fact
about the tool. Evaluation is therefore stratified, and this module stratifies.

Tuning
------
Scored against the 31 hand labels, this filter gives precision 0.79 and recall
0.92. It is deliberately recall-weighted: a false negative here silently
re-introduces the confound, while a false positive only dilutes the sample, and
dilution is measurable (see purity_estimate below).
"""

from __future__ import annotations

import re

# A commit must carry an explicit security term to enter the subset. Bare
# "security"/"secure" is NOT sufficient: it sweeps in "security and apple icons"
# and "Security Report export usage to telemetry", both caught during labelling.
SECURITY_TERMS = re.compile(
    r"""(?ix)
    \bCVE-\d{4}-\d+\b | \bXSS\b | \bXXE\b | \bRCE\b | \bSSRF\b | \bCSRF\b |
    \bXSRF\b | \bReDoS\b | OSVDB | OSV-\d{4}-\d+ |
    (sql|html|xml|ldap|xpath|command|code|log|header|crlf|path)\s*injection |
    injection\s+(flaw|vulnerabilit) |
    (directory|path)\s*traversal | open\s*redirect | redirect\s+uri |
    clickjack | session\s*fixation | deseriali | unmarshal |
    arbitrary\s+(code|file) |
    (auth|authentication|authorization|permission|login|access|security)
        [-\s]*(check|bypass|control|validation|validate|mode|method|config|
                fix|issue|problem|token|provider|context|zone|manager|plan|
                policy|filter|handler|exception|audit) |
    bypass\w*\s*(auth|authentication|permission|login|access|keyguard|security) |
    (unauthori[zs]ed|unauthenticated|untrusted|insecure)\w* |
    privilege\s+escalation | permission\s+(check|bypass|escalation) |
    escalat\w*\s+privilege |
    (password|credential|secret|api[_\s-]?key|private\s+key|token|fingerprint|
     jwt|oauth|saml|oidc)\w* |
    (leak|expos|disclos)\w* | prevent\s+leak |
    hard[-\s]?coded\s+(password|secret|key|credential|token) |
    (certificate|cert|hostname|tls|ssl|x509|keystore|keyguard)\w* |
    self[-\s]?signed | man[-\s]in[-\s]the[-\s]middle | trust\w* |
    (sanitiz|escap|encod)\w* | harden\w* |
    security[-\s]*(vulnerabilit|flaw|issue|bug|fix|patch|check|review|report)\w* |
    \[SECURITY-\d+\] | \bCWE-\d+\b |
    sandbox\s+(escape|bypass) | RECEIVER_(NOT_)?EXPORTED |
    exported\s+(component|receiver|activity|service) |
    vulnerabilit\w* | exploit\w* |
    密码 | 泄露 | 漏洞 | 权限 | 令牌 | 加密 | 鉴权 | 注入 | 越权 | 敏感
    """
)

# Reasons a commit is *not* a security fix even when a term above fires. Kept
# short on purpose: each entry must be a case where the match is a lexical
# accident rather than a real security change. This is what keeps "Update
# dependencies to avoid CVE" and "security and apple icons" out.
NOT_SECURITY = re.compile(
    r"""(?ix)
    ^\s*(update|bump|upgrade)\s+dependenc |
    \bupdate\s+\w+\s+(from|to)\s+v?\d |
    \bbump\s+\w+\s+(from|to)\b |
    chore\(deps\) |
    \bsecurity\s+(and|&)\s+\w+\s+icons?\b
    """
)

# A change confined to tests cannot be a production vulnerability fix.
TEST_PATH = re.compile(
    r"(?i)(^|/)(src/test|tests?|test-|/testing)/|Test\.java$|Tests\.java$"
)

# From the hand labelling: of the commits this filter admits, the share that are
# genuinely security-relevant. Used to report the subset's purity alongside any
# rate measured on it, so dilution is visible rather than assumed away.
PURITY_ESTIMATE = 0.79


def is_security_relevant(message: str) -> bool:
    """True if the commit message asserts a security fix."""
    if NOT_SECURITY.search(message):
        return False
    return bool(SECURITY_TERMS.search(message))


def has_non_test_java(commit) -> bool:
    """True if at least one reconstructible Java file is outside test trees."""
    return any(
        not TEST_PATH.search(f.path) for f in commit.reconstructible_java_files
    )


def security_subset(commits, *, single_file: bool = True) -> list:
    """Commits that are plausibly security fixes touching real source.

    single_file keeps the measurement unambiguous: with several changed files, a
    hit on any one of them does not say which file carried the vulnerability.
    """
    out = []
    for c in commits:
        if not c.is_usable or not has_non_test_java(c):
            continue
        if single_file and len(c.reconstructible_java_files) != 1:
            continue
        if is_security_relevant(c.message):
            out.append(c)
    return out
