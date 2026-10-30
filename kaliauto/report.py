"""What a run looks like to a human, and to a script."""

from __future__ import annotations

import json
from typing import Dict, List

from . import CHECKSET, __version__
from .findings import Finding

COLOUR = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"


def summary_line(findings: List[Finding]) -> str:
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] += 1
    if not findings:
        return "No issues found by checkset {}".format(CHECKSET)
    return "{} finding(s): {} high, {} medium, {} low (checkset {})".format(
        len(findings), counts["high"], counts["medium"], counts["low"], CHECKSET)


def render_plan(targets: List[str], modules: List[str], scope, limit: float) -> str:
    lines = ["kaliauto {}  dry run (nothing has been sent)".format(__version__),
             "",
             "authorized by: {}   on {}".format(scope.authorized_by, scope.authorized_on),
             "reference:     {}".format(scope.authorization_reference),
             "contact:       {}".format(scope.contact),
             "scope file:    {}  (sha256 {})".format(scope.path, scope.fingerprint()),
             "rate limit:    {:.1f} request(s)/second per host".format(limit),
             ""]
    from .modules import plan_module
    for target in targets:
        lines.append(target)
        for module in modules:
            lines.append("  [{}] {}".format(module, plan_module(module, target)))
    lines.extend(["", "Run again with --execute to perform these checks."])
    return "\n".join(lines)


def render_text(findings: List[Finding], skipped: List[str], scope, colour: bool = True) -> str:
    def paint(text: str, code: str) -> str:
        return "{}{}{}".format(code, text, RESET) if colour else text

    out = [paint("kaliauto {}  checkset {}".format(__version__, CHECKSET), DIM),
           paint("authorized by {} ({}), scope {}".format(scope.authorized_by, scope.authorized_on, scope.fingerprint()), DIM),
           ""]
    grouped: Dict[str, List[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.target, []).append(f)
    for target in sorted(grouped):
        out.append(paint(target, BOLD))
        for f in sorted(grouped[target], key=lambda x: (-x.rank, x.check_id)):
            out.append("  {} {}  {}".format(paint(f.severity.upper().ljust(6), COLOUR[f.severity]), f.check_id, f.title))
            if f.detail:
                out.append("      " + paint(f.detail[:140], DIM))
            if f.remediation:
                out.append("      fix: " + f.remediation)
    out.append("")
    out.append(summary_line(findings))
    if skipped:
        out.append("")
        out.append(paint("skipped:", DIM))
        out.extend("  " + s for s in skipped)
    out.append(paint('Findings are bounded by checkset {}: "none found" is not "safe".'.format(CHECKSET), DIM))
    return "\n".join(out)


def render_json(findings: List[Finding], skipped: List[str], scope) -> str:
    return json.dumps({"tool": "kaliauto", "version": __version__, "checkset": CHECKSET,
                       "scope": {"path": scope.path, "sha256": scope.digest,
                                 "authorized_by": scope.authorized_by,
                                 "authorized_on": scope.authorized_on,
                                 "reference": scope.authorization_reference},
                       "summary": summary_line(findings),
                       "findings": [f.as_dict() for f in findings],
                       "skipped": list(skipped)}, indent=2)
