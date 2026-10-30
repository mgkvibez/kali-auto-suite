"""kaliauto command line.

Exit codes are a contract:
  0  clean, or a dry run that only planned
  2  the invocation itself is wrong
  3  findings at or above the threshold
  4  refused: the target or the authorization is not in scope
  5  a dependency is missing for a requested module
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import CHECKSET, MODULES, __version__
from .audit import AuditLog
from .findings import ModuleUnavailable, sort_findings
from .modules import available, plan_module, run_module
from .ratelimit import RateLimiter
from .report import render_json, render_plan, render_text, summary_line
from .scope import ScopeError, days_since_authorization, load_scope, targets_for_run

EXIT_CLEAN, EXIT_USAGE, EXIT_FINDINGS, EXIT_REFUSED, EXIT_DEPENDENCY = 0, 2, 3, 4, 5


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kaliauto",
                                description="Authorized, non-destructive recon. Scope-gated, dry-run by default, audited.")
    p.add_argument("--version", action="version", version="kaliauto {} (checkset {})".format(__version__, CHECKSET))
    sub = p.add_subparsers(dest="cmd")

    def common(sp):
        sp.add_argument("--scope", required=True, help="JSON scope file naming who authorized the work")
        sp.add_argument("--targets", help="comma-separated subset of the scope, still checked against it")
        sp.add_argument("--modules", default=",".join(MODULES))
        sp.add_argument("--timeout", type=float, default=5.0)
        sp.add_argument("--max-rate", type=float, default=1.0, help="requests per second per host (default 1)")

    s = sub.add_parser("scan", help="run checks (dry run unless --execute is given)")
    common(s)
    s.add_argument("--execute", action="store_true", help="actually send traffic; without this only a plan is printed")
    s.add_argument("--json", action="store_true")
    s.add_argument("--no-colour", "--no-color", dest="no_colour", action="store_true")

    sub.add_parser("modules", help="list modules and whether their dependency is present")
    sc = sub.add_parser("scope", help="validate a scope file and show who authorized what")
    sc.add_argument("--scope", required=True)
    return p


def _modules_arg(raw: str) -> List[str]:
    wanted = [m.strip() for m in raw.split(",") if m.strip()]
    unknown = [m for m in wanted if m not in MODULES]
    if unknown:
        raise ValueError("unknown module(s): {}. Available: {}".format(", ".join(unknown), ", ".join(MODULES)))
    return wanted


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd is None:
        parser.print_help()
        return EXIT_USAGE

    if args.cmd == "modules":
        state = available()
        for name in MODULES:
            print("  {:8} {}".format(name, "ready" if state[name] else "dependency missing"))
        return EXIT_CLEAN

    audit = AuditLog()
    try:
        if args.cmd == "scope":
            scope = load_scope(args.scope)
            age = days_since_authorization(scope)
            print("scope:       {}  sha256 {}".format(scope.path, scope.fingerprint()))
            print("authorized:  {} on {}".format(scope.authorized_by, scope.authorized_on))
            print("reference:   {}".format(scope.authorization_reference))
            print("contact:     {}".format(scope.contact))
            print("targets:     {}".format(", ".join(scope.targets)))
            print("private ok:  {}".format(scope.allow_private))
            if age is not None:
                print("age:         {} day(s) since authorization".format(age))
            audit.record("scope_validated", scope=scope.path, digest=scope.digest)
            return EXIT_CLEAN

        modules = _modules_arg(args.modules)
    except (ScopeError, ValueError) as exc:
        audit.record("refused", reason=str(exc), scope=getattr(args, "scope", ""))
        print("refused: {}".format(exc), file=sys.stderr)
        return EXIT_REFUSED if isinstance(exc, ScopeError) else EXIT_USAGE

    try:
        scope = load_scope(args.scope)
        requested = [t.strip() for t in args.targets.split(",")] if args.targets else None
        targets = targets_for_run(scope, requested)
    except ScopeError as exc:
        audit.record("refused", reason=str(exc), scope=args.scope)
        print("refused: {}".format(exc), file=sys.stderr)
        print("(this refusal is recorded in the audit log)", file=sys.stderr)
        return EXIT_REFUSED

    if not args.execute:
        print(render_plan(targets, modules, scope, args.max_rate))
        audit.record("plan", scope=scope.path, digest=scope.digest, targets=targets, modules=modules)
        return EXIT_CLEAN

    limiter = RateLimiter(per_second=args.max_rate)
    findings, skipped = [], []
    for target in targets:
        host = target.split("/")[0]
        for module in modules:
            limiter.wait(host)
            audit.record("module_start", scope=scope.digest, target=target, module=module)
            try:
                findings.extend(run_module(module, target, timeout=args.timeout))
            except ModuleUnavailable as exc:
                skipped.append("{} / {}: {}".format(target, module, exc))
                audit.record("module_skipped", target=target, module=module, reason=str(exc))

    findings = sort_findings(findings)
    audit.record("scan_complete", scope=scope.digest, targets=targets,
                 modules=modules, findings=len(findings), summary=summary_line(findings))

    if args.json:
        print(render_json(findings, skipped, scope))
    else:
        print(render_text(findings, skipped, scope, colour=not args.no_colour))
    if skipped and not findings:
        return EXIT_DEPENDENCY
    return EXIT_FINDINGS if findings else EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
