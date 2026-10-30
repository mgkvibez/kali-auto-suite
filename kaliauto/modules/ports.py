"""Port exposure via nmap, with a fixed argument template and no user-supplied flags."""

from __future__ import annotations

import shutil
import subprocess
from typing import Callable, List, Optional

from ..findings import Finding, ModuleUnavailable

RISKY = {
    "21": ("FTP open", "high"), "23": ("Telnet open", "high"), "445": ("SMB open", "medium"),
    "1433": ("MSSQL reachable", "medium"), "3306": ("MySQL reachable", "medium"),
    "3389": ("RDP reachable", "high"), "5432": ("PostgreSQL reachable", "medium"),
    "6379": ("Redis reachable", "high"), "9200": ("Elasticsearch reachable", "medium"),
    "27017": ("MongoDB reachable", "high"),
}


def plan(target: str, timeout: float = 5.0) -> str:
    return "TCP connect scan of the 100 most common ports on {} with nmap (-sT -Pn, no scripts)".format(target)


def argv(target: str, timeout: float = 5.0) -> List[str]:
    """The only way nmap is ever invoked: fixed flags, target validated upstream."""
    return ["nmap", "-sT", "-Pn", "--top-ports", "100", "-T3",
            "--host-timeout", "{}s".format(int(max(1, timeout * 4))), "-oG", "-", target]


def _run_nmap(args: List[str], timeout: float) -> str:
    proc = subprocess.run(args, capture_output=True, text=True, timeout=max(10.0, timeout * 4))
    return proc.stdout


def parse_greppable(output: str, target: str) -> List[Finding]:
    """Read nmap's greppable format, which is stable and machine-readable."""
    found: List[Finding] = []
    for line in output.splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        for entry in line.split("Ports:", 1)[1].split(","):
            parts = entry.strip().split("/")
            if len(parts) < 2 or parts[1].lower() != "open":
                continue
            port = parts[0]
            if port in RISKY:
                title, severity = RISKY[port]
                service = parts[4] if len(parts) > 4 else ""
                found.append(Finding("KAP001", title, severity, target,
                                     detail="port {} is open ({})".format(port, service).strip(),
                                     remediation="Close it at the firewall unless it is the service you intend "
                                                 "to expose, and never expose it to the internet unprotected."))
    return found


def run(target: str, timeout: float = 5.0, runner: Optional[Callable] = None) -> List[Finding]:
    runner = runner or _run_nmap
    if runner is _run_nmap and shutil.which("nmap") is None:
        raise ModuleUnavailable("nmap is not installed; skipping port checks rather than guessing")
    return parse_greppable(runner(argv(target, timeout), timeout), target)


def available() -> bool:
    return shutil.which("nmap") is not None
