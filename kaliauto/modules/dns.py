"""DNS posture: does the name resolve, and does it publish the records that stop forgery?"""

from __future__ import annotations

import socket
import subprocess
from typing import Callable, List, Optional

from ..findings import Finding, ModuleUnavailable

IPAddresses = Callable[[str], List[str]]
TextRecords = Callable[[str, str], List[str]]


def plan(target: str, timeout: float = 5.0) -> str:
    return "resolve A/AAAA for {}, read TXT/CAA, check SPF and DMARC".format(target)


def _addresses(host: str) -> List[str]:
    infos = socket.getaddrinfo(host, None)
    return sorted({info[4][0] for info in infos})


def _dig(host: str, rrtype: str, runner=None) -> List[str]:
    if runner is not None:
        return runner(host, rrtype)
    try:
        out = subprocess.run(["dig", "+short", rrtype, host], capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        raise ModuleUnavailable("the 'dig' command is not available for TXT/CAA lookups")
    return [line.strip().strip('"') for line in out.stdout.splitlines() if line.strip()]


def run(target: str, timeout: float = 5.0, addresses: Optional[IPAddresses] = None,
        records: Optional[TextRecords] = None) -> List[Finding]:
    addresses = addresses or _addresses
    records = records or (lambda host, rrtype: _dig(host, rrtype))
    found: List[Finding] = []

    try:
        ips = addresses(target)
    except (socket.gaierror, OSError) as exc:
        return [Finding("KAD000", "Name does not resolve", "low", target,
                        detail="{} ({})".format(exc, type(exc).__name__),
                        remediation="Confirm the name is correct and published; nothing else can be checked if it does not resolve.")]
    if not ips:
        found.append(Finding("KAD001", "No A/AAAA record", "low", target,
                             remediation="Publish an address record if this name is meant to be reachable."))
    try:
        txt = records(target, "TXT")
        caa = records(target, "CAA")
    except ModuleUnavailable as exc:
        txt, caa = [], []
        found.append(Finding("KAD900", "Partial DNS check", "low", target, detail=str(exc),
                             remediation="Install a resolver client for full TXT/CAA coverage; both checks were skipped."))

    joined = " ".join(txt).lower()
    if txt and "v=spf1" not in joined:
        found.append(Finding("KAD004", "No SPF policy in TXT", "medium", target,
                             remediation="Publish v=spf1 with an explicit -all so receivers can reject forged senders."))
    if txt and not any(t.lower().startswith("v=dmarc1") for t in txt):
        found.append(Finding("KAD003", "No DMARC record", "medium", target,
                             remediation="Publish a _dmarc TXT record starting v=DMARC1 with policy quarantine or reject."))
    if txt and not caa:
        found.append(Finding("KAD002", "No CAA records", "low", target,
                             remediation="Publish CAA records naming the certificate authorities you actually use."))
    return found


def available() -> bool:
    return True
