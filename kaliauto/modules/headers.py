"""HTTP response headers that decide how much damage one injected script can do."""

from __future__ import annotations

import http.client
from typing import Callable, Dict, List, Optional

from ..findings import Finding


def plan(target: str, timeout: float = 5.0) -> str:
    return "one HEAD request to {}, read security headers and banners".format(target)


def _fetch(target: str, timeout: float) -> Dict[str, str]:
    host = target.split("/")[0]
    conn = http.client.HTTPSConnection(host, 443, timeout=timeout)
    try:
        conn.request("HEAD", "/", headers={"User-Agent": "kaliauto/0.1 (authorized recon)"})
        return {k.lower(): v for k, v in conn.getresponse().getheaders()}
    finally:
        conn.close()


def grade(headers: Dict[str, str], target: str, scheme: str = "https") -> List[Finding]:
    """Pure grading of a header map, so this is testable without a network."""
    h = {str(k).lower(): v for k, v in headers.items()}
    found: List[Finding] = []
    if scheme == "https" and "strict-transport-security" not in h:
        found.append(Finding("KAH001", "No HSTS header", "medium", target,
                             remediation="Send Strict-Transport-Security with a max-age of at least six months."))
    if "content-security-policy" not in h:
        found.append(Finding("KAH002", "No Content-Security-Policy", "medium", target,
                             remediation="Add a CSP; without one, a single injection runs with full script privileges."))
    if "x-content-type-options" not in h:
        found.append(Finding("KAH003", "No X-Content-Type-Options", "low", target,
                             remediation="Send X-Content-Type-Options: nosniff."))
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        found.append(Finding("KAH004", "No clickjacking protection", "low", target,
                             remediation="Send X-Frame-Options: DENY or frame-ancestors in the CSP."))
    for banner in ("server", "x-powered-by"):
        if banner in h and any(ch.isdigit() for ch in h[banner]):
            found.append(Finding("KAH005", "Version disclosed in headers", "low", target,
                                 detail="{}: {}".format(banner, h[banner])[:120],
                                 remediation="Drop the version from the header or remove the header entirely."))
    return found


def run(target: str, timeout: float = 5.0, fetch: Optional[Callable] = None) -> List[Finding]:
    fetch = fetch or _fetch
    try:
        headers = fetch(target, timeout)
    except (http.client.HTTPException, OSError) as exc:
        return [Finding("KAH000", "Could not read headers", "low", target, detail=str(exc)[:160],
                        remediation="Confirm the service answers HTTPS and is reachable from here.")]
    return grade(headers, target)


def available() -> bool:
    return True
