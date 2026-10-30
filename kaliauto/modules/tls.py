"""Certificate and protocol posture for one host:port."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from ..findings import Finding


def plan(target: str, timeout: float = 5.0) -> str:
    return "TLS handshake with {}, read certificate subject/issuer/expiry and negotiated protocol".format(target)


def _probe(target: str, port: int, timeout: float) -> Dict:
    host = target.split("/")[0]
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            return {"protocol": tls.version(), "expires": cert.get("notAfter", ""),
                    "issuer": dict(x[0] for x in cert.get("issuer", ())).get("organizationName", ""),
                    "subject": dict(x[0] for x in cert.get("subject", ())).get("commonName", ""),
                    "verified": True}


def _expiry(not_after: str) -> Optional[datetime]:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ"):
        try:
            return datetime.strptime(not_after, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def grade(probe: Dict, target: str, now: Optional[datetime] = None) -> List[Finding]:
    """Pure grading, so the rules are testable without a socket."""
    now = now or datetime.now(timezone.utc)
    found: List[Finding] = []
    if not probe.get("verified", True):
        found.append(Finding("KAT004", "Certificate did not verify", "high", target,
                             detail=str(probe.get("error", "handshake verification failed")),
                             remediation="Serve a certificate from a trusted CA that matches the hostname."))
    protocol = str(probe.get("protocol") or "")
    if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        found.append(Finding("KAT003", "Obsolete TLS version negotiated", "high", target, detail=protocol,
                             remediation="Disable TLS 1.0 and 1.1; serve TLS 1.2 or newer only."))
    expiry = _expiry(str(probe.get("expires", "")))
    if expiry is not None:
        days = (expiry - now).days
        if days < 0:
            found.append(Finding("KAT001", "Certificate has expired", "high", target,
                                 detail="expired {} day(s) ago".format(-days),
                                 remediation="Renew the certificate; most clients reject an expired one outright."))
        elif days <= 30:
            found.append(Finding("KAT002", "Certificate expires soon", "medium", target,
                                 detail="{} day(s) left".format(days),
                                 remediation="Renew now, and check that automated renewal is actually firing."))
    return found


def run(target: str, timeout: float = 5.0, port: int = 443, probe: Optional[Callable] = None) -> List[Finding]:
    probe = probe or _probe
    try:
        result = probe(target, port, timeout)
    except ssl.SSLCertVerificationError as exc:
        return grade({"verified": False, "error": getattr(exc, "verify_message", "") or str(exc)}, target)
    except ssl.SSLError as exc:
        return [Finding("KAT005", "TLS handshake failed", "medium", target, detail=str(exc)[:160],
                        remediation="Confirm the service speaks TLS on this port and supports a modern version.")]
    except (socket.timeout, TimeoutError):
        return [Finding("KAT006", "TLS handshake timed out", "low", target, detail="timeout after {}s".format(timeout),
                        remediation="Check reachability and whether the service is accepting connections.")]
    except OSError as exc:
        return [Finding("KAT007", "Could not connect", "low", target, detail=str(exc)[:160],
                        remediation="Confirm the host and port are reachable from where you are running this.")]
    return grade(result, target)


def available() -> bool:
    return True
